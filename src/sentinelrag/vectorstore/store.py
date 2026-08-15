"""
The vector database layer.

We use Chroma in persistent local mode -- no server, no credentials, easy to
inspect. Swapping in Qdrant/pgvector later means changing only this file.

SECURITY DESIGN DECISIONS
-------------------------
1. EVERY chunk carries provenance metadata: source path, sha256 of the original
   file, trust tier, ingest timestamp, and the injection score it got at ingest.
   Without this you can never answer "which document made the model say that?"
   after an incident.

2. Retrieval is TRUST-WEIGHTED. Raw cosine similarity is exactly what a
   PoisonedRAG attacker optimises against. We re-rank so that a trusted internal
   policy document beats a slightly-more-similar untrusted scraped page.

3. There is a SEPARATE collection for quarantined content. It is stored (so you
   can investigate) but never retrieved into a prompt.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import chromadb
from chromadb.config import Settings as ChromaSettings

from sentinelrag.audit import log_event
from sentinelrag.config import settings
from sentinelrag.ingest.poison_check import TRUST_TIERS
from sentinelrag.vectorstore.model_gate import embed

QUARANTINE_SUFFIX = "_quarantine"


@dataclass
class Chunk:
    text: str
    source: str
    trust: str = "unclassified"
    flagged: bool = False
    score: float = 0.0
    metadata: dict[str, Any] | None = None


def _client() -> chromadb.ClientAPI:
    settings.chroma_path.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(
        path=str(settings.chroma_path),
        settings=ChromaSettings(anonymized_telemetry=False),  # do not phone home
    )


def get_collection(name: str | None = None):
    name = name or settings.collection_name
    # We pass embeddings in ourselves, so Chroma must not fetch its own model.
    return _client().get_or_create_collection(name=name, embedding_function=None)


def chunk_id(source: str, index: int, text: str) -> str:
    """Deterministic ID = re-ingesting the same file updates instead of duplicating."""
    return hashlib.sha256(f"{source}:{index}:{text}".encode()).hexdigest()[:32]


def add_chunks(chunks: list[Chunk], *, quarantine: bool = False) -> int:
    if not chunks:
        return 0

    collection = get_collection(
        (settings.collection_name + QUARANTINE_SUFFIX) if quarantine else None
    )
    texts = [c.text for c in chunks]
    vectors = embed(texts)

    collection.upsert(
        ids=[chunk_id(c.source, i, c.text) for i, c in enumerate(chunks)],
        embeddings=vectors,
        documents=texts,
        metadatas=[
            {
                "source": c.source,
                "trust": c.trust,
                "flagged": c.flagged,
                "injection_score": c.score,
                **(c.metadata or {}),
            }
            for c in chunks
        ],
    )
    log_event("chunks_indexed", count=len(chunks), quarantine=quarantine)
    return len(chunks)


def search(query: str, *, k: int = 5, min_trust: str = "unclassified") -> list[Chunk]:
    """
    Trust-weighted retrieval.

    We over-fetch (3k), then re-rank with:
        final = similarity * (1 + 0.12 * trust_rank) - 0.25 * flagged
    so a poisoned untrusted chunk has to be dramatically more similar than a
    trusted one to win. Tune the weights; the principle is what matters.
    """
    collection = get_collection()
    if collection.count() == 0:
        return []

    query_vector = embed([query])[0]
    raw = collection.query(
        query_embeddings=[query_vector],
        n_results=min(k * 3, max(collection.count(), 1)),
        include=["documents", "metadatas", "distances"],
    )

    floor = TRUST_TIERS.get(min_trust, 0)
    scored: list[tuple[float, Chunk]] = []

    for doc, meta, distance in zip(
        raw["documents"][0], raw["metadatas"][0], raw["distances"][0]
    ):
        trust = str(meta.get("trust", "unclassified"))
        trust_rank = TRUST_TIERS.get(trust, 0)
        if trust_rank < floor:
            continue

        similarity = 1.0 - float(distance)          # cosine distance -> similarity
        flagged = bool(meta.get("flagged", False))
        final = similarity * (1 + 0.12 * trust_rank) - (0.25 if flagged else 0.0)

        scored.append((final, Chunk(
            text=doc,
            source=str(meta.get("source", "unknown")),
            trust=trust,
            flagged=flagged,
            score=round(similarity, 4),
            metadata=dict(meta),
        )))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [chunk for _, chunk in scored[:k]]


def stats() -> dict:
    main = get_collection()
    quarantine = get_collection(settings.collection_name + QUARANTINE_SUFFIX)
    return {"indexed": main.count(), "quarantined": quarantine.count()}
