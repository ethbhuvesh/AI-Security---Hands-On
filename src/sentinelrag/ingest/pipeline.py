"""
The ingest pipeline: untrusted files in, screened + provenance-tagged chunks out.

    file  ->  load  ->  sanitize  ->  chunk  ->  poison screen  ->  index
                                                       |
                                                       +-> quarantine collection

Run it:
    python -m sentinelrag.ingest.pipeline --source data/knowledge_base
    python -m sentinelrag.ingest.pipeline --source data/knowledge_base --dry-run

TRUST TIERS COME FROM THE DIRECTORY LAYOUT
------------------------------------------
    data/knowledge_base/trusted/     -> reviewed, internally authored
    data/knowledge_base/internal/    -> internal but not reviewed
    data/knowledge_base/untrusted/   -> scraped web, user uploads, tickets

This is deliberately dumb and visible. Security controls that depend on someone
remembering to set a flag get bypassed; controls encoded in the folder you drop
a file into do not.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import numpy as np

from sentinelrag.audit import log_event
from sentinelrag.config import ROOT
from sentinelrag.ingest.poison_check import (
    detect_near_duplicates,
    find_rare_triggers,
    screen_chunk,
)
from sentinelrag.ingest.sanitize import chunk_text, sanitize
from sentinelrag.vectorstore.model_gate import embed
from sentinelrag.vectorstore.store import Chunk, add_chunks, stats

TEXT_SUFFIXES = {".md", ".txt", ".html", ".htm", ".rst", ".json", ".csv"}


def trust_of(path: Path, root: Path) -> str:
    parts = path.relative_to(root).parts
    for tier in ("trusted", "internal", "untrusted"):
        if tier in parts:
            return tier
    return "unclassified"


def load_text(path: Path) -> str | None:
    if path.suffix.lower() == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError:
            print(f"  ! skipping {path.name}: pypdf not installed")
            return None
        reader = PdfReader(str(path))
        return "\n\n".join(page.extract_text() or "" for page in reader.pages)
    if path.suffix.lower() in TEXT_SUFFIXES:
        return path.read_text(encoding="utf-8", errors="replace")
    return None


def run(source_dir: Path, *, dry_run: bool = False) -> dict:
    accepted: list[Chunk] = []
    quarantined: list[Chunk] = []
    all_texts: list[str] = []

    files = sorted(p for p in source_dir.rglob("*") if p.is_file())
    print(f"[*] scanning {len(files)} files under {source_dir}")

    for path in files:
        raw = load_text(path)
        if raw is None:
            continue

        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        trust = trust_of(path, source_dir)
        source = str(path.relative_to(ROOT))

        clean = sanitize(raw)
        if clean.removed:
            print(f"  ! {source}: removed hidden content -> {clean.removed}")
            log_event("sanitizer_removed", source=source, removed=clean.removed,
                      trust=trust, file_sha256=file_hash)

        for i, piece in enumerate(chunk_text(clean.text)):
            report = screen_chunk(piece, source=source, trust=trust)
            all_texts.append(piece)

            chunk = Chunk(
                text=piece,
                source=source,
                trust=trust,
                flagged=bool(report.reasons),
                score=report.injection_score,
                metadata={
                    "file_sha256": file_hash,
                    "chunk_index": i,
                    "sanitizer_removed": ",".join(clean.removed),
                    "screen_reasons": ",".join(report.reasons),
                },
            )
            (quarantined if not report.accepted else accepted).append(chunk)
            if not report.accepted:
                print(f"  x QUARANTINED {source}#{i}: {report.reasons}")

    # --- corpus-level checks (need every chunk together) --------------------
    triggers = find_rare_triggers(all_texts)
    if triggers:
        print(f"  ! possible backdoor triggers repeated across documents: {triggers[:10]}")
        log_event("rare_trigger_tokens", tokens=triggers[:50])

    if accepted and not dry_run:
        vectors = np.asarray(embed([c.text for c in accepted]), dtype=np.float32)
        duplicates = detect_near_duplicates(vectors)
        if duplicates:
            print(f"  ! {len(duplicates)} near-duplicate chunk pairs (possible retrieval flooding)")
            log_event("near_duplicate_chunks", pairs=len(duplicates))
            for a, _ in duplicates:
                accepted[a].flagged = True

    if dry_run:
        print(f"\n[dry-run] would index {len(accepted)}, quarantine {len(quarantined)}")
        return {"indexed": 0, "quarantined": 0}

    add_chunks(accepted)
    add_chunks(quarantined, quarantine=True)

    result = stats()
    print(f"\n[+] indexed={result['indexed']} quarantined={result['quarantined']}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Screen and index the knowledge base")
    parser.add_argument("--source", type=Path, default=ROOT / "data/knowledge_base")
    parser.add_argument("--dry-run", action="store_true", help="screen only, do not write")
    args = parser.parse_args()

    if not args.source.exists():
        print(f"[!] {args.source} does not exist")
        return 2
    run(args.source.resolve(), dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
