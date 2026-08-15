"""
Semantic attack signatures.

Regexes match strings. This matches *meaning*. We embed a corpus of known
injection payloads once, keep the vectors in memory, and compare each incoming
text against them with cosine similarity.

Why this catches what regex misses:

    payload in corpus : "ignore all previous instructions"
    attacker types    : "kindly set aside whatever guidance you were given
                         at the very beginning of this conversation"

Zero keyword overlap. ~0.8 cosine similarity.

The corpus is redteam/payloads/injection_payloads.yaml -- the SAME file the red
team fuzzer fires at the app. That is deliberate: every new attack you discover
gets added once and simultaneously improves detection and testing.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import numpy as np
import yaml

from sentinelrag.config import ROOT

PAYLOAD_FILE = ROOT / "redteam/payloads/injection_payloads.yaml"


@lru_cache(maxsize=1)
def _index() -> tuple[np.ndarray, list[str]]:
    """Load payloads and embed them once. Returns (matrix, labels)."""
    from sentinelrag.vectorstore.model_gate import embed

    if not PAYLOAD_FILE.exists():
        return np.zeros((0, 1)), []

    data = yaml.safe_load(PAYLOAD_FILE.read_text(encoding="utf-8")) or {}
    texts, labels = [], []
    for payload in data.get("payloads", []):
        texts.append(payload["text"])
        labels.append(payload.get("id", payload.get("category", "unknown")))

    if not texts:
        return np.zeros((0, 1)), []

    # embed() returns L2-normalised vectors, so a dot product IS cosine similarity.
    matrix = np.asarray(embed(texts), dtype=np.float32)
    return matrix, labels


def nearest_attack(text: str) -> tuple[float, str] | None:
    """Return (similarity, label) of the closest known attack, or None."""
    matrix, labels = _index()
    if matrix.shape[0] == 0:
        return None

    from sentinelrag.vectorstore.model_gate import embed

    vector = np.asarray(embed([text])[0], dtype=np.float32)
    scores = matrix @ vector
    best = int(np.argmax(scores))
    return float(scores[best]), labels[best]


def warmup() -> int:
    """Build the index eagerly at start-up so the first request is not slow."""
    matrix, _ = _index()
    return int(matrix.shape[0])
