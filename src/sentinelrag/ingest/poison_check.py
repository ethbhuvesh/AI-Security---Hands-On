"""
Data poisoning and backdoor detection at ingest time.

TWO DIFFERENT ATTACKS, OFTEN CONFUSED
-------------------------------------
* TRAINING-TIME poisoning: attacker gets bad data into the corpus a model is
  trained/fine-tuned on, implanting a *backdoor* -- the model behaves normally
  until it sees a rare trigger phrase ("cf7x9"), then misbehaves. You cannot fix
  this at inference time; you fix it by controlling and auditing the data.

* RAG poisoning (a.k.a. knowledge-base poisoning / PoisonedRAG): attacker adds
  documents to your *retrieval* corpus. No training involved. They craft text
  that ranks highly for a target question and contains false facts or embedded
  instructions. This is far easier to pull off and is what most real systems
  face -- anything that ingests wiki pages, tickets, shared drives or scraped
  web content is exposed.

WHAT THIS MODULE CHECKS
-----------------------
1. Trust tier from provenance   -- untrusted sources can never outrank trusted ones.
2. Retrieval-flooding           -- many near-identical chunks (a classic way to
                                   dominate the top-k for a target query).
3. Anomalous keyword stuffing   -- unnatural repetition to game similarity search.
4. Rare-trigger detection       -- low-frequency tokens repeated across documents
                                   (the signature of a backdoor trigger).
5. Embedded instructions        -- delegates to input_guard (indirect injection).

Nothing here is a perfect classifier. The point is to QUARANTINE rather than
silently ingest, and to make a human look at anything odd.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

import numpy as np

from sentinelrag.audit import log_event
from sentinelrag.guardrails.input_guard import Action, inspect

TRUST_TIERS = {"trusted": 3, "internal": 2, "untrusted": 1, "unclassified": 0}


@dataclass
class PoisonReport:
    accepted: bool = True
    quarantined: bool = False
    reasons: list[str] = field(default_factory=list)
    injection_score: float = 0.0


def keyword_stuffing_score(text: str) -> float:
    """
    Natural prose has a characteristic word-frequency distribution. A chunk
    written to dominate similarity search for one query repeats that query's
    terms far more than a human would. We measure the share of the most common
    non-stopword.
    """
    words = re.findall(r"[a-z]{4,}", text.lower())
    if len(words) < 30:
        return 0.0
    counts = Counter(words)
    top_word, top_count = counts.most_common(1)[0]
    share = top_count / len(words)
    # >12% of a chunk being one word is very unusual in real documents.
    return max(0.0, min((share - 0.12) / 0.20, 1.0))


def repetition_entropy(text: str) -> float:
    """Low entropy over word bigrams = templated/duplicated filler."""
    words = re.findall(r"\w+", text.lower())
    if len(words) < 20:
        return 1.0
    bigrams = Counter(zip(words, words[1:]))
    total = sum(bigrams.values())
    return -sum((c / total) * math.log2(c / total) for c in bigrams.values()) / math.log2(total)


def find_rare_triggers(chunks: list[str], *, min_docs: int = 3) -> list[str]:
    """
    A backdoor trigger is a token that (a) is not a real word, and (b) appears
    across several otherwise unrelated documents. Legitimate corpora rarely
    contain the same nonsense string in many places.
    """
    token_docs: dict[str, set[int]] = {}
    for i, chunk in enumerate(chunks):
        for token in set(re.findall(r"\b[a-z0-9]{4,12}\b", chunk.lower())):
            # crude "not a real word" test: mixes letters and digits, or has no vowels
            if re.search(r"\d", token) and re.search(r"[a-z]", token):
                token_docs.setdefault(token, set()).add(i)
            elif not re.search(r"[aeiou]", token):
                token_docs.setdefault(token, set()).add(i)
    return sorted(t for t, docs in token_docs.items() if len(docs) >= min_docs)


def detect_near_duplicates(vectors: np.ndarray, *, threshold: float = 0.97) -> list[tuple[int, int]]:
    """Pairs of chunks whose embeddings are almost identical (flooding)."""
    if vectors.shape[0] < 2:
        return []
    similarity = vectors @ vectors.T
    np.fill_diagonal(similarity, 0.0)
    pairs = np.argwhere(similarity > threshold)
    return [(int(a), int(b)) for a, b in pairs if a < b]


def screen_chunk(text: str, *, source: str, trust: str) -> PoisonReport:
    """Per-chunk screening. Returns whether to accept, quarantine or reject."""
    report = PoisonReport()

    verdict = inspect(text, source=f"document:{source}", use_judge=False)
    report.injection_score = verdict.score
    if verdict.action is Action.BLOCK:
        report.accepted = False
        report.quarantined = True
        report.reasons.append(f"embedded_instructions:{','.join(verdict.signals[:4])}")
    elif verdict.action is Action.FLAG:
        report.reasons.append(f"suspicious_instructions:{','.join(verdict.signals[:4])}")

    stuffing = keyword_stuffing_score(text)
    if stuffing > 0.5:
        report.reasons.append(f"keyword_stuffing:{stuffing:.2f}")
        if trust == "untrusted":
            report.accepted = False
            report.quarantined = True

    if repetition_entropy(text) < 0.55:
        report.reasons.append("low_entropy_repetition")

    if report.reasons:
        log_event(
            "poison_screen",
            source=source,
            trust=trust,
            accepted=report.accepted,
            reasons=report.reasons,
        )
    return report
