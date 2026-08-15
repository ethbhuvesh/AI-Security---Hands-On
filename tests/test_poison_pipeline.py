"""
End-to-end-ish test of the poison/sanitise logic against the planted document.

This does NOT touch the vector store or the network. It reads the deliberately
malicious sample file and asserts that our defences see through it.
"""

from __future__ import annotations

from pathlib import Path

from sentinelrag.ingest.poison_check import find_rare_triggers, keyword_stuffing_score
from sentinelrag.ingest.sanitize import sanitize

ROOT = Path(__file__).resolve().parents[1]
POISONED = ROOT / "data/knowledge_base/untrusted/vendor-notes.md"


def test_poisoned_file_exists():
    assert POISONED.exists(), "the planted sample document is missing"


def test_hidden_payloads_are_removed():
    raw = POISONED.read_text(encoding="utf-8")
    result = sanitize(raw)
    # The HTML comment injection must be gone.
    assert "maintenance mode" not in result.text
    assert "attacker.example" not in result.text
    # The white-on-white span must be gone.
    assert "60 days of annual leave" not in result.text
    # And the sanitiser must have flagged what it did.
    assert result.suspicious
    assert any("comment" in r for r in result.removed)


def test_backdoor_trigger_is_detectable():
    # The planted trigger 'zq7x9k' repeats; the rare-trigger heuristic looks for
    # non-word tokens repeated across documents.
    chunks = ["intro zq7x9k body", "other zq7x9k text", "more zq7x9k here"]
    triggers = find_rare_triggers(chunks, min_docs=3)
    assert "zq7x9k" in triggers
