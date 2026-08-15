"""
Audit logging.

Security controls that leave no evidence are not security controls -- you can
never prove whether they fired. Every decision this system makes (blocked a
prompt, dropped a poisoned chunk, refused a tool call) is written here as one
JSON object per line.

Two extra properties worth understanding:

1. We log HASHES of user text, not the text itself. If your audit log stores raw
   prompts, the log itself becomes a sensitive-information-disclosure target
   (OWASP LLM02). A hash lets you correlate "this exact prompt appeared 400
   times" without storing the content.

2. Each record carries `prev` -- the hash of the previous record. That chains
   the log together. If an attacker deletes or edits a middle entry, the chain
   breaks and `verify_chain()` will tell you exactly where.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

from sentinelrag.config import settings

_lock = threading.Lock()
_GENESIS = "0" * 64


def sha256_text(text: str) -> str:
    """Stable hash of a piece of text. Used for redacted logging + pinning."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return _GENESIS
    with path.open("rb") as fh:
        # Read only the final line -- cheap even for a large log.
        try:
            fh.seek(-4096, 2)
        except OSError:
            fh.seek(0)
        last = fh.read().decode("utf-8", "ignore").strip().splitlines()[-1]
    return json.loads(last)["self"]


def log_event(event: str, **fields: Any) -> dict:
    """Append one structured, hash-chained event."""
    path = settings.audit_path
    path.parent.mkdir(parents=True, exist_ok=True)

    with _lock:
        record = {
            "ts": time.time(),
            "event": event,
            "prev": _last_hash(path),
            **fields,
        }
        # `self` is the hash of everything above it -> makes the chain verifiable.
        payload = json.dumps(record, sort_keys=True, default=str)
        record["self"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    return record


def verify_chain(path: Path | None = None) -> tuple[bool, int]:
    """Return (is_intact, index_of_first_broken_record)."""
    path = path or settings.audit_path
    if not path.exists():
        return True, -1

    expected_prev = _GENESIS
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        record = json.loads(line)
        claimed_self = record.pop("self")
        if record["prev"] != expected_prev:
            return False, i
        payload = json.dumps(record, sort_keys=True, default=str)
        if hashlib.sha256(payload.encode("utf-8")).hexdigest() != claimed_self:
            return False, i
        expected_prev = claimed_self
    return True, -1


if __name__ == "__main__":  # `python -m sentinelrag.audit` verifies the log
    ok, idx = verify_chain()
    print("audit log intact" if ok else f"AUDIT LOG TAMPERED at record {idx}")
