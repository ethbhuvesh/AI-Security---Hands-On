"""
The load-time integrity gate.

Signing a model is useless if nothing checks the signature. This module is the
*enforcement point*: the embedding model cannot be loaded unless its files still
match the signed MANIFEST.json.

This is deliberately the ONLY place in the codebase that constructs a
SentenceTransformer. Centralising it means there is exactly one door to guard.
"""

from __future__ import annotations

import json
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

from sentinelrag.audit import log_event
from sentinelrag.config import ROOT, settings

MANIFEST_NAME = "MANIFEST.json"


class ModelIntegrityError(RuntimeError):
    """Raised when a model artifact fails verification. Fail closed, never open."""


def verify_model_dir(model_dir: Path) -> None:
    """Re-run the hash comparison. Raises ModelIntegrityError on any mismatch."""
    manifest = model_dir / MANIFEST_NAME
    if not manifest.exists():
        raise ModelIntegrityError(
            f"No {MANIFEST_NAME} in {model_dir}. "
            f"Run: python security/signing/sign_artifact.py sign {model_dir}"
        )

    result = subprocess.run(  # noqa: S603 -- fixed argv, no shell interpolation
        [sys.executable, str(ROOT / "security/signing/sign_artifact.py"), "verify", str(model_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        log_event("model_integrity_failed", model_dir=str(model_dir), detail=result.stdout[-2000:])
        raise ModelIntegrityError(f"Model integrity check FAILED:\n{result.stdout}")

    n_files = len(json.loads(manifest.read_text())["files"])
    log_event("model_integrity_ok", model_dir=str(model_dir), files=n_files)


@lru_cache(maxsize=1)
def load_embedding_model():
    """Return a verified SentenceTransformer. Cached so we only load once."""
    from sentence_transformers import SentenceTransformer  # imported late: it is heavy

    model_dir = settings.model_dir_path
    if settings.enforce_model_signature:
        verify_model_dir(model_dir)
    else:
        log_event("model_integrity_skipped", model_dir=str(model_dir), reason="disabled_in_config")

    # local_files_only: never silently re-download from the internet at runtime.
    return SentenceTransformer(str(model_dir), local_files_only=True)


def embed(texts: list[str]) -> list[list[float]]:
    model = load_embedding_model()
    return model.encode(texts, normalize_embeddings=True).tolist()
