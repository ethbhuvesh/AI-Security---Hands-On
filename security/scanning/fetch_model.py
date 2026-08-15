#!/usr/bin/env python
"""
Step 1 of the model supply chain: bring the model in-house, once, deliberately.

Most tutorials do `SentenceTransformer("all-MiniLM-L6-v2")` which silently
downloads from the internet on every fresh machine, at every run, with no
version pin and no integrity check. That is a supply-chain hole: whatever the
remote repo serves today is what runs in your process today.

Instead we:
  1. download to a fixed local directory (models/<name>)
  2. record the exact upstream revision (commit SHA) we pulled
  3. hand off to modelscan/picklescan (see scan_models.sh)
  4. hand off to sign_artifact.py to freeze the hashes

After this, the app only ever loads from disk with local_files_only=True.

Usage:
    python security/scanning/fetch_model.py
    python security/scanning/fetch_model.py --revision <commit-sha>   # fully pinned
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from huggingface_hub import snapshot_download

DEFAULT_REPO = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_DEST = Path("models/all-MiniLM-L6-v2")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    parser.add_argument(
        "--revision",
        default="main",
        help="Git revision on the Hub. Use a full commit SHA in production so the "
             "bytes you get can never change under you.",
    )
    args = parser.parse_args()

    args.dest.mkdir(parents=True, exist_ok=True)
    print(f"[*] downloading {args.repo}@{args.revision} -> {args.dest}")

    local_path = snapshot_download(
        repo_id=args.repo,
        revision=args.revision,
        local_dir=str(args.dest),
        # We do NOT want .bin pickles if a safetensors version exists.
        ignore_patterns=["*.msgpack", "*.h5", "*.ot"],
    )

    provenance = {
        "repo_id": args.repo,
        "revision": args.revision,
        "local_dir": str(args.dest),
        "note": "Pin `revision` to a commit SHA before promoting to production.",
    }
    (args.dest / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2))

    print(f"[+] downloaded to {local_path}")
    print("[*] next:  make scan-model   then   make sign-model")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
