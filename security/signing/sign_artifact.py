#!/usr/bin/env python
"""
Artifact integrity: hash -> manifest -> signature -> verify-at-load.

THE PROBLEM
-----------
You download a model from Hugging Face. How do you know that the file on your
disk today is the same file the author published? You don't -- unless you pin
its hash. And how do you know the author is who they claim to be? You don't --
unless it is signed.

Real incidents this prevents:
  * A repo is renamed/hijacked and a backdoored model is served under the same
    path (a "model backdoor" / supply-chain attack).
  * A `.bin`/`.pt` pickle file that executes code on `torch.load()`.
  * Silent local tampering -- someone with disk access swaps your embedding
    model for one that maps "confidential" near "public".

WHAT THIS SCRIPT DOES
---------------------
  sign   <dir>  : walk the directory, SHA-256 every file, write MANIFEST.json,
                  then (optionally) sign MANIFEST.json with Sigstore.
  verify <dir>  : recompute all hashes, compare to MANIFEST.json, and verify the
                  Sigstore signature if one exists.

Sigstore is "keyless" signing: instead of you managing a private key (which can
leak), you authenticate with an identity provider (Google/GitHub), Sigstore
issues a short-lived certificate, signs, and records the signature in a public
transparency log called Rekor. Verification checks "was this signed by identity
X, and is it in the log?".

Usage:
    python security/signing/sign_artifact.py sign   models/
    python security/signing/sign_artifact.py verify models/
    python security/signing/sign_artifact.py sign models/ --sigstore   # interactive
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

MANIFEST_NAME = "MANIFEST.json"
SIGNATURE_NAME = "MANIFEST.json.sigstore.json"
# Files we never include in the manifest (they are the manifest itself).
SKIP = {MANIFEST_NAME, SIGNATURE_NAME}


def sha256_file(path: Path) -> str:
    """Stream the file in chunks so a 5 GB model does not blow up your RAM."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path) -> dict:
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name not in SKIP:
            files[str(path.relative_to(root))] = sha256_file(path)
    return {"version": 1, "root": root.name, "files": files}


def cmd_sign(root: Path, use_sigstore: bool) -> int:
    manifest = build_manifest(root)
    manifest_path = root / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[+] wrote {manifest_path} covering {len(manifest['files'])} files")

    if use_sigstore:
        # `sigstore` CLI ships with the `sigstore` pip package.
        # It opens a browser for OIDC login, then writes a bundle file.
        print("[*] launching Sigstore keyless signing (browser login required)...")
        result = subprocess.run(  # noqa: S603  (fixed argv, no shell)
            [sys.executable, "-m", "sigstore", "sign", str(manifest_path)],
            check=False,
        )
        if result.returncode != 0:
            print("[!] sigstore signing failed -- manifest is still usable for hash pinning")
            return result.returncode
        print(f"[+] signature bundle written next to {manifest_path}")
    return 0


def cmd_verify(root: Path, identity: str | None, issuer: str | None) -> int:
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.exists():
        print(f"[!] FAIL: no {MANIFEST_NAME} in {root}. Run `sign` first.")
        return 2

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    recorded = manifest["files"]
    actual = build_manifest(root)["files"]

    added = sorted(set(actual) - set(recorded))
    removed = sorted(set(recorded) - set(actual))
    changed = sorted(f for f in set(recorded) & set(actual) if recorded[f] != actual[f])

    if added or removed or changed:
        print("[!] FAIL: artifact directory does not match the manifest")
        for f in changed:
            print(f"    MODIFIED : {f}")
        for f in added:
            print(f"    UNEXPECTED: {f}")
        for f in removed:
            print(f"    MISSING  : {f}")
        return 1

    print(f"[+] all {len(recorded)} file hashes match the manifest")

    bundle = root / SIGNATURE_NAME
    if bundle.exists():
        if not identity or not issuer:
            print("[*] signature bundle present; pass --identity and --issuer to verify it")
            return 0
        result = subprocess.run(  # noqa: S603
            [
                sys.executable, "-m", "sigstore", "verify", "identity",
                "--cert-identity", identity,
                "--cert-oidc-issuer", issuer,
                str(manifest_path),
            ],
            check=False,
        )
        if result.returncode != 0:
            print("[!] FAIL: Sigstore signature verification failed")
            return 1
        print(f"[+] Sigstore signature valid for identity {identity}")
    else:
        print("[*] no Sigstore bundle found (hash pinning only)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Hash / sign / verify model artifacts")
    parser.add_argument("action", choices=["sign", "verify"])
    parser.add_argument("path", type=Path)
    parser.add_argument("--sigstore", action="store_true", help="also create a Sigstore signature")
    parser.add_argument("--identity", help="expected signer email, e.g. you@gmail.com")
    parser.add_argument("--issuer", default="https://accounts.google.com")
    args = parser.parse_args()

    root = args.path.resolve()
    if not root.is_dir():
        print(f"[!] {root} is not a directory")
        return 2

    if args.action == "sign":
        return cmd_sign(root, args.sigstore)
    return cmd_verify(root, args.identity, args.issuer)


if __name__ == "__main__":
    raise SystemExit(main())
