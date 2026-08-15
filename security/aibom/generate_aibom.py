#!/usr/bin/env python
"""
AI-BOM: an inventory of everything your AI system is made of.

A normal SBOM (Software Bill of Materials) lists your code dependencies. An
AI-BOM additionally lists the things unique to AI systems:

  * models        -- name, source, revision, file hashes, licence
  * datasets      -- where the knowledge base came from, and its trust tier
  * services      -- external inference APIs (here: the Gemini endpoint)
  * tools         -- MCP servers the agent can call

Why you need it: when the next "malicious model on a public hub" advisory
drops, the only question that matters is "am I affected?". Without an inventory
that takes a week of Slack archaeology. With one it takes a grep.

We emit CycloneDX JSON, which is an ISO-standard format that Dependency-Track,
Grype and most vulnerability tooling can ingest directly.

Usage:
    python security/aibom/generate_aibom.py
    -> security/reports/aibom.cdx.json
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "security/reports/aibom.cdx.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def python_components() -> list[dict]:
    """Every installed Python package, with its exact version."""
    raw = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pip", "list", "--format=json"],
        capture_output=True, text=True, check=True,
    ).stdout
    return [
        {
            "type": "library",
            "bom-ref": f"pkg:pypi/{pkg['name']}@{pkg['version']}",
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": f"pkg:pypi/{pkg['name']}@{pkg['version']}",
        }
        for pkg in json.loads(raw)
    ]


def model_components() -> list[dict]:
    """Local model artifacts, described as CycloneDX machine-learning-model."""
    components = []
    models_dir = ROOT / "models"
    if not models_dir.exists():
        return components

    for model_dir in sorted(p for p in models_dir.iterdir() if p.is_dir()):
        provenance_file = model_dir / "PROVENANCE.json"
        provenance = json.loads(provenance_file.read_text()) if provenance_file.exists() else {}

        manifest_file = model_dir / "MANIFEST.json"
        manifest_hash = sha256_file(manifest_file) if manifest_file.exists() else None

        components.append({
            "type": "machine-learning-model",
            "bom-ref": f"model/{model_dir.name}",
            "name": provenance.get("repo_id", model_dir.name),
            "version": provenance.get("revision", "unpinned"),
            "hashes": ([{"alg": "SHA-256", "content": manifest_hash}] if manifest_hash else []),
            "properties": [
                {"name": "ai:source", "value": "huggingface"},
                {"name": "ai:local_path", "value": str(model_dir.relative_to(ROOT))},
                {"name": "ai:signed", "value": str((model_dir / "MANIFEST.json.sigstore.json").exists())},
                {"name": "ai:task", "value": "text-embedding"},
            ],
        })
    return components


def dataset_components() -> list[dict]:
    """Knowledge-base sources. Trust tier comes from the ingest manifest."""
    components = []
    kb = ROOT / "data/knowledge_base"
    if not kb.exists():
        return components

    for path in sorted(kb.rglob("*")):
        if path.is_file() and not path.name.startswith("."):
            components.append({
                "type": "data",
                "bom-ref": f"data/{path.relative_to(kb)}",
                "name": str(path.relative_to(kb)),
                "hashes": [{"alg": "SHA-256", "content": sha256_file(path)}],
                "properties": [
                    {"name": "ai:role", "value": "rag-corpus"},
                    {"name": "ai:trust_tier", "value": _trust_tier(path)},
                ],
            })
    return components


def _trust_tier(path: Path) -> str:
    """Directory layout encodes trust: data/knowledge_base/<tier>/<file>."""
    parts = path.parts
    for tier in ("trusted", "internal", "untrusted"):
        if tier in parts:
            return tier
    return "unclassified"


def service_components() -> list[dict]:
    """External inference services -- these are dependencies too."""
    return [{
        "type": "platform",
        "bom-ref": "service/gemini",
        "name": "Google Gemini API (AI Studio)",
        "version": "gemini-3.5-flash",
        "properties": [
            {"name": "ai:endpoint", "value": "https://generativelanguage.googleapis.com"},
            {"name": "ai:data_residency", "value": "google-managed"},
            {"name": "ai:free_tier_trains_on_data", "value": "true"},
            {"name": "ai:risk", "value": "do-not-send-regulated-data-on-free-tier"},
        ],
    }]


def mcp_components() -> list[dict]:
    """MCP servers the agent is allowed to talk to, with pinned tool hashes."""
    registry = ROOT / "src/sentinelrag/mcp_layer/registry.yaml"
    if not registry.exists():
        return []
    import yaml
    data = yaml.safe_load(registry.read_text()) or {}
    out = []
    for name, server in (data.get("servers") or {}).items():
        out.append({
            "type": "application",
            "bom-ref": f"mcp/{name}",
            "name": f"MCP server: {name}",
            "version": server.get("version", "unknown"),
            "properties": [
                {"name": "ai:transport", "value": server.get("transport", "stdio")},
                {"name": "ai:allowed_tools", "value": ",".join(server.get("allowed_tools", {}))},
            ],
        })
    return out


def main() -> int:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "bom-ref": "sentinel-rag",
                "name": "sentinel-rag",
                "version": "0.1.0",
            },
            "tools": [{"name": "generate_aibom.py", "version": "0.1.0"}],
        },
        "components": (
            model_components()
            + dataset_components()
            + service_components()
            + mcp_components()
            + python_components()
        ),
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(bom, indent=2), encoding="utf-8")

    counts: dict[str, int] = {}
    for component in bom["components"]:
        counts[component["type"]] = counts.get(component["type"], 0) + 1
    print(f"[+] AI-BOM written to {OUT.relative_to(ROOT)}")
    for kind, n in sorted(counts.items()):
        print(f"      {kind:26} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
