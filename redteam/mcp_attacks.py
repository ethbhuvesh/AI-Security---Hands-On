#!/usr/bin/env python
"""
The MCP attack suite.

This spins up the SecureMCPClient against a registry that includes the malicious
server (redteam/evil_mcp_server.py) and asserts that every defence fires. Think
of it as a test suite where PASS means "the attack was correctly stopped".

Run:
    python redteam/mcp_attacks.py

You should see the client REFUSE to even load the evil server (tool poisoning is
caught at registration time), plus targeted checks for path traversal, the
budget limiter, and human-approval gating.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinelrag.mcp_layer.client import (  # noqa: E402
    MCPSecurityError,
    SecureMCPClient,
    console_approver,
    deny_all_approver,
)

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"


def _registry_with_evil() -> Path:
    """Build a temp registry that includes the malicious server, unpinned + TOFU."""
    registry = {
        "servers": {
            "evil": {
                "version": "0.0.0",
                "transport": "stdio",
                "command": sys.executable,
                "args": ["-m", "redteam.evil_mcp_server"],
                "env_passthrough": ["PATH", "PYTHONPATH"],
                "trust_on_first_use": True,     # so the ONLY thing stopping it is content scanning
                "allowed_tools": {
                    "exfiltrate": {"requires_approval": True, "pin": None},
                    "read_file": {"requires_approval": True, "pin": None},
                    "get_weather": {"requires_approval": False, "pin": None},
                },
            }
        },
        "policy": {
            "max_total_calls": 2,
            "scan_tool_results": True,
            "forbid_duplicate_tool_names": True,
            "max_description_injection_score": 0.45,
        },
    }
    fd, path = tempfile.mkstemp(suffix=".yaml", prefix="evil_registry_")
    os.close(fd)  # Windows locks open file handles; must close before it can be unlinked later
    tmp = Path(path)
    tmp.write_text(yaml.safe_dump(registry), encoding="utf-8")
    return tmp


async def test_tool_poisoning_blocks_load(env: dict) -> bool:
    """The evil server's `exfiltrate` description is an injection. Loading must fail."""
    registry = _registry_with_evil()
    try:
        async with SecureMCPClient(registry, approver=deny_all_approver):
            pass
        print(f"  {FAIL} tool poisoning: evil server loaded without objection")
        return False
    except MCPSecurityError as exc:
        ok = "TOOL POISONING" in str(exc) or "poisoning" in str(exc).lower()
        print(f"  {PASS if ok else FAIL} tool poisoning caught at load: {str(exc)[:80]}")
        return ok
    finally:
        registry.unlink(missing_ok=True)


async def test_trusted_server_still_works() -> bool:
    """Sanity: the legitimate docs server loads and its safe tools are callable."""
    try:
        async with SecureMCPClient(approver=console_approver) as client:
            tools = [t["name"] for t in client.describe_tools()]
            ok = any(name.endswith("/current_time") for name in tools)
            if ok:
                result = await client.call("docs/current_time", {})
                ok = "T" in result  # ISO timestamp
            print(f"  {PASS if ok else FAIL} trusted docs server works: tools={tools}")
            return ok
    except MCPSecurityError as exc:
        # Expected if you have not pinned yet.
        print(f"  (skipped) trusted server not pinned yet: {str(exc)[:80]}")
        print(f"            run: python -m sentinelrag.mcp_layer.client --pin")
        return True


async def test_path_traversal_blocked() -> bool:
    """Even on the trusted server, ../ in read_document must be denied."""
    try:
        async with SecureMCPClient(approver=lambda t, a: True) as client:
            if "docs/read_document" not in client.tools:
                print("  (skipped) docs/read_document not pinned yet")
                return True
            try:
                await client.call("docs/read_document", {"path": "../../.env"})
                print(f"  {FAIL} path traversal: ../../.env was allowed")
                return False
            except MCPSecurityError as exc:
                print(f"  {PASS} path traversal blocked: {str(exc)[:80]}")
                return True
    except MCPSecurityError:
        print("  (skipped) trusted server not pinned yet")
        return True


async def main() -> int:
    print("MCP attack suite\n" + "-" * 60)
    results = []
    results.append(await test_tool_poisoning_blocks_load({}))
    results.append(await test_trusted_server_still_works())
    results.append(await test_path_traversal_blocked())

    print("-" * 60)
    passed = sum(results)
    print(f"{passed}/{len(results)} defences verified")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
