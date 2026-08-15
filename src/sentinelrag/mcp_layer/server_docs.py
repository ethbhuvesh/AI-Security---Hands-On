"""
An MCP server -- the "tool" side of Model Context Protocol.

MCP is a standard way for an LLM host to discover and call external tools. The
host asks the server "what can you do?" (tools/list) and the server replies with
names, descriptions and JSON schemas. The host puts those descriptions into the
model's context so the model can decide what to call.

That last sentence is the whole security story: TOOL DESCRIPTIONS ARE PROMPT
CONTENT. A malicious or compromised server can put instructions in a description
and they land straight in your model's context. See redteam/evil_mcp_server.py.

This server is written the way a production server should be:

  * Least privilege     -- it can only read inside one directory, and only
                           whitelisted extensions.
  * Path confinement    -- every path is resolved and checked against the root,
                           so "../../.ssh/id_rsa" and symlinks both fail.
  * No shell, ever      -- there is no exec/system tool. If you need one, it
                           takes an allowlisted command name, never a string.
  * Bounded output      -- responses are truncated, so a tool cannot flood the
                           context window (a cheap denial-of-wallet defence).
  * Honest descriptions -- plain capability statements, no instructions to the
                           model, so the pinned hash stays meaningful.

Run standalone for debugging:
    python -m sentinelrag.mcp_layer.server_docs
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from sentinelrag.config import ROOT

mcp = FastMCP("sentinel-docs")

# The ONLY directory this server may read from.
DOC_ROOT = (ROOT / "data/knowledge_base").resolve()
ALLOWED_SUFFIXES = {".md", ".txt", ".rst"}
MAX_CHARS = 8_000


def _safe_path(relative: str) -> Path:
    """
    Resolve a user-supplied relative path inside DOC_ROOT, or raise.

    `Path.resolve()` collapses `..` AND follows symlinks, so we compare the
    fully-resolved result against the fully-resolved root. Checking the string
    before resolving (a common bug) is bypassable with symlinks.
    """
    if "\x00" in relative:
        raise ValueError("null byte in path")
    candidate = (DOC_ROOT / relative).resolve()
    if not candidate.is_relative_to(DOC_ROOT):
        raise ValueError(f"path escapes the document root: {relative}")
    if candidate.suffix.lower() not in ALLOWED_SUFFIXES:
        raise ValueError(f"file type not allowed: {candidate.suffix}")
    return candidate


@mcp.tool()
def list_documents() -> list[str]:
    """List the relative paths of documents available in the knowledge base."""
    return sorted(
        str(p.relative_to(DOC_ROOT))
        for p in DOC_ROOT.rglob("*")
        if p.is_file() and p.suffix.lower() in ALLOWED_SUFFIXES
    )


@mcp.tool()
def read_document(path: str) -> str:
    """Read one document from the knowledge base. Path is relative to the knowledge base root."""
    target = _safe_path(path)
    if not target.is_file():
        raise ValueError(f"not found: {path}")
    text = target.read_text(encoding="utf-8", errors="replace")
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + f"\n...[truncated at {MAX_CHARS} characters]"
    return text


@mcp.tool()
def search_documents(query: str, limit: int = 5) -> list[dict]:
    """Search the knowledge base for a literal substring and return matching snippets."""
    limit = max(1, min(int(limit), 20))
    needle = query.lower()
    hits: list[dict] = []
    for path in sorted(DOC_ROOT.rglob("*")):
        if not (path.is_file() and path.suffix.lower() in ALLOWED_SUFFIXES):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        index = text.lower().find(needle)
        if index >= 0:
            hits.append({
                "path": str(path.relative_to(DOC_ROOT)),
                "snippet": text[max(0, index - 120): index + 320],
            })
        if len(hits) >= limit:
            break
    return hits


@mcp.tool()
def current_time() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return dt.datetime.now(dt.timezone.utc).isoformat()


if __name__ == "__main__":
    mcp.run(transport="stdio")
