#!/usr/bin/env python
"""
Threat model AS CODE.

Threat modelling means answering four questions before you write defences:
  1. What are we building?     (a data-flow diagram)
  2. What can go wrong?        (threats against each flow)
  3. What are we doing about it? (mitigations, mapped to code)
  4. Did we do a good job?     (review + tests)

Writing it as code (pytm) instead of a Word doc means it lives next to the
system, gets diffed in code review, and can regenerate the diagram whenever the
architecture changes. We organise threats with STRIDE:

  S poofing       T ampering   R epudiation
  I nfo disclosure D oS         E levation of privilege

...and cross-reference the OWASP Top 10 for LLM Applications (LLM01..LLM10).

Usage:
    python docs/threat_model.py --dfd     | dot -Tpng -o docs/dfd.png
    python docs/threat_model.py --report docs/template_report.md
"""

from __future__ import annotations

import argparse

try:
    from pytm import TM, Actor, Boundary, Dataflow, Datastore, Process, Server
    HAVE_PYTM = True
except Exception:
    HAVE_PYTM = False


def build() -> "TM":
    tm = TM("Sentinel-RAG")
    tm.description = "Hardened RAG + MCP pipeline over Gemini"

    # --- trust boundaries --------------------------------------------------
    internet = Boundary("Internet / Untrusted")
    app_zone = Boundary("Application (our code)")
    google = Boundary("Google Cloud (Gemini)")

    # --- actors & elements -------------------------------------------------
    user = Actor("User")
    user.inBoundary = internet

    attacker = Actor("Attacker (direct + via poisoned documents)")
    attacker.inBoundary = internet

    api = Server("FastAPI service")
    api.inBoundary = app_zone

    guard = Process("Guardrail engine (input/output)")
    guard.inBoundary = app_zone

    vectordb = Datastore("Chroma vector store")
    vectordb.inBoundary = app_zone

    mcp = Process("Secure MCP host")
    mcp.inBoundary = app_zone

    docs = Datastore("Knowledge base (mixed trust)")
    docs.inBoundary = app_zone

    gemini = Server("Gemini API")
    gemini.inBoundary = google

    # --- data flows (each is an attack surface) ----------------------------
    Dataflow(user, api, "question (HTTPS)")
    Dataflow(attacker, docs, "poisoned document (indirect injection)")
    Dataflow(api, guard, "raw prompt")
    Dataflow(guard, vectordb, "retrieval query")
    Dataflow(vectordb, guard, "retrieved chunks (untrusted)")
    Dataflow(guard, gemini, "hardened prompt")
    Dataflow(gemini, guard, "model output (untrusted)")
    Dataflow(mcp, docs, "tool read (path-confined)")
    Dataflow(guard, user, "filtered answer")

    return tm


# ---------------------------------------------------------------------------
# The threat register. Even without pytm installed, this is the useful artifact.
# Each row: id, STRIDE, OWASP-LLM, threat, mitigation, where in the code.
# ---------------------------------------------------------------------------
THREATS = [
    ("T01", "Tampering", "LLM01", "Direct prompt injection overrides system rules",
     "Layered input guard (patterns+semantic+judge); refusal above threshold",
     "guardrails/input_guard.py"),
    ("T02", "Tampering", "LLM01", "Indirect injection via poisoned documents / tool results",
     "Sanitise hidden content at ingest; re-scan chunks and tool results at runtime; datamarking",
     "ingest/sanitize.py, rag/answerer.py, mcp_layer/client.py"),
    ("T03", "Info disclosure", "LLM02", "System prompt / secrets leak in the answer",
     "Canary token; output guard for secrets, PII, high-entropy tokens",
     "guardrails/output_guard.py, llm/prompts.py"),
    ("T04", "Info disclosure", "LLM02", "PII in retrieved docs surfaced to user",
     "Presidio PII detection + redaction on output",
     "guardrails/output_guard.py"),
    ("T05", "Elevation", "LLM06", "Excessive agency: model triggers destructive tool calls",
     "Per-tool allowlist; human approval for writes; call budgets",
     "mcp_layer/client.py, mcp_layer/registry.yaml"),
    ("T06", "Tampering", "LLM03", "Supply chain: backdoored model file executes on load",
     "Format policy (safetensors), modelscan/picklescan, hash pinning, load-time verify",
     "security/scanning/*, security/signing/*, vectorstore/model_gate.py"),
    ("T07", "Tampering", "LLM03", "Dependency compromise (hijacked PyPI package)",
     "Hash-pinned lock file (--require-hashes); pip-audit; AI-BOM",
     "requirements.txt, security/aibom/*"),
    ("T08", "Tampering", "LLM04", "Data poisoning / RAG knowledge-base poisoning",
     "Trust tiers; keyword-stuffing + near-duplicate + rare-trigger detection; quarantine",
     "ingest/poison_check.py, vectorstore/store.py"),
    ("T09", "Spoofing", "LLM03", "MCP rug pull: tool description changes after install",
     "Pin sha256 of every tool's name+description+schema; refuse on mismatch",
     "mcp_layer/client.py"),
    ("T10", "Elevation", "LLM07", "MCP tool poisoning: instructions hidden in descriptions",
     "Scan descriptions as untrusted; refuse server above injection threshold",
     "mcp_layer/client.py"),
    ("T11", "Info disclosure", "LLM02", "Confused deputy / credential exposure via MCP server",
     "Explicit env passthrough (deny by default); secret scan on outbound args",
     "mcp_layer/client.py"),
    ("T12", "DoS", "LLM10", "Denial of wallet: runaway tool loops / huge prompts",
     "Input size cap; per-request + per-tool call budgets; output token cap; rate limit",
     "api/app.py, mcp_layer/client.py, llm/gemini_client.py"),
    ("T13", "Repudiation", "-", "No evidence a control fired during an incident",
     "Hash-chained, tamper-evident audit log of every decision",
     "audit.py"),
    ("T14", "Tampering", "LLM05", "Insecure output handling (XSS/SQLi in downstream consumer)",
     "Output guard strips scripts/links; document that callers must encode output",
     "guardrails/output_guard.py, docs/security-policy.md"),
    ("T15", "Info disclosure", "LLM02", "Free-tier Gemini trains on submitted data",
     "AI-BOM flags the risk; policy forbids regulated data on free tier",
     "security/aibom/*, docs/security-policy.md"),
]


def render_report(template_path: str | None) -> str:
    lines = [
        "# Sentinel-RAG Threat Model (generated)",
        "",
        "Generated from `docs/threat_model.py`. Regenerate with `make threat-model`.",
        "",
        "## Threat register (STRIDE x OWASP-LLM)",
        "",
        "| ID | STRIDE | OWASP | Threat | Mitigation | Where |",
        "|----|--------|-------|--------|------------|-------|",
    ]
    for tid, stride, owasp, threat, mitigation, where in THREATS:
        lines.append(f"| {tid} | {stride} | {owasp} | {threat} | {mitigation} | `{where}` |")
    lines += [
        "",
        "## Residual risk",
        "",
        "- Prompt injection cannot be fully eliminated; we reduce likelihood and "
        "constrain blast radius. Assume some injections land and verify the "
        "downstream controls (least privilege, output filtering, approval) hold.",
        "- The LLM judge itself calls a model and can be wrong or rate-limited; it "
        "is one weighted signal, never the sole decision.",
        "- Detection thresholds trade false positives against false negatives; tune "
        "with `redteam/fuzz_injection.py` and the regression tests.",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dfd", action="store_true", help="emit Graphviz DOT for the data-flow diagram")
    parser.add_argument("--report", nargs="?", const=None, help="emit the markdown threat report")
    args = parser.parse_args()

    if args.dfd:
        if not HAVE_PYTM:
            print("// pytm not installed; run: pip install pytm", flush=True)
            return 0
        import sys
        sys.argv = ["tm", "--dfd"]   # pytm reads sys.argv
        build().process()
        return 0

    print(render_report(args.report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
