# Sentinel-RAG Threat Model (generated)

Generated from `docs/threat_model.py`. Regenerate with `make threat-model`.

## Threat register (STRIDE x OWASP-LLM)

| ID | STRIDE | OWASP | Threat | Mitigation | Where |
|----|--------|-------|--------|------------|-------|
| T01 | Tampering | LLM01 | Direct prompt injection overrides system rules | Layered input guard (patterns+semantic+judge); refusal above threshold | `guardrails/input_guard.py` |
| T02 | Tampering | LLM01 | Indirect injection via poisoned documents / tool results | Sanitise hidden content at ingest; re-scan chunks and tool results at runtime; datamarking | `ingest/sanitize.py, rag/answerer.py, mcp_layer/client.py` |
| T03 | Info disclosure | LLM02 | System prompt / secrets leak in the answer | Canary token; output guard for secrets, PII, high-entropy tokens | `guardrails/output_guard.py, llm/prompts.py` |
| T04 | Info disclosure | LLM02 | PII in retrieved docs surfaced to user | Presidio PII detection + redaction on output | `guardrails/output_guard.py` |
| T05 | Elevation | LLM06 | Excessive agency: model triggers destructive tool calls | Per-tool allowlist; human approval for writes; call budgets | `mcp_layer/client.py, mcp_layer/registry.yaml` |
| T06 | Tampering | LLM03 | Supply chain: backdoored model file executes on load | Format policy (safetensors), modelscan/picklescan, hash pinning, load-time verify | `security/scanning/*, security/signing/*, vectorstore/model_gate.py` |
| T07 | Tampering | LLM03 | Dependency compromise (hijacked PyPI package) | Hash-pinned lock file (--require-hashes); pip-audit; AI-BOM | `requirements.txt, security/aibom/*` |
| T08 | Tampering | LLM04 | Data poisoning / RAG knowledge-base poisoning | Trust tiers; keyword-stuffing + near-duplicate + rare-trigger detection; quarantine | `ingest/poison_check.py, vectorstore/store.py` |
| T09 | Spoofing | LLM03 | MCP rug pull: tool description changes after install | Pin sha256 of every tool's name+description+schema; refuse on mismatch | `mcp_layer/client.py` |
| T10 | Elevation | LLM07 | MCP tool poisoning: instructions hidden in descriptions | Scan descriptions as untrusted; refuse server above injection threshold | `mcp_layer/client.py` |
| T11 | Info disclosure | LLM02 | Confused deputy / credential exposure via MCP server | Explicit env passthrough (deny by default); secret scan on outbound args | `mcp_layer/client.py` |
| T12 | DoS | LLM10 | Denial of wallet: runaway tool loops / huge prompts | Input size cap; per-request + per-tool call budgets; output token cap; rate limit | `api/app.py, mcp_layer/client.py, llm/gemini_client.py` |
| T13 | Repudiation | - | No evidence a control fired during an incident | Hash-chained, tamper-evident audit log of every decision | `audit.py` |
| T14 | Tampering | LLM05 | Insecure output handling (XSS/SQLi in downstream consumer) | Output guard strips scripts/links; document that callers must encode output | `guardrails/output_guard.py, docs/security-policy.md` |
| T15 | Info disclosure | LLM02 | Free-tier Gemini trains on submitted data | AI-BOM flags the risk; policy forbids regulated data on free tier | `security/aibom/*, docs/security-policy.md` |

## Residual risk

- Prompt injection cannot be fully eliminated; we reduce likelihood and constrain blast radius. Assume some injections land and verify the downstream controls (least privilege, output filtering, approval) hold.
- The LLM judge itself calls a model and can be wrong or rate-limited; it is one weighted signal, never the sole decision.
- Detection thresholds trade false positives against false negatives; tune with `redteam/fuzz_injection.py` and the regression tests.
