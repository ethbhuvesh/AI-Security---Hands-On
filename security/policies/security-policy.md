# Security Policy & Control Catalogue

This is the human-readable companion to the code. It maps each concept from the
project brief to the file that implements it, and states the operational rules a
user of the system must follow.

## Controls at a glance

| Concept (from the brief) | Where it lives | One-line summary |
|---|---|---|
| RAG pipeline | `rag/answerer.py`, `vectorstore/` | Retrieve, harden, generate, filter |
| Vector database | `vectorstore/store.py` | Chroma, trust-weighted retrieval, provenance metadata |
| MCP secure integration | `mcp_layer/` | Pinned, allowlisted, approval-gated tool calls |
| Threat modelling | `docs/threat_model.py` | STRIDE x OWASP-LLM register, as code |
| AI-BOM | `security/aibom/` | CycloneDX inventory of models, data, services, deps |
| Dependency pinning | `requirements.txt` + `make lock` | Hash-locked deps, `--require-hashes` install |
| Model scanning | `security/scanning/` | modelscan + picklescan + format policy |
| Model signing | `security/signing/` | Manifest hashing + Sigstore keyless signing, verify at load |
| Validation guardrails | `guardrails/` | Input + output inspection, de-obfuscation, PII/secret redaction |
| Direct prompt injection | `guardrails/input_guard.py` | Layered detection of user-supplied attacks |
| Indirect prompt injection | `ingest/sanitize.py` + runtime chunk scan | Strip hidden payloads; re-scan retrieved + tool text |
| Sensitive info disclosure | `guardrails/output_guard.py` | Canary, PII, secrets, exfil-link stripping |
| Data poisoning | `ingest/poison_check.py` | Stuffing/dup/rare-trigger detection, quarantine |
| Model backdoor | `security/scanning/` + `poison_check.py` | Scan artifacts; flag rare repeated triggers |
| Fuzzing LLMs | `redteam/fuzz_injection.py`, `redteam/run_garak.sh` | Mutating payloads + garak baseline |
| MCP attacks & defences | `redteam/mcp_attacks.py`, `mcp_layer/client.py` | Poisoning, rug pull, shadowing, confused deputy |
| Audit / non-repudiation | `audit.py` | Hash-chained tamper-evident log |

## Operational rules (these are policy, not suggestions)

1. **Never send regulated or secret data to the free Gemini tier.** Free-tier
   inputs may be used to improve the model. The AI-BOM flags this on the Gemini
   component. Use a paid tier with data-processing terms for anything sensitive.

2. **The `.env` file is never committed.** It is in `.gitignore`. Keys are read
   only through `config.py` and never logged.

3. **New MCP servers start disabled, unpinned, and approval-required.** You pin
   with `make` / the `--pin` workflow, review the diff, and only then enable.

4. **Untrusted documents go in `data/knowledge_base/untrusted/`.** Trust tier is
   decided by directory, so it cannot be forgotten. Untrusted content can never
   out-rank trusted content in retrieval.

5. **Callers of `/ask` must treat the answer as untrusted for their own sink.**
   We strip scripts and links, but if you render the answer as HTML, encode it;
   if you put it in SQL, parameterise it. LLM output is data, not code.

6. **CI must be green before deploy.** `make ci` runs the supply-chain gate
   (AI-BOM, dependency CVE scan, code scan, model scan, signature verify) plus
   the security regression tests. A red gate blocks the release.

## Incident playbook (short version)

- **Suspected prompt-injection incident:** grep the audit log for
  `injection_detected`, `canary_leak`, `chunk_dropped`, `tool_result_blocked`.
  Each carries a `source` and a `text_sha256` so you can trace the origin
  without the log itself storing sensitive text.
- **Suspected poisoned document:** the offending chunk's provenance
  (`file_sha256`, `source`, `trust`) is in the vector store metadata and the
  ingest log. Remove the file, re-run `make ingest`.
- **Suspected supply-chain event:** regenerate the AI-BOM, run `pip-audit`, and
  `make verify-model`. A changed model hash or a new CVE tells you your exposure
  in minutes rather than days.
