# Sentinel-RAG

A hardened **Retrieval-Augmented Generation** service over Google **Gemini**,
plus a **secure Model Context Protocol (MCP)** tool layer, wrapped in
production-lifecycle security (threat modelling, AI-BOM, dependency pinning,
model scanning & signing) and a **red-team lab** that attacks all of it.

Built as a hands-on AI-security learning project. It implements mitigations
across the **OWASP Top 10 for LLM Applications** (LLM01–LLM10).

> ### → Read [`docs/00-START-HERE.md`](docs/00-START-HERE.md) first.
> It explains the whole project from zero, assuming no prior AI background, and
> guides you through setup, the code, and the attack lab.

## A note on how this was built

The code in this project — the security filters, the tool-safety layer, the
document-checking logic — was written by AI as a teaching example. It's meant
to be run and broken and poked at, not just read.

I went through the whole thing hands-on, working with Claude as a guide. I
didn't just read the code — I ran real attacks against the live server and
watched which defense caught each one, and step by step. I:

- Sent it prompt-injection attacks by hand and watched them get blocked, then
  looked at exactly which layer stopped them and why
- Planted a fake malicious document straight into the search index to prove
  the app checks retrieved content again at question-time, not just when
  documents are first added
- Broke the model's file signature on purpose and watched the app refuse to
  start, then fixed it properly
- Edited a tool's description to simulate an attacker changing it later, and
  watched the app catch the change and refuse to trust it
- Ran the app's own test suite and its red-team attack tools against the live
  server

Along the way, Claude found and helped fix several real bugs in the original
code — not planted on purpose, just things a close hands-on look turned up:
a broken regex that silently made the test tool always report "pass," a file
left open that crashed cleanup on Windows, a database setting that quietly
used the wrong distance formula, a report field that called the model
"unsigned" even though it was actually protected, and a real known security
flaw in one of the dependencies.

What I actually learned from doing this:

- Why prompt injection can't be fully "solved," and why real defenses use
  several layers instead of one filter
- The difference between an attacker hiding something in a *document* a
  model reads, versus an attacker changing the model's own training data
- Why you should never fully trust a third-party AI tool without checking
  its behavior, not just its description
- How to verify a model file hasn't been tampered with, and why that
  actually matters
- How to read a running system's logs and outputs to check whether a
  security control genuinely works, instead of trusting the documentation
- How to tell the difference between "this is a real security problem" and
  "this is just an environment or tooling issue" — a skill that took as
  much practice as the security concepts themselves
- How to read a vulnerability report (a CVE) critically, and judge whether
  it actually applies to how a project uses that dependency

This project is the result of that hands-on process, not a copy-paste of
AI-written code.

## 60-second tour

```bash
python -m venv .venv && source .venv/bin/activate
make lock && make install                 # hash-locked dependency install
cp .env.example .env                       # paste your free Gemini API key
ENFORCE_MODEL_SIGNATURE=false python security/scanning/fetch_model.py
make scan-model && make sign-model         # scan + sign the embedding model
make ingest                                # index sample docs (watch a poisoned one get quarantined)
python -m sentinelrag.mcp_layer.client --pin
make serve                                 # http://127.0.0.1:8000/docs
```

Then attack it:

```bash
make redteam        # prompt-injection fuzzer vs the running API
make redteam-mcp    # MCP attack suite vs the secure client
make test           # offline security regression tests
make supply-chain   # AI-BOM + dep CVE scan + code scan + model scan + signature verify
```

## What maps to what

| Résumé clause | Implementation |
|---|---|
| High-performance RAG + Vector DB | `src/sentinelrag/rag/`, `src/sentinelrag/vectorstore/` (Chroma) |
| MCP for secure tool integration | `src/sentinelrag/mcp_layer/` (pinning, allowlist, approval, result scanning) |
| Threat modeling | `docs/threat_model.py` (STRIDE × OWASP-LLM, as code) |
| AI-BOM implementation | `security/aibom/` (CycloneDX) |
| Dependency pinning | `requirements.txt` + `make lock` (`--require-hashes`) |
| Model scanning | `security/scanning/` (modelscan, picklescan) |
| Model signing | `security/signing/` (Sigstore) + load-time verify in `vectorstore/model_gate.py` |
| Prompt injection (direct + indirect) | `src/sentinelrag/guardrails/`, `ingest/sanitize.py` |
| Sensitive information disclosure | `guardrails/output_guard.py` (canary, PII, secrets, exfil) |
| Model backdoor / data poisoning | `ingest/poison_check.py` |
| Validation guardrails | `src/sentinelrag/guardrails/` |
| Fuzzing / scanning LLMs | `redteam/fuzz_injection.py`, `redteam/run_garak.sh` |
| MCP attacks & defences | `redteam/evil_mcp_server.py`, `redteam/mcp_attacks.py` |

## License / disclaimer

Teaching material. The malicious code in `redteam/` is for use **only** against
this project's own components in your local lab. Do not point the offensive tools
at systems you don't own.
