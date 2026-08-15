# =============================================================================
# Sentinel-RAG :: one command per lifecycle stage.
# Run `make help` to see everything.
# =============================================================================
.DEFAULT_GOAL := help
PY := python
VENV := .venv

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --- Environment ------------------------------------------------------------
venv:  ## Create the virtual environment
	$(PY) -m venv $(VENV)
	@echo "Now run: source $(VENV)/bin/activate   (Windows: .venv\\Scripts\\activate)"

lock:  ## Compile requirements.in -> requirements.txt with pinned versions + hashes
	pip-compile --generate-hashes --output-file=requirements.txt requirements.in

install:  ## Install EXACTLY what the lock file says (hash-verified) + the local package
	pip install --require-hashes -r requirements.txt
	pip install -e . --no-deps
	$(PY) -m spacy download en_core_web_lg

# --- Supply chain -----------------------------------------------------------
aibom:  ## Generate the AI Bill of Materials (CycloneDX JSON)
	$(PY) security/aibom/generate_aibom.py

scan-deps:  ## CVE scan of the dependency tree
	pip-audit --requirement requirements.txt --strict

scan-code:  ## Static analysis of our own source
	bandit -r src/ -c pyproject.toml
	semgrep --config p/python --config p/security-audit --error src/

scan-model:  ## Scan the embedding model files for malicious payloads
	bash security/scanning/scan_models.sh

sign-model:  ## Hash + keyless-sign the model artifacts with Sigstore
	$(PY) security/signing/sign_artifact.py sign models/

verify-model:  ## Verify model signatures (this also runs automatically at load time)
	$(PY) security/signing/sign_artifact.py verify models/

threat-model:  ## Render the threat model (DFD + report) from code
	$(PY) docs/threat_model.py --dfd | dot -Tpng -o docs/dfd.png || true
	$(PY) docs/threat_model.py --report docs/template_report.md > docs/threat-model-generated.md || true

supply-chain: aibom scan-deps scan-code scan-model verify-model  ## Run the whole supply-chain gate

# --- Application ------------------------------------------------------------
ingest:  ## Build the vector index from data/knowledge_base
	$(PY) -m sentinelrag.ingest.pipeline --source data/knowledge_base

serve:  ## Run the hardened API on http://127.0.0.1:8000
	uvicorn sentinelrag.api.app:app --reload --port 8000

# --- Red team ---------------------------------------------------------------
redteam:  ## Fuzz the running app with the prompt-injection payload corpus
	$(PY) redteam/fuzz_injection.py --target http://127.0.0.1:8000/ask

redteam-mcp:  ## Run the MCP attack suite against the secure client
	$(PY) redteam/mcp_attacks.py

garak:  ## Run garak (external LLM vulnerability scanner) against Gemini
	bash redteam/run_garak.sh

test:  ## Unit + security regression tests
	pytest -q

ci: supply-chain test  ## What CI runs

.PHONY: help venv lock install aibom scan-deps scan-code scan-model sign-model \
        verify-model threat-model supply-chain ingest serve redteam redteam-mcp \
        garak test ci
