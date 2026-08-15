#!/usr/bin/env bash
# =============================================================================
# garak -- an external, industry-standard LLM vulnerability scanner (NVIDIA).
#
# Your own fuzzer (fuzz_injection.py) tests YOUR pipeline end to end. garak
# tests the MODEL more broadly: it has dozens of "probes" for jailbreaks,
# prompt-injection families, toxicity, data leakage, encoding attacks, and more,
# each with an automatic "detector" that scores whether the model failed.
#
# Running BOTH is the point:
#   * garak against the raw Gemini model      -> baseline: how weak is the model alone?
#   * fuzz_injection against your API          -> how much do your guardrails add?
#
# The delta between those two is literally the value your security layer provides,
# which is a great thing to put in a report or a portfolio write-up.
#
# Docs: https://github.com/NVIDIA/garak
# =============================================================================
set -uo pipefail

if ! command -v garak >/dev/null 2>&1; then
  echo "[*] installing garak (pip install garak)..."
  pip install garak || { echo "[!] install failed"; exit 1; }
fi

: "${GEMINI_API_KEY:?set GEMINI_API_KEY in your environment or .env first}"
MODEL="${GEMINI_MODEL:-gemini-3.5-flash}"

mkdir -p security/reports

echo "=============================================="
echo " garak baseline scan of ${MODEL}"
echo "=============================================="
# A focused, quota-friendly probe set. Drop --probes to run everything (slow, and
# it will eat your free-tier quota fast).
garak \
  --model_type gemini \
  --model_name "${MODEL}" \
  --probes promptinject,dan,encoding,leakreplay \
  --report_prefix security/reports/garak \
  || echo "[!] garak exited non-zero (some probes may have found weaknesses -- that's data, not an error)"

echo
echo "[+] Reports in security/reports/garak.*"
echo "    Compare the promptinject failure rate here against your own"
echo "    fuzz_injection.py results to quantify what your guardrails add."
