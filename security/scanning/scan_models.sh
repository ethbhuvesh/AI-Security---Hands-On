#!/usr/bin/env bash
# =============================================================================
# Step 2 of the model supply chain: scan the bytes before you ever load them.
#
# WHY THIS EXISTS
# ---------------
# A PyTorch .bin / .pt file is a Python *pickle*. Unpickling runs code. The
# pickle format supports a `REDUCE` opcode that calls an arbitrary callable --
# so `torch.load("model.bin")` on a hostile file can run `os.system(...)` before
# a single tensor is read. Real malicious models have been found on public hubs
# doing exactly this (reverse shells, credential theft).
#
# Three layers of defence, cheapest first:
#   1. FORMAT POLICY  -- prefer .safetensors, which cannot execute code at all.
#   2. picklescan     -- disassembles pickles, flags dangerous imports/opcodes.
#   3. modelscan      -- Protect AI's broader scanner (pickle, TF, Keras, ONNX).
#
# Exit code is non-zero if anything is flagged, so CI fails closed.
# =============================================================================
set -uo pipefail

TARGET="${1:-models/}"
FAILED=0

echo "=============================================="
echo " Model scan: ${TARGET}"
echo "=============================================="

# --- 1. Format policy -------------------------------------------------------
echo
echo "[1/3] Format policy check (pickle formats are discouraged)"
UNSAFE=$(find "${TARGET}" -type f \( -name '*.bin' -o -name '*.pt' -o -name '*.pth' \
         -o -name '*.pkl' -o -name '*.ckpt' -o -name '*.joblib' \) 2>/dev/null || true)
if [ -n "${UNSAFE}" ]; then
  echo "  ! pickle-based weight files present:"
  echo "${UNSAFE}" | sed 's/^/      /'
  SAFETENSORS=$(find "${TARGET}" -type f -name '*.safetensors' 2>/dev/null || true)
  if [ -n "${SAFETENSORS}" ]; then
    echo "  > a .safetensors version exists -- delete the pickle files and use it."
  fi
else
  echo "  ok: no pickle-format weights found"
fi

# --- 2. picklescan ----------------------------------------------------------
echo
echo "[2/3] picklescan"
if command -v picklescan >/dev/null 2>&1; then
  picklescan --path "${TARGET}" || FAILED=1
else
  echo "  ! picklescan not installed (pip install picklescan)"; FAILED=1
fi

# --- 3. modelscan -----------------------------------------------------------
echo
echo "[3/3] modelscan"
if command -v modelscan >/dev/null 2>&1; then
  mkdir -p security/reports
  modelscan --path "${TARGET}" --reporting-format json \
            --output-file security/reports/modelscan.json || FAILED=1
  modelscan --path "${TARGET}" || FAILED=1
else
  echo "  ! modelscan not installed (pip install modelscan)"; FAILED=1
fi

echo
if [ "${FAILED}" -ne 0 ]; then
  echo "RESULT: FAILED -- do not load these artifacts."
  exit 1
fi
echo "RESULT: PASS"
