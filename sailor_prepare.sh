#!/usr/bin/env bash
# sailor_prepare.sh -- One-time project setup
# Usage: ./sailor_prepare.sh <PROJECT_ID>

set -euo pipefail

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <PROJECT_ID>"
  exit 1
fi

export PROJECT_ID="$1"

# Resolve SAILOR_ROOT: env var > script directory > cwd
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SAILOR_ROOT="${SAILOR_ROOT:-${SCRIPT_DIR}}"

export DATASET_ROOT="${DATASET_ROOT:-${SAILOR_ROOT}/dataset}"
export SA_OUT_DIR="${SA_OUT_DIR:-${SAILOR_ROOT}/sa_outputs}"
export SPECS_DIR="${SAILOR_ROOT}/specs/$(basename "$PROJECT_ID")"
export SRC_ROOT="$(realpath -m "${DATASET_ROOT}/${PROJECT_ID}")"
export PROJECT_BC="${SRC_ROOT}/project.bc"
PROJECT_NAME="$(basename "$PROJECT_ID")"

# --- 1. CONFIGURATION (Looks in ./configs or root) ---
if [ -f "${SAILOR_ROOT}/configs/${PROJECT_NAME}_config.sh" ]; then
    source "${SAILOR_ROOT}/configs/${PROJECT_NAME}_config.sh"
elif [ -f "${SAILOR_ROOT}/${PROJECT_NAME}_config.sh" ]; then
    source "${SAILOR_ROOT}/${PROJECT_NAME}_config.sh"
fi

# --- 2. CODEQL SCAN ---
echo "[=] Step 1: CodeQL Scan"
FINDINGS_JSON="${SA_OUT_DIR}/${PROJECT_NAME}/findings.json"
FACT_PACK_JSON="${SA_OUT_DIR}/${PROJECT_NAME}/fact_pack.json"

if [ ! -f "$FINDINGS_JSON" ]; then
  # Auto-detect build command if not set
  if [ -z "${BUILD_CMD:-}" ]; then
     if [ -f "$SRC_ROOT/build.sh" ]; then BUILD_CMD="./build.sh";
     elif [ -f "$SRC_ROOT/CMakeLists.txt" ]; then BUILD_CMD="mkdir -p build && cd build && cmake .. && make -j$(nproc)";
     else BUILD_CMD="make -j$(nproc)"; fi
  fi

  bash "${SAILOR_ROOT}/codeql_scan.sh" \
    PROJECT_NAME="$PROJECT_NAME" \
    SRC_ROOT="$SRC_ROOT" \
    BUILD_CMD="$BUILD_CMD" \
    QUERY_SUITES="${QUERY_SUITES:-rules/sailor-queries/suites/sailor.qls}" \
    TIME_PER_RULE=true
fi

# --- 3. GENERATE SPECS (skip if already populated) ---
echo "[=] Step 2: Generating Specs"
mkdir -p "$SPECS_DIR"

EXISTING_SPECS=$(find "$SPECS_DIR" -maxdepth 1 -name "*.json" 2>/dev/null | wc -l)
if [ "$EXISTING_SPECS" -gt 0 ]; then
  echo "  [SKIP] $EXISTING_SPECS spec(s) already exist in $SPECS_DIR. Delete them to regenerate."
else
  python3 "${SAILOR_ROOT}/make_vul_specs.py" \
    --findings "$FINDINGS_JSON" \
    --facts "$FACT_PACK_JSON" \
    --out "$SPECS_DIR"
fi

# --- 4. BUILD BITCODE ---
echo "[=] Step 3: Building Bitcode"

if [ ! -f "$PROJECT_BC" ]; then
  bash "${SAILOR_ROOT}/sailor_engine/build_project_bc.sh" "$SRC_ROOT" "$PROJECT_BC"

  if [ ! -f "$PROJECT_BC" ]; then
    echo "[ERROR] Failed to generate project.bc"
    exit 1
  fi
fi

echo "[OK] Preparation Complete. Specs in: $SPECS_DIR"
