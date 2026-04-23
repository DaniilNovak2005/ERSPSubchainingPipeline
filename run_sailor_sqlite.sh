#!/usr/bin/env bash
# run_sailor_sqlite.sh — Run the full SAILOR pipeline on SQLite only.
#
# Usage:
#   bash run_sailor_sqlite.sh
#
# Requires:
#   - Docker installed and the 'sailor' image already built:
#       docker build -t sailor .
#   - A populated dataset/0f08d958/sqlite_0f08d958_vul/ directory:
#       bash setup_dataset.sh   (clones all projects; SQLite is included)
#   - A .env file with LLM credentials (copy .env.example and fill in keys)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- Load environment ---
if [ ! -f ".env" ]; then
    echo "[ERROR] .env file not found. Copy .env.example and fill in your API keys."
    exit 1
fi
source .env

# --- SQLite project identifiers ---
COMMIT="0f08d958"
COMMIT_FULL="0f08d9586c4e93c6fd84666cbd17ab17d9a7f57c"
PROJECT="sqlite_0f08d958_vul"
COMMIT_PROJ="${COMMIT}/${PROJECT}"
DATASET_PATH="dataset/${COMMIT_PROJ}"

# --- Clone SQLite dataset if not already present ---
if [ ! -d "${DATASET_PATH}/.git" ]; then
    echo "[Setup] Cloning SQLite at commit ${COMMIT_FULL}..."
    mkdir -p "$(dirname "${DATASET_PATH}")"
    git clone "https://github.com/sqlite/sqlite.git" "${DATASET_PATH}"
    (cd "${DATASET_PATH}" && git checkout "${COMMIT_FULL}")
    echo "[Setup] Clone done."
    echo ""
else
    echo "[Setup] SQLite dataset already present, skipping clone."
    echo ""
fi

# --- Create build.sh for SQLite (not present in the cloned repo) ---
# SQLite uses ./configure + make; the project config expects a build.sh wrapper.
BUILD_SH="${DATASET_PATH}/build.sh"
if [ ! -f "$BUILD_SH" ]; then
    echo "[Setup] Creating build.sh for SQLite..."
    cat > "$BUILD_SH" << 'EOF'
#!/bin/bash
set -e
mkdir -p build
./configure --prefix="$(pwd)/build" --disable-shared
make -j$(nproc)
EOF
    chmod +x "$BUILD_SH"
    echo "[Setup] build.sh created."
    echo ""
fi

# --- Shared Docker volume mounts ---
MOUNTS=(
    -v "$(pwd)/dataset:/app/dataset"
    -v "$(pwd)/sa_outputs:/app/sa_outputs"
    -v "$(pwd)/specs:/app/specs"
    -v "$(pwd)/rules:/app/rules"
    -v "$(pwd)/configs:/app/configs"
    -v "$(pwd)/se_runs:/app/se_runs"
    # Mount scripts so edits on the host take effect without rebuilding the image
    -v "$(pwd)/sailor.sh:/app/sailor.sh"
    -v "$(pwd)/sailor_prepare.sh:/app/sailor_prepare.sh"
    -v "$(pwd)/sailor_engine:/app/sailor_engine"
)

echo "============================================================"
echo "  SAILOR — SQLite only run"
echo "  Project:  ${COMMIT_PROJ}"
echo "  Model:    ${LLM_MODEL:-<not set>}"
echo "  Jobs:     ${JOBS:-4}"
echo "============================================================"
echo ""

# ----------------------------------------------------------------
# Phase 1: CodeQL scan + vulnerability spec generation
# ----------------------------------------------------------------
# Sentinel files written by sailor_prepare.sh when each sub-step finishes.
FINDINGS_JSON="sa_outputs/${PROJECT}/findings.json"
PROJECT_BC="${DATASET_PATH}/project.bc"
SPECS_DIR="specs/${PROJECT}"
SPEC_COUNT=0
[ -d "${SPECS_DIR}" ] && SPEC_COUNT=$(find "${SPECS_DIR}" -maxdepth 1 -name "*.json" | wc -l)

if [ -f "${FINDINGS_JSON}" ] && [ -f "${PROJECT_BC}" ] && [ "${SPEC_COUNT}" -gt 0 ]; then
    echo "[Phase 1] Already complete (${SPEC_COUNT} specs, findings.json, project.bc found) — skipping."
else
    echo "[Phase 1] CodeQL scan + spec generation..."
    sudo docker run --rm \
        "${MOUNTS[@]}" \
        sailor bash -c "./sailor_prepare.sh ${COMMIT_PROJ}"
    SPEC_COUNT=0
    [ -d "${SPECS_DIR}" ] && SPEC_COUNT=$(find "${SPECS_DIR}" -maxdepth 1 -name "*.json" | wc -l)
    echo "[Phase 1] Done."
fi
echo ""

# ----------------------------------------------------------------
# Phase 2+3: LLM harness synthesis + KLEE + concrete validation
# ----------------------------------------------------------------
# run_worker.sh already skips individual specs that have a row in summary.tsv
# or an existing run_report.json. We skip the whole Docker run only when every
# spec has been processed (summary row count == spec count, excluding header).
SUMMARY="se_runs/sailor_engine/${PROJECT}/summary.tsv"
DONE_COUNT=0
if [ -f "${SUMMARY}" ]; then
    DONE_COUNT=$(tail -n +2 "${SUMMARY}" | wc -l)
fi

if [ "${SPEC_COUNT}" -gt 0 ] && [ "${DONE_COUNT}" -ge "${SPEC_COUNT}" ]; then
    echo "[Phase 2+3] Already complete (${DONE_COUNT}/${SPEC_COUNT} specs in summary.tsv) — skipping."
else
    echo "[Phase 2+3] LLM agent + KLEE symbolic execution + ASan replay..."
    echo "            Resuming from spec ${DONE_COUNT}/${SPEC_COUNT} (completed specs will be skipped by run_worker.sh)."
    sudo docker rm -f "sailor_${PROJECT}" 2>/dev/null || true
    sudo docker run --rm \
        --name "sailor_${PROJECT}" \
        -e LLM_API_KEY="${LLM_API_KEY}" \
        -e LLM_API_BASE="${LLM_API_BASE}" \
        -e LLM_MODEL="${LLM_MODEL}" \
        -e JOBS="${JOBS:-4}" \
        -e MAX_TURNS="${MAX_TURNS:-60}" \
        -e KLEE_TIMEOUT="${KLEE_TIMEOUT:-300}" \
        "${MOUNTS[@]}" \
        sailor bash -c "./sailor.sh ${COMMIT_PROJ}"
    echo "[Phase 2+3] Done."
fi
echo ""

# ----------------------------------------------------------------
# Results
# ----------------------------------------------------------------
SUMMARY="se_runs/sailor_engine/${PROJECT}/summary.tsv"
RESULTS_TSV="results.tsv"

if [ -f "$SUMMARY" ]; then
    # Write/update general results.tsv with a Project column prepended
    echo -e "Project\t$(head -1 "$SUMMARY")" > "$RESULTS_TSV"
    tail -n +2 "$SUMMARY" | sed "s/^/${PROJECT}\t/" >> "$RESULTS_TSV"

    echo "============================================================"
    echo "  Results: ${RESULTS_TSV}"
    echo "============================================================"
    column -t -s$'\t' "$RESULTS_TSV" 2>/dev/null || cat "$RESULTS_TSV"
else
    echo "[WARN] Summary file not found: ${SUMMARY}"
fi
