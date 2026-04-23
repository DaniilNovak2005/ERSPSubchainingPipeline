#!/usr/bin/env bash
# run_sailor_imagemagick.sh — Run the full SAILOR pipeline on ImageMagick only.
#
# Usage:
#   bash run_sailor_imagemagick.sh
#
# Requires:
#   - Docker installed and the 'sailor' image already built:
#       docker build -t sailor .
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

# --- ImageMagick source ---
IMAGEMAGICK_TAG="7.1.2-19"
IMAGEMAGICK_REPO="https://github.com/ImageMagick/ImageMagick.git"

# Cache the discovered commit hash so reruns don't need to re-clone
COMMIT_CACHE="dataset/.imagemagick_commit"

if [ -f "$COMMIT_CACHE" ]; then
    COMMIT_FULL=$(cat "$COMMIT_CACHE")
    COMMIT="${COMMIT_FULL:0:8}"
    echo "[Setup] Using cached commit ${COMMIT} (${IMAGEMAGICK_TAG})."
else
    echo "[Setup] Cloning ImageMagick ${IMAGEMAGICK_TAG} to discover commit hash..."
    TEMP_CLONE="dataset/_imagemagick_tmp"
    mkdir -p dataset/
    git clone --depth 1 --branch "$IMAGEMAGICK_TAG" "$IMAGEMAGICK_REPO" "$TEMP_CLONE"
    COMMIT_FULL=$(cd "$TEMP_CLONE" && git rev-parse HEAD)
    COMMIT="${COMMIT_FULL:0:8}"
    echo "$COMMIT_FULL" > "$COMMIT_CACHE"
    echo "[Setup] Detected commit: ${COMMIT_FULL}"

    # Move to final path now that we know the hash
    DATASET_PATH="dataset/${COMMIT}/imagemagick_${COMMIT}_vul"
    mkdir -p "$(dirname "$DATASET_PATH")"
    mv "$TEMP_CLONE" "$DATASET_PATH"
fi

# --- Project identifiers ---
PROJECT="imagemagick_${COMMIT}_vul"
COMMIT_PROJ="${COMMIT}/${PROJECT}"
DATASET_PATH="dataset/${COMMIT_PROJ}"

echo ""

# --- Clone if temp move didn't happen (e.g. cached run but dir missing) ---
if [ ! -d "${DATASET_PATH}/.git" ]; then
    echo "[Setup] Dataset missing — cloning ImageMagick ${IMAGEMAGICK_TAG} at ${COMMIT_FULL}..."
    mkdir -p "$(dirname "$DATASET_PATH")"
    git clone --depth 1 --branch "$IMAGEMAGICK_TAG" "$IMAGEMAGICK_REPO" "$DATASET_PATH"
    echo "[Setup] Clone done."
    echo ""
else
    echo "[Setup] ImageMagick dataset already present, skipping clone."
    echo ""
fi

# --- Create project config if it doesn't exist ---
# Config is volume-mounted into Docker via configs/, so it must exist on the host.
CONFIG_FILE="configs/${PROJECT}_config.sh"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[Setup] Creating ${CONFIG_FILE}..."
    cat > "$CONFIG_FILE" << 'EOF'
#!/bin/bash
# SAILOR config for ImageMagick
# autoconf build — configure auto-detects available codec libs and skips the rest
export BUILD_CMD="./configure \
    --disable-shared \
    --enable-static \
    --without-x \
    --without-perl \
    --without-magick-plus-plus \
    --disable-openmp \
    --prefix=\$(pwd)/build \
    CFLAGS='-g -O0' && \
    make -j\$(nproc) && make install"

export EXTRA_CFLAGS="-I\${SRC_ROOT} -I\${SRC_ROOT}/MagickCore -I\${SRC_ROOT}/MagickWand -I\${SRC_ROOT}/build/include/ImageMagick-7"

# CLI utilities — not part of the core library
export TOOL_FILES="magick.c,animate.c,compare.c,composite.c,conjure.c,convert.c,display.c,identify.c,import.c,mogrify.c,montage.c,stream.c"

# Test and script files — not part of core library
export NON_LIBRARY_FILES="test_*.c,validate.c,drawtest.c,wandtest.c,pidgin.c"

export PARALLEL_JOBS=64
EOF
    echo "[Setup] Config created."
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
echo "  SAILOR — ImageMagick only run"
echo "  Project:  ${COMMIT_PROJ}"
echo "  Model:    ${LLM_MODEL:-<not set>}"
echo "  Jobs:     ${JOBS:-4}"
echo "============================================================"
echo ""

# ----------------------------------------------------------------
# Phase 1: CodeQL scan + vulnerability spec generation
# ----------------------------------------------------------------
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
        --memory=32g \
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
# run_worker.sh skips individual specs that already have a summary.tsv row or
# run_report.json. We skip the whole Docker run only when all specs are done.
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
        --memory=32g \
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
RESULTS_TSV="results.tsv"

if [ -f "$SUMMARY" ]; then
    echo -e "Project\t$(head -1 "$SUMMARY")" > "$RESULTS_TSV"
    tail -n +2 "$SUMMARY" | sed "s/^/${PROJECT}\t/" >> "$RESULTS_TSV"

    echo "============================================================"
    echo "  Results: ${RESULTS_TSV}"
    echo "============================================================"
    column -t -s$'\t' "$RESULTS_TSV" 2>/dev/null || cat "$RESULTS_TSV"
else
    echo "[WARN] Summary file not found: ${SUMMARY}"
fi
