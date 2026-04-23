#!/usr/bin/env bash
# sailor_engine/run_batch.sh

set -euo pipefail

if [ $# -lt 3 ]; then
  echo "Usage: $0 PROJECT_ID RULE_ID SPEC_ROOT_DIR [JOBS] [EXTRA_ARGS] [MANUAL_STUBS]" >&2
  exit 1
fi

export PROJECT_ID="$1"
export RULE_ID="$2"
export SPEC_ROOT_DIR="$3"
export JOBS="${4:-4}"
export EXTRA_AGENT_ARGS="${5:-}"
export MANUAL_STUBS="${6:-}"

# SE_CONFIG_DIR is passed via environment from sailor.sh
export SE_CONFIG_DIR="${SE_CONFIG_DIR:-}"

# Paths
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SAILOR_ROOT="${SAILOR_ROOT:-${REPO_ROOT}}"
WORKER_SCRIPT="${SAILOR_ROOT}/sailor_engine/run_worker.sh"
PROJECT_SLUG="$(basename "$PROJECT_ID")"

export SE_RUNS_ROOT="${SE_RUNS_ROOT:-se_runs}"
OUTPUT_DIR="${SE_RUNS_ROOT}/sailor_engine/${PROJECT_SLUG}"
mkdir -p "$OUTPUT_DIR"
export SUMMARY_TSV="$(realpath "${OUTPUT_DIR}/summary.tsv")"
touch "$SUMMARY_TSV"

if [ -d "${SPEC_ROOT_DIR}/${PROJECT_SLUG}" ]; then
    TARGET_DIR="${SPEC_ROOT_DIR}/${PROJECT_SLUG}"
elif [ -d "${SPEC_ROOT_DIR}" ]; then
    TARGET_DIR="${SPEC_ROOT_DIR}"
else
    echo "[!] Spec directory not found: ${SPEC_ROOT_DIR}"
    exit 1
fi

echo "[BATCH] Target:    ${PROJECT_ID}"
echo "[BATCH] Specs:     ${TARGET_DIR}"
echo "[BATCH] Jobs:      ${JOBS}"
echo "[BATCH] Stubs:     ${MANUAL_STUBS}"
if [ -n "${SE_CONFIG_DIR}" ]; then
    echo "[BATCH] SE Config: ${SE_CONFIG_DIR}"
fi

COUNT=$(find "${TARGET_DIR}" -maxdepth 1 -name "*.json" ! -name "triage.json" | wc -l)
if [ "$COUNT" -eq 0 ]; then
    echo "[!] No .json spec files found in ${TARGET_DIR}"
    exit 0
fi

echo "[BATCH] Found ${COUNT} specs. Starting parallel execution..."

# Pass EXTRA_AGENT_ARGS, MANUAL_STUBS, SE_CONFIG_DIR via environment to worker
export EXTRA_AGENT_ARGS
export MANUAL_STUBS
export SE_CONFIG_DIR

# Use triage order if available (P0 specs first), otherwise alphabetical
TRIAGE_ORDER="${TARGET_DIR}/triage_order.txt"
if [ -f "$TRIAGE_ORDER" ]; then
    echo "[BATCH] Using triage priority order (P0 first)"
    # triage_order.txt has one filename per line in priority order
    # Convert to full paths and feed to xargs
    while IFS= read -r spec_name; do
        spec_path="${TARGET_DIR}/${spec_name}"
        [ -f "$spec_path" ] && echo "$spec_path"
    done < "$TRIAGE_ORDER" | \
    xargs -P "${JOBS}" -I {} \
    bash "${WORKER_SCRIPT}" "${PROJECT_ID}" "${RULE_ID}" "{}"
else
    find "${TARGET_DIR}" -maxdepth 1 -name "*.json" -print0 | \
      sort -z | \
      xargs -0 -P "${JOBS}" -I {} \
      bash "${WORKER_SCRIPT}" "${PROJECT_ID}" "${RULE_ID}" "{}"
fi

echo ""
echo "[BATCH] All jobs finished."
