#!/usr/bin/env bash
# restart_remaining.sh — Resume a SAILOR run by feeding only incomplete specs to xargs.
# Usage: restart_remaining.sh PROJECT_ID SUMMARY_TSV SPECS_DIR [JOBS] [RULE_ID]
#
# Example (inside Docker container):
#   bash /app/sailor_engine/restart_remaining.sh \
#       0f08d958/sqlite_0f08d958_vul \
#       /app/se_runs/sailor_engine/sqlite_0f08d958_vul/summary.tsv \
#       /app/specs/sqlite_0f08d958_vul \
#       128

set -euo pipefail

if [ $# -lt 3 ]; then
    echo "Usage: $0 PROJECT_ID SUMMARY_TSV SPECS_DIR [JOBS] [RULE_ID]" >&2
    echo "" >&2
    echo "  PROJECT_ID   e.g. 0f08d958/sqlite_0f08d958_vul" >&2
    echo "  SUMMARY_TSV  path to summary.tsv from previous run" >&2
    echo "  SPECS_DIR    directory containing spec .json files" >&2
    echo "  JOBS         parallelism (default: 128)" >&2
    echo "  RULE_ID      rule id passed to worker (default: auto)" >&2
    exit 1
fi

PROJECT_ID="$1"
SUMMARY_TSV="$2"
SPECS_DIR="$3"
JOBS="${4:-128}"
RULE_ID="${5:-auto}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKER_SCRIPT="${REPO_ROOT}/sailor_engine/run_worker.sh"

# --- Validate inputs ---
if [ ! -f "$SUMMARY_TSV" ]; then
    echo "[ERROR] summary.tsv not found: $SUMMARY_TSV" >&2
    exit 1
fi
if [ ! -d "$SPECS_DIR" ]; then
    echo "[ERROR] Specs directory not found: $SPECS_DIR" >&2
    exit 1
fi

# --- Get completed spec stems from summary.tsv (skip header) ---
COMPLETED_STEMS=$(mktemp)
tail -n +2 "$SUMMARY_TSV" | cut -f1 | sort -u > "$COMPLETED_STEMS"
COMPLETED_COUNT=$(wc -l < "$COMPLETED_STEMS")

# --- Get all spec stems ---
ALL_SPECS=$(mktemp)
find "$SPECS_DIR" -maxdepth 1 -name "*.json" ! -name "triage.json" -print0 | \
    xargs -0 -n1 basename | sed 's/\.json$//' | sort > "$ALL_SPECS"
TOTAL_COUNT=$(wc -l < "$ALL_SPECS")

# --- Compute remaining ---
REMAINING_STEMS=$(mktemp)
comm -23 "$ALL_SPECS" "$COMPLETED_STEMS" > "$REMAINING_STEMS"
REMAINING_COUNT=$(wc -l < "$REMAINING_STEMS")

echo "[RESTART] Project:    ${PROJECT_ID}"
echo "[RESTART] Rule:       ${RULE_ID}"
echo "[RESTART] Specs dir:  ${SPECS_DIR}"
echo "[RESTART] Summary:    ${SUMMARY_TSV}"
echo "[RESTART] Total:      ${TOTAL_COUNT}"
echo "[RESTART] Completed:  ${COMPLETED_COUNT}"
echo "[RESTART] Remaining:  ${REMAINING_COUNT}"
echo "[RESTART] Parallelism: ${JOBS}"
echo ""

if [ "$REMAINING_COUNT" -eq 0 ]; then
    echo "[RESTART] All specs already completed. Nothing to do."
    rm -f "$COMPLETED_STEMS" "$ALL_SPECS" "$REMAINING_STEMS"
    exit 0
fi

# Export SUMMARY_TSV so the worker reuses the same file
export SUMMARY_TSV

echo "[RESTART] Starting ${REMAINING_COUNT} remaining specs..."

# Convert stems back to full paths and feed to xargs
sed "s|^|${SPECS_DIR}/|; s|$|.json|" "$REMAINING_STEMS" | \
    xargs -P "${JOBS}" -I {} \
    bash "${WORKER_SCRIPT}" "${PROJECT_ID}" "${RULE_ID}" "{}"

echo ""
echo "[RESTART] All jobs finished."

# Cleanup
rm -f "$COMPLETED_STEMS" "$ALL_SPECS" "$REMAINING_STEMS"
