#!/usr/bin/env bash
# Run all baselines and ablations for a given project.
#
# Usage:
#   bash baselines/run_all.sh <PROJECT> [BASELINES...]
#
# Examples:
#   bash baselines/run_all.sh libtiff_f324415_vul          # all baselines + ablations
#   bash baselines/run_all.sh libtiff_f324415_vul b3 b4    # only B3 and B4
#   bash baselines/run_all.sh libtiff_f324415_vul a1       # only A1
#
# Environment:
#   JOBS=128          Parallel jobs for A1 (default: 4)
#   KLEE_TIMEOUT=300  KLEE timeout for B1/B2 (default: 300s)
#   NUM_ROUNDS=3      LLM generation rounds for B2 (default: 3)
#   MAX_FILES=50      Max files for B3 scan (default: 50)
#   MAX_FINDINGS=0    Max findings for B4 (default: 0=all)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${REPO_ROOT}/venv/bin/python3"
[ -f "$PYTHON" ] || PYTHON="python3"

PROJECT="${1:?Usage: $0 <PROJECT> [baselines...]}"
shift
BASELINES=("${@:-b1 b2 b3 b4 a1}")
if [ ${#BASELINES[@]} -eq 0 ]; then
    BASELINES=(b1 b2 b3 b4 a1)
fi

# Resolve project paths
# Project format: libtiff_f324415_vul → hash=f324415
HASH=$(echo "$PROJECT" | grep -oP '(?<=_)[a-f0-9]+(?=_vul)')
DATASET_ROOT="${REPO_ROOT}/dataset/${HASH}/${PROJECT}"
SA_OUTPUTS="${REPO_ROOT}/sa_outputs/${PROJECT}"
JOBS="${JOBS:-4}"
KLEE_TIMEOUT="${KLEE_TIMEOUT:-300}"
NUM_ROUNDS="${NUM_ROUNDS:-3}"
MAX_FILES="${MAX_FILES:-50}"
MAX_FINDINGS="${MAX_FINDINGS:-0}"

echo "══════════════════════════════════════════════════════"
echo "  SAILOR Baseline & Ablation Runner"
echo "══════════════════════════════════════════════════════"
echo "  Project:     ${PROJECT}"
echo "  Dataset:     ${DATASET_ROOT}"
echo "  SA Outputs:  ${SA_OUTPUTS}"
echo "  Baselines:   ${BASELINES[*]}"
echo "  Jobs:        ${JOBS}"
echo "══════════════════════════════════════════════════════"

for baseline in "${BASELINES[@]}"; do
    OUTPUT_DIR="${REPO_ROOT}/se_runs/${baseline}/${PROJECT}"
    echo ""
    echo "━━━ Running ${baseline} ━━━"

    case "$baseline" in
        b1)
            "$PYTHON" "${REPO_ROOT}/baselines/b1_ossfuzz_se/run_b1.py" \
                --project "$PROJECT" \
                --dataset-root "$DATASET_ROOT" \
                --output-dir "$OUTPUT_DIR" \
                --klee-timeout "$KLEE_TIMEOUT"
            ;;
        b2)
            "$PYTHON" "${REPO_ROOT}/baselines/b2_llm_harness_se/run_b2.py" \
                --project "$PROJECT" \
                --dataset-root "$DATASET_ROOT" \
                --output-dir "$OUTPUT_DIR" \
                --num-rounds "$NUM_ROUNDS" \
                --klee-timeout "$KLEE_TIMEOUT"
            ;;
        b3)
            "$PYTHON" "${REPO_ROOT}/baselines/b3_llm_detect/run_b3.py" \
                --project "$PROJECT" \
                --dataset-root "$DATASET_ROOT" \
                --output-dir "$OUTPUT_DIR" \
                --max-files "$MAX_FILES"
            ;;
        b4)
            "$PYTHON" "${REPO_ROOT}/baselines/b4_sa_llm_detect/run_b4.py" \
                --project "$PROJECT" \
                --dataset-root "$DATASET_ROOT" \
                --sa-outputs-dir "$SA_OUTPUTS" \
                --output-dir "$OUTPUT_DIR"
            ;;
        a1)
            "$PYTHON" "${REPO_ROOT}/baselines/a1_sailor_no_sa/run_a1.py" \
                --project "$PROJECT" \
                --dataset-root "$DATASET_ROOT" \
                --output-dir "$OUTPUT_DIR" \
                --max-files "$MAX_FILES" \
                --jobs "$JOBS"
            ;;
        *)
            echo "[!] Unknown baseline: $baseline"
            continue
            ;;
    esac

    echo "━━━ ${baseline} complete ━━━"
done

# Run comparison
echo ""
echo "━━━ Generating comparison ━━━"
SAILOR_DIR="${REPO_ROOT}/se_runs/sailor_engine/${PROJECT}"
COMPARE_ARGS=(
    --sailor "$SAILOR_DIR"
    --output "${REPO_ROOT}/reports/comparison/${PROJECT}"
)
for baseline in "${BASELINES[@]}"; do
    BDIR="${REPO_ROOT}/se_runs/${baseline}/${PROJECT}"
    if [ -f "${BDIR}/summary.tsv" ]; then
        COMPARE_ARGS+=(--"$baseline" "$BDIR")
    fi
done

"$PYTHON" "${REPO_ROOT}/baselines/compare_baselines.py" "${COMPARE_ARGS[@]}"

echo ""
echo "══════════════════════════════════════════════════════"
echo "  All baselines complete!"
echo "══════════════════════════════════════════════════════"
