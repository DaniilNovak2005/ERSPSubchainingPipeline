#!/usr/bin/env bash
# run_baselines_parallel.sh — Launch all baselines + ablations inside Docker.
# Usage: bash run_baselines_parallel.sh [b1 b2 b3 b4 a1]  (default: all)
#
# B2 is project-level LLM harness generation (LLM-bound + KLEE).
# A1 runs the full SAILOR agent loop (128 parallel workers) — CPU-heavy.
# B3/B4 are LLM-bound (sequential per-finding/file).
# B1 is KLEE-only (lightweight).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f .env ]; then
    echo "[ERROR] .env file not found in $SCRIPT_DIR"
    exit 1
fi
set -a; source .env; set +a

# Auto-detect project
PROJECT_ID=$(find dataset -mindepth 2 -maxdepth 2 -type d ! -name '*_fix' | head -1 | sed 's|^dataset/||')
PROJECT_NAME="$(basename "$PROJECT_ID")"
HASH=$(echo "$PROJECT_NAME" | grep -oP '(?<=_)[a-f0-9]+(?=_vul)')
BASELINES="${@:-b1 b2 b3 b4 a1}"

echo "═══════════════════════════════════════════════════════"
echo "  SAILOR Baselines + Ablations — Parallel Execution"
echo "  Project: $PROJECT_NAME"
echo "  Hash:    $HASH"
echo "  Model:   $LLM_MODEL"
echo "  Targets: ${BASELINES}"
echo "═══════════════════════════════════════════════════════"

DOCKER_COMMON=(
    -e LLM_API_KEY -e LLM_API_BASE -e LLM_MODEL
    -e PYTHONUNBUFFERED=1
    -v "${SCRIPT_DIR}/dataset:/app/dataset"
    -v "${SCRIPT_DIR}/specs:/app/specs"
    -v "${SCRIPT_DIR}/sa_outputs:/app/sa_outputs"
    -v "${SCRIPT_DIR}/se_runs:/app/se_runs"
    -v "${SCRIPT_DIR}/artifacts:/app/artifacts"
    -v "${SCRIPT_DIR}/baselines:/app/baselines"
    -v "${SCRIPT_DIR}/configs:/app/configs"
    -v "${SCRIPT_DIR}/sailor_engine:/app/sailor_engine"
    sailor
)

# Short project tag for container names (e.g. libtiff, libxml2, libpng)
PROJ_TAG=$(echo "$PROJECT_NAME" | grep -oP '^[a-z]+')

DATASET="/app/dataset/${HASH}/${PROJECT_NAME}"
PIDS=()
NAMES=()

launch_docker() {
    local name="$1" ; shift
    local logfile="$1" ; shift
    local container="${PROJ_TAG}_${name}"

    # Skip if already complete
    local tsv="${SCRIPT_DIR}/se_runs/${name}/${PROJECT_NAME}/summary.tsv"
    if [ -f "$tsv" ]; then
        echo "  [SKIP] $name: already has summary.tsv ($(wc -l < "$tsv") lines)"
        return 0
    fi

    # Skip if container already running
    if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        echo "  [SKIP] $name: Docker container '${container}' already running"
        return 0
    fi

    echo "  [START] $name (container: ${container}) → ${logfile}"
    docker run --rm --name "$container" \
        "${DOCKER_COMMON[@]}" \
        bash -c "$*" \
        > "${SCRIPT_DIR}/${logfile}" 2>&1 &
    PIDS+=($!)
    NAMES+=("$name")
}

# ─── Phase 1: LLM-bound baselines (can run in parallel) ─────────
echo ""
echo "[Phase 1] Launching LLM-bound baselines in parallel..."
echo ""

for bl in $BASELINES; do
    case "$bl" in
        b1)
            launch_docker b1 b1_log.txt \
                "cd /app && python3 baselines/b1_ossfuzz_se/run_b1.py \
                    --project ${PROJECT_NAME} \
                    --dataset-root ${DATASET} \
                    --output-dir /app/se_runs/b1/${PROJECT_NAME} \
                    --klee-timeout ${KLEE_TIMEOUT:-300}"
            ;;
        b2)
            launch_docker b2 b2_log.txt \
                "cd /app && python3 baselines/b2_llm_harness_se/run_b2.py \
                    --project ${PROJECT_NAME} \
                    --dataset-root ${DATASET} \
                    --output-dir /app/se_runs/b2/${PROJECT_NAME} \
                    --num-rounds ${NUM_ROUNDS:-3} \
                    --klee-timeout ${KLEE_TIMEOUT:-300}"
            ;;
        b3)
            launch_docker b3 b3_log.txt \
                "cd /app && python3 baselines/b3_llm_detect/run_b3.py \
                    --project ${PROJECT_NAME} \
                    --dataset-root ${DATASET} \
                    --output-dir /app/se_runs/b3/${PROJECT_NAME} \
                    --max-files ${MAX_FILES:-50}"
            ;;
        b4)
            launch_docker b4 b4_log.txt \
                "cd /app && python3 baselines/b4_sa_llm_detect/run_b4.py \
                    --project ${PROJECT_NAME} \
                    --dataset-root ${DATASET} \
                    --sa-outputs-dir /app/sa_outputs/${PROJECT_NAME} \
                    --output-dir /app/se_runs/b4/${PROJECT_NAME}"
            ;;
        a1)
            # A1 deferred to Phase 2 (CPU-heavy, needs 128 cores)
            ;;
    esac
done

# Wait for Phase 1
echo ""
echo "[Phase 1] Waiting for ${#PIDS[@]} jobs..."
for i in "${!PIDS[@]}"; do
    if wait "${PIDS[$i]}" 2>/dev/null; then
        echo "  [OK] ${NAMES[$i]} complete"
    else
        echo "  [!!] ${NAMES[$i]} failed (check ${NAMES[$i]}_log.txt)"
    fi
done

# ─── Phase 2: A1 (CPU-heavy, full agent loop) ───────────────────
if echo "$BASELINES" | grep -qw a1; then
    A1_TSV="${SCRIPT_DIR}/se_runs/a1/${PROJECT_NAME}/summary.tsv"
    if [ -f "$A1_TSV" ]; then
        echo ""
        echo "[Phase 2] A1: already has summary.tsv ($(wc -l < "$A1_TSV") lines) — SKIP"
    else
        echo ""
        echo "[Phase 2] Launching A1 (SAILOR − SA, 128 jobs)..."
        docker run --rm --name "${PROJ_TAG}_a1" \
            -e JOBS=${JOBS:-128} \
            "${DOCKER_COMMON[@]}" \
            bash -c "cd /app && python3 baselines/a1_sailor_no_sa/run_a1.py \
                --project ${PROJECT_NAME} \
                --dataset-root ${DATASET} \
                --output-dir /app/se_runs/a1/${PROJECT_NAME} \
                --max-files ${MAX_FILES:-50} \
                --jobs ${JOBS:-128}" \
            > "${SCRIPT_DIR}/a1_log.txt" 2>&1
        echo "  [OK] A1 complete"
    fi
fi

# ─── Comparison ──────────────────────────────────────────────────
echo ""
echo "[Final] Generating comparison..."

COMPARE_ARGS="--sailor /app/se_runs/sailor_engine/${PROJECT_NAME}"
COMPARE_ARGS="${COMPARE_ARGS} --output /app/reports/comparison/${PROJECT_NAME}"
for bl in b1 b2 b3 b4 a1; do
    tsv="${SCRIPT_DIR}/se_runs/${bl}/${PROJECT_NAME}/summary.tsv"
    if [ -f "$tsv" ]; then
        COMPARE_ARGS="${COMPARE_ARGS} --${bl} /app/se_runs/${bl}/${PROJECT_NAME}"
    fi
done

docker run --rm \
    -e PYTHONUNBUFFERED=1 \
    -v "${SCRIPT_DIR}/se_runs:/app/se_runs" \
    -v "${SCRIPT_DIR}/baselines:/app/baselines" \
    -v "${SCRIPT_DIR}/reports:/app/reports" \
    -v "${SCRIPT_DIR}/sailor_engine:/app/sailor_engine" \
    sailor \
    bash -c "cd /app && python3 baselines/compare_baselines.py ${COMPARE_ARGS}" \
    2>&1 | tee "${SCRIPT_DIR}/comparison_log.txt"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  All experiments complete for ${PROJECT_NAME}!"
echo "═══════════════════════════════════════════════════════"
