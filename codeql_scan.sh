#!/usr/bin/env bash
set -euo pipefail

# One-time CodeQL scan script.

# ---- read KEY=VALUE args ----
for kv in "$@"; do export "$kv"; done

: "${PROJECT_NAME:?PROJECT_NAME is required}"
: "${SRC_ROOT:?SRC_ROOT is required}"
: "${BUILD_CMD:?BUILD_CMD is required}"
: "${QUERY_SUITES:?QUERY_SUITES is required}"

CONTEXT_LINES="${CONTEXT_LINES:-20}"
ALSO_CPP="${ALSO_CPP:-false}"
ADDITIONAL_PACKS="${ADDITIONAL_PACKS:-}"

# Tunables for CodeQL (forwarded to the Python wrapper → CodeQL CLI)
CODEQL_THREADS="${CODEQL_THREADS:-0}"         # 0 = all cores
CODEQL_RAM="${CODEQL_RAM:-80%}"
CODEQL_VERBOSITY="${CODEQL_VERBOSITY:--v}"    # -v | -vv | -vvv
CODEQL_LOG_TO_STDERR="${CODEQL_LOG_TO_STDERR:-true}"

# If true, run each expanded query separately and write per-rule timing logs.
TIME_PER_RULE="${TIME_PER_RULE:-false}"

# Build a search path:
# 1) explicit CODEQL_SEARCH_PATH if provided
# 2) else default CLI dirs
# 3) append ADDITIONAL_PACKS if set
# Resolve the pack search path: explicit env > CodeQL default dirs > fallback
if [ -n "${CODEQL_SEARCH_PATH:-}" ]; then
    DEFAULT_SEARCH_PATH="${CODEQL_SEARCH_PATH}"
else
    DEFAULT_SEARCH_PATH="$(codeql resolve qlpacks --format=path 2>/dev/null | tr '\n' ':' | sed 's/:$//' || echo /root/.codeql/packages)"
fi
if [[ -n "${ADDITIONAL_PACKS}" ]]; then
  DEFAULT_SEARCH_PATH="${DEFAULT_SEARCH_PATH}:${ADDITIONAL_PACKS}"
elif [[ -z "${ADDITIONAL_PACKS}" && " ${QUERY_SUITES} " == *" rules/"* ]]; then
  # auto-add local 'rules' when suites reference it
  ADDITIONAL_PACKS="rules"
  DEFAULT_SEARCH_PATH="${DEFAULT_SEARCH_PATH}:rules"
fi

args=(
  --project-name   "${PROJECT_NAME}"
  --source-path    "${SRC_ROOT}"
  --build-command  "${BUILD_CMD}"
  --context-lines  "${CONTEXT_LINES}"
  --overwrite
  --threads        "${CODEQL_THREADS}"
  --ram            "${CODEQL_RAM}"
  --search-path    "${DEFAULT_SEARCH_PATH}"
)

# Pass additional packs explicitly if set (some wrappers like to see both)
if [[ -n "${ADDITIONAL_PACKS}" ]]; then
  args+=( --additional-packs "${ADDITIONAL_PACKS}" )
fi

# Add suites (support multiple entries separated by spaces)
read -r -a suites <<< "${QUERY_SUITES}"
if [[ ${#suites[@]} -eq 0 ]]; then
  echo "[!] QUERY_SUITES is empty"; exit 2
fi
args+=( --query-suites "${suites[@]}" )
# Optionally include the stock cpp query pack
if [[ "${ALSO_CPP}" == "true" ]]; then
  args+=( --also-run-cpp-queries )
fi

# Always show CodeQL progress logs
if [[ "${CODEQL_LOG_TO_STDERR}" == "true" ]]; then
  args+=( --log-to-stderr )
fi
# Verbosity must be a separate flag, not a value to --log-to-stderr
if [[ -n "${CODEQL_VERBOSITY}" ]]; then
  args+=( "${CODEQL_VERBOSITY}" )
fi

if [[ "${TIME_PER_RULE}" == "true" ]]; then
  args+=( --time-per-rule )
fi

OUT_ROOT="${SA_OUT_DIR:-sa_outputs}/${PROJECT_NAME}"
mkdir -p "${OUT_ROOT}"
TIME_LOG="${OUT_ROOT}/codeql_time.log"

echo "[i] Running CodeQL analysis once for project: ${PROJECT_NAME}"
echo "[dbg] run_codeql_analysis.py ${args[*]}"
echo "[i] Total runtime (wall-clock) will be written to: ${TIME_LOG}"
if [[ "${TIME_PER_RULE}" == "true" ]]; then
  echo "[i] Per-rule timing will be written to: ${OUT_ROOT}/codeql_rule_time.(jsonl|csv)"
fi

# Resolve the analysis script: check multiple candidate locations
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYSIS_SCRIPT=""
for candidate in \
    "${SCRIPT_DIR}/run_codeql_analysis.py" \
    "${SCRIPT_DIR}/scripts/run_codeql_analysis.py" \
    "run_codeql_analysis.py" \
    "scripts/run_codeql_analysis.py"; do
    if [ -f "$candidate" ]; then
        ANALYSIS_SCRIPT="$candidate"
        break
    fi
done
if [ -z "$ANALYSIS_SCRIPT" ]; then
    echo "[!] ERROR: run_codeql_analysis.py not found"; exit 2
fi

# Use /usr/bin/time so only timing goes to TIME_LOG (stdout/stderr unchanged)
LOGLEVEL=DEBUG /usr/bin/time -p -o "${TIME_LOG}" \
  python3 "${ANALYSIS_SCRIPT}" "${args[@]}"

echo
echo "[i] Artifacts ready in ${OUT_ROOT}:"
echo " - findings.json / findings.jsonl / findings.csv"
echo " - compile_commands.json"
echo " - codeql-results.sarif"
echo " - run_meta.json"
echo " - fact_pack.json (LLM context bundle)"
echo " - codeql_time.log (wall-clock runtime from /usr/bin/time)"
if [[ "${TIME_PER_RULE}" == "true" ]]; then
  echo " - codeql_rule_time.jsonl / codeql_rule_time.csv (per-rule timing)"
fi
echo
echo "[tip] List candidate targets from findings:"
echo "  jq -r '.results[] | \"\(.file):\(.startLine)  |  \(.ruleId)  |  \(.message)\"' ${OUT_ROOT}/findings.json | nl -ba"