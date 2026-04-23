#!/usr/bin/env bash
# sailor_engine/run_worker.sh
# Orchestrator: Search -> Validate -> Report

set -euo pipefail
START_TIME=$(date +%s)

if [ $# -lt 3 ]; then
  echo "Usage: $0 PROJECT_ID RULE_ID SPEC_FILE_PATH [QL_FILE]" >&2
  exit 1
fi

export PROJECT_ID="$1"
export RULE_ID="$2"
export SPEC_FILE="$3"
export QL_FILE="${4:-}"

# --- Configuration & Defaults ---
export SA_OUT_DIR="${SA_OUT_DIR:-sa_outputs}"
export DATASET_ROOT="$(realpath "${DATASET_ROOT:-dataset}")"
export LLM_MODEL="${LLM_MODEL:-}"
export LLM_API_BASE="${LLM_API_BASE:-}"
export MAX_TURNS="${MAX_TURNS:-60}"
export MAX_CYCLES="${MAX_CYCLES:-2}"
export TIMEOUT="${TIMEOUT:-600}"
export KLEE="${KLEE:-klee}"

# --- SE Config Directory (optional, passed from sailor.sh or env) ---
export SE_CONFIG_DIR="${SE_CONFIG_DIR:-}"

# --- Paths ---
export REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS_DIR="${REPO_ROOT}/sailor_engine/scripts"
PROJECT_SLUG="$(basename "$PROJECT_ID")"
export SRC_ROOT="${DATASET_ROOT}/${PROJECT_ID}"
export SA_PROJECT_DIR="${SA_OUT_DIR}/${PROJECT_SLUG}"
export SE_RUNS_ROOT="${SE_RUNS_ROOT:-se_runs}"
export MODE_ROOT="${SE_RUNS_ROOT}/sailor_engine/${PROJECT_SLUG}"
export PROJECT_BC="${SRC_ROOT}/project.bc"

# --- Python Environment Auto-Detection ---
if [ -f "${REPO_ROOT}/venv/bin/python3" ]; then
    PYTHON="${REPO_ROOT}/venv/bin/python3"
else
    PYTHON="python3"
fi

# --- STRICT LLVM 14 ENFORCEMENT (FIXED) ---
# Respect user ENV variables first. If unset, try auto-detection.
if [ -x "/usr/lib/llvm-14/bin/clang" ]; then
    : "${CLANG:=/usr/lib/llvm-14/bin/clang}"
    : "${LLVM_LINK:=/usr/lib/llvm-14/bin/llvm-link}"
    : "${LLVM_NM:=/usr/lib/llvm-14/bin/llvm-nm}"
else
    : "${CLANG:=clang-14}"
    : "${LLVM_LINK:=llvm-link-14}"
    : "${LLVM_NM:=llvm-nm-14}"
fi

export CLANG
export LLVM_LINK
export LLVM_NM

if ! command -v "$CLANG" &> /dev/null; then
    echo "[ERROR] clang-14 not found. Install llvm-14." >&2; exit 1
fi

# --- Setup Output Directories ---
mkdir -p "${MODE_ROOT}"

if [ -z "${SUMMARY_TSV:-}" ]; then
    export SUMMARY_TSV="$(realpath "${MODE_ROOT}/summary.tsv")"
fi
touch "$SUMMARY_TSV"
export VALIDATION_LOG="$(realpath "${MODE_ROOT}/validation_summary.tsv")"
touch "$VALIDATION_LOG"

# --- Spec Parsing ---
STEM="$(basename "${SPEC_FILE}" .json)"
RUN_DIR="${MODE_ROOT}/${STEM}"

# --- Skip Already-Completed Specs ---
if [ -f "$SUMMARY_TSV" ]; then
    EXISTING_VERDICT=$(awk -F'\t' -v stem="$STEM" '$1==stem {print $2; exit}' "$SUMMARY_TSV")
    if [ -n "$EXISTING_VERDICT" ]; then
        if [ "${RETRY_ERRORS:-0}" = "1" ] && [ "$EXISTING_VERDICT" = "BUILD_ERROR" ]; then
            echo "[RETRY] ${STEM}: previous BUILD_ERROR — retrying"
            # Remove old row so the new result replaces it
            awk -F'\t' -v stem="$STEM" '$1!=stem' "$SUMMARY_TSV" > "${SUMMARY_TSV}.${STEM}.tmp" && mv "${SUMMARY_TSV}.${STEM}.tmp" "$SUMMARY_TSV"
            # Clean old run directory
            rm -rf "$RUN_DIR"
        else
            echo "[SKIP] ${STEM}: already ${EXISTING_VERDICT}"
            exit 0
        fi
    fi
fi

# FIX: Extract vul_file and vul_line from the spec JSON directly (reliable),
# falling back to filename parsing only if jq/python extraction fails.
VUL_FILE=""
VUL_LINE=""
if [ -f "${SPEC_FILE}" ]; then
    VUL_FILE=$("$PYTHON" -c "
import json, os, sys
try:
    s = json.load(open('${SPEC_FILE}'))
    f = s.get('file', '')
    print(os.path.basename(f) if f else '')
except: print('')
" 2>/dev/null) || true
    VUL_LINE=$("$PYTHON" -c "
import json, sys
try:
    s = json.load(open('${SPEC_FILE}'))
    print(s.get('line', 0))
except: print(0)
" 2>/dev/null) || true
fi

# Fallback: parse from stem if JSON parsing failed
if [ -z "$VUL_FILE" ] || [ -z "$VUL_LINE" ] || [ "$VUL_LINE" = "0" ]; then
    NAME_NO_ID="${STEM#*_}"
    _parsed_line="$(echo "$NAME_NO_ID" | grep -oE '\.[a-z]+_[0-9]+_' | head -1 | grep -oE '[0-9]+' || echo "")"
    if [ -n "$_parsed_line" ]; then
        [ -z "$VUL_FILE" ] && VUL_FILE="${NAME_NO_ID%%_${_parsed_line}_*}"
        [ -z "$VUL_LINE" ] || [ "$VUL_LINE" = "0" ] && VUL_LINE="$_parsed_line"
    else
        [ -z "$VUL_FILE" ] && VUL_FILE="$(echo "${STEM}" | cut -d'_' -f2)"
        [ -z "$VUL_LINE" ] || [ "$VUL_LINE" = "0" ] && VUL_LINE="$(echo "${STEM}" | cut -d'_' -f3)"
    fi
fi

if [[ "$VUL_FILE" == *"conftest.c"* ]]; then
    echo "[SKIP] Ignoring temporary build file: ${VUL_FILE}"
    exit 0
fi

TARGET_VUL="${PROJECT_ID}:${VUL_FILE}:${VUL_LINE}"

mkdir -p "${RUN_DIR}"
if [ -f "${RUN_DIR}/run_report.json" ]; then
    if [ "${RETRY_ERRORS:-0}" = "1" ]; then
        OLD_STATUS=$("$PYTHON" -c "import json; print(json.load(open('${RUN_DIR}/run_report.json')).get('search_status',''))" 2>/dev/null || echo "")
        if [ "$OLD_STATUS" = "BUILD_ERROR" ]; then
            echo "[RETRY] ${STEM}: previous BUILD_ERROR — retrying"
            rm -rf "$RUN_DIR"
            mkdir -p "$RUN_DIR"
        else
            echo "[SKIP] ${STEM}: already ${OLD_STATUS}"
            exit 0
        fi
    else
        echo "[SKIP] Already finished: ${STEM}"
        exit 0
    fi
fi

# ==============================================================================
# SE-CONFIG EXTRAS RESOLUTION
# Merges: auto-generated + global extras + per-spec extras
# ==============================================================================
resolve_se_config_extras() {
    local CONFIG_DIR="$1"
    local SPEC_STEM="$2"
    local HARNESS_DIR="$3"

    # Guard: refuse to use the samples directory
    local DIR_BASENAME
    DIR_BASENAME="$(basename "$CONFIG_DIR")"
    if [[ "$DIR_BASENAME" == "samples" || "$CONFIG_DIR" == */samples/* ]]; then
        echo "[ERROR] SE_CONFIG points to the samples directory."
        echo "  Copy it first: cp -r se_config/samples/ se_config/my_project/"
        exit 1
    fi

    local PER_SPEC_DIR="${CONFIG_DIR}/per_spec/${SPEC_STEM}"

    # --- Load config.json overrides if present ---
    if [ -f "${CONFIG_DIR}/config.json" ]; then
        # Override MAX_TURNS, TIMEOUT etc. from config if set
        local cfg_max_turns cfg_timeout cfg_max_cycles
        cfg_max_turns=$("$PYTHON" -c "import json; c=json.load(open('${CONFIG_DIR}/config.json')); print(c.get('agent',{}).get('max_turns',''))" 2>/dev/null || echo "")
        cfg_timeout=$("$PYTHON" -c "import json; c=json.load(open('${CONFIG_DIR}/config.json')); print(c.get('agent',{}).get('timeout',''))" 2>/dev/null || echo "")
        cfg_max_cycles=$("$PYTHON" -c "import json; c=json.load(open('${CONFIG_DIR}/config.json')); print(c.get('agent',{}).get('max_cycles',''))" 2>/dev/null || echo "")

        [ -n "$cfg_max_turns" ]  && export MAX_TURNS="$cfg_max_turns"
        [ -n "$cfg_timeout" ]    && export TIMEOUT="$cfg_timeout"
        [ -n "$cfg_max_cycles" ] && export MAX_CYCLES="$cfg_max_cycles"

        # Additional KLEE flags from config
        local cfg_klee_extra
        cfg_klee_extra=$("$PYTHON" -c "
import json
c=json.load(open('${CONFIG_DIR}/config.json'))
flags=c.get('klee',{}).get('additional_flags',[])
print(' '.join(flags))
" 2>/dev/null || echo "")
        if [ -n "$cfg_klee_extra" ]; then
            for flag in $cfg_klee_extra; do
                append_klee_flag "$flag"
            done
        fi

        echo "[SE-CONFIG] Loaded config.json from ${CONFIG_DIR}"
    fi

    # --- Stubs Extra: global + per-spec (appended to MANUAL_STUBS) ---
    # We build a merged stubs_extra file in RUN_DIR and pass it
    local MERGED_STUBS_EXTRA="${HARNESS_DIR}/stubs_extra_merged.c"
    local HAS_STUBS_EXTRA=false

    if [ -f "${CONFIG_DIR}/stubs_extra.c" ]; then
        echo "/* === Global stubs_extra.c === */" > "$MERGED_STUBS_EXTRA"
        cat "${CONFIG_DIR}/stubs_extra.c" >> "$MERGED_STUBS_EXTRA"
        HAS_STUBS_EXTRA=true
        echo "[SE-CONFIG] Found global stubs_extra.c"
    fi

    if [ -f "${PER_SPEC_DIR}/stubs_extra.c" ]; then
        if [ "$HAS_STUBS_EXTRA" = true ]; then
            echo "" >> "$MERGED_STUBS_EXTRA"
        else
            : > "$MERGED_STUBS_EXTRA"
        fi
        echo "/* === Per-spec stubs_extra.c (${SPEC_STEM}) === */" >> "$MERGED_STUBS_EXTRA"
        cat "${PER_SPEC_DIR}/stubs_extra.c" >> "$MERGED_STUBS_EXTRA"
        HAS_STUBS_EXTRA=true
        echo "[SE-CONFIG] Found per-spec stubs_extra.c for ${SPEC_STEM}"
    fi

    if [ "$HAS_STUBS_EXTRA" = true ]; then
        # Append to existing MANUAL_STUBS or set it
        if [ -n "${MANUAL_STUBS:-}" ]; then
            export MANUAL_STUBS="${MANUAL_STUBS},${MERGED_STUBS_EXTRA}"
        else
            export MANUAL_STUBS="${MERGED_STUBS_EXTRA}"
        fi
    fi

    # --- Types Extra: global + per-spec ---
    local MERGED_TYPES_EXTRA="${HARNESS_DIR}/types_extra_merged.h"
    local HAS_TYPES_EXTRA=false

    if [ -f "${CONFIG_DIR}/types_extra.h" ]; then
        echo "/* === Global types_extra.h === */" > "$MERGED_TYPES_EXTRA"
        cat "${CONFIG_DIR}/types_extra.h" >> "$MERGED_TYPES_EXTRA"
        HAS_TYPES_EXTRA=true
        echo "[SE-CONFIG] Found global types_extra.h"
    fi

    if [ -f "${PER_SPEC_DIR}/types_extra.h" ]; then
        if [ "$HAS_TYPES_EXTRA" = true ]; then
            echo "" >> "$MERGED_TYPES_EXTRA"
        else
            : > "$MERGED_TYPES_EXTRA"
        fi
        echo "/* === Per-spec types_extra.h (${SPEC_STEM}) === */" >> "$MERGED_TYPES_EXTRA"
        cat "${PER_SPEC_DIR}/types_extra.h" >> "$MERGED_TYPES_EXTRA"
        HAS_TYPES_EXTRA=true
        echo "[SE-CONFIG] Found per-spec types_extra.h for ${SPEC_STEM}"
    fi

    if [ "$HAS_TYPES_EXTRA" = true ]; then
        export TYPES_EXTRA_FILE="${MERGED_TYPES_EXTRA}"
    fi

    # --- Prompt Extra: config.json + global file + per-spec file ---
    local PROMPT_EXTRA_COMBINED=""

    # From config.json
    if [ -f "${CONFIG_DIR}/config.json" ]; then
        local cfg_prompt
        cfg_prompt=$("$PYTHON" -c "import json; c=json.load(open('${CONFIG_DIR}/config.json')); print(c.get('llm',{}).get('prompt_extra',''))" 2>/dev/null || echo "")
        if [ -n "$cfg_prompt" ]; then
            PROMPT_EXTRA_COMBINED="${cfg_prompt}"
        fi
    fi

    # Global file
    if [ -f "${CONFIG_DIR}/prompt_extra.txt" ]; then
        PROMPT_EXTRA_COMBINED="${PROMPT_EXTRA_COMBINED}

$(cat "${CONFIG_DIR}/prompt_extra.txt")"
        echo "[SE-CONFIG] Found global prompt_extra.txt"
    fi

    # Per-spec file
    if [ -f "${PER_SPEC_DIR}/prompt_extra.txt" ]; then
        PROMPT_EXTRA_COMBINED="${PROMPT_EXTRA_COMBINED}

$(cat "${PER_SPEC_DIR}/prompt_extra.txt")"
        echo "[SE-CONFIG] Found per-spec prompt_extra.txt for ${SPEC_STEM}"
    fi

    # Write merged prompt to file so agent can read it
    if [ -n "$PROMPT_EXTRA_COMBINED" ]; then
        local PROMPT_FILE="${HARNESS_DIR}/prompt_extra_merged.txt"
        echo "$PROMPT_EXTRA_COMBINED" > "$PROMPT_FILE"
        export PROMPT_EXTRA_FILE="${PROMPT_FILE}"
    fi
}

# --- Argument Construction ---

# 1. KLEE Flags
append_klee_flag() {
  local f="$1"
  if [[ " ${KLEE_FLAGS:-} " != *" ${f} "* ]]; then
    KLEE_FLAGS="${KLEE_FLAGS:-} ${f}"
  fi
}
append_klee_flag "--libc=uclibc"
append_klee_flag "--posix-runtime"
append_klee_flag "--max-memory=4096"

# Apply SE config extras BEFORE finalizing flags
# (creates merged files in RUN_DIR, may update KLEE_FLAGS, MANUAL_STUBS, etc.)
if [ -n "${SE_CONFIG_DIR}" ] && [ -d "${SE_CONFIG_DIR}" ]; then
    mkdir -p "${RUN_DIR}"
    resolve_se_config_extras "${SE_CONFIG_DIR}" "${STEM}" "${RUN_DIR}"
fi

KLEE_FLAGS="$(echo "${KLEE_FLAGS:-}" | xargs)"

KLEE_FLAGS_ARG=()
if [[ -n "${KLEE_FLAGS:-}" ]]; then KLEE_FLAGS_ARG=( --klee-flags "${KLEE_FLAGS}" ); fi

# 2. Clang Flags
CLANG_FLAGS_ARG=()
if [[ -n "${CLANG_FLAGS:-}" ]]; then CLANG_FLAGS_ARG=( --clang-flags "${CLANG_FLAGS}" ); fi

# 3. QL File
QL_FILE_ARG=()
if [[ -n "${QL_FILE}" ]]; then QL_FILE_ARG=( --ql-file "${QL_FILE}" ); fi

# 4. Build Command (Critical for creating instrumented bc)
BUILD_PROJECT_BC_CMD_ARG=()
if [[ -n "${BUILD_PROJECT_BC_CMD:-}" ]]; then
  BUILD_PROJECT_BC_CMD_ARG=( --build-project-bc-cmd "${BUILD_PROJECT_BC_CMD}" )
fi

# 5. Compile Commands (Optional)
COMPILE_COMMANDS_JSON="${SA_PROJECT_DIR}/compile_commands.json"
COMPILE_COMMANDS_ARG=()
if [[ -f "${COMPILE_COMMANDS_JSON}" ]]; then
  COMPILE_COMMANDS_ARG=( --compile-commands "${COMPILE_COMMANDS_JSON}" )
fi

# 6. Manual Stubs (From Config + SE-Config extras)
MANUAL_STUBS_ARG=()
if [[ -n "${MANUAL_STUBS:-}" ]]; then
    MANUAL_STUBS_ARG=( --manual-stubs "${MANUAL_STUBS}" )
fi

# 7. Setup Script (From Config)
SETUP_SCRIPT_ARG=()
if [[ -n "${PROJECT_SETUP_SCRIPT:-}" ]]; then
    SETUP_SCRIPT_ARG=( --setup-script "${PROJECT_SETUP_SCRIPT}" )
fi

# 8. Extra Agent Args (From Config)
EXTRA_ARGS_ARR=()
if [[ -n "${EXTRA_AGENT_ARGS:-}" ]]; then
    read -r -a EXTRA_ARGS_ARR <<< "${EXTRA_AGENT_ARGS}"
fi

# 9. Types Extra (From SE-Config)
TYPES_EXTRA_ARG=()
if [[ -n "${TYPES_EXTRA_FILE:-}" ]]; then
    TYPES_EXTRA_ARG=( --types-extra "${TYPES_EXTRA_FILE}" )
fi

# 10. Prompt Extra (From SE-Config)
PROMPT_EXTRA_ARG=()
if [[ -n "${PROMPT_EXTRA_FILE:-}" ]]; then
    PROMPT_EXTRA_ARG=( --prompt-extra-file "${PROMPT_EXTRA_FILE}" )
fi

echo "[WORKER] Processing: ${STEM} (Target: ${VUL_FILE}:${VUL_LINE})"

# ==============================================================================
# PHASE 2: SEARCH (The Agent)
# ==============================================================================
echo "[WORKER] Starting Search Phase..."

# Call Python Driver — capture exit code but NEVER abort.
# Phases 3+4 MUST always run to write summary.tsv / validation_summary.tsv.
AGENT_RC=0
"$PYTHON" "${SCRIPTS_DIR}/run_agent_for_spec.py" \
  --project-id "${PROJECT_ID}" \
  --src-root "${SRC_ROOT}" \
  --spec "${SPEC_FILE}" \
  --spec-stem "${STEM}" \
  --vul-file "${VUL_FILE}" \
  --vul-line "${VUL_LINE}" \
  --target-vul "${TARGET_VUL}" \
  --run-dir "${RUN_DIR}" \
  --project-bc "${PROJECT_BC}" \
  --sa-out-dir "${SA_PROJECT_DIR}" \
  --dataset-root "${DATASET_ROOT}" \
  --clang "${CLANG}" \
  --llvm-link "${LLVM_LINK}" \
  --llvm-nm "${LLVM_NM}" \
  --klee "${KLEE}" \
  --max-turns "${MAX_TURNS}" \
  --max-cycles "${MAX_CYCLES}" \
  --timeout "${TIMEOUT}" \
  "${CLANG_FLAGS_ARG[@]}" \
  "${KLEE_FLAGS_ARG[@]}" \
  "${QL_FILE_ARG[@]}" \
  "${COMPILE_COMMANDS_ARG[@]}" \
  "${BUILD_PROJECT_BC_CMD_ARG[@]}" \
  "${MANUAL_STUBS_ARG[@]}" \
  "${SETUP_SCRIPT_ARG[@]}" \
  "${TYPES_EXTRA_ARG[@]}" \
  "${PROMPT_EXTRA_ARG[@]}" \
  "${EXTRA_ARGS_ARR[@]}" || AGENT_RC=$?

if [[ $AGENT_RC -ne 0 ]]; then
    echo "[WORKER] Agent exited with code $AGENT_RC"
fi

# ==============================================================================
# PHASE 3: STRICT VALIDATION (The Judge)
# ==============================================================================
echo "[WORKER] Starting Validation Phase..."

VALIDATED_COUNT=0
STUBBED_COUNT=0

# Write validation_summary.tsv header if empty
(
  flock -x 200
  if [ ! -s "$VALIDATION_LOG" ]; then
      echo -e "Spec\tCrashIdx\tRelevance\tBugType\tBugFunc\tOrigFile\tOrigLine\tVerdict\tHarnessConfirmed\tTimestamp" > "$VALIDATION_LOG"
  fi
) 200>"${VALIDATION_LOG}.lock"

# Read ALL crashes from bug_report.json (the agent's output).
# Each crash gets one row in validation_summary.tsv.
BUG_REPORT="${RUN_DIR}/bug_report.json"
if [[ ! -f "$BUG_REPORT" ]]; then
    # Also check harness parent
    BUG_REPORT="${RUN_DIR}/harness/../bug_report.json"
fi

if [[ -f "$BUG_REPORT" ]]; then
    echo "[WORKER] Reading bug report: ${BUG_REPORT}"

    # Extract all crashes via single Python call, output as TSV lines
    CRASH_LINES=$("$PYTHON" -c "
import json, sys
try:
    r = json.load(open('$BUG_REPORT'))
    verdict = r.get('summary', {}).get('verdict', 'FP')
    cwe = r.get('summary', {}).get('cwe', '')

    crashes = r.get('all_asan_crashes', [])
    if not crashes:
        # Fallback: use primary asan_result if all_asan_crashes is empty
        ar = r.get('asan_result', {})
        if ar.get('triggered'):
            crashes = [{
                'error_type': ar.get('error_type', ''),
                'crash_function': ar.get('crash_function', ''),
                'original_file': ar.get('original_file', ''),
                'original_line': ar.get('original_line', 0),
                'relevance': r.get('summary', {}).get('crash_relevance', 'unknown'),
            }]
    if not crashes and r.get('asan_result', {}).get('harness_artifact'):
        # Harness artifact — ASan crash was in harness code, skip klee fallback
        crashes = []
    elif not crashes:
        # Fallback: use klee_crash if no ASAN data
        kc = r.get('klee_crash', {})
        if kc.get('error_type'):
            crashes = [{
                'error_type': kc.get('error_type', ''),
                'crash_function': r.get('vulnerability', {}).get('function', ''),
                'original_file': kc.get('original_file', ''),
                'original_line': kc.get('original_line', 0),
                'relevance': 'klee_only',
            }]

    for i, c in enumerate(crashes):
        def s(v): return str(v).replace('\t', ' ').replace('\n', ' ')[:200]
        etype = s(c.get('error_type', ''))
        func = s(c.get('crash_function', ''))
        ofile = s(c.get('original_file', ''))
        oline = c.get('original_line', 0)
        rel = s(c.get('relevance', ''))
        asan = 'true' if c.get('error_type') else 'false'
        # TSV: idx, relevance, bug_type, func, file, line, verdict, asan
        print(f'{i}\t{rel}\t{etype}\t{func}\t{ofile}\t{oline}\t{verdict}\t{asan}')
except Exception as e:
    print(f'ERR\t\t{e}\t\t\t\tFP\tfalse', file=sys.stderr)
" 2>/dev/null) || true

    if [[ -n "$CRASH_LINES" ]]; then
        CRASH_COUNT=0
        while IFS=$'\t' read -r C_IDX C_REL C_TYPE C_FUNC C_FILE C_LINE C_VERDICT C_ASAN; do
            CRASH_COUNT=$((CRASH_COUNT + 1))
            echo "[WORKER] Crash #${C_IDX}: ${C_TYPE} in ${C_FUNC} at ${C_FILE}:${C_LINE} [${C_REL}]"

            # Count validated (ASan-confirmed) crashes
            if [[ "$C_ASAN" == "true" ]]; then
                VALIDATED_COUNT=$((VALIDATED_COUNT + 1))
            fi

            (
              flock -x 200
              echo -e "${STEM}\t${C_IDX}\t${C_REL}\t${C_TYPE}\t${C_FUNC}\t${C_FILE}\t${C_LINE}\t${C_VERDICT}\t${C_ASAN}\t$(date -Iseconds)" >> "${VALIDATION_LOG}"
            ) 200>"${VALIDATION_LOG}.lock"

        done <<< "$CRASH_LINES"
        echo "[WORKER] Total crashes: $CRASH_COUNT (ASan-confirmed: $VALIDATED_COUNT)"
    else
        echo "[WORKER] Bug report exists but no crashes extracted."
    fi
else
    echo "[WORKER] No bug report found — no crashes to log."
fi

# ==============================================================================
# PHASE 4: FINAL REPORTING (The Registrar)
# ==============================================================================
END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))

# 1. Parse Agent Report — extract all fields from run_report.json
REPORT_JSON="${RUN_DIR}/run_report.json"
SEARCH_STATUS="UNKNOWN"
VERDICT="FP"
TOKENS=0
TURNS=0
KLEE_RUNS=0
CRASH_RELEVANCE=""
SECONDARY_BUGS=0
FAILURE_REASON=""
BUG_TYPE=""
BUG_FILE=""
BUG_LINE=0
BUG_FUNC=""
BUG_CWE=""
ASAN_CONFIRMED="false"
HARNESS_ARTIFACT="false"

# Check harness_artifact flag from bug_report.json (set by SE-stage ASan replay)
if [[ -f "$BUG_REPORT" ]]; then
    HARNESS_ARTIFACT=$("$PYTHON" -c "
import json
try:
    r = json.load(open('$BUG_REPORT'))
    print(str(r.get('asan_result', {}).get('harness_artifact', False)).lower())
except: print('false')
" 2>/dev/null) || HARNESS_ARTIFACT="false"
fi

if [[ -f "$REPORT_JSON" ]]; then
    # Single Python call to extract all fields at once (efficient)
    # Values are single-quoted to handle spaces/special chars safely
    eval "$("$PYTHON" -c "
import json, sys
try:
    r = json.load(open('$REPORT_JSON'))
    m = r.get('metrics', {})
    b = r.get('bug', {})
    # Shell-safe: replace tabs/newlines/single-quotes with spaces, then single-quote
    def s(v): return str(v).replace('\t',' ').replace('\n',' ').replace(\"'\",\" \")[:200]
    def q(v): return \"'\" + s(v) + \"'\"
    print(f'SEARCH_STATUS={q(r.get(\"search_status\",\"ERR\"))}')
    print(f'VERDICT={q(r.get(\"verdict\",\"FP\"))}')
    print(f'TOKENS={m.get(\"tokens_total\",0)}')
    print(f'TURNS={m.get(\"turns\",0)}')
    print(f'KLEE_RUNS={m.get(\"klee_runs\",0)}')
    print(f'CRASH_RELEVANCE={q(r.get(\"crash_relevance\",\"\"))}')
    print(f'SECONDARY_BUGS={r.get(\"secondary_bugs\",0)}')
    print(f'FAILURE_REASON={q(r.get(\"failure_reason\",\"\"))}')
    print(f'BUG_TYPE={q(b.get(\"type\",\"\"))}')
    print(f'BUG_FILE={q(b.get(\"file\",\"\"))}')
    print(f'BUG_LINE={b.get(\"line\",0)}')
    print(f'BUG_FUNC={q(b.get(\"function\",\"\"))}')
    print(f'BUG_CWE={q(b.get(\"cwe\",\"\"))}')
    print(f'ASAN_CONFIRMED={str(b.get(\"asan_confirmed\",False)).lower()}')
except Exception as e:
    print(f'SEARCH_STATUS=ERR', file=sys.stderr)
" 2>/dev/null)" || true
else
    SEARCH_STATUS="CRASHED"
    FAILURE_REASON="run_report.json not found (agent exit code: ${AGENT_RC})"
fi

# 2. Determine Final Worker Status
FINAL_STATUS="$SEARCH_STATUS"

if [[ "$HARNESS_ARTIFACT" == "true" ]]; then
    FINAL_STATUS="HARNESS_ARTIFACT"
elif [[ "$SEARCH_STATUS" == "SLICING_ARTIFACT" ]] || [[ "$VERDICT" == "SLICING_ARTIFACT" ]]; then
    FINAL_STATUS="SLICING_ARTIFACT"
elif [[ $VALIDATED_COUNT -gt 0 ]]; then
    FINAL_STATUS="SE_DETECTED"
elif [[ $STUBBED_COUNT -gt 0 ]]; then
    FINAL_STATUS="VALIDATED_STUBBED"
elif [[ "$SEARCH_STATUS" == "SPEC_BUG" ]]; then
    FINAL_STATUS="FP_SPEC_BUG"
elif [[ "$SEARCH_STATUS" == *"FOUND_UNTARGETED"* ]]; then
    FINAL_STATUS="FP_UNTARGETED"
elif [[ "$SEARCH_STATUS" == "INCONCLUSIVE" ]] || [[ "$VERDICT" == "INCONCLUSIVE_LOW_COVERAGE" ]]; then
    FINAL_STATUS="INCONCLUSIVE_LOW_COVERAGE"
fi

echo "[WORKER] Final Status: $FINAL_STATUS (Verdict: $VERDICT, Time: ${TOTAL_DURATION}s, Tokens: $TOKENS, Turns: $TURNS, KLEE: $KLEE_RUNS)"
if [[ -n "$BUG_TYPE" ]]; then
    echo "[WORKER] Bug: $BUG_TYPE at $BUG_FILE:$BUG_LINE ($BUG_FUNC) CWE=$BUG_CWE ASAN=$ASAN_CONFIRMED"
fi
if [[ -n "$CRASH_RELEVANCE" ]]; then
    echo "[WORKER] Crash Relevance: $CRASH_RELEVANCE"
fi
if [[ -n "$FAILURE_REASON" ]]; then
    echo "[WORKER] Failure: $FAILURE_REASON"
fi
if [[ "$SECONDARY_BUGS" -gt 0 ]]; then
    echo "[WORKER] Secondary Bugs: $SECONDARY_BUGS"
fi

# 3. Write summary.tsv
(
  flock -x 200
  if [ ! -s "$SUMMARY_TSV" ]; then
      echo -e "Spec\tFinalStatus\tVerdict\tSearchStatus\tValTP\tValStub\tTime\tTokens\tTurns\tKleeRuns\tBugType\tBugFile\tBugLine\tBugFunc\tCWE\tHarnessConfirmed\tCrashRelevance\tSecondaryBugs\tFailureReason" > "$SUMMARY_TSV"
  fi
  echo -e "${STEM}\t${FINAL_STATUS}\t${VERDICT}\t${SEARCH_STATUS}\t${VALIDATED_COUNT}\t${STUBBED_COUNT}\t${TOTAL_DURATION}\t${TOKENS}\t${TURNS}\t${KLEE_RUNS}\t${BUG_TYPE}\t${BUG_FILE}\t${BUG_LINE}\t${BUG_FUNC}\t${BUG_CWE}\t${ASAN_CONFIRMED}\t${CRASH_RELEVANCE}\t${SECONDARY_BUGS}\t${FAILURE_REASON}" >> "$SUMMARY_TSV"
) 200>"${SUMMARY_TSV}.lock"