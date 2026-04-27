#!/usr/bin/env bash
# Batch compile + run pipeline-generated replay drivers for all LIKELY_TP specs.
# Outputs: manual_replay/specs/<spec_name>/{replay_driver, asan_output.txt, bug_report.json}
set -uo pipefail

SE_BASE="/home/danii/Documents/SAILOR_Replication_Package/se_runs/sailor_engine/libxml2_8effcb57_vul"
ASAN_LIB="/home/danii/Documents/SAILOR_Replication_Package/manual_replay/asan_build/.libs/libxml2.a"
INCLUDE_DIR="/home/danii/Documents/SAILOR_Replication_Package/manual_replay/asan_build/include"
OUT_BASE="/home/danii/Documents/SAILOR_Replication_Package/manual_replay/specs"
KLEE_COMPAT="/home/danii/Documents/SAILOR_Replication_Package/manual_replay/klee_compat.h"

mkdir -p "$OUT_BASE"

# Write klee_compat.h once
cat > "$KLEE_COMPAT" << 'EOF'
#pragma once
#define klee_make_symbolic(a,b,c)    do{}while(0)
#define klee_assume(x)               do{}while(0)
#define klee_warning(x)              do{}while(0)
#define klee_warning_once(x)         do{}while(0)
#define klee_assert(x)               do{}while(0)
#define klee_report_error(a,b,c,d)   do{}while(0)
#define klee_get_obj_size(x)         (0)
#define klee_check_memory_access(a,b) do{}while(0)
/* Silence klee/klee.h if included */
#ifndef KLEE_H
#define KLEE_H
#endif
EOF

ASAN_FLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer"
LINK_FLAGS="-lm -lz -lpthread -ldl -Wl,--allow-multiple-definition"

total=0; crash=0; no_crash=0; fail=0

# Get all LIKELY_TP specs from summary
mapfile -t SPECS < <(
    awk -F'\t' '$3=="LIKELY_TP" {print $1}' "$SE_BASE/summary.tsv"
)

for stem in "${SPECS[@]}"; do
    SPEC_DIR="$SE_BASE/$stem"
    DRIVER="$SPEC_DIR/asan_real/replay_driver.c"
    HARNESS_TYPES="$SPEC_DIR/harness/harness_types.h"

    # Skip if no substantial replay_driver.c
    [ -f "$DRIVER" ] || continue
    [ "$(wc -c < "$DRIVER")" -gt 200 ] || continue

    total=$((total+1))
    OUT_DIR="$OUT_BASE/$stem"
    mkdir -p "$OUT_DIR"

    # Copy driver and harness_types.h
    cp "$DRIVER" "$OUT_DIR/replay_driver.c"
    [ -f "$HARNESS_TYPES" ] && cp "$HARNESS_TYPES" "$OUT_DIR/harness_types.h"

    # Compile
    COMPILE_LOG="$OUT_DIR/compile.log"
    gcc $ASAN_FLAGS \
        -I"$INCLUDE_DIR" \
        -I"$OUT_DIR" \
        -include "$KLEE_COMPAT" \
        "$OUT_DIR/replay_driver.c" \
        "$ASAN_LIB" \
        -o "$OUT_DIR/replay_driver" \
        $LINK_FLAGS \
        >"$COMPILE_LOG" 2>&1
    COMPILE_RC=$?

    if [ $COMPILE_RC -ne 0 ]; then
        echo "FAIL_COMPILE $stem"
        fail=$((fail+1))
        continue
    fi

    # Run with ASan
    ASAN_LOG="$OUT_DIR/asan_output.txt"
    ASAN_OPTIONS="abort_on_error=0:detect_leaks=0" \
        "$OUT_DIR/replay_driver" >"$ASAN_LOG" 2>&1 || true

    ASAN_CONFIRMED=false
    CRASH_LINE=""
    CRASH_FUNC=""
    if grep -q "AddressSanitizer" "$ASAN_LOG" 2>/dev/null; then
        ASAN_CONFIRMED=true
        CRASH_LINE=$(grep -oP 'at \K[a-zA-Z_]+\.c:\d+' "$ASAN_LOG" | head -1)
        CRASH_FUNC=$(grep -oP 'in \K[a-zA-Z_]+' "$ASAN_LOG" | grep -v "main\|interceptor\|libc\|start" | head -1)
        crash=$((crash+1))
        echo "CRASH $stem | ${CRASH_LINE:-?} in ${CRASH_FUNC:-?}"
    else
        no_crash=$((no_crash+1))
        echo "OK    $stem (no crash)"
    fi

    # Write bug_report.json matching pipeline format
    ASAN_SUMMARY=$(grep "SUMMARY: AddressSanitizer" "$ASAN_LOG" 2>/dev/null | head -1 || echo "")
    cat > "$OUT_DIR/bug_report.json" << ENDJSON
{
  "summary": {
    "verdict": "LIKELY_TP",
    "manual_replay": true,
    "asan_confirmed": $ASAN_CONFIRMED,
    "crash_relevance": "$([ "$ASAN_CONFIRMED" = "true" ] && echo "target" || echo "no_asan")",
    "crash_location": "$CRASH_LINE",
    "crash_function": "$CRASH_FUNC"
  },
  "manual_replay": {
    "driver_source": "replay_driver.c",
    "binary": "replay_driver",
    "asan_output_file": "asan_output.txt",
    "asan_confirmed": $ASAN_CONFIRMED,
    "asan_summary": $(echo "$ASAN_SUMMARY" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip()))" 2>/dev/null || echo '""')
  }
}
ENDJSON
done

echo ""
echo "=============================="
echo " Batch Replay Summary"
echo "=============================="
echo " Total specs processed: $total"
echo " ASan crashes:          $crash"
echo " No crash:              $no_crash"
echo " Compile failures:      $fail"
