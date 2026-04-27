#!/usr/bin/env bash
# Usage: ./replay_spec.sh <spec_number>
# Compiles and runs the ASAN replay driver for a single spec.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPECS_DIR="$SCRIPT_DIR/specs"
ASAN_LIB="$SCRIPT_DIR/asan_build/.libs/libxml2.a"
INCLUDE_DIR="$SCRIPT_DIR/asan_build/include"

ASAN_FLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer"
LINK_FLAGS="-lm -lz -lpthread -ldl -Wl,--allow-multiple-definition"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <spec_number>"
    echo "Example: $0 529"
    exit 1
fi

SPEC_NUM="$1"

# Find matching spec directory (prefix match on the number)
matches=("$SPECS_DIR"/${SPEC_NUM}_*)
real_matches=()
for m in "${matches[@]}"; do
    [ -f "$m/replay_driver.c" ] && real_matches+=("$m")
done

if [ ${#real_matches[@]} -eq 0 ]; then
    echo "Error: no spec directory with a replay_driver.c found for spec $SPEC_NUM in $SPECS_DIR"
    exit 1
fi

if [ ${#real_matches[@]} -gt 1 ]; then
    echo "Multiple matches for spec $SPEC_NUM:"
    for i in "${!real_matches[@]}"; do
        echo "  [$i] $(basename "${real_matches[$i]}")"
    done
    read -rp "Select index: " idx
    SPEC_DIR="${real_matches[$idx]}"
else
    SPEC_DIR="${real_matches[0]}"
fi

SPEC_NAME="$(basename "$SPEC_DIR")"
DRIVER="$SPEC_DIR/replay_driver.c"
BIN="$SPEC_DIR/replay_driver"
COMPILE_LOG="$SPEC_DIR/compile.log"
ASAN_OUT="$SPEC_DIR/asan_output.txt"

if [ ! -f "$ASAN_LIB" ]; then
    echo "Error: ASAN library not found at $ASAN_LIB"
    echo "Run build_asan_libxml2.sh first."
    exit 1
fi

echo "=== Spec $SPEC_NUM: $SPEC_NAME ==="
echo ""

echo -n "[Compile] ... "
if gcc $ASAN_FLAGS -I"$INCLUDE_DIR" \
        "$DRIVER" \
        "$ASAN_LIB" \
        -o "$BIN" \
        $LINK_FLAGS 2>"$COMPILE_LOG"; then
    echo "OK"
else
    echo "FAILED"
    echo "--- compile.log ---"
    cat "$COMPILE_LOG"
    exit 1
fi

echo -n "[Run]     ... "
EXIT_CODE=0
ASAN_OPTIONS="abort_on_error=0:detect_leaks=0" \
    "$BIN" >"$ASAN_OUT" 2>&1 || EXIT_CODE=$?

if grep -q "AddressSanitizer\|ASan" "$ASAN_OUT" 2>/dev/null; then
    echo "CRASH (ASan confirmed)"
else
    echo "no crash (exit=$EXIT_CODE)"
fi

echo ""
echo "--- ASAN output ---"
cat "$ASAN_OUT"
