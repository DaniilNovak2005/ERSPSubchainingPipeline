#!/bin/bash
# sailor_engine/build_project_bc.sh
# Universal Bitcode Builder (Fixed Linker & Extensions)
# Updated: supports extracting from .so if no .a is produced (e.g., libxml2 via CMake)

set -euo pipefail

SRC_DIR="${1:-}"
OUT_ARG="${2:-}"

if [[ -z "$SRC_DIR" || -z "$OUT_ARG" ]]; then
    echo "[!] Usage: $0 <SRC_DIR> <OUTPUT_BC>"
    exit 1
fi

OUTPUT_BC="$(realpath -m "$OUT_ARG")"

# Skip rebuild if bitcode already exists and is non-empty
if [ -f "$OUTPUT_BC" ] && [ -s "$OUTPUT_BC" ]; then
    echo "[*] Bitcode already exists: $OUTPUT_BC ($(stat -c%s "$OUTPUT_BC") bytes). Skipping rebuild."
    echo "    Delete it to force a fresh build."
    exit 0
fi

# 1. Setup Environment
export LLVM_COMPILER=clang
# Ensure wllvm knows where LLVM tools live
export LLVM_COMPILER_PATH="${LLVM_COMPILER_PATH:-/usr/lib/llvm-14/bin}"
export CC=wllvm
export CXX=wllvm++

# --- HARDEN FLAGS (avoid PIC/PIE lowering like llvm.load.relative) ---
# Some build systems append -fPIC/-fPIE anyway; we add explicit negations and also
# provide LDFLAGS to force non-PIE linking when relevant.
BASE_CFLAGS="-g -O1 -fno-inline-functions -Wno-error"
# Note: -fno-pic/-fno-pie removed — on PIE-default distros the system linker rejects
# non-PIC objects, and wllvm's internal re-link doesn't forward LDFLAGS=-no-pie.
# PIC/PIE doesn't affect LLVM IR semantics for KLEE analysis.
export CFLAGS="${CFLAGS:-} ${BASE_CFLAGS}"
export CXXFLAGS="${CXXFLAGS:-} ${BASE_CFLAGS}"
export LDFLAGS="${LDFLAGS:-}"

# If a build system injects -fPIC/-fPIE, our explicit -fno-pic/-fno-pie should win
# for clang, but not all wrappers behave perfectly. We'll verify at the end.


# [FIX] Use LLVM_LINK from environment if set, otherwise auto-detect
if [[ -n "${LLVM_LINK:-}" ]] && command -v "$LLVM_LINK" &> /dev/null; then
    : # Already set and valid
elif command -v llvm-link-14 &> /dev/null; then
    LLVM_LINK=llvm-link-14
elif command -v llvm-link &> /dev/null; then
    LLVM_LINK=llvm-link
else
    echo "[!] Error: llvm-link not found. Please install llvm-14."
    exit 1
fi
echo "[*] Using Linker: $LLVM_LINK"

if [ ! -d "$SRC_DIR" ]; then
    echo "[!] Source directory not found: $SRC_DIR"
    exit 1
fi

cd "$SRC_DIR" || exit 1

# --- STEP 1: DEEP CLEANING ---
echo "[*] Cleaning build artifacts..."
set +e
make distclean > /dev/null 2>&1
make clean > /dev/null 2>&1
set -e

find . -name "config.cache" -delete || true
find . -name "config.status" -delete || true
find . -name "config.log" -delete || true

# Remove any previously installed prefix directory (commonly ./build/).
# Without this, extract-bc finds the stale system-compiler .a installed
# by the CodeQL-phase build instead of the freshly wllvm-compiled one.
rm -rf build/ 2>/dev/null || true

# --- STEP 2: CONFIGURE ---
echo "[*] Configuring build..."

if [ -f "./configure" ]; then
    CONFIG_FLAGS=()
    HELP_TEXT="$(./configure --help 2>&1 || true)"

    # Only add flags the project's configure actually supports
    for flag in --disable-nls --disable-werror --disable-shared --enable-static; do
        if echo "$HELP_TEXT" | grep -q -- "${flag#--}"; then
            CONFIG_FLAGS+=("$flag")
        fi
    done
    # MAKEINFO override is harmless even if unsupported
    CONFIG_FLAGS+=("MAKEINFO=true")
    # Explicitly pass wllvm as CC/CXX so libtool bakes it into its wrapper
    # at configure time — env-only export is not enough for libtool projects.
    CONFIG_FLAGS+=("CC=wllvm" "CXX=wllvm++")

    if [ -d "bfd" ]; then
        echo "[*] Detected Binutils. Disabling optional tools..."
        CONFIG_FLAGS+=(
            "--disable-gdb" "--disable-sim" "--disable-readline"
            "--disable-libdecnumber" "--disable-gold" "--disable-ld"
            "--enable-targets=all"
        )
    fi

    ./configure "${CONFIG_FLAGS[@]}"

    echo "[*] Building (Ignoring non-critical tool failures)..."
    # Pass CC/CXX to make as well — some Makefiles ignore the configure-time value
    make -j"$(nproc)" CC=wllvm CXX=wllvm++ MAKEINFO=true || echo "[!] Make hit errors, checking if libraries survived..."

elif [ -f "CMakeLists.txt" ]; then
    echo "[*] Detected CMake"

    # [FIX] CMake cache/compiler drift is a frequent cause of "BUILD_SHARED_LIBS=OFF doesn't stick".
    # Always reset the build directory for deterministic wllvm builds.
    rm -rf build

    mkdir -p build
    cd build
    # shellcheck disable=SC2086
    cmake .. \
        -DCMAKE_C_COMPILER=wllvm \
        -DCMAKE_CXX_COMPILER=wllvm++ \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_POSITION_INDEPENDENT_CODE=OFF \
        -DCMAKE_C_FLAGS="${CFLAGS}" \
        -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
        -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}" \
        ${CMAKE_EXTRA_OPTS:-}
    make -j"$(nproc)" || true
    cd ..

elif [ -f "Makefile" ]; then
    echo "[*] Detected Bare Makefile"
    make -j"$(nproc)" CC=wllvm CXX=wllvm++ || true
else
    echo "[!] Warning: No configure/CMakeLists/Makefile detected; attempting best-effort make."
    make -j"$(nproc)" CC=wllvm CXX=wllvm++ || true
fi

# --- STEP 3: EXTRACT & CHECK ---
echo "[*] Extracting bitcode..."

# Strategy: Binutils Multi-Lib Linker
# Check both in-tree and .libs/ paths (libtool puts archives under .libs/)
BINUTILS_BFD="$(find . -name 'libbfd.a' -not -path '*/build/*' 2>/dev/null | head -1)"
if [ -n "$BINUTILS_BFD" ]; then
    echo "[*] Strategy: Binutils Libraries Found"
    BC_FILES=()

    # Discover all core library archives
    BINUTILS_LIBS=()
    for name in libbfd.a libiberty.a libopcodes.a libctf.a libsframe.a; do
        found="$(find . -name "$name" -not -path '*/build/*' 2>/dev/null | head -1)"
        [ -n "$found" ] && BINUTILS_LIBS+=("$found")
    done

    for lib in "${BINUTILS_LIBS[@]}"; do
        if [ -f "$lib" ]; then
            echo "    -> Extracting $lib"
            extract-bc -b "$lib" || true

            # [FIX] Check for both possible output names (.bca or .a.bc)
            if [ -f "${lib%.a}.bca" ]; then
                BC_FILES+=("${lib%.a}.bca")
            elif [ -f "${lib}.bc" ]; then
                BC_FILES+=("${lib}.bc")
            else
                echo "[!] Warning: Bitcode extraction failed for $lib (No .bca or .bc found)"
            fi
        fi
    done

    if [ ${#BC_FILES[@]} -eq 0 ]; then
        echo "[!] Critical: No bitcode files found to link."
        exit 1
    fi

    echo "[*] Linking combined bitcode..."
    "$LLVM_LINK" "${BC_FILES[@]}" -o "$OUTPUT_BC"

# Strategy: Generic Main Artifact (.a preferred; fall back to .so)
else
    # For libtool-based projects (autoconf), the wllvm-compiled archive lives in
    # .libs/ subdirectories. Prefer those over top-level .a files, which may be
    # libtool wrapper stubs or stale install-prefix artifacts without wllvm bitcode.
    TARGET_ARTIFACT="$(find . -path "*/.libs/*.a" -type f -printf "%s\t%p\n" 2>/dev/null \
        | sort -nr | head -1 | cut -f2 || true)"

    # Fall back to any .a not in .libs/ (CMake, bare Makefile, etc.)
    if [ -z "$TARGET_ARTIFACT" ]; then
        TARGET_ARTIFACT="$(find . -type f -not -path "*/.libs/*" -name "*.a" -printf "%s\t%p\n" 2>/dev/null \
            | sort -nr | head -1 | cut -f2 || true)"
    fi

    if [ -z "$TARGET_ARTIFACT" ]; then
        TARGET_ARTIFACT="$(find . -type f -not -path "*/.libs/*" \( -name "*.so" -o -name "*.so.*" \) -printf "%s\t%p\n" 2>/dev/null \
            | sort -nr | head -1 | cut -f2 || true)"
    fi

    # Optional last-resort fallback: try an executable in build/
    if [ -z "$TARGET_ARTIFACT" ]; then
        TARGET_ARTIFACT="$(find . -path "*/build/*" -type f -executable -printf "%s\t%p\n" 2>/dev/null \
            | sort -nr | head -1 | cut -f2 || true)"
    fi

    if [ -z "$TARGET_ARTIFACT" ]; then
        echo "[!] Error: No library (.a/.so) or build executable found."
        exit 1
    fi

    echo "    -> Target Artifact: $TARGET_ARTIFACT"
    extract-bc -b "$TARGET_ARTIFACT" || true

    # [FIX] Handle extension variants for .a and .so
    if [[ "$TARGET_ARTIFACT" == *.a ]]; then
        if [ -f "${TARGET_ARTIFACT%.a}.bca" ]; then
            "$LLVM_LINK" "${TARGET_ARTIFACT%.a}.bca" -o "$OUTPUT_BC"
        elif [ -f "${TARGET_ARTIFACT}.bc" ]; then
            mv "${TARGET_ARTIFACT}.bc" "$OUTPUT_BC"
        else
            echo "[!] Error: Failed to find extracted bitcode for $TARGET_ARTIFACT (expected .bca or .bc)"
            exit 1
        fi
    else
        # Shared libs/executables: extract-bc typically emits "<artifact>.bc"
        if [ -f "${TARGET_ARTIFACT}.bc" ]; then
            mv "${TARGET_ARTIFACT}.bc" "$OUTPUT_BC"
        else
            echo "[!] Error: Failed to find extracted bitcode for $TARGET_ARTIFACT (expected ${TARGET_ARTIFACT}.bc)"
            exit 1
        fi
    fi
fi

# --- VERIFY ---
if [ -f "$OUTPUT_BC" ]; then
    echo "[✓] Bitcode successfully created: $OUTPUT_BC"
    ls -lh "$OUTPUT_BC"
else
    echo "[!] Failed to create bitcode."
    exit 1
fi

# --- FAIL-FAST VERIFY: llvm.load.relative should not exist for KLEE-friendly bc ---
if command -v llvm-dis &>/dev/null; then
    if llvm-dis "$OUTPUT_BC" -o - | grep -q "llvm.load.relative"; then
        echo "[!] FATAL: llvm.load.relative still present in bitcode."
        echo "    Likely cause: build system forced PIC/PIE (e.g., extracted from .so or injected -fPIC/-fPIE)."
        echo "    Action: ensure static build artifacts exist and avoid extracting from .so; verify compile flags."
        exit 2
    fi
fi