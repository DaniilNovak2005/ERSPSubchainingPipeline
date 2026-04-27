#!/usr/bin/env bash
# Install libxml2 v2.9.4-rc2 (commit 8effcb57) into asan_build/ and compile
# with AddressSanitizer. Safe to re-run — skips steps already completed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/asan_build"
TARGET_COMMIT="8effcb578e0590cc01bbcab0f9dccefc6bdbcdbd"
LIBXML2_REMOTE="https://github.com/GNOME/libxml2.git"

# Dataset source path — used as a local copy source if available (faster than cloning)
DATASET_SRC="$(cd "$SCRIPT_DIR/.." && pwd)/dataset/8effcb57/libxml2_8effcb57_vul"

ASAN_CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer"

echo "=== SAILOR ASAN Build Installer ==="
echo "Target:    libxml2 v2.9.4-rc2 (${TARGET_COMMIT:0:8})"
echo "Build dir: $BUILD_DIR"
echo ""

# ── Step 1: Populate source ──────────────────────────────────────────────────
if [ -f "$BUILD_DIR/configure" ]; then
    echo "[1/3] Source already present in $BUILD_DIR — skipping copy."
else
    mkdir -p "$BUILD_DIR"

    if [ -f "$DATASET_SRC/configure" ]; then
        echo "[1/3] Copying source from local dataset..."
        rsync -a \
            --exclude='.libs' \
            --exclude='*.o' --exclude='*.lo' --exclude='*.la' --exclude='*.a' \
            --exclude='*.bc' --exclude='*.bc.tmp' --exclude='*.o.tmp' \
            --exclude='Makefile' --exclude='config.status' \
            --exclude='config.log' --exclude='config.h' --exclude='stamp-h1' \
            "$DATASET_SRC/" "$BUILD_DIR/"
        echo "[1/3] Copy done."
    else
        echo "[1/3] Dataset source not found. Cloning from remote (this takes a few minutes)..."
        git clone --depth=1 --branch v2.9.4-rc2 "$LIBXML2_REMOTE" "$BUILD_DIR"
        echo "[1/3] Clone done."
    fi
fi

cd "$BUILD_DIR"

# ── Step 2: Configure ────────────────────────────────────────────────────────
if [ -f "Makefile" ]; then
    echo "[2/3] Already configured — skipping ./configure."
else
    echo "[2/3] Configuring with ASan ($ASAN_CFLAGS)..."
    CC=gcc CFLAGS="$ASAN_CFLAGS" \
        ./configure \
            --disable-shared \
            --enable-static \
            --without-python \
            --without-readline \
            --without-lzma \
            --without-icu \
            2>&1 | tee config.log
    echo "[2/3] Configure done."
fi

# ── Step 3: Build ────────────────────────────────────────────────────────────
ASAN_LIB="$BUILD_DIR/.libs/libxml2.a"

if [ -f "$ASAN_LIB" ]; then
    echo "[3/3] Library already built — skipping make."
else
    echo "[3/3] Building (~3 minutes)..."
    make -j"$(nproc)" 2>&1 | tee -a config.log
    echo "[3/3] Build done."
fi

# ── Verify ───────────────────────────────────────────────────────────────────
echo ""
if [ -f "$ASAN_LIB" ]; then
    ASAN_SYMS=$(nm "$ASAN_LIB" 2>/dev/null | grep -c "__asan" || echo 0)
    echo "Library : $ASAN_LIB"
    echo "Size    : $(du -sh "$ASAN_LIB" | cut -f1)"
    echo "ASan symbols: $ASAN_SYMS"
    if [ "$ASAN_SYMS" -gt 0 ]; then
        echo ""
        echo "Install complete. Run replay_spec.sh <spec_number> to test a spec."
    else
        echo "WARNING: No ASan symbols found — library may not be instrumented."
        exit 1
    fi
else
    echo "ERROR: Build failed — $ASAN_LIB not found."
    echo "Check $BUILD_DIR/config.log for details."
    exit 1
fi
