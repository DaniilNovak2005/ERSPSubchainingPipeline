#!/usr/bin/env bash
# Build libxml2 with ASan for manual replay harnesses
set -euo pipefail

SRC_DIR="/home/danii/Documents/SAILOR_Replication_Package/dataset/8effcb57/libxml2_8effcb57_vul"
BUILD_DIR="/home/danii/Documents/SAILOR_Replication_Package/manual_replay/asan_build"
LOG="$BUILD_DIR/build.log"

mkdir -p "$BUILD_DIR"

# Copy source if not already done
if [ ! -f "$BUILD_DIR/configure" ]; then
    echo "[1/3] Copying source..."
    rsync -a --exclude='.libs' --exclude='*.o' --exclude='*.lo' --exclude='*.la' \
        --exclude='*.a' --exclude='*.bc' --exclude='*.bc.tmp' --exclude='*.o.tmp' \
        --exclude='Makefile' --exclude='config.status' --exclude='config.log' \
        --exclude='config.h' --exclude='stamp-h1' \
        "$SRC_DIR/" "$BUILD_DIR/"
    echo "[1/3] Copy done."
fi

cd "$BUILD_DIR"

# Configure with ASan
if [ ! -f "Makefile" ]; then
    echo "[2/3] Configuring with ASan..."
    CC=gcc CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer" \
    ./configure \
        --disable-shared \
        --enable-static \
        --without-python \
        --without-readline \
        --without-lzma \
        --without-icu \
        2>&1 | tee "$LOG"
    echo "[2/3] Configure done."
fi

# Build
echo "[3/3] Building (this takes ~3 minutes)..."
make -j$(nproc) 2>&1 | tee -a "$LOG"
echo "[3/3] Build done."
echo ""
echo "Library: $BUILD_DIR/.libs/libxml2.a"
ls -la "$BUILD_DIR/.libs/libxml2.a"
