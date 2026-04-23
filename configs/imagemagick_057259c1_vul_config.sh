#!/bin/bash
# SAILOR config for ImageMagick
# autoconf build — configure auto-detects available codec libs and skips the rest
export BUILD_CMD="./configure \
    --disable-shared \
    --enable-static \
    --without-x \
    --without-perl \
    --without-magick-plus-plus \
    --disable-openmp \
    --prefix=\$(pwd)/build \
    CFLAGS='-g -O0' && \
    make -j\$(nproc) && make install"

export EXTRA_CFLAGS="-I\${SRC_ROOT} -I\${SRC_ROOT}/MagickCore -I\${SRC_ROOT}/MagickWand -I\${SRC_ROOT}/build/include/ImageMagick-7"

# CLI utilities — not part of the core library
export TOOL_FILES="magick.c,animate.c,compare.c,composite.c,conjure.c,convert.c,display.c,identify.c,import.c,mogrify.c,montage.c,stream.c"

# Test and script files — not part of core library
export NON_LIBRARY_FILES="test_*.c,validate.c,drawtest.c,wandtest.c,pidgin.c"

export PARALLEL_JOBS=64
