#!/bin/bash
# SAILOR config for libpng
export BUILD_CMD="mkdir -p build && cd build && cmake .. && make -j\$(nproc)"
export EXTRA_CFLAGS="-I${SRC_ROOT}"

# Tool/test file basenames to exclude from analysis
export TOOL_FILES="pngtest.c,pngvalid.c,pngstest.c,pngfix.c,png-fix-itxt.c,pngimage.c,timepng.c,pngunknown.c,pngcp.c,makepng.c,fakepng.c,readpng.c,tarith.c,genpng.c,checksum-icc.c,cvtcolor.c,makesRGB.c,iccfrompng.c,pngpixel.c,pngtopng.c,simpleover.c,png2pnm.c,pnm2png.c,example.c"

# Test/contrib files — not part of core library, bugs here are non-reportable
export NON_LIBRARY_FILES=""

# Parallelism used for this experiment
export PARALLEL_JOBS=128
