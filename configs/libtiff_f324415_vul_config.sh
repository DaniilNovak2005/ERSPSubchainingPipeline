#!/bin/bash
# SAILOR config for libtiff
export BUILD_CMD="mkdir -p build && cd build && cmake .. -Djbig=OFF -Dlerc=OFF -Dwebp=OFF -Dzstd=OFF && make -j\$(nproc)"
export EXTRA_CFLAGS="-I${SRC_ROOT}/libtiff"

# Tool/test file basenames to exclude from analysis
export TOOL_FILES="tiffcrop.c,tiff2pdf.c,tiffmedian.c,tiffdump.c,tiffinfo.c,tiffsplit.c,tiffdither.c,tiff2ps.c,tiff2bw.c,tiff2rgba.c,ppm2tiff.c,pal2rgb.c,fax2ps.c,fax2tiff.c,raw2tiff.c,rgb2ycbcr.c,thumbnail.c,mkg3states.c,check_tag.c,tiffcmp.c,tiffcp.c,tiffgt.c,tiffset.c"

# Test/contrib files — not part of core library, bugs here are non-reportable
export NON_LIBRARY_FILES="defer_strile_loading.c,defer_strile_writing.c,tif_overview.c"

# Parallelism used for this experiment
export PARALLEL_JOBS=128
