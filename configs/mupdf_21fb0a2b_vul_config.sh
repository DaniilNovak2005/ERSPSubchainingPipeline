#!/bin/bash
# SAILOR config for MuPDF 1.24.0 (21fb0a2b)
#
# Analysis target: libmupdf core (source/fitz, source/pdf, source/cbz,
#                  source/html, source/svg, source/xps, source/reflow, source/helpers)
# Excluded: source/tools/ (CLI programs), source/tests/, platform/ (viewers/apps)

export BUILD_CMD="./build.sh"
export EXTRA_CFLAGS="-I\${SRC_ROOT}/include -I\${SRC_ROOT}/source"

# Tool/CLI file basenames to exclude from analysis (source/tools/)
export TOOL_FILES="cmapdump.c,muconvert.c,mudraw.c,muraster.c,murun.c,mutool.c,mutrace.c,pdfbake.c,pdfclean.c,pdfcreate.c,pdfextract.c,pdfinfo.c,pdfmerge.c,pdfpages.c,pdfposter.c,pdfrecolor.c,pdfshow.c,pdfsign.c,pdftrim.c"

# Test files — not part of core library
export NON_LIBRARY_FILES="mu-office-test.c"

# Upstream URL for concrete verification
export UPSTREAM_URL="https://github.com/ArtifexSoftware/mupdf.git"

# Parallelism
export PARALLEL_JOBS=128
