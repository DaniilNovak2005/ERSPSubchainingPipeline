#!/bin/bash
# SAILOR config for bzip2
# bzip2 uses a bare Makefile — build the static library directly.
export BUILD_CMD="make -j4 libbz2.a"

export EXTRA_CFLAGS="-I${SRC_ROOT}"

# CLI tools — not part of the core library
export TOOL_FILES="bzip2.c,bzip2recover.c,dlltest.c,mk251.c,spewG.c,unzcrash.c"

# Test files
export NON_LIBRARY_FILES="randtable.c"

export PARALLEL_JOBS=64
