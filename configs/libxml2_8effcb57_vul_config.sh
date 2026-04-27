#!/bin/bash
# SAILOR config for libxml2 v2.9.4-rc2
# autoconf build — produces libxml2.a

export BUILD_CMD="autoreconf -fiv && ./configure \
    --disable-shared \
    --enable-static \
    --without-python \
    --without-readline && \
    make -j$(nproc)"

export EXTRA_CFLAGS="-I\${SRC_ROOT}/include"

# CLI tools — not part of the core library
export TOOL_FILES="xmllint.c,xmlcatalog.c"

# Test files
export NON_LIBRARY_FILES="runtest.c,runsuite.c,testapi.c,testchar.c,testdict.c,testlimits.c,testModule.c,testrecurse.c,testrelax.c,testregexp.c,testSAX.c,testSchemas.c,testThreads.c,testURI.c,testXPath.c"

export PARALLEL_JOBS=64
