#!/bin/bash
# SAILOR config for tcpdump 4.9.2
# autoconf build — depends on libpcap (installed in the sailor Docker image)

export BUILD_CMD="autoreconf -f -i 2>/dev/null || true && \
    ./configure \
        --disable-smb \
        --without-crypto && \
    make -j\$(nproc)"

export EXTRA_CFLAGS="-I\${SRC_ROOT} -I\${SRC_ROOT}/missing"

# Main tcpdump binary entry point — not a library function
export TOOL_FILES="tcpdump.c"

# Compatibility shims and non-dissector files
export NON_LIBRARY_FILES="missing/getopt_long.c,missing/strdup.c,missing/strftime.c,missing/strlcat.c,missing/strlcpy.c,missing/strsep.c,missing/win_getaddrinfo.c"

export PARALLEL_JOBS=64
