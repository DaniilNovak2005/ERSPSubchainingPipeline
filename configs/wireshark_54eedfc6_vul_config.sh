#!/bin/bash
# SAILOR config for Wireshark
export BUILD_CMD="rm -rf build && mkdir -p build && cd build && cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_wireshark=OFF -DBUILD_tshark=OFF -DBUILD_rawshark=OFF \
    -DBUILD_dumpcap=OFF -DBUILD_text2pcap=OFF -DBUILD_mergecap=OFF \
    -DBUILD_reordercap=OFF -DBUILD_editcap=OFF -DBUILD_capinfos=OFF \
    -DBUILD_captype=OFF -DBUILD_sharkd=OFF -DBUILD_androiddump=OFF \
    -DBUILD_sshdump=OFF -DBUILD_ciscodump=OFF -DBUILD_dpauxmon=OFF \
    -DBUILD_randpkt=OFF -DBUILD_mmdbresolve=OFF \
    -DENABLE_PLUGINS=OFF -DENABLE_LTO=OFF \
    -DENABLE_GNUTLS=OFF -DENABLE_GCRYPT=OFF -DENABLE_LUA=OFF \
    -DENABLE_KERBEROS=OFF -DENABLE_MAXMINDDB=OFF -DENABLE_CARES=OFF \
    -DENABLE_SBC=OFF -DENABLE_SPEEX=OFF -DENABLE_SNAPPY=OFF \
    -DENABLE_LZ4=OFF -DENABLE_ZSTD=OFF -DENABLE_SMI=OFF \
    -DENABLE_OPUS=OFF -DENABLE_LIBXML2=OFF \
    && make -j\$(nproc)"
export EXTRA_CFLAGS="-I${SRC_ROOT} -I${SRC_ROOT}/build -I${SRC_ROOT}/build/include -I${SRC_ROOT}/epan -I${SRC_ROOT}/wiretap -I${SRC_ROOT}/wsutil"

# Top-level tool executables — not part of the core library
export TOOL_FILES="tshark.c,dumpcap.c,capinfos.c,captype.c,editcap.c,mergecap.c,randpkt.c,reordercap.c,rawshark.c,sharkd.c,fuzzshark.c"

# extcap tools and test/fuzz files — not part of core library
export NON_LIBRARY_FILES="androiddump.c,sshdump.c,udpdump.c,ciscodump.c,dpauxmon.c,wifidump.c,etwdump.c,falcodump.c,wifidump.c,fuzz_*.c,oss-fuzz-*.c,wslua_test.c"

export PARALLEL_JOBS=64
