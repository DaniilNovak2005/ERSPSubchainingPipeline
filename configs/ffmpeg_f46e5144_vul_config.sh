#!/bin/bash
# SAILOR config for FFmpeg 7.1.3
#
# Analysis target: libavcodec, libavformat, libavfilter, libavutil,
#                  libswscale, libswresample, libpostproc
# Excluded: fftools/ (CLI programs), doc/, tests/

export EXTRA_CFLAGS="-I${SRC_ROOT} -I${SRC_ROOT}/libavcodec -I${SRC_ROOT}/libavformat -I${SRC_ROOT}/libavutil"

# Tool/CLI file basenames to exclude (fftools/ directory)
export TOOL_FILES="cmdutils.c,ffmpeg.c,ffmpeg_dec.c,ffmpeg_demux.c,ffmpeg_enc.c,ffmpeg_filter.c,ffmpeg_hw.c,ffmpeg_mux.c,ffmpeg_mux_init.c,ffmpeg_opt.c,ffmpeg_sched.c,ffplay.c,ffplay_renderer.c,ffprobe.c,objpool.c,opt_common.c,sync_queue.c,thread_queue.c"

# Test files — not part of core library
export NON_LIBRARY_FILES=""

# Upstream URL for concrete verification
export UPSTREAM_URL="https://github.com/FFmpeg/FFmpeg.git"

# Parallelism
export PARALLEL_JOBS=128
