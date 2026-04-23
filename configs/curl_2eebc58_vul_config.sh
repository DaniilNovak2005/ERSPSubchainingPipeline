#!/bin/bash
# SAILOR config for curl/libcurl 8.18.0
#
# Analysis target: libcurl (lib/) only
# Excluded: curl CLI tool (src/), tests, docs, examples

export EXTRA_CFLAGS="-I${SRC_ROOT}/include -I${SRC_ROOT}/lib"

# Tool/CLI file basenames to exclude from analysis (src/ = curl CLI tool)
export TOOL_FILES="config2setopts.c,curlinfo.c,slist_wc.c,terminal.c,tool_bname.c,tool_cb_dbg.c,tool_cb_hdr.c,tool_cb_prg.c,tool_cb_rea.c,tool_cb_see.c,tool_cb_soc.c,tool_cb_wrt.c,tool_cfgable.c,tool_dirhie.c,tool_doswin.c,tool_easysrc.c,tool_filetime.c,tool_findfile.c,tool_formparse.c,tool_getparam.c,tool_getpass.c,tool_help.c,tool_helpers.c,tool_ipfs.c,tool_libinfo.c,tool_listhelp.c,tool_main.c,tool_msgs.c,tool_operate.c,tool_operhlp.c,tool_paramhlp.c,tool_parsecfg.c,tool_progress.c,tool_setopt.c,tool_ssls.c,tool_stderr.c,tool_strdup.c,tool_urlglob.c,tool_util.c,tool_vms.c,tool_writeout.c,tool_writeout_json.c,tool_xattr.c,var.c"

# Test/contrib files — not part of core library
export NON_LIBRARY_FILES=""

# Upstream URL for concrete verification + OSS-Fuzz reproduction
export UPSTREAM_URL="https://github.com/curl/curl.git"

# Parallelism
export PARALLEL_JOBS=128
