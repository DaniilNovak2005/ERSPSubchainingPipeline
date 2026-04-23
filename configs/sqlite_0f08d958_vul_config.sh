#!/bin/bash
# SAILOR config for SQLite
export BUILD_CMD="./build.sh"
export EXTRA_CFLAGS="-I\${SRC_ROOT}/src -I\${SRC_ROOT}/build -I\${SRC_ROOT}/ext/fts3 -I\${SRC_ROOT}/ext/rtree -I\${SRC_ROOT}/ext/session -I\${SRC_ROOT}/ext/misc"

# Tool/shell files to exclude from analysis
export TOOL_FILES="shell.c,tclsqlite.c,tclsqlite3.c,speedtest1.c,speedtest8.c,threadtest1.c,threadtest2.c,kvtest.c,ossshell.c,mptester.c,fuzzershell.c,dbfuzz.c,dbfuzz2.c,wordcount.c,sqldiff.c,showdb.c,showstat4.c,showwal.c,changeset.c,showshm.c,dbtotxt.c,rbu.c"

# Test files — not part of core library
export NON_LIBRARY_FILES="test_bestindex.c,test_blob.c,test_btree.c,test_config.c,test_demovfs.c,test_devsym.c,test_fs.c,test_func.c,test_hexio.c,test_init.c,test_intarray.c,test_journal.c,test_malloc.c,test_md5.c,test_multiplex.c,test_mutex.c,test_onefile.c,test_osinst.c,test_pcache.c,test_quota.c,test_rtree.c,test_schema.c,test_server.c,test_sqllog.c,test_superlock.c,test_syscall.c,test_tclsh.c,test_tclvar.c,test_thread.c,test_vdbecov.c,test_vfs.c,test_wsd.c,test_window.c"

# Parallelism
export PARALLEL_JOBS=64
