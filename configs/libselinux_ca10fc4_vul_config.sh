#!/bin/bash
# SAILOR config for libselinux 3.10 (ca10fc4)
#
# Analysis target: libselinux core (libselinux/src/)
# Excluded: libselinux/utils/ (CLI tools), audit2why.c (Python binding)

export BUILD_CMD="./build.sh"
export EXTRA_CFLAGS="-I\${SRC_ROOT}/libselinux/include -I\${SRC_ROOT}/libsepol/include -I\${SRC_ROOT}/libselinux/src"

# Tool/CLI file basenames to exclude from analysis
export TOOL_FILES="avcstat.c,compute_av.c,compute_create.c,compute_member.c,compute_relabel.c,getconlist.c,getdefaultcon.c,getenforce.c,getfilecon.c,getpidcon.c,getpidprevcon.c,getpolicyload.c,getsebool.c,getseuser.c,matchpathcon.c,policyvers.c,sefcontext_compile.c,selabel_compare.c,selabel_digest.c,selabel_get_digests_all_partial_matches.c,selabel_lookup_best_match.c,selabel_lookup.c,selabel_partial_match.c,selinux_check_access.c,selinux_check_securetty_context.c,selinuxenabled.c,selinuxexeccon.c,setenforce.c,setfilecon.c,togglesebool.c,validatetrans.c"

# Non-library files (Python/SWIG bindings)
export NON_LIBRARY_FILES="audit2why.c,selinuxswig_python_wrap.c,selinuxswig_ruby_wrap.c"

# Upstream URL for concrete verification
export UPSTREAM_URL="https://github.com/SELinuxProject/selinux.git"

# Parallelism
export PARALLEL_JOBS=128
