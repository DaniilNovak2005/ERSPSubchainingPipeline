#!/bin/bash
# SAILOR config for binutils (bfd, libiberty, opcodes, libctf)
#
# Analysis target: core libraries only
# Excluded: CLI tools (binutils/), assembler (gas/), linker (ld/), all of gdb/

export EXTRA_CFLAGS="-I${SRC_ROOT}/include -I${SRC_ROOT}/bfd -I${SRC_ROOT}/build/bfd"

# Tool/CLI file basenames to exclude from analysis
# These are standalone programs, not library code
export TOOL_FILES="addr2line.c,ar.c,arsup.c,bin2c.c,binemul.c,bucomm.c,coffdump.c,coffgrok.c,cxxfilt.c,demanguse.c,dlltool.c,dllwrap.c,elfedit.c,elfcomm.c,emul_aix.c,emul_vanilla.c,filemode.c,is-ranlib.c,is-strip.c,maybe-ranlib.c,maybe-strip.c,mclex.c,nm.c,not-ranlib.c,not-strip.c,objcopy.c,objdump.c,od-elf32_avr.c,od-macho.c,od-pe.c,od-xcoff.c,prdbg.c,rclex.c,rdcoff.c,rddbg.c,readelf.c,rename.c,resbin.c,rescoff.c,resrc.c,resres.c,size.c,srconv.c,stabs.c,strings.c,sysdump.c,syslex_wrap.c,unwind-ia64.c,version.c,windmc.c,windres.c,winduni.c,wrstabs.c,as.c,ldmain.c,lexsup.c"

# Test/contrib files — not part of core library
export NON_LIBRARY_FILES="bfdtest1.c,bfdtest2.c,debug.c,dwarf.c"

# Parallelism
export PARALLEL_JOBS=128
