#pragma once
#define klee_make_symbolic(a,b,c)    do{}while(0)
#define klee_assume(x)               do{}while(0)
#define klee_warning(x)              do{}while(0)
#define klee_warning_once(x)         do{}while(0)
#define klee_assert(x)               do{}while(0)
#define klee_report_error(a,b,c,d)   do{}while(0)
#define klee_get_obj_size(x)         (0)
#define klee_check_memory_access(a,b) do{}while(0)
/* Silence klee/klee.h if included */
#ifndef KLEE_H
#define KLEE_H
#endif
