/**
 * @id local/cpp/cwe-120-overflow
 * @name CWE-120: Buffer Copy without Checking Size of Input
 * @description Flags memory write functions where the copy length is not validated.
 * @kind problem
 * @precision low
 * @problem.severity warning
 * @tags security external/cwe/cwe-120
 */

import cpp

predicate isWriteFunc(Function f) {
  f.getName().regexpMatch("(?i)^(memcpy|memmove|memset)$") or
  f.getName().regexpMatch("(?i)^(strncpy|strncat|strlcpy|strlcat)$") or
  f.getName().regexpMatch("(?i)^(recv|recvfrom|read|pread|fgets|copy_from_user)$")
}

predicate isSizeofLike(Expr e) { e instanceof SizeofOperator }

predicate isStringBound(Expr e) {
  exists(FunctionCall c | c = e and c.getTarget().getName().regexpMatch("(?i)^(strlen|strnlen)$"))
}

predicate countArg(FunctionCall fc, Expr n) {
  exists(Function f | f = fc.getTarget() |
    // Case 1: Standard 3-arg writes (memcpy, read, etc)
    (isWriteFunc(f) and fc.getNumberOfArguments() >= 3 and n = fc.getArgument(2) and not f.getName() = "fgets")
    or 
    // Case 2: Special case for fgets (2nd arg is size)
    (f.getName() = "fgets" and fc.getNumberOfArguments() >= 2 and n = fc.getArgument(1))
  )
}

from FunctionCall fc, Function f, Expr n
where
  fc.getTarget() = f and
  isWriteFunc(f) and
  countArg(fc, n) and
  not isStringBound(n) and
  not isSizeofLike(n)
select fc, "CWE-120: Potential Buffer Overflow via " + f.getName() + " (unchecked length)."