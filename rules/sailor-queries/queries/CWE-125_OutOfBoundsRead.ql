/**
 * @id local/cpp/cwe-125-oob-read
 * @name CWE-125: Out-of-Bounds Read
 * @description Flags memory read/compare functions (memcmp, write) where the length 
 * argument might exceed the source buffer.
 * @kind problem
 * @problem.severity warning
 * @tags security
 * external/cwe/cwe-125
 */
import cpp

/* --- Reuse Helpers --- */
predicate isReadFunc(Function f) {
  f.getName().regexpMatch("(?i)^(memcmp|bcmp|strncmp|strncasecmp)$") or
  f.getName().regexpMatch("(?i)^(memchr|strnstr|memscan)$") or
  f.getName().regexpMatch("(?i)^(write|send|sendto)$")
}

predicate isSizeofLike(Expr e) { e instanceof SizeofOperator }
predicate isStringBound(Expr e) {
  exists(FunctionCall c | c = e and c.getTarget().getName().regexpMatch("(?i)^(strlen|strnlen)$"))
}

predicate countArg(FunctionCall fc, Expr n) {
  exists(Function f | f = fc.getTarget() |
    (isReadFunc(f) and fc.getNumberOfArguments() >= 3 and n = fc.getArgument(2))
  )
}

/* --- Main Query --- */
from FunctionCall fc, Function f, Expr n
where
  fc.getTarget() = f and
  isReadFunc(f) and           // <--- CONSTRAINT: Reads Only
  countArg(fc, n) and
  not isStringBound(n) and
  not isSizeofLike(n)
select fc, "CWE-125: Potential OOB Read via " + f.getName() + " (unchecked length)."