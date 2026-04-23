/**
 * @id local/cpp/cwe-823-pointer-offset
 * @name CWE-823: Use of Out-of-range Pointer Offset
 * @description Flags memory writes where the destination pointer is calculated 
 * using dynamic arithmetic without visible bounds verification.
 * @kind problem
 * @problem.severity warning
 * @tags security external/cwe/cwe-823
 */
import cpp

/* --- Logic Helpers --- */
predicate isWriteFunc(Function f) {
  f.getName().regexpMatch("(?i)^(memcpy|memmove|memset|strncpy|strncat|strlcpy|strlcat|strcpy|strcat)$") or
  f.getName().regexpMatch("(?i)^(recv|recvfrom|read|pread|fgets|copy_from_user)$")
}

predicate isRiskyPointerArithmetic(Expr e) {
  e instanceof PointerAddExpr or
  exists(ArrayExpr ae | ae = e.(AddressOfExpr).getOperand())
}

predicate isSafeConstant(Expr e) {
  exists(PointerAddExpr add | add = e | add.getRightOperand().isConstant()) or
  exists(ArrayExpr arr | arr = e.(AddressOfExpr).getOperand() | arr.getArrayOffset().isConstant())
}

/* --- Main Query --- */
from FunctionCall fc, Function f, Expr dest
where
  fc.getTarget() = f and
  isWriteFunc(f) and
  // Bind 'dest' based on function signature
  (
    (f.getName() = "fgets" and dest = fc.getArgument(0)) or 
    (f.getName() != "fgets" and dest = fc.getArgument(0))
  ) and
  isRiskyPointerArithmetic(dest) and
  not isSafeConstant(dest)
select fc, "CWE-823: Potential Out-of-Range Pointer Offset used in write operation.", dest, "Destination"