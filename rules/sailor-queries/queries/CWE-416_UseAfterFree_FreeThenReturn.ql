/**
 * @name CWE-416: free(var) then later return(var) (intra, bare var)
 * @kind problem
 * @precision low
 * @problem.severity warning
 * @id sailor/cpp/uaf/free-then-return/intra.min
 * @tags security external/cwe/cwe-416
 */

import cpp

/** Match any C/C++ source file (previously restricted to libxml2 paths). */
predicate inProject(Locatable l) {
  l.getLocation().getFile().getExtension().regexpMatch("c|cc|cpp|cxx|h|hh|hpp")
}

/** A function considered as a deallocator (free/xmlFree/.../Release/Unref). */
class Deallocator extends Function {
  Deallocator() {
    exists(string n |
      n = this.getName() and
      ( n = "free"
        or n.regexpMatch("(?i)^xmlFree.*")
        or n.regexpMatch(".*(Free|Release|Unref|UnRef)$")
      )
    )
  }
}

/** v is declared as a local or parameter of f (no getFunction() on base Variable). */
predicate declaredIn(Function f, Variable v) {
  (v instanceof LocalVariable  and v.(LocalVariable).getFunction() = f) or
  (v instanceof Parameter      and v.(Parameter).getFunction()     = f)
}

/** Simple source order (same file) check. */
predicate isBefore(Locatable a, Locatable b) {
  a.getLocation().getFile() = b.getLocation().getFile() and
  a.getLocation().getStartLine() < b.getLocation().getStartLine()
}

/** A bare-variable free: free(v) or xmlFree*(v) inside f. */
predicate freesVar(Function f, Variable v, Call c) {
  c.getEnclosingFunction() = f and
  c.getTarget() instanceof Deallocator and
  inProject(c) and
  exists(VariableAccess va |
    va = c.getArgument(0) and
    va.getTarget() = v
  )
}

/** Later `return v;` (bare variable in the return expression) inside the same f. */
predicate laterReturnsVar(Function f, Variable v, ReturnStmt r) {
  r.getEnclosingFunction() = f and
  inProject(r) and
  exists(VariableAccess va |
    r.getExpr() = va and
    va.getTarget() = v
  )
}

from Function f, Variable v, Call freeC, ReturnStmt r
where declaredIn(f, v)
  and freesVar(f, v, freeC)
  and laterReturnsVar(f, v, r)
  and isBefore(freeC, r)
select r,
  "Potential UAF: variable '" + v.getName() + "' freed by '" +
  freeC.getTarget().getName() + "()' is later returned."
