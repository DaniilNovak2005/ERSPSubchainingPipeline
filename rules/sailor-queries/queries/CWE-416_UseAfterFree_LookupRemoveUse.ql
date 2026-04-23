/** 
 * @name CWE-416: Use-After-Free — lookup → remove → use (intra-procedural)
 * @kind problem
 * @precision low
 * @problem.severity error
 * @id sailor/cpp/uaf/lookup-remove-use/intra
 * @tags security external/cwe/cwe-416
 *
 * @shortDescription UAF when a value from a lookup is used after an intervening remove/erase/delete.
 * @description
 * Flags flows where a pointer returned by a lookup (Lookup/Find/… patterns) is later used
 * (deref/field/array/call/return) after a remove/erase/delete call in the same function.
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.exprs.Access as Access
import semmle.code.cpp.controlflow.Dereferenced as Deref

/** Use site: deref, field/array, call arg, return. */
predicate isWideUse(Expr e) {
  exists(Access::PointerFieldAccess m | m.getQualifier() = e) or
  exists(Access::DotFieldAccess     d | d.getQualifier() = e) or
  exists(Access::ArrayExpr          a | a.getArrayBase() = e) or
  Deref::dereferenced(e) or
  exists(FunctionCall fc | fc.getAnArgument() = e) or
  exists(ReturnStmt  r  | r.getExpr() = e)
}

/** a appears before b in same function & file. */
private predicate isBefore(Expr a, Expr b) {
  a.getEnclosingFunction() = b.getEnclosingFunction() and
  a.getLocation().getFile() = b.getLocation().getFile() and
  a.getLocation().getStartLine() < b.getLocation().getStartLine()
}

/** Source: functions whose names look like lookups. */
class HashLookupCall extends FunctionCall {
  HashLookupCall() {
    exists(Function f |
      this.getTarget() = f and
      (
        f.getName().regexpMatch(".*Lookup.*") or
        f.getName().regexpMatch(".*Find.*") or
        f.getName().regexpMatch(".*(Hash|Table|Map).*(Lookup|Find).*")
      )
    )
  }
}

/** Intervening removal. */
class HashRemoveCall extends FunctionCall {
  HashRemoveCall() {
    exists(Function f |
      this.getTarget() = f and
      (
        f.getName().regexpMatch(".*(Remove|Erase|Delete).*") or
        f.getName().regexpMatch(".*(Hash|Table|Map).*(Remove|Erase|Delete).*")
      )
    )
  }
}

/** Minimal pointer copy propagation. */
predicate isPointerCopy(AssignExpr a) {
  a.getLValue().getType() instanceof PointerType and
  a.getRValue().getType() instanceof PointerType
}

/** Flow config: lookup result → use. */
module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) { exists(HashLookupCall lc | s.asExpr() = lc) }
  predicate isSink  (DataFlow::Node t) { exists(Expr e | isWideUse(e) and t.asExpr() = e) }
  additional predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(AssignExpr a |
      isPointerCopy(a) and n1.asExpr() = a.getRValue() and n2.asExpr() = a.getLValue()
    )
  }
}
module DF = DataFlow::Global<Cfg>;

/** Require at least one remove between lookup and use in same function. */
private predicate hasInterveningRemove(HashLookupCall lc, Expr use) {
  exists(HashRemoveCall rc |
    isBefore(lc, rc) and isBefore(rc, use) and
    lc.getEnclosingFunction() = rc.getEnclosingFunction() and
    rc.getEnclosingFunction() = use.getEnclosingFunction()
  )
}

from DataFlow::Node s, DataFlow::Node t, HashLookupCall lc, Expr sink
where
  DF::flow(s, t) and
  s.asExpr() = lc and
  t.asExpr() = sink and
  hasInterveningRemove(lc, sink)
select sink,
  "Potential UAF (lookup→remove→use): result of '" + lc.getTarget().getName() +
  "()' is used after a removal call."
