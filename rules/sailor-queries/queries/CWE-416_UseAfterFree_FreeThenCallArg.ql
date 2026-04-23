/**
 * @name CWE-416: Use-After-Free — direct-free -> call-arg (fast intra)
 * @kind problem
 * @precision low
 * @problem.severity error
 * @id sailor/cpp/CWE-416/DirectFreeArgUseFast
 * @tags security external/cwe/cwe-416
 * @shortDescription Value freed is later passed as a call argument (intra).
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.exprs.Access as Access

private predicate ordered(Expr a, Expr b) {
  a.getEnclosingFunction() = b.getEnclosingFunction() and
  a.getLocation().getFile() = b.getLocation().getFile() and
  a.getLocation().getStartLine() < b.getLocation().getStartLine()
}

/** Previously restricted to libxml2 paths; now matches any C/C++ source. */
predicate inProjectPath(Expr e) {
  e.getLocation().getFile().getExtension().regexpMatch("c|cc|cpp|cxx|h|hh|hpp")
}

/* Deallocators incl. libxml2 variants. */
class Deallocator extends Function {
  Deallocator() {
    exists(string n |
      n = this.getName() and
      ( n = "free" or n = "kfree" or n = "vfree" or n = "g_free" or
        n = "xfree" or n = "safe_free" or n = "cfree" or n = "av_free" or
        n.regexpMatch(".*(Delete|Destroy|Dispose|Free|Release|Unref|UnRef)$") or
        n.regexpMatch("(?i)^xmlFree.*") or n.regexpMatch("(?i)^xmlHashFree.*") or
        n = "xmlDictFree" or n = "xmlBufferFree" )
    )
  }
}

/* Source: any subexpr of the freed argument. */
predicate isDirectFreeSource(Expr src, FunctionCall c) {
  c.getTarget() instanceof Deallocator and
  src = c.getArgument(0).getAChild*() and
  src.getType() instanceof PointerType and
  inProjectPath(src)
}

/* Sink: any subexpr that participates in a call argument. */
predicate isArgUseSubexpr(Expr e) {
  exists(FunctionCall fc, Expr arg |
    arg = fc.getAnArgument() and e = arg.getAChild*()
  )
}

/* Cheap pointer copy + aggregate store/load. */
predicate isPointerCopy(AssignExpr a) {
  a.getLValue().getType() instanceof PointerType and
  a.getRValue().getType() instanceof PointerType
}
predicate storeIntoAggregate(Expr src, Expr aggLHS) {
  exists(AssignExpr a |
    a.getRValue() = src and a.getLValue() = aggLHS and
    ( aggLHS instanceof Access::DotFieldAccess or
      aggLHS instanceof Access::PointerFieldAccess or
      aggLHS instanceof Access::ArrayExpr ))
}
predicate loadFromAggregate(Expr aggRHS, Expr dst) {
  exists(AssignExpr a |
    a.getLValue() = dst and a.getRValue() = aggRHS and
    ( aggRHS instanceof Access::DotFieldAccess or
      aggRHS instanceof Access::PointerFieldAccess or
      aggRHS instanceof Access::ArrayExpr ))
}

/* Generic syntax peel: move between an expr and any of its children. */
predicate peelOne(Expr outer, Expr inner) { inner = outer.getAChild() }

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) {
    exists(FunctionCall c, Expr a | isDirectFreeSource(a, c) and s.asExpr() = a)
  }
  predicate isSink(DataFlow::Node t) {
    exists(Expr e | isArgUseSubexpr(e) and t.asExpr() = e)
  }
  additional predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(AssignExpr a | isPointerCopy(a) and n1.asExpr() = a.getRValue() and n2.asExpr() = a.getLValue())
    or exists(Expr src, Expr aggLHS | storeIntoAggregate(src, aggLHS) and n1.asExpr() = src and n2.asExpr() = aggLHS)
    or exists(Expr aggRHS, Expr dst | loadFromAggregate(aggRHS, dst) and n1.asExpr() = aggRHS and n2.asExpr() = dst)
    or exists(Access::PointerFieldAccess m | n1.asExpr() = m and n2.asExpr() = m.getQualifier())
    or exists(Access::DotFieldAccess d    | n1.asExpr() = d and n2.asExpr() = d.getQualifier())
    or exists(Expr o, Expr i | peelOne(o, i) and n1.asExpr() = o and n2.asExpr() = i)
    or exists(Expr o, Expr i | peelOne(o, i) and n1.asExpr() = i and n2.asExpr() = o)
  }
}
module DF = DataFlow::Global<Cfg>;

from DataFlow::Node s, DataFlow::Node t, FunctionCall freeC, Expr freed, Expr sink, FunctionCall useC, Expr arg
where
  DF::flow(s, t) and
  s.asExpr() = freed and
  t.asExpr() = sink and
  isDirectFreeSource(freed, freeC) and
  arg = useC.getAnArgument() and sink = arg.getAChild*() and
  freed.getEnclosingFunction() = useC.getEnclosingFunction() and
  ordered(freed, useC)
select sink,
  "Potential UAF (free->arg): value freed by '" +
  freeC.getTarget().getName() + "()' flows into a later call argument."
