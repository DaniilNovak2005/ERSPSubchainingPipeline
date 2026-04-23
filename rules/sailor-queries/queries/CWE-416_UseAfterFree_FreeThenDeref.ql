/**
 * @name CWE-416: Free-then-Dereference (intra-procedural)
 * @kind problem
 * @precision medium
 * @problem.severity error
 * @security-severity 7.5
 * @id sailor/cpp/pattern/free-then-deref/intra
 * @tags security external/cwe/cwe-416
 *
 * @shortDescription CWE-416 free-then-deref (intra; direct deref/ptr field/array)
 * @description
 * Detects intra-procedural use-after-free where a pointer freed by a deallocator
 * (generic project frees) is later dereferenced: `*p`, `p->f`, or used as an array base.
 *
 * PATTERN (what this flags):
 *   In the same function, a pointer value that is freed flows to a dereference site:
 *     - dereference: *p
 *     - pointer-field access: p->f
 *     - array base: p[i]
 *
 * SCOPE:
 *   - Single function (fast intra-procedural)
 *   - Recognizes common deallocators (free/kfree/vfree/g_free/xfree/safe_free/cfree/av_free
 *     and functions ending with Delete/Destroy/Dispose/Free/Release/Unref/UnRef)
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.exprs.Access as Access
import semmle.code.cpp.controlflow.Dereferenced as Deref

/** True if `e` is dereferenced (directly or via pointer-field/array). */
predicate isDerefUse(Expr e) {
  exists(Access::PointerFieldAccess m | m.getQualifier() = e) or
  exists(Access::ArrayExpr          a | a.getArrayBase() = e) or
  Deref::dereferenced(e)
}

/** Common deallocators (generic/project variants). */
class Deallocator extends Function {
  Deallocator() {
    exists(string n |
      n = this.getName() and
      (
        n = "free" or n = "kfree" or n = "vfree" or n = "g_free" or
        n = "xfree" or n = "safe_free" or n = "cfree" or n = "av_free" or
        n.regexpMatch(".*(Delete|Destroy|Dispose|Free|Release|Unref|UnRef)$")
      )
    )
  }
}

/** Direct call of a deallocator on a pointer argument. */
predicate isDirectFreeCall(FunctionCall c, Expr freed) {
  c.getTarget() instanceof Deallocator and
  freed = c.getArgument(0) and
  freed.getType() instanceof PointerType
}

/** True if `a` appears before `b` in the same function and file (line order). */
private predicate isBefore(Expr a, Expr b) {
  a.getEnclosingFunction() = b.getEnclosingFunction() and
  a.getLocation().getFile() = b.getLocation().getFile() and
  a.getLocation().getStartLine() < b.getLocation().getStartLine()
}

/** Data-flow config: from freed value to its later dereference. */
module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) {
    exists(FunctionCall c, Expr a | isDirectFreeCall(c, a) and s.asExpr() = a)
  }
  predicate isSink(DataFlow::Node t) {
    exists(Expr e | isDerefUse(e) and t.asExpr() = e)
  }
}

module DF = DataFlow::Global<Cfg>;

/** Report when a freed pointer flows to a later dereference in the same function. */
from DataFlow::Node src, DataFlow::Node snk, FunctionCall freeC, Expr freed, Expr use
where
  DF::flow(src, snk) and
  src.asExpr() = freed and
  snk.asExpr() = use and
  isDirectFreeCall(freeC, freed) and
  freed.getEnclosingFunction() = use.getEnclosingFunction() and
  isBefore(freed, use)
select use,
  "Potential use-after-free (direct dereference): value freed by '" +
  freeC.getTarget().getName() + "()' is later dereferenced."
