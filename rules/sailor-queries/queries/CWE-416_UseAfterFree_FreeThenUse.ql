/**
 * @name CWE-416: Free-then-Use (intra-procedural, field-collapse)
 * @kind problem
 * @precision low
 * @problem.severity error
 * @id sailor/cpp/pattern/free-then-use/intra
 * @tags security external/cwe/cwe-416
 *
 * @shortDescription CWE-416 free-then-use (intra, field-collapse: x->f/x.f, deref/call/return)
 * @description
 * Detects intra-procedural free-then-use: a pointer freed by a deallocator
 * (generic or libxml2) later flows into a deref/field/array access, call, or return.
 * Includes a field-collapse step so `ctxt->f`/`ctxt.f` counts as using `ctxt`.
 * PATTERN (what this flags):
 *   In the same function, a pointer value that is freed (by generic or project-specific
 *   deallocators) later flows into a use site such as:
 *     - dereference: *p, p->f
 *     - field/array access: x.f, x[i]
 *     - call: foo(p)
 *     - return: return p
 *
 *   To catch cases like `ctxt->field` after `free(ctxt)`, the flow step collapses
 *   field access back to the base object (“field-collapse”).
 *
 * SCOPE:
 *   - Single function (fast intra-procedural)
 *   - Recognizes common deallocators + libxml2 frees
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.exprs.Access as Access
import semmle.code.cpp.controlflow.Dereferenced as Deref

/** True if `e` is a likely post-free use site. */
predicate isUseSite(Expr e) {
  exists(Access::PointerFieldAccess m | m.getQualifier() = e) or
  exists(Access::DotFieldAccess     d | d.getQualifier() = e) or
  exists(Access::ArrayExpr          a | a.getArrayBase() = e) or
  Deref::dereferenced(e) or
  exists(FunctionCall fc | fc.getAnArgument() = e) or
  exists(ReturnStmt  r  | r.getExpr() = e)
}

/** True if `a` appears before `b` in the same function and file (line order). */
private predicate isBefore(Expr a, Expr b) {
  a.getEnclosingFunction() = b.getEnclosingFunction() and
  a.getLocation().getFile() = b.getLocation().getFile() and
  a.getLocation().getStartLine() < b.getLocation().getStartLine()
}

/** Project/generic deallocators (includes libxml2 flavors). */
class Deallocator extends Function {
  Deallocator() {
    exists(string name |
      name = this.getName() and
      (
        // Generic
        name = "free" or name = "g_free" or name = "cfree" or name = "av_free" or
        name = "xfree" or name = "safe_free" or
        name.regexpMatch(".*(Delete|Destroy|Dispose|Free|Release|Unref|UnRef)$")
        or
        // libxml2
        name = "xmlHashFreeEntry" or name = "xmlHashFree" or
        name.regexpMatch("xmlFree.*")
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

/**
 * Field-collapse step: treat `base->field` / `base.field` as flowing from `base`.
 * This lets uses like `ctxt->field` be sinks when `ctxt` was freed.
 */
predicate fieldCollapsesToBase(Expr fieldExpr, Expr base) {
  exists(Access::PointerFieldAccess m | m = fieldExpr and base = m.getQualifier()) or
  exists(Access::DotFieldAccess     d | d = fieldExpr and base = d.getQualifier())
}

/** Data-flow configuration capturing free-then-use within a function. */
module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) {
    exists(FunctionCall c, Expr a | isDirectFreeCall(c, a) and s.asExpr() = a)
  }

  predicate isSink(DataFlow::Node t) {
    exists(Expr e | isUseSite(e) and t.asExpr() = e)
  }

  additional predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(Expr fld, Expr base |
      fieldCollapsesToBase(fld, base) and
      n1.asExpr() = fld and
      n2.asExpr() = base
    )
  }
}

module DF = DataFlow::Global<Cfg>;

/**
 * Detect free-then-reassign-then-error-use pattern:
 *   free(p); p = alloc(); if (!p) goto err;
 * On the error path after goto, p holds the return of alloc() which is NULL,
 * but the cleanup at 'err:' label may use the OLD freed memory via other aliases
 * or the pointer may be freed again (double-free).
 *
 * More importantly, this also catches:
 *   free(p); p = alloc(); if (!p) goto err;
 *   // ... err label does free(p) again → double-free
 */
predicate isFreeReassignErrorUse(FunctionCall freeC, Expr freed, Expr use) {
  exists(Variable v, AssignExpr reassign, IfStmt guard, GotoStmt gotoStmt |
    // Step 1: free(v)
    isDirectFreeCall(freeC, freed) and
    freed.(VariableAccess).getTarget() = v and
    // Step 2: v = alloc_or_func()
    reassign.getLValue().(VariableAccess).getTarget() = v and
    reassign.getEnclosingFunction() = freed.getEnclosingFunction() and
    isBefore(freed, reassign) and
    // Step 3: if (!v) goto err;  (NULL check + goto)
    guard.getEnclosingFunction() = freed.getEnclosingFunction() and
    isBefore(reassign, guard.getCondition()) and
    exists(Expr condChild |
      condChild = guard.getCondition().getAChild*() and
      condChild.(VariableAccess).getTarget() = v
    ) and
    gotoStmt.getParent+() = guard.getThen() and
    // Step 4: use of v after the goto target (in cleanup/error path)
    use.(VariableAccess).getTarget() = v and
    isUseSite(use) and
    isBefore(guard.getCondition(), use) and
    use.getEnclosingFunction() = freed.getEnclosingFunction()
  )
}

/**
 * Report a potential free-then-use when the freed value flows to a later use site
 * within the same function.
 */
from FunctionCall freeC, Expr freed, Expr use
where
  (
    // Original: direct dataflow from freed pointer to use
    exists(DataFlow::Node src, DataFlow::Node snk |
      DF::flow(src, snk) and
      src.asExpr() = freed and
      snk.asExpr() = use and
      isDirectFreeCall(freeC, freed) and
      freed.getEnclosingFunction() = use.getEnclosingFunction() and
      isBefore(freed, use)
    )
    or
    // New: free-then-reassign-then-error-path-use
    isFreeReassignErrorUse(freeC, freed, use)
  )
select use,
  "Potential use-after-free (intra): value freed by '" +
  freeC.getTarget().getName() + "()' flows to a later use."
