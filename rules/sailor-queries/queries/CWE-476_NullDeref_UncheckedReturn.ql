/**
 * @name CWE-476: NULL Pointer Dereference — unchecked allocation/creation result
 * @kind problem
 * @precision low
 * @problem.severity warning
 * @id sailor/cpp/cwe-476-unchecked-alloc-deref
 * @tags security external/cwe/cwe-476
 *
 * @shortDescription NULL dereference when allocation or creation function result is used without a NULL check.
 * @description
 * Flags intra-procedural patterns where a pointer returned by an allocator, creator,
 * or lookup function is dereferenced (p->f, *p, p[i]) without an intervening NULL guard.
 *
 * Targets common C allocators, libxml2 creators (xmlNew*, xmlCreate*, xmlGet*,
 * xmlBuf*, xmlHash*, xmlDict*), and generic creation/lookup naming patterns.
 *
 * PATTERN:
 *   ptr = xmlNewFoo(...);   // returns NULL on failure
 *   ptr->field = val;       // no NULL check — SEGV
 *
 * Historic bugs caught:
 *   - xmlSaveCtxtInit SEGV (CVE-less, libxml2 2.12.0-dev)
 *   - xmlSchematronRunTest SEGV (predates CVE-2025-49795)
 *   - xmlXPtrEvalChildSeq SEGV (CVE-2016-4658 lineage)
 *   - xmlInitSAXParserCtxt SEGV (OSS-Fuzz 62911 root cause)
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.exprs.Access as Access
import semmle.code.cpp.controlflow.Dereferenced as Deref

/**
 * Functions whose return value may be NULL: allocators, creators, lookups.
 */
class NullableReturnCall extends FunctionCall {
  NullableReturnCall() {
    exists(Function f | this.getTarget() = f |
      exists(string n | n = f.getName() |
        // Standard C allocators
        n = "malloc" or n = "calloc" or n = "realloc" or
        n = "strdup" or n = "strndup" or n = "reallocarray" or
        // Project-agnostic wrapper allocators (catches OPENSSL_realloc, g_malloc, etc.)
        n.regexpMatch(".*_malloc$") or
        n.regexpMatch(".*_calloc$") or
        n.regexpMatch(".*_realloc$") or
        n.regexpMatch(".*_strdup$") or
        n.regexpMatch(".*_strndup$") or
        n.regexpMatch(".*_zalloc$") or
        // OpenSSL allocators (OPENSSL_malloc, CRYPTO_malloc, etc.)
        n.regexpMatch("^(OPENSSL|CRYPTO)_(malloc|zalloc|realloc|strdup|strndup|memdup)$") or
        // GLib allocators
        n.regexpMatch("^g_(malloc|realloc|strdup|strndup|new|try_malloc|try_realloc).*") or
        // libxml2 allocators
        n.regexpMatch("^xml(Malloc|MallocAtomic|Realloc|MemStrdup)$") or
        // libxml2 creators / constructors (return NULL on failure)
        n.regexpMatch("^xml(New|Create|Copy|Build|Dup).*") or
        n.regexpMatch("^html(New|Create|Copy).*") or
        n.regexpMatch("^xml(Buf|Buffer)(Create|CreateSize).*") or
        n.regexpMatch("^xmlHash(Create|Copy).*") or
        n.regexpMatch("^xmlDict(Create|CreateSub).*") or
        n.regexpMatch("^xmlParse[A-Z].*") or
        // libxml2 lookups that return NULL on miss
        n.regexpMatch("^xml(Get|Lookup|Search|Find).*") or
        n.regexpMatch("^xmlHash(Lookup|DefaultDeallocator).*") or
        n.regexpMatch("^xmlDict(Lookup|Exists|QLookup).*") or
        // Generic creation/alloc naming conventions
        n.regexpMatch(".*_alloc$") or
        n.regexpMatch(".*_create$") or
        n.regexpMatch(".*_new$") or
        n.regexpMatch(".*Alloc$") or
        n.regexpMatch(".*Create$") or
        n.regexpMatch(".*New$")
      )
    ) and
    // Must return a pointer type
    this.getType() instanceof PointerType
  }
}

/** Dereference site: pointer-field access, direct deref, or array base. */
predicate isDerefSite(Expr e) {
  exists(Access::PointerFieldAccess pfa | pfa.getQualifier() = e) or
  exists(Access::ArrayExpr ae | ae.getArrayBase() = e) or
  Deref::dereferenced(e)
}

/** Source-order check within same function and file. */
private predicate isBefore(Expr a, Expr b) {
  a.getEnclosingFunction() = b.getEnclosingFunction() and
  a.getLocation().getFile() = b.getLocation().getFile() and
  a.getLocation().getStartLine() < b.getLocation().getStartLine()
}

/**
 * NULL guard: checks if there is a conditional test of the variable between
 * the assignment and the use. Covers:
 *   if (ptr == NULL), if (!ptr), if (ptr == 0), if (ptr)
 */
predicate hasNullGuard(Variable v, Expr allocSite, Expr useSite) {
  exists(IfStmt ifs |
    ifs.getEnclosingFunction() = allocSite.getEnclosingFunction() and
    ifs.getLocation().getStartLine() >= allocSite.getLocation().getStartLine() and
    ifs.getLocation().getStartLine() <= useSite.getLocation().getStartLine() and
    exists(Expr condChild |
      condChild = ifs.getCondition().getAChild*() and
      condChild.(VariableAccess).getTarget() = v
    )
  )
}

/**
 * NULL guard via early return: if (!ptr) return;
 * Also covers: if (ptr == NULL) goto error;
 */
predicate hasEarlyReturnGuard(Variable v, Expr allocSite, Expr useSite) {
  exists(IfStmt ifs, Stmt exitStmt |
    ifs.getEnclosingFunction() = allocSite.getEnclosingFunction() and
    ifs.getLocation().getStartLine() >= allocSite.getLocation().getStartLine() and
    ifs.getLocation().getStartLine() <= useSite.getLocation().getStartLine() and
    exists(Expr condChild |
      condChild = ifs.getCondition().getAChild*() and
      condChild.(VariableAccess).getTarget() = v
    ) and
    exitStmt.getParent+() = ifs.getThen() and
    (exitStmt instanceof ReturnStmt or exitStmt instanceof GotoStmt)
  )
}

/** Data-flow config: from nullable return to dereference. */
module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) {
    s.asExpr() instanceof NullableReturnCall
  }
  predicate isSink(DataFlow::Node t) {
    exists(Expr e | isDerefSite(e) and t.asExpr() = e)
  }
}
module DF = DataFlow::Global<Cfg>;

from
  DataFlow::Node src, DataFlow::Node snk,
  NullableReturnCall alloc, Expr use,
  Variable v, AssignExpr assign
where
  DF::flow(src, snk) and
  src.asExpr() = alloc and
  snk.asExpr() = use and
  // Assigned to a variable
  assign.getRValue() = alloc and
  assign.getLValue().(VariableAccess).getTarget() = v and
  // Use is through same variable
  use.(VariableAccess).getTarget() = v and
  isDerefSite(use) and
  // Same function, use after alloc
  alloc.getEnclosingFunction() = use.getEnclosingFunction() and
  isBefore(alloc, use) and
  // Within 50 lines (avoid distant false positives)
  use.getLocation().getStartLine() - alloc.getLocation().getStartLine() <= 50 and
  // No NULL guard between alloc and use
  not hasNullGuard(v, alloc, use) and
  not hasEarlyReturnGuard(v, alloc, use)
select use,
  "Potential NULL pointer dereference: result of '" + alloc.getTarget().getName() +
  "()' assigned to '" + v.getName() + "' is dereferenced without NULL check."
