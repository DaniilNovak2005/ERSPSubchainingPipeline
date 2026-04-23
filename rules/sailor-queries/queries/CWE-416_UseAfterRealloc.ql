/**
 * @name CWE-416: Use-After-Realloc — stale pointer after grow/realloc
 * @kind problem
 * @precision low
 * @problem.severity error
 * @id sailor/cpp/cwe-416-use-after-realloc
 * @tags security external/cwe/cwe-416
 *
 * @shortDescription Stale pointer dereference after realloc/grow invalidates the old buffer.
 * @description
 * Flags intra-procedural patterns where a pointer (or pointer into a buffer) is obtained
 * before a realloc/grow call, and then used after the grow — at which point the old
 * memory may have been freed and relocated.
 *
 * PATTERN A (direct realloc):
 *   old = ptr;
 *   ptr = realloc(ptr, newsize);   // old is now stale
 *   use(old);                      // UAF
 *
 * PATTERN B (grow through container):
 *   entry = &table->entries[i];    // pointer into table's buffer
 *   growTable(table);              // internally reallocs entries
 *   entry->key = k;               // STALE — entries may have moved
 *
 * Historic bugs caught:
 *   - hash.c: xmlHashUpdateInternal — pointer into hash bucket stale after xmlHashGrow
 *   - dict.c: xmlDictLookupInternal — entry pointer stale after dict grow
 */

import cpp
import semmle.code.cpp.exprs.Access as Access

/** Source-order check within same function. */
private predicate isBefore(Expr a, Expr b) {
  a.getEnclosingFunction() = b.getEnclosingFunction() and
  a.getLocation().getFile() = b.getLocation().getFile() and
  a.getLocation().getStartLine() < b.getLocation().getStartLine()
}

/** Dereference site: pointer-field access, array, or direct deref. */
predicate isDerefUse(Expr e) {
  exists(Access::PointerFieldAccess pfa | pfa.getQualifier() = e) or
  exists(Access::ArrayExpr ae | ae.getArrayBase() = e) or
  exists(PointerDereferenceExpr pde | pde.getOperand() = e)
}

// =============================================================================
// PATTERN A: Direct realloc — old alias becomes stale
// =============================================================================

/** Realloc-family functions that may relocate memory. */
class ReallocCall extends FunctionCall {
  ReallocCall() {
    exists(string n | n = this.getTarget().getName() |
      n = "realloc" or n = "reallocarray" or n = "reallocf" or
      n = "xmlRealloc" or n = "xmlReallocLoc" or
      n = "g_realloc" or n = "av_realloc" or
      n.regexpMatch(".*[Rr]ealloc.*")
    ) and
    this.getType() instanceof PointerType
  }

  /** The pointer being reallocated (first argument). */
  Expr getOldPointer() { result = this.getArgument(0) }
}

/**
 * Pattern A: variable `v` aliases the old pointer, realloc is called,
 * then `v` is used (now stale).
 */
predicate patternDirectRealloc(Variable v, ReallocCall realloc, Expr staleUse) {
  exists(AssignExpr aliasAssign |
    // v = ptr (or v = &ptr->field, v = ptr + offset)
    aliasAssign.getLValue().(VariableAccess).getTarget() = v and
    aliasAssign.getRValue().getType() instanceof PointerType and
    // alias is before realloc
    isBefore(aliasAssign, realloc) and
    // realloc is in same function
    aliasAssign.getEnclosingFunction() = realloc.getEnclosingFunction() and
    // stale use of v after realloc
    staleUse.(VariableAccess).getTarget() = v and
    isDerefUse(staleUse) and
    isBefore(realloc, staleUse) and
    staleUse.getEnclosingFunction() = realloc.getEnclosingFunction() and
    // v is not reassigned between realloc and use
    not exists(AssignExpr reassign |
      reassign.getLValue().(VariableAccess).getTarget() = v and
      isBefore(realloc, reassign) and
      isBefore(reassign, staleUse)
    )
  )
}

// =============================================================================
// PATTERN B: Grow through function call — pointer into container becomes stale
// =============================================================================

/** Functions that grow/resize a container (may internally realloc). */
class GrowCall extends FunctionCall {
  GrowCall() {
    exists(string n | n = this.getTarget().getName() |
      n.regexpMatch(".*[Gg]row.*") or
      n.regexpMatch(".*[Rr]esize.*") or
      n.regexpMatch(".*[Rr]eserve.*") or
      n.regexpMatch(".*[Ee]xpand.*") or
      n.regexpMatch(".*[Rr]ehash.*") or
      // libxml2 specific
      n = "xmlHashGrow" or n = "xmlDictGrow" or
      n = "xmlBufGrow" or n = "xmlBufGrowInternal" or
      n = "xmlBufferGrow" or n = "xmlBufferResize"
    )
  }
}

/**
 * Pattern B: pointer derived from container element (address-of array element
 * or field chain into container), then grow called on container, then pointer used.
 */
predicate patternContainerGrow(Variable v, GrowCall grow, Expr staleUse) {
  exists(AssignExpr elemAssign |
    // v = &container[i] or v = container->table[i] etc.
    elemAssign.getLValue().(VariableAccess).getTarget() = v and
    elemAssign.getRValue().getType() instanceof PointerType and
    // Heuristic: RHS involves array access or address-of
    (
      elemAssign.getRValue() instanceof AddressOfExpr or
      exists(Access::ArrayExpr ae | ae = elemAssign.getRValue().getAChild*()) or
      exists(PointerAddExpr pae | pae = elemAssign.getRValue().getAChild*())
    ) and
    elemAssign.getEnclosingFunction() = grow.getEnclosingFunction() and
    isBefore(elemAssign, grow) and
    // stale use of v after grow
    staleUse.(VariableAccess).getTarget() = v and
    isDerefUse(staleUse) and
    isBefore(grow, staleUse) and
    staleUse.getEnclosingFunction() = grow.getEnclosingFunction() and
    // v is not reassigned between grow and use
    not exists(AssignExpr reassign |
      reassign.getLValue().(VariableAccess).getTarget() = v and
      isBefore(grow, reassign) and
      isBefore(reassign, staleUse)
    )
  )
}

from Variable v, Expr growOrRealloc, Expr staleUse, string pattern
where
  (
    exists(ReallocCall rc |
      patternDirectRealloc(v, rc, staleUse) and
      growOrRealloc = rc and
      pattern = "realloc"
    )
    or
    exists(GrowCall gc |
      patternContainerGrow(v, gc, staleUse) and
      growOrRealloc = gc and
      pattern = "grow"
    )
  )
select staleUse,
  "Potential use-after-realloc: '" + v.getName() +
  "' may be stale after " + pattern + " call to '" +
  growOrRealloc.(FunctionCall).getTarget().getName() + "()'."
