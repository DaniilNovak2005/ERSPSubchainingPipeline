/**
 * @name WMI-3: Arbitrary Free via Stale Pointer Traversal
 * @description Detects when a cleanup/delete function traverses a linked structure
 *              through a pointer that could be stale, and frees each element.
 *              If the linked structure has been reclaimed, the attacker controls
 *              what gets freed.
 *
 *              Pattern: del_trigger(id) finds trigger, follows trigger->owner
 *              (stale pointer), reads owner->triggers (attacker-controlled),
 *              iterates and frees each. The attacker controls the free target.
 *
 *              In kernel: nf_tables_chain_destroy() follows chain->dev (stale)
 *              to iterate dev hooks and free them. If dev is reclaimed, the hook
 *              list is attacker-controlled → arbitrary kfree.
 *
 * @kind problem
 * @problem.severity error
 * @id sailor/wmi-3-arbitrary-free-stale-traversal
 * @tags security
 *       wmi
 *       arbitrary-free
 *       use-after-free
 *       cwe-416
 *       cwe-761
 *       kernel
 */

import cpp

/**
 * A free call inside a loop — the "iterate and free" pattern.
 */
class FreeInLoop extends FunctionCall {
  FreeInLoop() {
    this.getTarget().getName() in [
      "free", "kfree", "kfree_rcu", "kmem_cache_free", "kvfree"
    ] and
    exists(Loop loop |
      loop.getStmt().getAChild*() = this or
      this.getEnclosingStmt().getParentStmt*() = loop.getStmt()
    )
  }
}

/**
 * A function that:
 * 1. Takes an ID or pointer parameter
 * 2. Looks up an object
 * 3. Follows a pointer field (potential stale reference)
 * 4. Reads a linked list/array from the dereferenced pointer
 * 5. Frees elements in a loop
 *
 * This is the del_trigger / nf_tables_chain_destroy pattern.
 */
class DestructorWithStaleTraversal extends Function {
  FreeInLoop freeInLoop;
  FieldAccess traversalAccess;

  DestructorWithStaleTraversal() {
    freeInLoop.getEnclosingFunction() = this and
    traversalAccess.getEnclosingFunction() = this and
    // The traversal reads a field through a pointer
    traversalAccess.getQualifier().getType().getUnspecifiedType() instanceof PointerType and
    // The traversal field is a pointer (to a linked list head)
    traversalAccess.getTarget().getType().getUnspecifiedType() instanceof PointerType and
    // The traversal happens before the free loop
    traversalAccess.getASuccessor*() = freeInLoop and
    // The function name suggests cleanup/deletion
    (
      this.getName().matches("%del%") or
      this.getName().matches("%destroy%") or
      this.getName().matches("%remove%") or
      this.getName().matches("%cleanup%") or
      this.getName().matches("%release%") or
      this.getName().matches("%unregister%") or
      this.getName().matches("%free%")
    )
  }

  FreeInLoop getFreeInLoop() { result = freeInLoop }

  FieldAccess getTraversalAccess() { result = traversalAccess }

  /** The pointer being dereferenced for traversal (potential stale ref). */
  Expr getTraversedPointer() {
    result = traversalAccess.getQualifier()
  }

  /** The field containing the list/array to iterate. */
  Field getTraversedField() {
    result = traversalAccess.getTarget()
  }
}

/**
 * Detect the pattern: a destructor function dereferences a pointer field
 * to get a linked list, then frees elements. If the pointer field comes
 * from a struct where the pointed-to type is freed elsewhere without
 * invalidating the pointer, this is an arbitrary free primitive.
 */
from DestructorWithStaleTraversal destructor, FieldAccess traversal, FreeInLoop freeCall
where
  traversal = destructor.getTraversalAccess() and
  freeCall = destructor.getFreeInLoop() and
  // The pointer being dereferenced points to a type that has its own free path
  exists(FunctionCall otherFree, Type traversedType |
    traversedType = traversal.getQualifier().getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() and
    otherFree.getTarget().getName() in ["free", "kfree", "kfree_rcu", "kmem_cache_free"] and
    otherFree.getArgument(0).getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() = traversedType and
    otherFree.getEnclosingFunction() != destructor
  )
select freeCall,
  "WMI-3 Arbitrary Free: " + destructor.getName() +
  "() traverses '" + destructor.getTraversedField().getName() +
  "' through a pointer that could be stale (type " +
  traversal.getQualifier().getType().getUnspecifiedType().(PointerType).getBaseType().getName() +
  " is freed elsewhere). Elements reached through this traversal are freed here. " +
  "If the pointer was reclaimed, attacker controls what gets freed."
