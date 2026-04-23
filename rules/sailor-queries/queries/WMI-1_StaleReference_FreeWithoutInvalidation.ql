/**
 * @name WMI-1: Stale Reference Creation (Free Without Pointer Invalidation)
 * @description Detects when an object is freed but other structures still hold
 *              pointers to it, creating a dangling/stale reference. This is the
 *              foundation of UAF exploitation chains.
 *
 *              Pattern: Object A is freed, but Object B still has a field pointing
 *              to A. The pointer in B is never set to NULL after A is freed.
 *
 *              In kernel context: e.g., nf_chain->dev pointer not cleared when
 *              net_device is freed, or list_head entries freed without list_del.
 *
 * @kind problem
 * @problem.severity warning
 * @id sailor/wmi-1-stale-reference-creation
 * @tags security
 *       wmi
 *       use-after-free
 *       stale-reference
 *       cwe-416
 *       kernel
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow

/**
 * A free-like function call (free, kfree, kfree_rcu, kmem_cache_free, etc.)
 */
class FreeCall extends FunctionCall {
  FreeCall() {
    this.getTarget().getName() in [
      "free", "kfree", "kfree_rcu", "kfree_sensitive",
      "kmem_cache_free", "kvfree", "vfree",
      "put_device", "dev_put", "netdev_put",
      "nf_tables_chain_destroy", "nft_chain_del",
      "sk_free", "sock_put", "__sock_put",
      "fput", "iput", "dput",
      "kobject_put", "kref_put"
    ]
  }

  /** The argument being freed. */
  Expr getFreedArg() {
    // free(ptr) — first arg; kmem_cache_free(cache, ptr) — second arg
    if this.getTarget().getName() = "kmem_cache_free"
    then result = this.getArgument(1)
    else result = this.getArgument(0)
  }
}

/**
 * A struct field that holds a pointer to another struct — a "back-pointer"
 * or "owner pointer" that can become stale.
 */
class OwnerPointerField extends Field {
  OwnerPointerField() {
    this.getType().getUnspecifiedType() instanceof PointerType and
    // Must point to a struct/class type
    this.getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() instanceof Struct
  }
}

/**
 * Assignment to a struct field that stores a pointer to another object.
 * e.g., trig->owner = ent; or chain->dev = dev;
 */
class OwnerPointerAssignment extends AssignExpr {
  OwnerPointerAssignment() {
    exists(FieldAccess fa |
      fa = this.getLValue() and
      fa.getTarget() instanceof OwnerPointerField
    )
  }

  /** The field being assigned. */
  Field getField() {
    result = this.getLValue().(FieldAccess).getTarget()
  }

  /** The struct type that owns the field. */
  Type getOwnerType() {
    result = this.getLValue().(FieldAccess).getQualifier().getType().getUnspecifiedType().(PointerType).getBaseType()
  }

  /** The type being pointed to. */
  Type getPointedType() {
    result = this.getField().getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType()
  }
}

/**
 * A free call where the freed object's type matches a type that is pointed-to
 * by an owner pointer field, and the owner field is NOT nullified after the free.
 */
from FreeCall freeCall, OwnerPointerAssignment ptrAssign, Function freeFunc
where
  freeFunc = freeCall.getEnclosingFunction() and
  // The freed argument's type matches the pointed-to type in the assignment
  exists(Type freedType, Type pointedType |
    freedType = freeCall.getFreedArg().getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() and
    pointedType = ptrAssign.getPointedType() and
    freedType = pointedType
  ) and
  // The owner pointer assignment reaches the free (the pointer was set before the free)
  // i.e., there exists a code path where the pointer was set and then the object was freed
  ptrAssign.getEnclosingFunction() != freeFunc and
  // CRITICAL: The field is NOT set to NULL anywhere in the free function or after the free
  not exists(AssignExpr nullAssign |
    nullAssign.getLValue().(FieldAccess).getTarget() = ptrAssign.getField() and
    nullAssign.getRValue() instanceof NullValue and
    // The null assignment is reachable from the free call
    freeCall.getASuccessor*() = nullAssign
  ) and
  // Exclude cases where the whole containing struct is also freed
  not exists(FreeCall containerFree |
    containerFree.getEnclosingFunction() = freeFunc and
    containerFree != freeCall
  )
select freeCall,
  "WMI-1 Stale Reference: " + freeCall.getFreedArg().toString() +
  " is freed here but field '" + ptrAssign.getField().getName() +
  "' (type " + ptrAssign.getOwnerType().getName() +
  ") still holds a pointer to it. This creates a dangling reference exploitable for UAF."
