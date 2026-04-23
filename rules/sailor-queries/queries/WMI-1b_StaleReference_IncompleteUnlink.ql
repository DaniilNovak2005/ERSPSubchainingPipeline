/**
 * @name WMI-1b: Stale Reference via Incomplete Unlink
 * @description Detects when an object is removed from a container (linked list,
 *              hash table, tree) but back-references from other objects are not
 *              updated. The object may be freed later while stale pointers remain.
 *
 *              Kernel pattern: list_del(&obj->list) followed by kfree(obj), but
 *              other structures still reference obj through non-list pointers.
 *              e.g., netfilter chain removal doesn't clear device hook references.
 *
 * @kind problem
 * @problem.severity warning
 * @id sailor/wmi-1b-stale-reference-incomplete-unlink
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
 * Kernel list/container removal operations.
 */
class ContainerRemoveCall extends FunctionCall {
  ContainerRemoveCall() {
    this.getTarget().getName() in [
      "list_del", "list_del_init", "list_del_rcu",
      "hlist_del", "hlist_del_init", "hlist_del_rcu",
      "rb_erase", "rhashtable_remove_fast",
      "hash_del", "hash_del_rcu",
      // Netfilter-specific
      "nf_unregister_net_hook", "nft_unregister_chain"
    ]
  }
}

/**
 * A free call in the same function as or reachable from a container remove.
 */
class RemoveThenFreePattern extends FunctionCall {
  ContainerRemoveCall removeCall;

  RemoveThenFreePattern() {
    this.getTarget().getName() in [
      "free", "kfree", "kfree_rcu", "kmem_cache_free", "kvfree"
    ] and
    removeCall.getEnclosingFunction() = this.getEnclosingFunction() and
    removeCall.getASuccessor*() = this
  }

  ContainerRemoveCall getRemoveCall() { result = removeCall }
}

/**
 * A struct field assignment that creates a cross-reference between two different
 * struct types (the "back-pointer" that can become stale).
 */
class CrossTypeReference extends AssignExpr {
  CrossTypeReference() {
    exists(FieldAccess lhs, Type assignerType, Type fieldTargetType |
      lhs = this.getLValue() and
      lhs.getTarget().getType().getUnspecifiedType() instanceof PointerType and
      assignerType = lhs.getQualifier().getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() and
      fieldTargetType = lhs.getTarget().getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() and
      // Cross-type: the struct holding the field is different from the type pointed to
      assignerType != fieldTargetType and
      // Both must be struct types
      assignerType instanceof Struct and
      fieldTargetType instanceof Struct
    )
  }

  Field getField() {
    result = this.getLValue().(FieldAccess).getTarget()
  }

  Type getContainerType() {
    result = this.getLValue().(FieldAccess).getQualifier().getType().getUnspecifiedType().(PointerType).getBaseType()
  }

  Type getReferencedType() {
    result = this.getField().getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType()
  }
}

from RemoveThenFreePattern freeCall, CrossTypeReference xref
where
  // The type being freed matches the type referenced by the cross-reference
  exists(Type freedType |
    freedType = freeCall.getArgument(0).getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() and
    freedType = xref.getReferencedType()
  ) and
  // The cross-reference field is NOT nullified in or after the remove+free function
  not exists(AssignExpr nullify |
    nullify.getLValue().(FieldAccess).getTarget() = xref.getField() and
    nullify.getRValue() instanceof NullValue and
    nullify.getEnclosingFunction() = freeCall.getEnclosingFunction()
  )
select freeCall,
  "WMI-1b Incomplete Unlink: Object freed after " +
  freeCall.getRemoveCall().getTarget().getName() +
  "() but field '" + xref.getField().getName() +
  "' in " + xref.getContainerType().getName() +
  " still references the freed " + xref.getReferencedType().getName() +
  ". Back-pointer not invalidated after removal."
