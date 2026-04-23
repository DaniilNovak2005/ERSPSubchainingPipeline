/**
 * @name WMI-2: Information Leak via Type Confusion (Stale Pointer Dereference)
 * @description Detects when a pointer to a freed object is dereferenced to read
 *              a field, and the freed memory could have been reclaimed by a
 *              different type. This enables information leaks.
 *
 *              Pattern: Object A is freed. Stale pointer still exists.
 *              Memory is reclaimed by Object B (different type).
 *              Reading field through stale pointer yields B's data as A's type.
 *
 *              In kernel: reading chain->dev->name after net_device is freed and
 *              memory reclaimed by packet_fanout reveals fanout's net pointer.
 *
 * @kind problem
 * @problem.severity error
 * @id sailor/wmi-2-type-confusion-leak
 * @tags security
 *       wmi
 *       information-leak
 *       type-confusion
 *       cwe-416
 *       cwe-125
 *       kernel
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow

/**
 * A deallocation call (free, kfree, etc.)
 */
class DeallocCall extends FunctionCall {
  DeallocCall() {
    this.getTarget().getName() in [
      "free", "kfree", "kfree_rcu", "kfree_sensitive",
      "kmem_cache_free", "kvfree", "vfree",
      "dev_put", "netdev_put", "put_device",
      "kobject_put", "kref_put",
      "sk_free", "sock_put"
    ]
  }

  Expr getFreedExpr() {
    if this.getTarget().getName() = "kmem_cache_free"
    then result = this.getArgument(1)
    else result = this.getArgument(0)
  }
}

/**
 * A field access through a pointer — reading obj->field.
 * This is the "dereference through stale pointer" pattern.
 */
class StaleFieldRead extends FieldAccess {
  StaleFieldRead() {
    // Must be a read (not an assignment target)
    not exists(AssignExpr ae | ae.getLValue() = this) and
    // Must go through a pointer (obj->field, not obj.field)
    this.getQualifier().getType().getUnspecifiedType() instanceof PointerType
  }

  /** The pointer being dereferenced. */
  Expr getBasePointer() {
    result = this.getQualifier()
  }

  /** The type of struct being accessed. */
  Type getAccessedType() {
    result = this.getQualifier().getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType()
  }
}

/**
 * Holds if `readAccess` is guarded by a null check on its base pointer.
 * Simple version that avoids BasicBlock APIs for cpp-all compatibility.
 */
predicate hasNullGuard(StaleFieldRead readAccess) {
  exists(IfStmt ifStmt, EqualityOperation eq |
    eq = ifStmt.getCondition().getAChild*() and
    eq.getAnOperand().toString() = readAccess.getBasePointer().toString() and
    eq.getAnOperand() instanceof NullValue and
    // The read is inside the then or else branch of this null check
    readAccess.getEnclosingStmt().getParentStmt*() = ifStmt.getThen()
    or
    readAccess.getEnclosingStmt().getParentStmt*() = ifStmt.getElse()
  )
}

/**
 * A function that returns a field value obtained through a pointer dereference.
 * e.g., get_owner_uid() reads t->owner->uid and returns it.
 */
class LeakFunction extends Function {
  FieldAccess leakAccess;
  ReturnStmt returnStmt;

  LeakFunction() {
    leakAccess.getEnclosingFunction() = this and
    returnStmt.getEnclosingFunction() = this and
    // The return value flows from the field access
    DataFlow::localExprFlow(leakAccess, returnStmt.getExpr()) and
    // The field access is through a pointer (potential stale reference)
    leakAccess.getQualifier().getType().getUnspecifiedType() instanceof PointerType and
    // The accessed pointer comes from another struct's field (chained dereference)
    exists(FieldAccess outerAccess |
      outerAccess.getAChild*() = leakAccess.getQualifier() or
      DataFlow::localExprFlow(outerAccess, leakAccess.getQualifier())
    )
  }

  FieldAccess getLeakAccess() { result = leakAccess }
}

from DeallocCall freeCall, StaleFieldRead readAccess, Function freeFunc, Function readFunc
where
  freeFunc = freeCall.getEnclosingFunction() and
  readFunc = readAccess.getEnclosingFunction() and
  // The freed type matches the accessed type
  freeCall.getFreedExpr().getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() =
    readAccess.getAccessedType() and
  // The read is NOT in the same function as the free (cross-function UAF)
  freeFunc != readFunc and
  // There's no null check on the pointer before the read
  not hasNullGuard(readAccess)
select readAccess,
  "WMI-2 Type Confusion Leak: Field '" + readAccess.getTarget().getName() +
  "' read through pointer of type " + readAccess.getAccessedType().getName() +
  " in " + readFunc.getName() +
  "(). This type is freed in " + freeFunc.getName() +
  "() without invalidating all references. " +
  "If memory is reclaimed by a different type, this read leaks attacker-controlled data."
