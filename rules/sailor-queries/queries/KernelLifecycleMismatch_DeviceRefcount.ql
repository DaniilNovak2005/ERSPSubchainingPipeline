/**
 * @name Kernel: Device/Object Lifecycle Mismatch (CVE-2024-26808 Pattern)
 * @description Detects when a kernel object (net_device, sock, inode, etc.) can
 *              be destroyed while other subsystems still hold references to it
 *              without proper refcount protection.
 *
 *              This is the root cause of CVE-2024-26808: nf_tables chains hold
 *              a pointer to net_device, but device deletion doesn't unregister
 *              the chain's reference. Destroying the chain later dereferences
 *              the freed device.
 *
 *              Pattern: Object A registers/attaches to Object B.
 *              B can be destroyed independently (different lifecycle owner).
 *              A's destructor dereferences B without checking validity.
 *
 * @kind problem
 * @problem.severity error
 * @id sailor/kernel-lifecycle-mismatch
 * @tags security
 *       wmi
 *       kernel
 *       use-after-free
 *       lifetime
 *       cwe-416
 */

import cpp

/**
 * Kernel reference-count increment functions.
 */
class RefGetCall extends FunctionCall {
  RefGetCall() {
    this.getTarget().getName() in [
      "dev_hold", "netdev_hold", "dev_get_by_name", "dev_get_by_index",
      "get_device", "kobject_get", "kref_get",
      "sock_hold", "igrab", "ihold",
      "nf_ct_get", "nf_conntrack_get",
      "atomic_inc", "refcount_inc"
    ]
  }
}

/**
 * Kernel reference-count decrement / release functions.
 */
class RefPutCall extends FunctionCall {
  RefPutCall() {
    this.getTarget().getName() in [
      "dev_put", "netdev_put",
      "put_device", "kobject_put", "kref_put",
      "sock_put", "__sock_put",
      "iput", "fput", "dput",
      "nf_ct_put", "nf_conntrack_put"
    ]
  }
}

/**
 * A struct field assignment that stores a kernel object pointer without
 * taking a reference.
 */
class UnprotectedRefStore extends AssignExpr {
  FieldAccess fieldAccess;

  UnprotectedRefStore() {
    fieldAccess = this.getLValue() and
    fieldAccess.getTarget().getType().getUnspecifiedType() instanceof PointerType and
    // The field points to a struct type (kernel object)
    fieldAccess.getTarget().getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() instanceof Struct and
    // No reference-count get call for the same value in the enclosing function
    not exists(RefGetCall refGet |
      refGet.getEnclosingFunction() = this.getEnclosingFunction() and
      // The ref get argument matches the stored value
      refGet.getAnArgument().toString() = this.getRValue().toString()
    )
  }

  Field getField() { result = fieldAccess.getTarget() }

  Type getStoredType() {
    result = fieldAccess.getTarget().getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType()
  }

  Function getStoringFunction() {
    result = this.getEnclosingFunction()
  }
}

/**
 * A function that dereferences a struct field (potential stale pointer) as part
 * of its cleanup/destroy logic.
 */
class DestructorDeref extends FieldAccess {
  DestructorDeref() {
    this.getQualifier().getType().getUnspecifiedType() instanceof PointerType and
    this.getTarget().getType().getUnspecifiedType() instanceof PointerType and
    exists(Function f |
      f = this.getEnclosingFunction() and
      (
        f.getName().matches("%destroy%") or
        f.getName().matches("%del%") or
        f.getName().matches("%remove%") or
        f.getName().matches("%release%") or
        f.getName().matches("%unregister%") or
        f.getName().matches("%cleanup%") or
        f.getName().matches("%free%") or
        f.getName().matches("%put%")
      )
    )
  }
}

from UnprotectedRefStore store, DestructorDeref deref
where
  // The stored type matches the type dereferenced in the destructor
  store.getStoredType() = deref.getTarget().getType().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() and
  // The field names match (same pointer being stored and later dereferenced)
  store.getField() = deref.getTarget() and
  // Different functions (store != destructor)
  store.getStoringFunction() != deref.getEnclosingFunction() and
  // The store's type is a kernel-relevant type
  (
    store.getStoredType().getName().matches("%device%") or
    store.getStoredType().getName().matches("%net%") or
    store.getStoredType().getName().matches("%sock%") or
    store.getStoredType().getName().matches("%inode%") or
    store.getStoredType().getName().matches("%sk_buff%") or
    store.getStoredType().getName().matches("%nft_%") or
    store.getStoredType().getName().matches("%nf_%") or
    // Generic: any struct pointer stored without refcount
    not exists(RefGetCall rc | rc.getEnclosingFunction() = store.getStoringFunction())
  )
select deref,
  "Lifecycle Mismatch: Field '" + store.getField().getName() +
  "' stores a " + store.getStoredType().getName() +
  " pointer in " + store.getStoringFunction().getName() +
  "() WITHOUT taking a reference. The destructor " +
  deref.getEnclosingFunction().getName() +
  "() dereferences this field. If the referenced object is independently freed, " +
  "this creates a UAF exploitable as WMI-1 → WMI-2 → WMI-3 chain."
