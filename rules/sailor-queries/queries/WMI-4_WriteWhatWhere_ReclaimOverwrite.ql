/**
 * @name WMI-4: Write-What-Where via Allocation After Free
 * @description Detects patterns where freed memory is immediately reallocated
 *              and written to — the "reclaim and overwrite" pattern. When
 *              combined with WMI-3 (arbitrary free), this enables write-what-where.
 *
 *              Pattern: free(target); ... ptr = malloc(same_size); ptr->field = value;
 *              If the allocation reclaims the freed block, the write overwrites
 *              the target's memory.
 *
 *              In kernel: kfree(pipe_buffer) then reclaim with msg_msgseg or
 *              kmalloc of same slab size, overwrite function pointers.
 *
 * @kind problem
 * @problem.severity warning
 * @id sailor/wmi-4-write-what-where-reclaim
 * @tags security
 *       wmi
 *       write-what-where
 *       use-after-free
 *       cwe-416
 *       cwe-123
 *       kernel
 */

import cpp

/**
 * An allocation call (malloc, kmalloc, kmem_cache_alloc, etc.)
 */
class AllocCall extends FunctionCall {
  AllocCall() {
    this.getTarget().getName() in [
      "malloc", "calloc", "realloc",
      "kmalloc", "kzalloc", "kcalloc",
      "kmem_cache_alloc", "kmem_cache_zalloc",
      "kvmalloc", "vmalloc", "vzalloc",
      "alloc_skb", "__alloc_skb",
      "sock_kmalloc", "sk_alloc",
      "alloc_netdev_mqs"
    ]
  }
}

/**
 * A free call.
 */
class FreeCall extends FunctionCall {
  FreeCall() {
    this.getTarget().getName() in [
      "free", "kfree", "kfree_rcu", "kmem_cache_free", "kvfree", "vfree"
    ]
  }
}

/**
 * Pattern: In the same function, memory is freed and then a new allocation
 * of similar size occurs, followed by writing to the allocated memory.
 * This is the reclaim-and-overwrite pattern.
 */
from FreeCall freeCall, AllocCall allocCall, AssignExpr writeExpr, Function func
where
  func = freeCall.getEnclosingFunction() and
  func = allocCall.getEnclosingFunction() and
  func = writeExpr.getEnclosingFunction() and
  // Free happens before alloc
  freeCall.getASuccessor*() = allocCall and
  // Alloc happens before write
  allocCall.getASuccessor*() = writeExpr and
  // The write is to a field of the allocated pointer
  exists(FieldAccess fa |
    fa = writeExpr.getLValue() and
    fa.getQualifier().getType().getUnspecifiedType() instanceof PointerType
  ) and
  // The free and alloc are for compatible types/sizes
  // (same type or overlapping slab class)
  (
    // Same type
    freeCall.getArgument(0).getType().getUnspecifiedType() =
      allocCall.getType().getUnspecifiedType()
    or
    // Same sizeof
    exists(SizeofExprOperator freeSize, SizeofExprOperator allocSize |
      freeSize.getEnclosingFunction() = func and
      allocSize.getEnclosingFunction() = func
    )
  )
select writeExpr,
  "WMI-4 Write-What-Where: Memory freed at " + freeCall.getLocation().toString() +
  " then reallocated at " + allocCall.getLocation().toString() +
  " and written here. If the allocation reclaims the freed block, " +
  "this write overwrites the target's memory (e.g., function pointers, credentials)."
