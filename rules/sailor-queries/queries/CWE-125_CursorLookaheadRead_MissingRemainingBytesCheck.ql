/**
 * @id local/cpp/cwe-125-cursor-lookahead-missing-bytes-check
 * @name CWE-125: Cursor lookahead read without remaining-bytes check
 *
 * @description
 * Flags direct fixed-offset reads from a cursor-like pointer (e.g., cur[3]) in stream/parsing code
 * when there is no nearby early-exit guard that checks the remaining bytes.
 *
 * @kind problem
 * @problem.severity warning
 * @tags security
 * external/cwe/cwe-125
 */
import cpp

/** =========================
 * 1) Heuristics: identify cursor-like and end-like expressions
 * =========================
 */

/** Match pointer-like names commonly used as stream cursors. */
private predicate isCurLike(Expr e) {
  exists(string n |
    (
      exists(VariableAccess va | va = e and n = va.getTarget().getName()) or
      exists(FieldAccess fa | fa = e and n = fa.getTarget().getName())
    ) and
    n.regexpMatch("(?i).*(cur|cursor|ptr|pos|p|buf|data|src|in).*")
  )
  or
  // Also match any FieldAccess chain ending in "cur" (e.g., ctxt->input->cur)
  exists(FieldAccess fa |
    fa = e and
    fa.getTarget().getName().regexpMatch("(?i).*(cur|cursor|ptr|pos|buf|data).*")
  )
}

private predicate isEndLike(Expr e) {
  exists(string n |
    (
      exists(VariableAccess va | va = e and n = va.getTarget().getName()) or
      exists(FieldAccess fa | fa = e and n = fa.getTarget().getName())
    ) and
    n.regexpMatch("(?i).*(end|limit|last|bound|max|size|len|avail).*")
  )
}

/** =========================
 * 2) Pattern: fixed-offset (lookahead) read of a cursor
 * =========================
 */
private predicate isCursorLookaheadRead(ArrayExpr ae, Expr base, int idxVal) {
  base = ae.getArrayBase() and
  isCurLike(base) and
  // Ensure the offset is an integer literal
  exists(Literal idxLit |
    idxLit = ae.getArrayOffset() and
    idxLit.getValue().regexpMatch("\\d+") and
    idxVal = idxLit.getValue().toInt()
  ) and
  idxVal >= 0 and
  idxVal <= 8
}

/** =========================
 * 3) Guard recognition: remaining-bytes early exit
 * =========================
 *
 * Matches patterns like:
 *   if ((end - cur) < N) { return/goto/break; }
 *   if ((end - cur) >= N) { ... } else { return; }
 */
bindingset[read, base, requiredBytes]
private predicate hasNearbyRemainingBytesGuard(ArrayExpr read, Expr base, int requiredBytes) {
  exists(IfStmt ifs, RelationalOperation cmp, SubExpr sub, Literal nLit |
    // Guard and read must be in the same function.
    ifs.getEnclosingFunction() = read.getEnclosingFunction() and
    ifs.getCondition() = cmp and

    // Support <, <=, >, >=
    (cmp.getOperator() = "<" or cmp.getOperator() = "<=" or
     cmp.getOperator() = ">" or cmp.getOperator() = ">=") and

    // Match (end - cur) on either side of the comparison
    (
      // Pattern A: (end - cur) < N  or  (end - cur) >= N
      (
        sub = cmp.getLeftOperand() and
        nLit = cmp.getRightOperand()
      )
      or
      // Pattern B: N > (end - cur)  or  N <= (end - cur)
      (
        nLit = cmp.getLeftOperand() and
        sub = cmp.getRightOperand()
      )
    ) and

    // left side of subtraction: end-like
    isEndLike(sub.getLeftOperand()) and

    // right side of subtraction: the cursor base (structural or toString match)
    (
      sub.getRightOperand() = base
      or
      sub.getRightOperand().toString() = base.toString()
    ) and

    // Guard must ensure enough bytes.
    nLit.getValue().regexpMatch("\\d+") and
    nLit.getValue().toInt() >= requiredBytes and

    // Accept any control flow exit: return, goto, break, continue
    exists(Stmt exitStmt |
        exitStmt.getParent+() = ifs.getThen() and
        (exitStmt instanceof ReturnStmt or exitStmt instanceof GotoStmt or
         exitStmt instanceof BreakStmt or exitStmt instanceof ContinueStmt)
    ) and

    // Proximity: guard must be before the read, within 50 lines
    ifs.getLocation().getStartLine() < read.getLocation().getStartLine() and
    read.getLocation().getStartLine() - ifs.getLocation().getStartLine() <= 50
  )
}

/** =========================
 * 4) Main query
 * =========================
 */
from ArrayExpr ae, Expr base, int idxVal, int requiredBytes
where
  // 1. Match the pattern
  isCursorLookaheadRead(ae, base, idxVal) and

  // 2. Only flag non-trivial lookaheads (idx >= 1 requires at least 2 bytes)
  requiredBytes = idxVal + 1 and

  // 3. Exclude "&base[idx]"
  not exists(AddressOfExpr u | u.getOperand() = ae) and

  // 4. Exclude if we see a nearby early-exit guard.
  not hasNearbyRemainingBytesGuard(ae, base, requiredBytes) and

  // 5. DE-DUPLICATION: Report only the highest offset per source line.
  //    This avoids reporting cur[0], cur[1], cur[2], cur[3] separately.
  not exists(ArrayExpr ae2, int idx2 |
    ae2 != ae and
    isCursorLookaheadRead(ae2, _, idx2) and
    ae2.getLocation().getStartLine() = ae.getLocation().getStartLine() and
    ae2.getEnclosingFunction() = ae.getEnclosingFunction() and
    idx2 > idxVal
  )

select ae,
  "Potential OOB lookahead read: " + base.toString() + "[" + idxVal.toString() +
  "] (requires " + requiredBytes.toString() + " bytes) without a nearby remaining-bytes guard."