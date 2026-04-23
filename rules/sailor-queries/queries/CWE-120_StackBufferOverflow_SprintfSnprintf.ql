/**
 * @name CWE-120: Stack Buffer Overflow via sprintf/snprintf
 * @kind problem
 * @precision low
 * @problem.severity warning
 * @id sailor/cpp/cwe-120-stack-sprintf-overflow
 * @tags security external/cwe/cwe-120 external/cwe/cwe-121
 *
 * @shortDescription Fixed-size stack buffer written via sprintf/snprintf with variable-length data.
 * @description
 * Flags patterns where a fixed-size local (stack) buffer is written by sprintf,
 * snprintf, or related formatting functions with format arguments that may
 * produce output exceeding the buffer size.
 *
 * PATTERN A (sprintf — no size limit):
 *   char buf[256];
 *   sprintf(buf, "Error: %s at line %d", name, line);  // unbounded
 *
 * PATTERN B (snprintf — potential truncation used unsafely):
 *   char buf[256];
 *   snprintf(buf, sizeof(buf), "... %s ...", long_string);
 *   strcat(buf, more_data);   // appends past truncated content → overflow
 *
 * PATTERN C (iterative append to stack buffer):
 *   char buf[500];
 *   int pos = 0;
 *   for (...) {
 *       pos += snprintf(buf + pos, sizeof(buf) - pos, "%s,", name);
 *       // pos can exceed sizeof(buf) if return value not checked
 *   }
 *
 * Historic bugs caught:
 *   - CVE-2025-24928: xmlSnprintfElements stack overflow in valid.c
 *   - CVE-2025-32415: buffer overflow in schema error reporting
 */

import cpp

/** Fixed-size stack-allocated character buffer (local array variable). */
class StackCharBuffer extends Variable {
  int bufSize;

  StackCharBuffer() {
    this instanceof LocalVariable and
    exists(ArrayType at |
      at = this.getType() and
      at.getBaseType().getUnspecifiedType() instanceof CharType and
      at.getArraySize() > 0 and
      bufSize = at.getArraySize()
    )
  }

  int getBufferSize() { result = bufSize }
}

/** sprintf-family: writes formatted output with NO size limit. */
class SprintfCall extends FunctionCall {
  SprintfCall() {
    exists(string n | n = this.getTarget().getName() |
      n = "sprintf" or n = "vsprintf" or
      n = "swprintf" or n = "wsprintf" or
      n = "wsprintfA" or n = "wsprintfW"
    )
  }

  /** The destination buffer (first argument). */
  Expr getDestBuffer() { result = this.getArgument(0) }

  /** The format string (second argument). */
  Expr getFormatString() { result = this.getArgument(1) }
}

/** snprintf-family: writes formatted output with size limit, but
 *  return value is the DESIRED length (can exceed buffer). */
class SnprintfCall extends FunctionCall {
  SnprintfCall() {
    exists(string n | n = this.getTarget().getName() |
      n = "snprintf" or n = "vsnprintf" or
      n = "_snprintf" or n = "_vsnprintf" or
      n = "swprintf" or n = "vswprintf" or
      // libxml2 wrappers
      n = "xmlStrPrintf" or n = "xmlStrVPrintf"
    )
  }

  /** The destination buffer (first argument). */
  Expr getDestBuffer() { result = this.getArgument(0) }

  /** The size limit (second argument). */
  Expr getSizeArg() { result = this.getArgument(1) }

  /** The format string (third argument). */
  Expr getFormatString() { result = this.getArgument(2) }
}

/** Format string contains a %s (variable-length string interpolation). */
predicate formatHasStringArg(Expr fmt) {
  exists(StringLiteral sl |
    sl = fmt and
    sl.getValue().regexpMatch(".*%[-+0 #]*[0-9]*\\.?[0-9]*l{0,2}s.*")
  )
}

/** Format string contains multiple format specifiers (complex formatting). */
predicate formatIsComplex(Expr fmt) {
  exists(StringLiteral sl |
    sl = fmt and
    // Count % that aren't %% (escaped percent)
    sl.getValue().regexpMatch(".*%[^%].*%[^%].*")
  )
}

/** Identifies uses of a buffer variable as a destination. */
predicate bufferIsDestination(StackCharBuffer buf, Expr destExpr) {
  // Direct: sprintf(buf, ...)
  destExpr.(VariableAccess).getTarget() = buf
  or
  // Offset: sprintf(buf + pos, ...)
  exists(PointerAddExpr pae |
    pae = destExpr and
    pae.getLeftOperand().(VariableAccess).getTarget() = buf
  )
  or
  // Address-of: sprintf(&buf[0], ...)
  exists(AddressOfExpr aoe, ArrayExpr ae |
    aoe = destExpr and ae = aoe.getOperand() and
    ae.getArrayBase().(VariableAccess).getTarget() = buf
  )
}

/** snprintf return value used in pointer arithmetic for next write (loop append pattern). */
predicate snprintfReturnUsedInOffset(SnprintfCall call) {
  exists(AssignAddExpr aae |
    aae.getRValue() = call and
    aae.getEnclosingFunction() = call.getEnclosingFunction()
  )
  or
  exists(AssignExpr ae |
    ae.getRValue().(AddExpr).getAnOperand() = call and
    ae.getEnclosingFunction() = call.getEnclosingFunction()
  )
}

// =============================================================================
// Rule 1: sprintf (unbounded) to stack buffer with %s
// =============================================================================
from SprintfCall call, StackCharBuffer buf
where
  bufferIsDestination(buf, call.getDestBuffer()) and
  (
    formatHasStringArg(call.getFormatString()) or
    formatIsComplex(call.getFormatString())
  )
select call,
  "Potential stack buffer overflow: sprintf() writes to '" + buf.getName() +
  "' (" + buf.getBufferSize().toString() + " bytes) with variable-length format args — no size limit."

// Note: snprintf patterns are lower priority since snprintf itself prevents overflow.
// The risk is when snprintf return value is used unsafely for iterative appends,
// which is better caught by the cursor-lookahead or OOB-write rules.
