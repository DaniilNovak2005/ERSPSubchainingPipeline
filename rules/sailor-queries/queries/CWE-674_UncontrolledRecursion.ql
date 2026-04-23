/**
 * @name CWE-674: Uncontrolled Recursion — recursive function without depth guard
 * @kind problem
 * @precision low
 * @problem.severity warning
 * @id sailor/cpp/cwe-674-uncontrolled-recursion
 * @tags security external/cwe/cwe-674 external/cwe/cwe-400
 *
 * @shortDescription Recursive function lacks a depth/recursion-limit check, risking stack overflow.
 * @description
 * Flags functions that call themselves (directly or via a short mutual-recursion cycle)
 * without an apparent depth counter guard. In parsing libraries like libxml2, crafted
 * input with deep nesting can exhaust the stack.
 *
 * PATTERN (direct recursion, no depth guard):
 *   void parseElement(xmlParserCtxtPtr ctxt) {
 *       ...
 *       parseElement(ctxt);   // recursive call
 *       ...
 *   }
 *   // No check like: if (ctxt->depth++ > MAX_DEPTH) return;
 *
 * PATTERN (mutual recursion):
 *   parseContent() → parseElement() → parseContent()  // cycle without depth check
 *
 * Historic bugs caught:
 *   - CVE-2025-9714: XPath evaluation uncontrolled recursion → stack overflow
 *   - CVE-2025-8732: xmlParseSGMLCatalog uncontrolled recursion
 *   - CVE-2017-16932: DTD parameter entity infinite recursion
 *   - Multiple entity expansion / billion laughs variants
 */

import cpp

// =============================================================================
// Depth guard detection: check if function has a recursion depth limiter
// =============================================================================

/**
 * Variable names that suggest a depth/recursion counter.
 */
predicate isDepthVariable(Variable v) {
  exists(string n | n = v.getName().toLowerCase() |
    n.regexpMatch(".*(depth|level|recursi|nesting|limit|count|maxdepth|max_depth).*")
  )
}

/**
 * Parameter names that suggest a depth/recursion counter.
 */
predicate isDepthParameter(Parameter p) {
  exists(string n | n = p.getName().toLowerCase() |
    n.regexpMatch(".*(depth|level|recursi|nesting).*")
  )
}

/**
 * Field access names that suggest a depth counter (e.g., ctxt->depth, ctxt->nsLevel).
 */
predicate isDepthFieldAccess(FieldAccess fa) {
  exists(string n | n = fa.getTarget().getName().toLowerCase() |
    n.regexpMatch(".*(depth|level|recursi|nesting|maxdepth|entitynr|sizeentcopy).*")
  )
}

/**
 * The function contains a guard that compares a depth-like variable against a limit
 * and exits (return/goto) if exceeded.
 */
predicate hasDepthGuard(Function f) {
  exists(IfStmt ifs |
    ifs.getEnclosingFunction() = f and
    exists(Expr cond | cond = ifs.getCondition().getAChild*() |
      (
        // Check: if (depth > MAX) or if (depth >= MAX) or if (++depth > MAX)
        exists(RelationalOperation cmp |
          cmp = cond and
          (
            exists(VariableAccess va | va = cmp.getAnOperand() and isDepthVariable(va.getTarget())) or
            exists(FieldAccess fa | fa = cmp.getAnOperand().getAChild*() and isDepthFieldAccess(fa))
          )
        )
        or
        // Check: if (depth == MAX)
        exists(EqualityOperation eq |
          eq = cond and
          (
            exists(VariableAccess va | va = eq.getAnOperand() and isDepthVariable(va.getTarget())) or
            exists(FieldAccess fa | fa = eq.getAnOperand().getAChild*() and isDepthFieldAccess(fa))
          )
        )
      )
    ) and
    // The guarded block has an exit: return, goto, break
    exists(Stmt exitStmt |
      exitStmt.getParent+() = ifs.getThen() and
      (exitStmt instanceof ReturnStmt or exitStmt instanceof GotoStmt or
       exitStmt instanceof BreakStmt)
    )
  )
}

/**
 * The function increments a depth-like variable (depth++, ++depth, depth += 1)
 * OR increments a depth-like field (ctxt->depth++).
 */
predicate incrementsDepthCounter(Function f) {
  exists(Expr inc | inc.getEnclosingFunction() = f |
    (
      // depth++ or ++depth
      exists(IncrementOperation co |
        co = inc and
        (
          exists(VariableAccess va | va = co.getOperand() and isDepthVariable(va.getTarget())) or
          exists(FieldAccess fa | fa = co.getOperand() and isDepthFieldAccess(fa))
        )
      )
      or
      // depth += 1 or depth = depth + 1
      exists(AssignAddExpr aae |
        aae = inc and
        (
          exists(VariableAccess va | va = aae.getLValue() and isDepthVariable(va.getTarget())) or
          exists(FieldAccess fa | fa = aae.getLValue() and isDepthFieldAccess(fa))
        )
      )
    )
  )
}

/**
 * Function has a depth parameter that it passes incremented to the recursive call.
 * Pattern: f(int depth) { ... f(depth + 1) ... }
 */
predicate passesIncrementedDepth(Function f, FunctionCall recursiveCall) {
  exists(Parameter p, Expr arg |
    isDepthParameter(p) and
    p.getFunction() = f and
    arg = recursiveCall.getAnArgument() and
    (
      // f(depth + 1) or f(1 + depth)
      exists(AddExpr ae |
        ae = arg and
        ae.getAnOperand().(VariableAccess).getTarget() = p
      )
      or
      // f(depth++) or f(++depth)
      exists(IncrementOperation co |
        co = arg and
        co.getOperand().(VariableAccess).getTarget() = p
      )
    )
  )
}

/**
 * Any form of recursion depth protection.
 */
predicate hasRecursionProtection(Function f, FunctionCall recursiveCall) {
  hasDepthGuard(f) or
  incrementsDepthCounter(f) or
  passesIncrementedDepth(f, recursiveCall)
}

// =============================================================================
// Direct recursion: f() calls f()
// =============================================================================

predicate isDirectRecursion(Function f, FunctionCall call) {
  call.getTarget() = f and
  call.getEnclosingFunction() = f
}

// =============================================================================
// Mutual recursion: f() → g() → f() (2-step cycle)
// =============================================================================

predicate isMutualRecursion(Function f, Function g, FunctionCall callToG) {
  callToG.getTarget() = g and
  callToG.getEnclosingFunction() = f and
  f != g and
  // g calls back to f
  exists(FunctionCall callBackToF |
    callBackToF.getTarget() = f and
    callBackToF.getEnclosingFunction() = g
  )
}

// =============================================================================
// Filter: only flag functions likely involved in input processing
// =============================================================================

/**
 * Function name suggests it processes input (parsing, evaluation, traversal).
 * Avoids flagging recursive utility functions like tree walkers with natural limits.
 */
predicate isInputProcessor(Function f) {
  exists(string n | n = f.getName().toLowerCase() |
    n.regexpMatch(".*(pars|read|load|decode|expand|eval|process|handle|resolve|walk|travers|visit|scan|validate|catalog|schema|xpath|xpointer|xinclude|entity|dtd|element|content|attribute|node|namespace|relax).*")
  )
  or
  // Fallback: function takes a parser context or input stream
  exists(Parameter p | p.getFunction() = f |
    exists(string tn | tn = p.getType().getUnspecifiedType().toString().toLowerCase() |
      tn.regexpMatch(".*(ctxt|context|parser|input|reader|stream|handler).*")
    )
  )
}

from Function f, FunctionCall recursiveCall, string recursionType
where
  (
    // Direct recursion
    isDirectRecursion(f, recursiveCall) and
    recursionType = "direct"
    or
    // Mutual recursion (report on the first function in the cycle)
    exists(Function g |
      isMutualRecursion(f, g, recursiveCall) and
      recursionType = "mutual (via " + g.getName() + ")"
    )
  ) and
  // No depth protection found
  not hasRecursionProtection(f, recursiveCall) and
  // Only flag input-processing functions
  isInputProcessor(f) and
  // Exclude test files
  not f.getFile().getRelativePath().regexpMatch("(?i).*(test|bench|example|fuzz).*")
select recursiveCall,
  "Potential uncontrolled recursion (" + recursionType + "): '" + f.getName() +
  "()' calls itself without a visible depth guard. Crafted input may cause stack overflow."
