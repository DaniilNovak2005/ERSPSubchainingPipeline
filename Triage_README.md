# Triage Step with LLM 
## Goal
Filter specs that are more likely to be part of a subchain by creating a ranking. These specs can be used or prioritized for Phase 2+3, saving further computing/LLM costs.

## Lightweight Pre-filtering Step Before LLM
Remove files from CWE's that are isolated and won't be in chains. 
Remove files that don't have evidence of being in a chain in the "facts" area of the JSON file (currently looks for pointer vars, length vars, suspect calls -> if there are none, it skips).
Remove files that aren't part of the list of trigger/sink CWEs.
Remove files that have patterns such as "test", "example", "sample", or "demo".
Build an overlap index: specs that share signals with other specs (same variable name for pointers/length, same function name, or same filename).

```
ISOLATED_CWES = {
    "369",   # divide-by-zero — no memory side-effects
    "400",   # uncontrolled resource consumption — usually terminal
    "404",   # improper resource shutdown — terminal, not a trigger
    "476",   # null deref — usually a sink, rarely a useful trigger
    "835",   # infinite loop — no downstream memory corruption
    "401",   # memory leak — DoS only, no chain potential
    "772",   # missing release — resource leak, no chain
    "252",   # unchecked return — logic error, rarely chainable
}
```

```
TRIGGER_CWES = {"119", "120", "122", "125", "190", "191", "194", "787", "126", "127", "823"}
SINK_CWES    = {"122", "125", "416", "787", "823", "824", "908", "415", "121"}
```

## LLM Step
The LLM is given ~10 lines of code around the vulnerability

## LLM Scoring Criteria
90–100  DEFINITE: Explicit shared pointer + composable CWE pair + same call chain

75–89   STRONG: Shared vars + same file + dangerous calls (memcpy, realloc, free)

50–74   MEDIUM: Same file OR shared length var, but no direct pointer aliasing

25–49   WEAK: Only weak signals (same CWE class, no shared state)

0–24    NONE: Completely isolated, self-contained, or terminal sink

**Specs that have a score below 50 are low priority, meaning we shouldn't run Phase 2 on them.**

## Goals for next week:
- test triage pipeline + tweak prompt/prefiltering based on results
