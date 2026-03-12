

##  Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          AUTOMATED PIPELINE                           │
│                                                                         │
│   [Phase 0]          [Stage 1]        [Stage 2]       [Stage 3 & 4]    │
│                                                                         │
│  AI Rule Gen   ──►  CodeQL Scan  ──►  LLM Harness ──►  KLEE Prover    │
│  & Prompts          & Ingestion       Generation        & Correlation   │
│                                                                         │
│   Wendy           Sahasra              Vishva            Mahima         │
│  ──────────         ─────────         ─────────        ─────────        │
│  Intelligence    Static Analysis    LLM Harness     Symbolic Exec       │
│   Director           Scout           Architect        Specialist        │
│                                                                         │
│          ▼  Workflow/Build Pipeline Structure  ▼                        │
│                         Person 5 — Daniil                               │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Team Roles & Responsibilities

###  Sahasra
> *AI & Vulnerability Research · Phase 0*

**Task:** Drive the entire pipeline.

| Task | Deliverable |
|------|-------------|
| Prompt an LLM to write complex CodeQL queries (`.ql`) detecting WMI chains | `config/queries/` |
| Test AI-generated CodeQL rules on sample vulnerable C code | Validated `.ql` files |
| Write System Prompts (LLM Context) for the Harness | `config/prompts/` |

---

###   Wendy
> *Stage 1*

**Task:** Take CodeQL rules and unleash them on the target codebase.

| Task | Deliverable |
|------|-------------|
| Python wrapper to run `codeql database create` + `codeql database analyze` | `src/static_analysis.py` |
| Parse raw SARIF JSON output into clean `VulnerabilityFinding` objects | `src/ingestion.py` |

---

###  Vishva 
> *Stage 2*

**Task:** Bridge the gap between static analysis results and symbolic execution inputs.

| Task | Deliverable |
|------|-------------|
| Send `VulnerabilityFinding` + System Prompt to LLM API (OpenAI / Gemini) | `src/harness_gen.py` |
| Parse LLM response and extract the generated C test harness | LLM API integration |
| **Self-healing loop:** catch compile errors → feed back to LLM → auto-fix | Built-in retry logic |

---

###  Mahima 
> *Stages 3 & 4*

**Task:** Mathematically prove whether the LLM's harness actually triggers the bug.

| Task | Deliverable |
|------|-------------|
| Compile C harnesses to LLVM bitcode via `clang -emit-llvm` | Build automation |
| Run KLEE with strict timeouts + memory limits | `src/symbolic_exec.py` |
| Parse KLEE `.err` logs — mark confirmed bugs as `CONFIRMED` | `src/analysis.py` |

---

###  Daniil
> *Stage 5*

**Task:** The glue that holds every other role together. Define the contracts, run the show.

| Task | Deliverable |
|------|-------------|
| Define `VulnerabilityFinding` schema so all roles share identical data types | `src/models.py` |
| Orchestrate the end-to-end pipeline execution | `src/pipeline.py` |
| Generate final vulnerability reports | `reports/` |

---

## Project Structure

```
test-center/
├── config/
│   ├── queries/          # AI-generated CodeQL .ql rules
│   └── prompts/          # LLM system prompts / WMI context
├── src/
│   ├── models.py         # Shared data models (VulnerabilityFinding, etc.)
│   ├── static_analysis.py
│   ├── ingestion.py
│   ├── harness_gen.py
│   ├── symbolic_exec.py
│   ├── analysis.py
│   └── pipeline.py
└── reports/              # Final confirmed vulnerability output
```

---

##  Pipeline Flow

```
1. CodeQL scans target codebase using AI-generated .ql rules
        │
        ▼
2. SARIF output parsed into VulnerabilityFinding objects
        │
        ▼
3. LLM receives Finding + System Prompt → generates C test harness
        │
        ├── (compile error?) ──► Self-healing loop feeds error back to LLM
        │
        ▼
4. Harness compiled to LLVM bitcode → KLEE runs symbolic execution
        │
        ▼
5. KLEE .err logs parsed → vulnerability marked CONFIRMED or UNCONFIRMED
        │
        ▼
6. Final report generated
```

---

##  Tech Stack

| Component | Technology |
|-----------|-----------|
| Static Analysis | [CodeQL](https://codeql.github.com/) |
| LLM Integration | OpenAI / Gemini API |
| Symbolic Execution | [KLEE](https://klee-se.org/) |
| Compiler | `clang` (LLVM) |
| Language | Python 3.10+ |
| Output Format | SARIF, `.err` logs, structured reports |

---

