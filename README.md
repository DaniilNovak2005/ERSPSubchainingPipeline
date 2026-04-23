# SAILOR: Static Analysis Informed and LLM-Orchestrated Symbolic Execution

## Overview
SAILOR is a pipeline for automated vulnerability discovery in C/C++ codebases.
It combines CodeQL static analysis, LLM-guided harness synthesis, and KLEE
symbolic execution to find memory safety bugs.

## Repository Structure

```
SAILOR/
├── sailor.sh                   # Phase 2+3 entry point (LLM + KLEE + validation)
├── sailor_prepare.sh           # Phase 1 entry point (CodeQL + spec generation)
├── codeql_scan.sh              # CodeQL database creation + query runner
├── run_codeql_analysis.py      # CodeQL CLI wrapper (DB create + analyze)
├── make_vul_specs.py           # Converts CodeQL findings → vulnerability specs
├── setup_dataset.sh            # Clone all 10 projects at exact commits
├── Dockerfile                  # Docker image (KLEE 3.1, Clang 14, CodeQL)
│
├── sailor_engine/              # Core SAILOR pipeline
│   ├── scripts/
│   │   ├── run_agent_for_spec.py    # Main loop (LLM + KLEE per spec)
│   │   ├── asan_replay_batch.py     # Batch ASan replay for concrete validation
│   │   └── asan_replay.py           # Single spec ASan replay
│   ├── run_worker.sh                # Per-spec worker (build + KLEE + replay)
│   ├── run_batch.sh                 # Parallel spec orchestrator
│   ├── build_project_bc.sh          # LLVM bitcode builder
│   └── triage_specs.py              # Spec filtering and prioritization
│
├── baselines/                  # Baseline implementations
│   ├── b1_ossfuzz_se/               # B1: SE with human-written harnesses
│   ├── b2_llm_harness_se/           # B2: SE with LLM-generated harnesses
│   ├── b3_llm_detect/               # B3: LLM vulnerability detection
│   │   └── run_b3.py
│   ├── b4_sa_llm_detect/            # B4: SA-guided LLM vulnerability detection
│   │   └── run_b4.py
│   ├── b5_agentic_llm/              # B5: Agentic LLM vulnerability detection
│   │   └── run_b5.py
│   ├── a1_sailor_no_sa/             # A1: SAILOR − SA (ablation)
│   │   └── run_a1.py
│   └── common/                      # Shared utilities
│       ├── baseline_utils.py
│       └── harness_templates/       # Per-project validation harnesses
│
├── rules/                      # CodeQL rules
│   └── sailor-queries/
│       └── queries/                 # 21 custom CWE rules
│           ├── CWE-120_BufferOverflow.ql
│           ├── CWE-125_OutOfBoundsRead.ql
│           ├── CWE-416_UseAfterFree_*.ql
│           ├── CWE-787_OutOfBoundsWrite.ql
│           └── ...
│
├── scripts/                    # Validation & analysis scripts
│   ├── revalidate_against_lib.py    # Validate against project .a
│   ├── revalidate_baselines.py      # Strip-and-relink for B3/B4
│   ├── unified_validate.py          # Template-based validation
│   └── collect_token_usage.py       # LLM token tracking
│
├── configs/                    # Per-project build configs
│   ├── libtiff_f324415_vul_config.sh
│   ├── mupdf_21fb0a2b_vul_config.sh
│   └── ...
│
└── export/                     # Aggregate results (no vulnerability data)
    └── baseline_confirmed/
        ├── baseline_confirmed.csv        # Per-project comparison table
        ├── budget_breakdown.csv          # Compute/token budget per run
        └── llm_token_usage.csv           # LLM token consumption
```

## Quick Start

### Prerequisites
- Docker (for SAILOR pipeline with KLEE)
- Python 3.10+
- GCC/Clang with ASan support
- OpenAI API key (GPT-5) or DeepSeek API key
- For B5: Claude Code CLI 

### Documentation

| Document | Description |
|----------|-------------|
| [DATASET.md](DATASET.md) | Dataset setup: clone commands for all 10 projects at exact commits |
| [EXPERIMENTS.md](EXPERIMENTS.md) | Step-by-step reproduction of all experiments (SAILOR, B1--B5, A1) |
| [NEW_TARGET.md](NEW_TARGET.md) | How to run SAILOR on a new C/C++ project |

### Running SAILOR

All commands should be run from the repository root directory.
The pipeline creates the following directories automatically:

```
SAILOR/                 ← run all commands from here
├── dataset/            ← project source (created by setup_dataset.sh)
├── sa_outputs/         ← CodeQL scan results (created by Phase 1)
├── specs/              ← vulnerability specifications (created by Phase 1)
├── se_runs/            ← symbolic execution results (created by Phase 2+3)
├── rules/              ← CodeQL queries (included in repo)
└── configs/            ← project build configs (included in repo)
```

```bash
# 1. Set up environment — replace the placeholder API key in .env
#    Set LLM_API_KEY 

# 2. Clone target projects at exact commits
bash setup_dataset.sh

# 3. Build Docker image
docker build -t sailor .

# 4. Phase 1: CodeQL scan + spec generation (example: libtiff)
docker run --rm \
    -v $(pwd)/dataset:/app/dataset \
    -v $(pwd)/sa_outputs:/app/sa_outputs \
    -v $(pwd)/specs:/app/specs \
    -v $(pwd)/rules:/app/rules \
    -v $(pwd)/configs:/app/configs \
    sailor bash -c "./sailor_prepare.sh f324415/libtiff_f324415_vul"

# 5. Phase 2+3: LLM harness synthesis + KLEE + concrete validation
source .env
docker run --rm \
    -e LLM_API_KEY="$LLM_API_KEY" \
    -e LLM_API_BASE="$LLM_API_BASE" \
    -e LLM_MODEL="$LLM_MODEL" \
    -e JOBS=128 \
    -v $(pwd)/dataset:/app/dataset \
    -v $(pwd)/sa_outputs:/app/sa_outputs \
    -v $(pwd)/specs:/app/specs \
    -v $(pwd)/se_runs:/app/se_runs \
    -v $(pwd)/rules:/app/rules \
    -v $(pwd)/configs:/app/configs \
    sailor bash -c "./sailor.sh f324415/libtiff_f324415_vul"

# 6. Results
cat se_runs/sailor_engine/libtiff_f324415_vul/summary.tsv
```

### Running Baselines

B1 and B2 run inside Docker (need KLEE). See EXPERIMENTS.md for
full commands. B3--B5 run outside Docker:

```bash
source .env

# B3: Pure LLM detect
python3 baselines/b3_llm_detect/run_b3.py \
    --project libtiff_f324415_vul \
    --dataset-root dataset/f324415/libtiff_f324415_vul \
    --output-dir se_runs/b3/libtiff_f324415_vul

# B4: SA + LLM detect
python3 baselines/b4_sa_llm_detect/run_b4.py \
    --project libtiff_f324415_vul \
    --dataset-root dataset/f324415/libtiff_f324415_vul \
    --sa-outputs-dir sa_outputs/libtiff_f324415_vul \
    --output-dir se_runs/b4/libtiff_f324415_vul

# B5: Agentic (Claude Code — requires claude login)
python3 baselines/b5_agentic_llm/run_b5.py \
    --project libtiff_f324415_vul \
    --dataset-root dataset/f324415/libtiff_f324415_vul \
    --output-dir se_runs/b5/libtiff_f324415_vul \
    --upstream-libs dataset/f324415/libtiff_f324415_vul/build/libtiff.a \
    --jobs 16
```

### Concrete Validation

SAILOR's concrete validation (Phase 3) runs automatically as part
of `sailor.sh`.  For baselines (B3--B5), a separate validation
step compiles crashing inputs against the `.a`:

```bash
python3 scripts/revalidate_baselines.py \
    --baseline b3 \
    --findings-dir se_runs/b3/libtiff_f324415_vul/findings \
    --upstream-libs dataset/f324415/libtiff_f324415_vul/build/libtiff.a \
    --src-root dataset/f324415/libtiff_f324415_vul \
    --output-dir /tmp/b3_validated/libtiff \
    --jobs 16
```

## Target Projects (10)

| Project | Commit | LOC | Files |
|---------|--------|-----|-------|
| libxml2 | e334a9d | 149K | 204 |
| libtiff | f324415 | 95K | 150 |
| libpng | 747dd02 | 63K | 106 |
| binutils | b2bc71a | 1.84M | 2,662 |
| curl | 2eebc58 | 174K | 697 |
| OpenSSL | 67b5686b | 710K | 2,260 |
| FFmpeg | f46e5144 | 1.3M | 4,349 |
| SELinux | ca10fc4 | 190K | 551 |
| SQLite | 0f08d958 | 1.05M | 511 |
| mupdf | 21fb0a2b | 1.25M | 3,144 |
| **Total** | | **6.8M** | **14,634** |

## Results Summary

All baselines validated with the same strict standard: crash must occur
in the project's unmodified `.a`.

| Baseline | Unique | Confirmed | Detected |
|----------|--------|-----------|----------|
| B1: SE with human-written harnesses | 0 | 0 | 19 |
| B2: SE with LLM-generated harnesses | 0 | 0 | 86 |
| B3: LLM vulnerability detection | 5 | 6 | 1,781 |
| B4: SA-guided LLM vulnerability detection | 2 | 2 | 1,363 |
| B5: Agentic LLM vulnerability detection | 12 | 12 | 430 |
| A1: SAILOR−SA | 31 | 31 | 276 |
| **SAILOR** | **379** | **421** | **1,345** |


## Running SAILOR on a New Target

See [NEW_TARGET.md](NEW_TARGET.md) for step-by-step instructions
on applying SAILOR to any C/C++ project.

