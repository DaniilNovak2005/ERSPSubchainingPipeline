# Manual Replay — Instructions

Replays SAILOR-detected bugs against an ASan-instrumented build of
libxml2 v2.9.4-rc2 (commit `8effcb57`) to confirm whether each finding
triggers a real memory-safety violation.

## Prerequisites

- `gcc` with AddressSanitizer support (GCC 4.8+)
- `make`, `autoconf`
- `libz-dev` (zlib headers)
- `rsync`, `git`

```bash
sudo apt install build-essential autoconf libz-dev rsync git
```

---

## Step 1 — Build the ASan library

Run once. Populates `asan_build/` with a fully instrumented `libxml2.a`.

```bash
./install_asan_build.sh
```

**What it does:**
1. Copies the libxml2 source from `../dataset/8effcb57/libxml2_8effcb57_vul/`
   (or clones from GitHub if the dataset is absent)
2. Runs `./configure` with `-fsanitize=address -g -O1`
3. Runs `make` — produces `asan_build/.libs/libxml2.a`

The script is idempotent — re-running it skips completed steps.

---

## Step 2 — Run a single spec

```bash
./replay_spec.sh <spec_number>
```

Example:
```bash
./replay_spec.sh 529    # parserInternals.c xmlCurrentChar OOB read
./replay_spec.sh 982    # tree.c xmlBufferAddHead OOB write
./replay_spec.sh 1543   # HTMLtree.c use-after-free
```

**What it does:**
1. Finds `specs/<number>_*/replay_driver.c`
2. Compiles it against `asan_build/.libs/libxml2.a` with ASan flags
3. Runs the binary and prints the full ASan output

If a spec number matches multiple directories, you are prompted to pick one.

Output files written to `specs/<spec_name>/`:
- `replay_driver` — compiled binary
- `asan_output.txt` — full runtime output
- `compile.log` — compiler output (on failure)

---

## Step 3 — Run all specs

Two options depending on what you want to run:

**Pipeline-generated drivers** (reads `se_runs/` summary, compiles all `LIKELY_TP` specs):
```bash
./batch_replay.sh
```

**Manually written drivers** (the hand-crafted drivers in `specs/`):
```bash
./run_manual_replays.sh
```

Both scripts print a summary at the end:
```
ASan crashes:      N   ← confirmed true positives
No crash:          N   ← driver ran clean
Compile failures:  N   ← driver didn't compile
```

---

## Understanding the output

A confirmed bug looks like:

```
[Run] ... CRASH (ASan confirmed)

=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 1 at 0x... thread T0
    #0 xmlCurrentChar parserInternals.c:620
    #1 ...
```

A spec without an ASan crash (`no crash`) means the concrete input in
the driver does not trigger the violation — the spec may still be a real
bug but needs a better driver.

---

## File layout

```
manual_replay/
├── install_asan_build.sh   ← Step 1: build the ASan library
├── replay_spec.sh          ← Step 2: compile + run one spec
├── batch_replay.sh         ← Step 3a: run all pipeline specs
├── run_manual_replays.sh   ← Step 3b: run hand-written drivers
├── asan_build/             ← ASan-instrumented libxml2 source + build
│   └── .libs/libxml2.a     ← the library all drivers link against
├── klee_compat.h           ← stubs for KLEE intrinsics (used at compile time)
└── specs/                  ← one directory per spec
    └── <spec_name>/
        ├── replay_driver.c     ← concrete C driver
        ├── replay_driver       ← compiled binary (after running)
        ├── harness_types.h     ← minimal struct stubs (if needed)
        ├── asan_output.txt     ← runtime output
        ├── compile.log         ← compiler log
        └── bug_report.json     ← verdict + ASan confirmation flag
```
