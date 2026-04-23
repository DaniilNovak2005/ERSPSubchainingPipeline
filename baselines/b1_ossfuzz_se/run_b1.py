#!/usr/bin/env python3
"""B1: OSS-Fuzz Manual Harness + KLEE Symbolic Execution.

Adapts existing OSS-Fuzz harnesses for KLEE by converting
LLVMFuzzerTestOneInput to a symbolic main().

Pipeline:
  1. Locate OSS-Fuzz harnesses in the project source tree
  2. Convert each harness to KLEE-compatible C driver
  3. Compile harness + project to LLVM bitcode
  4. Run KLEE with same flags as SAILOR
  5. Parse crashes, run ASan replay
  6. Output SAILOR-compatible summary.tsv

Usage:
    python3 baselines/b1_ossfuzz_se/run_b1.py \
        --project libtiff_f324415_vul \
        --dataset-root dataset/f324415/libtiff_f324415_vul \
        --output-dir se_runs/b1/libtiff_f324415_vul
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Add common utilities
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from baseline_utils import (
    run_cmd,
    run_with_asan,
    dedup_bugs,
    write_summary_tsv,
    write_bug_report,
    SUMMARY_HEADER,
)

# Add sailor_engine for asan_utils
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "sailor_engine"))
from asan_utils import parse_asan_frames, is_harness_crash

# ── OSS-Fuzz Harness Discovery ───────────────────────────────────────

OSSFUZZ_HARNESS_PATTERNS = [
    "**/oss-fuzz/**/*.c",
    "**/oss-fuzz/**/*.cc",
    "**/fuzz/*.c",
    "**/fuzz/**/*.c",
    "**/fuzz/*.cc",
    "**/fuzz/**/*.cc",
    "**/tools/target_*_fuzzer.c",
    "**/curl-fuzzer/*.c",
    "**/curl-fuzzer/*.cc",
    "**/contrib/oss-fuzz/*.c",
    "**/contrib/oss-fuzz/*.cc",
]

# Entry point signatures used by OSS-Fuzz harnesses across projects.
# Some projects (e.g. OpenSSL) use a project-local wrapper name like
# FuzzerTestOneInput that is bridged to LLVMFuzzerTestOneInput by a
# separate driver file.
FUZZER_ENTRY_SIGNATURES = [
    "LLVMFuzzerTestOneInput",
    "FuzzerTestOneInput",
]

# Files that are just the libFuzzer<->project bridge (not actual harnesses)
BRIDGE_DRIVER_NAMES = {
    "driver.c", "driver.cc",
    "standalone_fuzz_target_runner.cc",  # curl-fuzzer standalone runner
    "fuzz.c",       # libxml2 fuzz support library (not a harness)
    "genSeed.c",    # libxml2 seed generator (not a harness)
}


def discover_harnesses(dataset_root: Path) -> list[dict]:
    """Find OSS-Fuzz harness files in the project source tree."""
    harnesses = []
    seen = set()

    for pattern in OSSFUZZ_HARNESS_PATTERNS:
        for f in dataset_root.glob(pattern):
            if f.name.startswith(".") or f.name in seen:
                continue
            # Skip bridge driver files (e.g. openssl/fuzz/driver.c)
            if f.name in BRIDGE_DRIVER_NAMES:
                continue
            try:
                content = f.read_text(errors="replace")
            except Exception:
                continue
            if any(sig in content for sig in FUZZER_ENTRY_SIGNATURES):
                seen.add(f.name)
                harnesses.append({
                    "path": f,
                    "name": f.stem,
                    "is_cpp": f.suffix in (".cc", ".cpp", ".cxx"),
                    "content": content,
                })
    return harnesses


# ── Harness Conversion ───────────────────────────────────────────────

KLEE_DRIVER_TEMPLATE = """\
/*
 * B1 Baseline: KLEE driver converted from OSS-Fuzz harness.
 * Original: {original_path}
 */
#include <klee/klee.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define B1_MAX_INPUT_SIZE {max_input_size}

/* Forward declaration of the fuzz target */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(void) {{
    uint8_t data[B1_MAX_INPUT_SIZE];
    int size_sym;

    klee_make_symbolic(data, sizeof(data), "fuzz_data");
    klee_make_symbolic(&size_sym, sizeof(size_sym), "fuzz_size");
    klee_assume(size_sym >= 0);
    klee_assume(size_sym <= B1_MAX_INPUT_SIZE);

    size_t size = (size_t)size_sym;
    LLVMFuzzerTestOneInput(data, size);

    return 0;
}}
"""


def prepare_harness(harness: dict, output_dir: Path) -> Path:
    """Copy original OSS-Fuzz harness and write KLEE symbolic driver.

    The harness source is kept in its original language (C or C++) and
    compiled to LLVM bitcode using the appropriate compiler (clang or
    clang++).  No source-level C++ → C conversion is attempted — KLEE
    operates on bitcode, so source language doesn't matter.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Copy harness as-is (preserving original language)
    harness_src = output_dir / harness["path"].name
    shutil.copy2(harness["path"], harness_src)

    # Write the KLEE symbolic driver (always C)
    driver_c = output_dir / "klee_driver.c"
    driver_c.write_text(
        KLEE_DRIVER_TEMPLATE.format(
            original_path=harness["path"],
            max_input_size=4096,
        ),
        encoding="utf-8",
    )

    return output_dir


def _cpp_to_c(cpp_content: str) -> str:
    """Best-effort conversion of C++ OSS-Fuzz harness to C.

    Handles common patterns:
    - std::istringstream → memory-based I/O
    - C++ headers → C equivalents
    - extern "C" → remove wrapper
    - Templates → remove
    """
    c = cpp_content

    # Remove C++ headers
    c = re.sub(r'#include\s*<(cstdint|cstdlib|cstring|cstdio)>', lambda m: {
        "cstdint": "#include <stdint.h>",
        "cstdlib": "#include <stdlib.h>",
        "cstring": "#include <string.h>",
        "cstdio": "#include <stdio.h>",
    }.get(m.group(1), ""), c)

    # Remove stream-related includes
    c = re.sub(r'#include\s*<(sstream|iostream|fstream)>\n?', '', c)
    c = re.sub(r'#include\s*<tiffio\.hxx>\n?', '', c)

    # Remove extern "C" wrappers (keep the content)
    c = re.sub(r'extern\s+"C"\s*\{', '', c)

    # Remove template functions (standalone section)
    c = re.sub(r'template\s*<[^>]*>\s*static\s+void\s+\w+\([^)]*\)\s*\{[^}]*\}', '', c)

    # Remove C++ casts
    c = re.sub(r'static_cast<([^>]+)>\s*\(([^)]+)\)', r'(\1)(\2)', c)

    # Replace std::string construction
    c = re.sub(
        r'std::string\s*\(\s*Data\s*,\s*Data\s*\+\s*Size\s*\)',
        '(const char *)Data',
        c,
    )

    # Replace istringstream pattern with TIFFClientOpen / memory approach
    # This is libtiff-specific: TIFFStreamOpen → TIFFClientOpen with memory
    c = re.sub(
        r'std::istringstream\s+\w+\([^)]*\);\s*'
        r'TIFF\s*\*\s*(\w+)\s*=\s*TIFFStreamOpen\([^)]*\);',
        _libtiff_mem_open_replacement(),
        c,
    )

    # Remove #ifdef STANDALONE section entirely
    standalone_start = c.find("#ifdef STANDALONE")
    if standalone_start != -1:
        c = c[:standalone_start]

    # Remove nullptr → NULL
    c = c.replace("nullptr", "NULL")

    # Remove CPL_IGNORE_RET_VAL references
    c = re.sub(r'CPL_IGNORE_RET_VAL\(([^)]+)\)', r'\1', c)

    return c


def _libtiff_mem_open_replacement() -> str:
    """Generate a C replacement for TIFFStreamOpen using TIFFClientOpen."""
    return """\
/* B1: Memory-based TIFF open (replaces TIFFStreamOpen) */
    typedef struct {
        const uint8_t *data;
        size_t size;
        size_t offset;
    } MemBuf;
    static MemBuf membuf;
    membuf.data = Data;
    membuf.size = Size;
    membuf.offset = 0;
    TIFF *tif = TIFFClientOpen("MemTIFF", "r",
        (thandle_t)&membuf,
        _b1_mem_read, _b1_mem_write, _b1_mem_seek,
        _b1_mem_close, _b1_mem_size, NULL, NULL);"""


# ── KLEE Compilation & Execution ─────────────────────────────────────

def find_llvm14(name: str) -> str:
    """Find LLVM-14 tool binary."""
    for p in [f"/usr/lib/llvm-14/bin/{name}", f"{name}-14", name]:
        if shutil.which(p):
            return p
    return name


def compile_to_bitcode(
    harness_dir: Path,
    project_bc: Path,
    dataset_root: Path,
    extra_cflags: list[str] = None,
) -> tuple[bool, Path, str]:
    """Compile harness + project into a single LLVM bitcode file.

    Handles both C (.c) and C++ (.cc/.cpp/.cxx) harness sources by
    selecting the appropriate compiler (clang vs clang++).
    """
    clang = find_llvm14("clang")
    clangxx = find_llvm14("clang++")
    llvm_link = find_llvm14("llvm-link")

    # Compile all source files in the harness dir to bitcode
    bc_files = []
    src_exts = {".c", ".cc", ".cpp", ".cxx"}
    src_files = sorted(
        f for f in harness_dir.iterdir()
        if f.suffix in src_exts and f.name != "klee_driver.c"
    )

    for src_file in src_files:
        is_cpp = src_file.suffix in (".cc", ".cpp", ".cxx")
        compiler = clangxx if is_cpp else clang
        bc_out = harness_dir / f"{src_file.stem}.bc"
        cmd = [
            compiler,
            "-emit-llvm",
            "-c",
            "-g",
            "-O0",
            "-w",
            "-Wno-everything",
        ]
        # Add include paths for the project
        cmd.extend(["-I", str(dataset_root)])
        for sub in ["libtiff", "include", ".", "lib", "src"]:
            inc = dataset_root / sub
            if inc.is_dir():
                cmd.extend(["-I", str(inc)])
        cmd.extend(extra_cflags or [])
        cmd.extend([str(src_file), "-o", str(bc_out)])

        rc, _, stderr, _ = run_cmd(cmd, timeout=60)
        if rc != 0:
            return False, Path(), f"Failed to compile {src_file.name}: {stderr[:500]}"
        bc_files.append(bc_out)

    # Compile the KLEE driver
    driver_bc = harness_dir / "klee_driver.bc"
    cmd = [
        clang, "-emit-llvm", "-c", "-g", "-O0", "-w",
    ]
    # Pass extra_cflags to driver too (needed for KLEE include path)
    cmd.extend(extra_cflags or [])
    cmd.extend([
        str(harness_dir / "klee_driver.c"),
        "-o", str(driver_bc),
    ])
    rc, _, stderr, _ = run_cmd(cmd, timeout=60)
    if rc != 0:
        return False, Path(), f"Failed to compile klee_driver.c: {stderr[:500]}"
    bc_files.append(driver_bc)

    # Link all bitcode: harness BCs + project.bc
    combined_bc = harness_dir / "combined.bc"
    cmd = [llvm_link] + [str(b) for b in bc_files]
    if project_bc.exists():
        cmd.append(str(project_bc))
    cmd.extend(["-o", str(combined_bc)])

    rc, _, stderr, _ = run_cmd(cmd, timeout=120)
    if rc != 0:
        return False, Path(), f"llvm-link failed: {stderr[:500]}"

    return True, combined_bc, ""


def run_klee(
    bc_path: Path,
    output_dir: Path,
    timeout: int = 300,
    klee_bin: str = "klee",
) -> dict:
    """Run KLEE on a bitcode file and parse results."""
    klee_out = output_dir / "klee_out"
    if klee_out.exists():
        shutil.rmtree(klee_out)

    cmd = [
        klee_bin,
        f"--output-dir={klee_out}",
        f"--max-time={timeout}s",
        "--optimize",
        "--search=random-path",
        "--search=dfs",
        "--only-output-states-covering-new",
        "--external-calls=all",
        "--check-overshift",
        "--max-depth=1000",
        "--max-memory=4096",
        "--libc=uclibc",
        "--posix-runtime",
        str(bc_path),
    ]

    print(f"    [KLEE] Running: timeout={timeout}s")
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
        elapsed = time.time() - start
        full_log = proc.stdout + "\n" + proc.stderr
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        full_log = "TIMEOUT"
    except Exception as e:
        elapsed = time.time() - start
        full_log = str(e)

    # Save log
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "klee.log").write_text(full_log, encoding="utf-8")

    # Parse .err files
    crashes = []
    if klee_out.exists():
        for ef in sorted(klee_out.glob("*.err")):
            content = ef.read_text(errors="replace")
            m_file = re.search(r"File:\s*(\S+)", content)
            m_line = re.search(r"Line:\s*(\d+)", content)
            stem_parts = ef.stem.split(".")
            err_type = stem_parts[-1] if len(stem_parts) > 1 else "unknown"

            crash = {
                "err_file": str(ef),
                "crash_type": err_type,
                "crash_file": m_file.group(1).strip() if m_file else "",
                "crash_line": int(m_line.group(1)) if m_line else 0,
                "ktest_file": str(ef).replace(".err", ".ktest"),
            }

            # Skip crashes in driver/stubs
            basename = os.path.basename(crash["crash_file"])
            if basename in ("klee_driver.c", "driver.c"):
                crash["is_driver_crash"] = True
            else:
                crash["is_driver_crash"] = False
            crashes.append(crash)

    # Parse KLEE stats
    stats = {
        "elapsed": elapsed,
        "total_crashes": len(crashes),
        "crashes": crashes,
    }
    for pattern, key in [
        (r"KLEE: done: total instructions = (\d+)", "total_instructions"),
        (r"KLEE: done: completed paths = (\d+)", "completed_paths"),
        (r"KLEE: done: generated tests = (\d+)", "generated_tests"),
    ]:
        m = re.search(pattern, full_log)
        if m:
            stats[key] = int(m.group(1))

    print(f"    [KLEE] Done: {elapsed:.1f}s, {len(crashes)} crashes, "
          f"{stats.get('completed_paths', 0)} paths")
    return stats


# ── Main Pipeline ────────────────────────────────────────────────────

def run_b1(args):
    dataset_root = Path(args.dataset_root)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    project_bc = dataset_root / "project.bc"
    if not project_bc.exists():
        # Try build/ subdirectory
        project_bc = dataset_root / "build" / "project.bc"

    print(f"[B1] Project:     {args.project}")
    print(f"[B1] Dataset:     {dataset_root}")
    print(f"[B1] Output:      {output_dir}")
    print(f"[B1] Project BC:  {project_bc} (exists={project_bc.exists()})")

    # 1. Discover OSS-Fuzz harnesses
    harnesses = discover_harnesses(dataset_root)
    print(f"[B1] Found {len(harnesses)} OSS-Fuzz harness(es)")
    for h in harnesses:
        print(f"  - {h['name']} ({h['path']}) [{'C++' if h['is_cpp'] else 'C'}]")

    # Write harness inventory for paper reproducibility
    inventory = []
    for h in harnesses:
        rel_path = str(h["path"].relative_to(dataset_root)) if str(h["path"]).startswith(str(dataset_root)) else str(h["path"])
        entry_sig = "LLVMFuzzerTestOneInput"
        for sig in FUZZER_ENTRY_SIGNATURES:
            if sig in h["content"]:
                entry_sig = sig
                break
        inventory.append({
            "name": h["name"],
            "path": rel_path,
            "language": "C++" if h["is_cpp"] else "C",
            "entry_point": entry_sig,
        })
    manifest_path = output_dir / "harness_inventory.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "w") as f:
        json.dump({
            "project": args.project,
            "dataset_root": str(dataset_root),
            "total_harnesses": len(harnesses),
            "harnesses": inventory,
        }, f, indent=2)
    print(f"[B1] Inventory written to {manifest_path}")

    if not harnesses:
        print("[B1] No OSS-Fuzz harnesses found. Exiting.")
        write_summary_tsv(output_dir / "summary.tsv", [])
        return

    all_results = []
    total_start = time.time()

    # 2. Process each harness
    for h_idx, harness in enumerate(harnesses):
        harness_name = harness["name"]
        harness_dir = output_dir / harness_name / "harness"
        results_dir = output_dir / harness_name

        print(f"\n[B1] === Harness {h_idx+1}/{len(harnesses)}: {harness_name} ===")

        # Prepare harness (copy source + write KLEE driver)
        try:
            prepare_harness(harness, harness_dir)
            print(f"  [+] Harness prepared in {harness_dir}")
        except Exception as e:
            print(f"  [!] Conversion failed: {e}")
            all_results.append({
                "Spec": harness_name,
                "FinalStatus": "BUILD_ERROR",
                "Verdict": "FP",
                "BugType": "",
                "BugFile": "",
                "BugLine": 0,
                "BugFunc": "",
                "CWE": "",
                "Time": 0,
                "Tokens": 0,
            })
            continue

        # Compile to bitcode
        extra_cflags = []
        if args.extra_cflags:
            extra_cflags = shlex.split(args.extra_cflags)

        ok, combined_bc, err = compile_to_bitcode(
            harness_dir, project_bc, dataset_root, extra_cflags
        )
        if not ok:
            print(f"  [!] Bitcode compilation failed: {err}")
            all_results.append({
                "Spec": harness_name,
                "FinalStatus": "BUILD_ERROR",
                "Verdict": "FP",
                "BugType": "",
                "BugFile": "",
                "BugLine": 0,
                "BugFunc": "",
                "CWE": "",
                "Time": 0,
                "Tokens": 0,
            })
            continue

        print(f"  [+] Bitcode compiled: {combined_bc}")

        # Run KLEE
        klee_results = run_klee(
            combined_bc,
            results_dir,
            timeout=args.klee_timeout,
            klee_bin=args.klee_bin,
        )

        # Process crashes
        real_crashes = [c for c in klee_results["crashes"] if not c["is_driver_crash"]]

        if not real_crashes:
            all_results.append({
                "Spec": harness_name,
                "FinalStatus": "NO_BUG",
                "Verdict": "FP",
                "BugType": "",
                "BugFile": "",
                "BugLine": 0,
                "BugFunc": "",
                "CWE": "",
                "Time": int(klee_results["elapsed"]),
                "Tokens": 0,
            })
            continue

        # Record each unique crash
        for crash in real_crashes:
            bug_type = crash["crash_type"]
            bug_file = os.path.basename(crash["crash_file"])
            bug_line = crash["crash_line"]

            status = "SE_DETECTED"
            if crash.get("is_driver_crash"):
                status = "HARNESS_ARTIFACT"

            result = {
                "Spec": f"{harness_name}_{bug_file}_{bug_line}_{bug_type}",
                "FinalStatus": status,
                "Verdict": "TP" if status == "SE_DETECTED" else "FP",
                "BugType": bug_type,
                "BugFile": bug_file,
                "BugLine": bug_line,
                "BugFunc": "",
                "CWE": "",
                "Time": int(klee_results["elapsed"]),
                "Tokens": 0,
            }
            all_results.append(result)

            # Write per-crash report
            crash_dir = results_dir / f"crash_{bug_file}_{bug_line}_{bug_type}"
            write_bug_report(crash_dir / "bug_report.json", {
                "baseline": "B1",
                "harness": harness_name,
                "crash": crash,
                "klee_stats": {k: v for k, v in klee_results.items() if k != "crashes"},
            })

    total_elapsed = time.time() - total_start

    # Deduplicate
    se_detected = [r for r in all_results if r["FinalStatus"] == "SE_DETECTED"]
    if se_detected:
        bugs_for_dedup = [
            {"bug_file": r["BugFile"], "bug_line": r["BugLine"], "bug_type": r["BugType"], **r}
            for r in se_detected
        ]
        unique_bugs, n_dups = dedup_bugs(bugs_for_dedup)
        # Update results with dedup info
        unique_ids = {b["Spec"]: b["UniqueBugID"] for b in unique_bugs}
        for r in all_results:
            r["UniqueBugID"] = unique_ids.get(r["Spec"], "")
            r["IsDuplicate"] = "" if r["Spec"] in unique_ids else "true"
    else:
        unique_bugs = []
        n_dups = 0

    # Write summary
    write_summary_tsv(output_dir / "summary.tsv", all_results)

    print(f"\n[B1] ═══ Summary ═══")
    print(f"  Harnesses processed: {len(harnesses)}")
    print(f"  Total crashes:       {sum(1 for r in all_results if r['FinalStatus'] == 'SE_DETECTED')}")
    print(f"  Unique bugs:         {len(unique_bugs)}")
    print(f"  Duplicates:          {n_dups}")
    print(f"  Build errors:        {sum(1 for r in all_results if r['FinalStatus'] == 'BUILD_ERROR')}")
    print(f"  Wall-clock time:     {total_elapsed:.1f}s")
    print(f"  Results:             {output_dir / 'summary.tsv'}")


def main():
    parser = argparse.ArgumentParser(description="B1: OSS-Fuzz Harness + KLEE SE")
    parser.add_argument("--project", required=True, help="Project slug (e.g. libtiff_f324415_vul)")
    parser.add_argument("--dataset-root", required=True, help="Project source root")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--klee-timeout", type=int, default=300, help="KLEE timeout per harness (seconds)")
    parser.add_argument("--klee-bin", default="klee", help="Path to KLEE binary")
    parser.add_argument("--extra-cflags", default="", help="Extra compiler flags")
    args = parser.parse_args()

    run_b1(args)


if __name__ == "__main__":
    main()
