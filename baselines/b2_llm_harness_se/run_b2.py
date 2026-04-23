#!/usr/bin/env python3
"""B2: Project-Level LLM Harness + KLEE (No Static Analysis).

Gives the LLM the project's public API surface and asks it to generate
KLEE harnesses for the whole library. No specs, no per-vulnerability
targeting, no SA context.

Pipeline:
  1. Discover API surface — scan for public headers (.h), extract function
     prototypes, read key source files. Cap at ~60K chars for LLM context.
  2. Multi-round harness generation — 2-3 LLM calls:
     - Round 1: "Write KLEE harnesses for these main API functions"
     - Round 2+: "Write harnesses for secondary APIs (exclude already covered)"
     - Each round returns JSON with harnesses list.
  3. Compile & run KLEE — for each generated harness, use shared
     compile_harness_to_bitcode() + run_klee().
  4. Aggregate — parse crashes, dedup by (BugFile, BugLine, BugType),
     write summary.tsv.

Usage:
    python3 baselines/b2_llm_harness_se/run_b2.py \
        --project libtiff_f324415_vul \
        --dataset-root dataset/f324415/libtiff_f324415_vul \
        --output-dir se_runs/b2/libtiff_f324415_vul \
        --klee-timeout 300 \
        --num-rounds 3 \
        --jobs 4
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from baseline_utils import (
    call_llm,
    compile_harness_to_bitcode,
    dedup_bugs,
    find_source_files,
    get_token_counts,
    reset_token_counts,
    run_klee,
    write_bug_report,
    write_summary_tsv,
)

# ── Constants ───────────────────────────────────────────────────────

# Maximum chars of API surface context to send to LLM per round
_MAX_CONTEXT_CHARS = 60000

# Vulnerability types we target (same as SAILOR)
TARGET_VULNERABILITY_TYPES = """\
The vulnerability types we are searching for are:
- Buffer Overflow / Out-of-bounds Write (CWE-120, CWE-121, CWE-122, CWE-787)
- Out-of-bounds Read (CWE-125)
- Use-After-Free (CWE-416)
- Double Free (CWE-415)
- NULL Pointer Dereference (CWE-476)
- Integer Overflow/Underflow (CWE-190, CWE-191)
- Divide by Zero (CWE-369)
- Use of Out-of-range Pointer Offset (CWE-823)
- Write-what-where Condition (CWE-123)
"""

# ── Prompts ─────────────────────────────────────────────────────────

HARNESS_GEN_SYSTEM = """\
You are an expert C security engineer specializing in symbolic execution \
with KLEE. Your task is to generate multiple KLEE harnesses that exercise \
a C library's API to discover memory safety vulnerabilities.

""" + TARGET_VULNERABILITY_TYPES + """
For each harness, produce THREE files:

1. **harness.c**: Contains the target function(s) and required type \
definitions, extracted/adapted from the library source. Include only the \
code needed to reach the target location. Re-declare structs, typedefs, \
enums, and function signatures as needed to make the harness self-contained.

2. **driver.c**: Contains `main()` that:
   - Uses `klee_make_symbolic()` to create symbolic inputs
   - Calls the target function with those inputs
   - Include: `#include <klee/klee.h>` and `#include "harness.c"`

3. **stubs.c**: Contains stub implementations for any external functions \
called by the target that are NOT part of the standard C library. Each \
stub should provide a minimal valid implementation (return 0/NULL, \
allocate minimal buffers, etc.) that allows KLEE to explore paths. \
If no stubs are needed, return an empty file with just a comment.

IMPORTANT RULES:
- Do NOT include any library headers that won't be available during \
compilation (e.g., <tiffio.h>, <png.h>, <libxml/parser.h>). Re-declare \
everything needed from scratch.
- Use `#include <klee/klee.h>` only in driver.c
- Use standard headers: <stdlib.h>, <string.h>, <stdint.h>, <stdio.h>
- All three files will be compiled to LLVM bitcode and linked together
- driver.c includes harness.c via `#include "harness.c"`
- stubs.c is compiled separately and linked at the bitcode level
- Focus on making the harness COMPILABLE and the target REACHABLE
- Each harness should target a DIFFERENT function or code path
- Aim for bugs that a symbolic executor can find: buffer overflows, \
use-after-free, null dereferences, integer overflows

Respond with a JSON object:
{
  "harnesses": [
    {
      "name": "short_descriptive_name",
      "target_function": "function_being_tested",
      "harness_c": "// harness.c content",
      "driver_c": "// driver.c content",
      "stubs_c": "// stubs.c content (or just a comment if none needed)",
      "reasoning": "brief explanation of what bug this might find"
    }
  ]
}"""


# ── API Surface Discovery ──────────────────────────────────────────

def _extract_prototypes(header_text: str) -> List[str]:
    """Extract function prototypes from header file text."""
    # Match function declarations (not definitions — no opening brace)
    proto_re = re.compile(
        r"^[A-Za-z_][\w\s*]+\s+\**\s*(\w+)\s*\([^)]*\)\s*;",
        re.MULTILINE,
    )
    protos = []
    for m in proto_re.finditer(header_text):
        name = m.group(1)
        # Skip internal/private names
        if name.startswith("_") and not name.startswith("__"):
            continue
        protos.append(m.group(0).strip())
    return protos


def discover_api_surface(dataset_root: Path) -> Tuple[str, List[str]]:
    """Discover the project's public API surface from headers and source.

    Returns (context_text, list_of_function_names) where context_text is
    suitable for sending to the LLM (capped at _MAX_CONTEXT_CHARS).
    """
    # Find public headers
    headers = sorted(dataset_root.rglob("*.h"))
    # Prefer top-level and include/ headers
    public_headers = []
    internal_headers = []
    for h in headers:
        rel = h.relative_to(dataset_root)
        parts = set(rel.parts)
        if parts & {"test", "tests", "tools", ".git", "build", "doc", "docs"}:
            continue
        if "include" in rel.parts or len(rel.parts) <= 2:
            public_headers.append(h)
        else:
            internal_headers.append(h)

    # Collect prototypes and header content
    all_protos = []
    header_contents = []
    seen_functions = set()

    for h in public_headers[:20]:
        try:
            text = h.read_text(errors="replace")
        except Exception:
            continue
        rel = str(h.relative_to(dataset_root))
        protos = _extract_prototypes(text)
        new_protos = [p for p in protos
                      if p.split("(")[0].split()[-1].strip("* ") not in seen_functions]
        for p in new_protos:
            fname = p.split("(")[0].split()[-1].strip("* ")
            seen_functions.add(fname)
        all_protos.extend(new_protos)
        header_contents.append(f"// --- {rel} ---\n{text}")

    # Also read key source files for type definitions and implementations
    src_files = find_source_files(dataset_root, extensions=(".c",))
    src_contents = []
    for sf in src_files[:15]:
        try:
            text = sf.read_text(errors="replace")
        except Exception:
            continue
        rel = str(sf.relative_to(dataset_root))
        # Only include first 200 lines to save context
        lines = text.splitlines()[:200]
        src_contents.append(f"// --- {rel} (first 200 lines) ---\n" + "\n".join(lines))

    # Build context text
    context_parts = []

    if all_protos:
        context_parts.append("## Public API Functions\n\n```c\n"
                             + "\n".join(all_protos[:150])
                             + "\n```\n")

    # Add header content up to budget
    remaining = _MAX_CONTEXT_CHARS - sum(len(p) for p in context_parts)
    if remaining > 5000:
        hdr_text = "\n\n".join(header_contents)
        if len(hdr_text) > remaining // 2:
            hdr_text = hdr_text[: remaining // 2]
        context_parts.append(f"## Header Files\n\n```c\n{hdr_text}\n```\n")

    remaining = _MAX_CONTEXT_CHARS - sum(len(p) for p in context_parts)
    if remaining > 5000:
        src_text = "\n\n".join(src_contents)
        if len(src_text) > remaining:
            src_text = src_text[:remaining]
        context_parts.append(f"## Source Files (excerpts)\n\n```c\n{src_text}\n```\n")

    context = "\n".join(context_parts)
    func_names = list(seen_functions)
    return context, func_names


# ── Harness Generation ─────────────────────────────────────────────

def generate_harnesses_round(
    api_context: str,
    round_num: int,
    covered_functions: List[str],
    project_name: str,
    log_dir: Path,
) -> List[dict]:
    """Run one round of LLM harness generation.

    Returns list of harness dicts with keys:
    name, target_function, harness_c, driver_c, stubs_c, reasoning.
    """
    if round_num == 1:
        user_msg = (
            f"## Library: {project_name}\n\n"
            f"Below is the public API surface of this C library. "
            f"Generate KLEE harnesses for the **main API functions** — "
            f"focus on functions that handle external input, allocate memory, "
            f"parse data, or perform buffer operations.\n\n"
            f"Generate as many harnesses as you can (aim for 5-15), "
            f"each targeting a different function or code path.\n\n"
            f"{api_context}"
        )
    else:
        covered_str = ", ".join(covered_functions[:50]) if covered_functions else "none"
        user_msg = (
            f"## Library: {project_name}\n\n"
            f"Generate KLEE harnesses for **secondary API functions** that were "
            f"NOT covered in previous rounds.\n\n"
            f"**Already covered** (do NOT repeat): {covered_str}\n\n"
            f"Focus on lesser-used functions, error handling paths, "
            f"cleanup/destruction routines, and edge cases.\n\n"
            f"Generate as many harnesses as you can (aim for 5-15), "
            f"each targeting a different function or code path.\n\n"
            f"{api_context}"
        )

    messages = [{"role": "user", "content": user_msg}]
    # B2 needs large output: 5-15 harnesses × 3 files each.
    # For reasoning models (o1/o3/gpt-5), max_completion_tokens includes
    # internal reasoning tokens, so we need a much higher limit.
    result = call_llm(
        HARNESS_GEN_SYSTEM,
        messages,
        tag=f"harness_gen_round{round_num}",
        log_dir=log_dir,
        max_tokens_override=65536,
    )

    if "error" in result:
        print(f"  [!] LLM error in round {round_num}: {result['error']}")
        return []

    harnesses = result.get("harnesses", [])

    # Fallback: try parsing from raw_text
    if not harnesses and "raw_text" in result:
        raw = result["raw_text"]
        # Try to find JSON array in the raw text
        try:
            m = re.search(r'"harnesses"\s*:\s*\[', raw)
            if m:
                # Find matching bracket
                start = m.start()
                brace_start = raw.rfind("{", 0, start)
                if brace_start >= 0:
                    parsed = json.loads(raw[brace_start:])
                    harnesses = parsed.get("harnesses", [])
        except Exception:
            pass

    return harnesses


# ── Per-Harness Pipeline ──────────────────────────────────────────

def process_harness(
    harness: dict,
    harness_idx: int,
    dataset_root: Path,
    output_dir: Path,
    project_bc: Optional[Path],
    klee_timeout: int,
) -> List[dict]:
    """Compile and run KLEE on a single generated harness.

    Returns a list of result dicts (one per crash, or one for no-crash/error).
    """
    name = harness.get("name", f"harness_{harness_idx:03d}")
    target_func = harness.get("target_function", "unknown")
    harness_c = harness.get("harness_c", "")
    driver_c = harness.get("driver_c", "")
    stubs_c = harness.get("stubs_c", "// No stubs needed\n")

    if not harness_c or not driver_c:
        return [{
            "Spec": name,
            "FinalStatus": "LLM_ERROR",
            "Verdict": "FP",
            "BugType": "",
            "BugFile": "",
            "BugLine": 0,
            "BugFunc": target_func,
            "CWE": "",
            "Time": 0,
            "Tokens": 0,
            "UniqueBugID": "",
            "IsDuplicate": "",
        }]

    finding_dir = output_dir / "findings" / name
    harness_dir = finding_dir / "harness"
    harness_dir.mkdir(parents=True, exist_ok=True)

    # Write harness files
    (harness_dir / "harness.c").write_text(harness_c, encoding="utf-8")
    (harness_dir / "driver.c").write_text(driver_c, encoding="utf-8")
    (harness_dir / "stubs.c").write_text(stubs_c, encoding="utf-8")

    start_time = time.time()

    # Compile to bitcode
    ok, combined_bc, err_msg = compile_harness_to_bitcode(
        harness_dir, dataset_root, project_bc=project_bc
    )

    if not ok:
        (finding_dir / "compile_error.txt").write_text(err_msg, encoding="utf-8")
        return [{
            "Spec": name,
            "FinalStatus": "BUILD_ERROR",
            "Verdict": "FP",
            "BugType": "",
            "BugFile": "",
            "BugLine": 0,
            "BugFunc": target_func,
            "CWE": "",
            "Time": int(time.time() - start_time),
            "Tokens": 0,
            "UniqueBugID": "",
            "IsDuplicate": "",
        }]

    # Run KLEE
    klee_stats = run_klee(combined_bc, finding_dir, timeout=klee_timeout)

    # Save KLEE stats
    (finding_dir / "klee_stats.json").write_text(
        json.dumps(
            {k: v for k, v in klee_stats.items() if k != "crashes"},
            indent=2, default=str,
        ),
        encoding="utf-8",
    )

    klee_time = int(klee_stats["elapsed"])

    # Classify crashes
    real_crashes = [
        c for c in klee_stats["crashes"]
        if not c["is_harness_crash"]
    ]

    if not real_crashes:
        harness_crashes = [c for c in klee_stats["crashes"] if c["is_harness_crash"]]
        if harness_crashes:
            hc = harness_crashes[0]
            return [{
                "Spec": name,
                "FinalStatus": "HARNESS_ARTIFACT",
                "Verdict": "HARNESS_ARTIFACT",
                "BugType": hc["crash_type"],
                "BugFile": hc["crash_basename"],
                "BugLine": hc["crash_line"],
                "BugFunc": target_func,
                "CWE": "",
                "Time": klee_time,
                "Tokens": 0,
                "UniqueBugID": "",
                "IsDuplicate": "",
            }]
        return [{
            "Spec": name,
            "FinalStatus": "NO_BUG",
            "Verdict": "FP",
            "BugType": "",
            "BugFile": "",
            "BugLine": 0,
            "BugFunc": target_func,
            "CWE": "",
            "Time": klee_time,
            "Tokens": 0,
            "UniqueBugID": "",
            "IsDuplicate": "",
        }]

    # Return one result per real crash
    results = []
    for c_idx, crash in enumerate(real_crashes):
        spec_name = f"{name}_crash{c_idx}" if c_idx > 0 else name
        results.append({
            "Spec": spec_name,
            "FinalStatus": "SE_DETECTED",
            "Verdict": "TP",
            "BugType": crash["crash_type"],
            "BugFile": crash["crash_basename"],
            "BugLine": crash["crash_line"],
            "BugFunc": target_func,
            "CWE": "",
            "Time": klee_time,
            "Tokens": 0,
            "UniqueBugID": "",
            "IsDuplicate": "",
        })

    return results


# ── Main Pipeline ─────────────────────────────────────────────────

def run_b2(args):
    dataset_root = Path(args.dataset_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    num_rounds = args.num_rounds
    klee_timeout = args.klee_timeout

    print(f"[B2] Project:     {args.project}")
    print(f"[B2] Dataset:     {dataset_root}")
    print(f"[B2] Output:      {output_dir}")
    print(f"[B2] Rounds:      {num_rounds}")
    print(f"[B2] KLEE timeout: {klee_timeout}s")

    total_start = time.time()
    reset_token_counts()

    # Find project.bc if available
    project_bc = None
    for p in [dataset_root / "project.bc", dataset_root / "build" / "project.bc"]:
        if p.exists():
            project_bc = p
            break
    if project_bc:
        print(f"[B2] Project BC:  {project_bc}")

    # 1. Discover API surface
    print(f"\n[B2] Discovering API surface...")
    api_context, func_names = discover_api_surface(dataset_root)
    print(f"[B2] Found {len(func_names)} public functions, "
          f"{len(api_context):,} chars of context")

    if not api_context:
        write_summary_tsv(output_dir / "summary.tsv", [])
        print("[B2] No API surface discovered. Done.")
        return

    # 2. Multi-round harness generation
    all_harnesses = []
    covered_functions = []
    log_dir = output_dir / "llm_logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    for rnd in range(1, num_rounds + 1):
        print(f"\n[B2] ── Round {rnd}/{num_rounds} ──")
        harnesses = generate_harnesses_round(
            api_context, rnd, covered_functions, args.project, log_dir
        )
        print(f"[B2] Round {rnd}: {len(harnesses)} harnesses generated")

        for h in harnesses:
            tf = h.get("target_function", "")
            if tf:
                covered_functions.append(tf)
        all_harnesses.extend(harnesses)

        # Save round results
        (log_dir / f"round{rnd}_harnesses.json").write_text(
            json.dumps(harnesses, indent=2, default=str), encoding="utf-8"
        )

    print(f"\n[B2] Total harnesses across {num_rounds} rounds: {len(all_harnesses)}")

    if not all_harnesses:
        write_summary_tsv(output_dir / "summary.tsv", [])
        print("[B2] No harnesses generated. Done.")
        return

    # 3. Compile & run KLEE for each harness
    all_results = []
    for h_idx, harness in enumerate(all_harnesses):
        h_name = harness.get("name", f"harness_{h_idx:03d}")
        h_func = harness.get("target_function", "unknown")
        print(f"\n[B2] [{h_idx+1}/{len(all_harnesses)}] {h_name} → {h_func}")

        results = process_harness(
            harness, h_idx, dataset_root, output_dir,
            project_bc, klee_timeout
        )
        all_results.extend(results)

        for r in results:
            status = r["FinalStatus"]
            print(f"  [{status}] {r['BugType']} "
                  f"at {r['BugFile']}:{r['BugLine']}")

    total_elapsed = time.time() - total_start
    tokens = get_token_counts()

    # 4. Deduplicate confirmed bugs
    se_detected = [r for r in all_results if r["FinalStatus"] == "SE_DETECTED"]
    if se_detected:
        bugs_for_dedup = [
            {
                "bug_file": r["BugFile"],
                "bug_line": r["BugLine"],
                "bug_type": r["BugType"],
                **r,
            }
            for r in se_detected
        ]
        unique_bugs, n_dups = dedup_bugs(bugs_for_dedup)
        unique_ids = {b["Spec"]: b["UniqueBugID"] for b in unique_bugs}
        for r in all_results:
            if r["FinalStatus"] == "SE_DETECTED":
                uid = unique_ids.get(r["Spec"], "")
                r["UniqueBugID"] = uid
                r["IsDuplicate"] = "" if uid else "true"
    else:
        unique_bugs = []
        n_dups = 0

    # Update token counts
    per_harness_tokens = tokens["total"] // max(len(all_harnesses), 1)
    for r in all_results:
        r["Tokens"] = per_harness_tokens

    # 5. Write summary
    write_summary_tsv(output_dir / "summary.tsv", all_results)

    (output_dir / "token_stats.json").write_text(
        json.dumps(tokens, indent=2), encoding="utf-8"
    )

    # 6. Print report
    n_build_err = sum(1 for r in all_results if r["FinalStatus"] == "BUILD_ERROR")
    n_harness_art = sum(1 for r in all_results if r["FinalStatus"] == "HARNESS_ARTIFACT")
    n_no_bug = sum(1 for r in all_results if r["FinalStatus"] == "NO_BUG")
    n_llm_err = sum(1 for r in all_results if r["FinalStatus"] == "LLM_ERROR")

    print(f"\n[B2] ═══ Summary ═══")
    print(f"  Harnesses generated: {len(all_harnesses)}")
    print(f"  SE_DETECTED:         {len(se_detected)}")
    print(f"  Unique bugs:         {len(unique_bugs)}")
    print(f"  Duplicates:          {n_dups}")
    print(f"  Build errors:        {n_build_err}")
    print(f"  Harness artifacts:   {n_harness_art}")
    print(f"  No bug / FP:         {n_no_bug}")
    print(f"  LLM errors:          {n_llm_err}")
    print(f"  LLM tokens:          {tokens['total']:,}")
    print(f"  Wall-clock time:     {total_elapsed:.1f}s")
    print(f"  Results:             {output_dir / 'summary.tsv'}")


def main():
    parser = argparse.ArgumentParser(
        description="B2: Project-Level LLM Harness + KLEE (No SA)"
    )
    parser.add_argument("--project", required=True)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--num-rounds", type=int, default=3,
                        help="Number of LLM generation rounds (default: 3)")
    parser.add_argument("--klee-timeout", type=int, default=300,
                        help="KLEE timeout per harness in seconds (default: 300)")
    parser.add_argument("--jobs", type=int, default=4,
                        help="Parallel KLEE jobs (default: 4)")
    args = parser.parse_args()

    run_b2(args)


if __name__ == "__main__":
    main()
