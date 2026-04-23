#!/usr/bin/env python3
"""B3: Pure LLM Vulnerability Detection.

No static analysis, no symbolic execution. The LLM:
  1. Reads source files and identifies potential memory safety vulnerabilities
  2. For each finding, outputs structured crashing inputs (entry function,
     argument values, trigger condition). Large files are chunked to fit
     within the LLM's context window.
  3. The infrastructure compiles a replay driver against the project .a
     and validates with ASan
  4. Results are classified using asan_utils

This measures what a state-of-the-art LLM can find without any tooling.

Usage:
    python3 baselines/b3_llm_detect/run_b3.py \
        --project libtiff_f324415_vul \
        --dataset-root dataset/f324415/libtiff_f324415_vul \
        --output-dir se_runs/b3/libtiff_f324415_vul
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from baseline_utils import (
    call_llm,
    call_llm_text,
    compile_with_asan,
    run_with_asan,
    dedup_bugs,
    write_summary_tsv,
    write_bug_report,
    find_source_files,
    read_source_context,
    find_function_at_line,
    get_token_counts,
    reset_token_counts,
)

# ── Prompts ──────────────────────────────────────────────────────────

SCAN_SYSTEM = """\
You are an expert C/C++ security auditor. Your task is to identify \
memory safety vulnerabilities in C source code.

Focus on these vulnerability classes:
- Buffer overflow (heap/stack): CWE-122, CWE-121, CWE-787, CWE-120
- Out-of-bounds read: CWE-125
- Use-after-free: CWE-416
- Double free: CWE-415
- NULL pointer dereference: CWE-476
- Integer overflow leading to memory corruption: CWE-190
- Divide by zero: CWE-369

For each vulnerability, report the exact file, line, function, bug type, \
and a brief explanation. Only report real bugs with concrete exploitation \
paths — do NOT report speculative issues, coding style problems, or \
potential issues that require unusual conditions.

Respond with a JSON object:
{
  "vulnerabilities": [
    {
      "file": "filename.c",
      "line": 123,
      "function": "func_name",
      "bug_type": "heap-buffer-overflow",
      "cwe": "CWE-122",
      "confidence": "high|medium",
      "explanation": "brief description of the bug"
    }
  ]
}

If no vulnerabilities are found, return {"vulnerabilities": []}."""

REPRODUCER_SYSTEM = """\
You are an expert at analyzing C/C++ vulnerabilities and identifying how to \
trigger them through the library's public API.

Given a vulnerability description and source code, identify:
1. The vulnerable function (where the bug occurs)
2. The entry function (public API function that reaches the vulnerable code)
3. The crashing inputs (specific values for function arguments, struct fields, \
   buffer sizes that trigger the bug)

Do NOT write a standalone reproducer. Instead, provide structured information \
about how to trigger the bug through the library's real API.

Respond with a JSON object:
{
  "vulnerable_function": "internal_func_name",
  "vulnerable_file": "source_file.c",
  "vulnerable_line": 123,
  "entry_function": "public_api_func",
  "entry_header": "header_file.h",
  "call_chain": "public_api_func -> middle_func -> internal_func_name",
  "crashing_inputs": {
    "arg1_name": "value or description",
    "arg2_name": "value or description",
    "struct_field": "value that triggers overflow"
  },
  "trigger_condition": "description of what input condition triggers the bug",
  "explanation": "how this triggers the bug"
}"""

# Maximum source lines to send per file chunk
MAX_LINES_PER_CHUNK = 500
# Maximum files to scan (0 = unlimited, scan all source files)
MAX_FILES = 0


def scan_file_for_vulns(src_file: Path, dataset_root: Path, log_dir: Path = None) -> list[dict]:
    """Ask the LLM to scan a source file for vulnerabilities."""
    try:
        content = src_file.read_text(errors="replace")
    except Exception:
        return []

    lines = content.splitlines()
    if len(lines) < 5:
        return []

    rel_path = str(src_file.relative_to(dataset_root))
    all_vulns = []

    # Process in chunks for large files
    for chunk_start in range(0, len(lines), MAX_LINES_PER_CHUNK):
        chunk_end = min(chunk_start + MAX_LINES_PER_CHUNK, len(lines))
        chunk_lines = lines[chunk_start:chunk_end]
        numbered = "\n".join(
            f"{chunk_start + i + 1:5d}: {line}"
            for i, line in enumerate(chunk_lines)
        )

        messages = [
            {
                "role": "user",
                "content": (
                    f"Analyze this C source file for memory safety vulnerabilities.\n"
                    f"File: {rel_path}\n"
                    f"Lines {chunk_start+1}-{chunk_end} of {len(lines)}:\n\n"
                    f"```c\n{numbered}\n```"
                ),
            }
        ]

        result = call_llm(SCAN_SYSTEM, messages, tag=f"scan_{src_file.stem}_{chunk_start}", log_dir=log_dir)
        if "error" in result:
            print(f"  [!] LLM error scanning {rel_path}: {result['error']}")
            continue

        vulns = result.get("vulnerabilities", [])
        for v in vulns:
            v["file"] = rel_path
            v["abs_path"] = str(src_file)
        all_vulns.extend(vulns)

    return all_vulns


def generate_reproducer(
    vuln: dict,
    dataset_root: Path,
    output_dir: Path,
) -> dict:
    """Ask the LLM to generate crashing inputs for a vulnerability."""
    src_file = Path(vuln.get("abs_path", ""))
    if not src_file.exists():
        src_file = dataset_root / vuln["file"]

    context = ""
    if src_file.exists():
        context = read_source_context(src_file, vuln.get("line", 0), context=40)

    # Also provide any header files for the function
    func_name = vuln.get("function", "")

    messages = [
        {
            "role": "user",
            "content": (
                f"Identify how to trigger this vulnerability through the library's API:\n\n"
                f"File: {vuln['file']}\n"
                f"Line: {vuln.get('line', '?')}\n"
                f"Function: {func_name}\n"
                f"Bug type: {vuln.get('bug_type', '?')}\n"
                f"CWE: {vuln.get('cwe', '?')}\n"
                f"Explanation: {vuln.get('explanation', '?')}\n\n"
                f"Source context:\n```c\n{context}\n```\n\n"
                f"Provide the entry function, crashing argument values, and trigger condition.\n"
                f"The project source root is: {dataset_root}"
            ),
        }
    ]

    vuln_id = f"{Path(vuln['file']).stem}_{vuln.get('line', 0)}_{vuln.get('bug_type', 'unknown')}"
    result = call_llm(
        REPRODUCER_SYSTEM,
        messages,
        tag=f"reproducer_{vuln_id}",
        log_dir=output_dir,
    )

    return result


def compile_and_validate(
    reproducer_code: str,
    vuln: dict,
    dataset_root: Path,
    output_dir: Path,
) -> dict:
    """Compile a replay driver with ASan and run it."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write reproducer
    reproducer_c = output_dir / "reproducer.c"
    reproducer_c.write_text(reproducer_code, encoding="utf-8")

    # Compile
    binary = str(output_dir / "reproducer")
    include_dirs = [str(dataset_root)]
    # Add common include subdirs
    for sub in ["libtiff", "include", "."]:
        inc = dataset_root / sub
        if inc.is_dir():
            include_dirs.append(str(inc))

    # Try to find project library
    lib_dirs = []
    libs = []
    for lib_path in [
        dataset_root / "build" / ".libs",
        dataset_root / ".libs",
        dataset_root / "build",
    ]:
        if lib_path.is_dir():
            lib_dirs.append(str(lib_path))

    extra_flags = []
    for ld in lib_dirs:
        extra_flags.extend(["-L", ld])
        extra_flags.extend([f"-Wl,-rpath,{ld}"])

    ok, err = compile_with_asan(
        [str(reproducer_c)],
        binary,
        include_dirs=include_dirs,
        extra_flags=extra_flags,
    )

    if not ok:
        return {
            "verdict": "REPRODUCER_BUILD_FAIL",
            "compile_error": err,
        }

    # Run with ASan
    asan_result = run_with_asan(binary, timeout=30)

    # Save ASan output
    if "output" in asan_result:
        (output_dir / "asan_output.txt").write_text(asan_result["output"], encoding="utf-8")

    if asan_result.get("asan_triggered"):
        if asan_result.get("is_harness_artifact"):
            return {
                "verdict": "HARNESS_ARTIFACT",
                "asan": asan_result,
            }
        return {
            "verdict": "CONCRETE_CONFIRMED",
            "asan": asan_result,
        }
    elif asan_result.get("timeout"):
        return {"verdict": "TIMEOUT", "asan": asan_result}
    else:
        return {"verdict": "NOT_REPRODUCIBLE", "asan": asan_result}


# ── Main Pipeline ────────────────────────────────────────────────────

def run_b3(args):
    dataset_root = Path(args.dataset_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[B3] Project:     {args.project}")
    print(f"[B3] Dataset:     {dataset_root}")
    print(f"[B3] Output:      {output_dir}")

    total_start = time.time()
    reset_token_counts()

    # 1. Find source files to scan
    src_files = find_source_files(dataset_root, extensions=(".c",))
    if args.max_files and len(src_files) > args.max_files:
        src_files = src_files[: args.max_files]
    print(f"[B3] Found {len(src_files)} source files to scan")

    # 2. Scan each file for vulnerabilities
    all_vulns = []
    for i, src_file in enumerate(src_files):
        rel = src_file.relative_to(dataset_root)
        print(f"[B3] Scanning [{i+1}/{len(src_files)}]: {rel}")

        vulns = scan_file_for_vulns(src_file, dataset_root, log_dir=output_dir / "scan_logs")
        if vulns:
            print(f"  [+] Found {len(vulns)} potential vulnerability(ies)")
            all_vulns.extend(vulns)

    print(f"\n[B3] Total vulnerabilities reported by LLM: {len(all_vulns)}")
    tokens_after_scan = get_token_counts()

    if not all_vulns:
        write_summary_tsv(output_dir / "summary.tsv", [])
        print("[B3] No vulnerabilities found. Done.")
        return

    # Save scan results
    (output_dir / "scan_results.json").write_text(
        json.dumps(all_vulns, indent=2, default=str), encoding="utf-8"
    )

    # 3. Generate crashing inputs and validate
    all_results = []
    for v_idx, vuln in enumerate(all_vulns):
        vuln_id = f"{Path(vuln['file']).stem}_{vuln.get('line', 0)}_{vuln.get('bug_type', 'unknown')}"
        vuln_dir = output_dir / "findings" / vuln_id

        print(f"\n[B3] Crashing input [{v_idx+1}/{len(all_vulns)}]: {vuln_id}")
        print(f"  {vuln.get('explanation', '')[:100]}")

        # Generate reproducer
        repro_result = generate_reproducer(vuln, dataset_root, vuln_dir)
        repro_code = repro_result.get("reproducer_code", "")

        if not repro_code:
            print(f"  [!] No crashing input generated")
            all_results.append({
                "Spec": vuln_id,
                "FinalStatus": "NO_REPRODUCER",
                "Verdict": "FP",
                "BugType": vuln.get("bug_type", ""),
                "BugFile": os.path.basename(vuln.get("file", "")),
                "BugLine": vuln.get("line", 0),
                "BugFunc": vuln.get("function", ""),
                "CWE": vuln.get("cwe", ""),
                "Time": 0,
                "Tokens": 0,
            })
            continue

        # Compile and validate
        validation = compile_and_validate(repro_code, vuln, dataset_root, vuln_dir)
        verdict = validation.get("verdict", "INCONCLUSIVE")

        status = "FP"
        if verdict == "CONCRETE_CONFIRMED":
            status = "SE_DETECTED"
        elif verdict == "HARNESS_ARTIFACT":
            status = "HARNESS_ARTIFACT"

        asan = validation.get("asan", {})
        result = {
            "Spec": vuln_id,
            "FinalStatus": status,
            "Verdict": verdict,
            "BugType": asan.get("error_type", vuln.get("bug_type", "")),
            "BugFile": os.path.basename(asan.get("crash_file", vuln.get("file", ""))),
            "BugLine": asan.get("crash_line", vuln.get("line", 0)),
            "BugFunc": asan.get("crash_function", vuln.get("function", "")),
            "CWE": vuln.get("cwe", ""),
            "Time": int(asan.get("elapsed", 0)),
            "Tokens": 0,
        }
        all_results.append(result)

        # Write per-finding report
        write_bug_report(vuln_dir / "bug_report.json", {
            "baseline": "B3",
            "vulnerability": vuln,
            "reproducer_code": repro_code,
            "validation": validation,
        })

        print(f"  [{verdict}] {asan.get('error_type', 'no crash')} "
              f"at {result['BugFile']}:{result['BugLine']}")

    total_elapsed = time.time() - total_start
    tokens = get_token_counts()

    # Deduplicate
    confirmed = [r for r in all_results if r["FinalStatus"] == "SE_DETECTED"]
    if confirmed:
        bugs_for_dedup = [
            {"bug_file": r["BugFile"], "bug_line": r["BugLine"], "bug_type": r["BugType"], **r}
            for r in confirmed
        ]
        unique_bugs, n_dups = dedup_bugs(bugs_for_dedup)
        unique_ids = {b["Spec"]: b["UniqueBugID"] for b in unique_bugs}
        for r in all_results:
            r["UniqueBugID"] = unique_ids.get(r["Spec"], "")
            r["IsDuplicate"] = "" if r["Spec"] in unique_ids else "true"
    else:
        unique_bugs = []
        n_dups = 0

    # Write summary
    write_summary_tsv(output_dir / "summary.tsv", all_results)

    print(f"\n[B3] ═══ Summary ═══")
    print(f"  Files scanned:       {len(src_files)}")
    print(f"  LLM-reported vulns:  {len(all_vulns)}")
    print(f"  Reproducers built:   {sum(1 for r in all_results if r['Verdict'] != 'NO_REPRODUCER')}")
    print(f"  Confirmed bugs:      {len(confirmed)}")
    print(f"  Unique bugs:         {len(unique_bugs)}")
    print(f"  Build failures:      {sum(1 for r in all_results if r['Verdict'] == 'REPRODUCER_BUILD_FAIL')}")
    print(f"  Not reproducible:    {sum(1 for r in all_results if r['Verdict'] == 'NOT_REPRODUCIBLE')}")
    print(f"  LLM tokens:          {tokens['total']:,}")
    print(f"  Wall-clock time:     {total_elapsed:.1f}s")
    print(f"  Results:             {output_dir / 'summary.tsv'}")


def main():
    parser = argparse.ArgumentParser(description="B3: Pure LLM Vulnerability Detection")
    parser.add_argument("--project", required=True)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-files", type=int, default=MAX_FILES)
    args = parser.parse_args()

    run_b3(args)


if __name__ == "__main__":
    main()
