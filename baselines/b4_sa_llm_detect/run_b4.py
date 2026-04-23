#!/usr/bin/env python3
"""B4: Raw CodeQL + LLM Vulnerability Detection (File-Level Batching).

Uses raw CodeQL findings (from sa_outputs/) — NOT enriched SAILOR specs.
Sends ALL findings for each source file in a single LLM call, letting the
LLM triage and output crashing inputs for likely TPs. This avoids per-finding
targeting (which is SAILOR's spec-generation contribution).

Pipeline:
  1. Load all raw CodeQL findings from sa_outputs/<project>/findings.json
  2. Group findings by source file
  3. For each file: send all findings + source code to LLM in one call
  4. LLM triages findings and outputs crashing inputs for likely TPs
  5. Infrastructure compiles replay driver against project .a and validates with ASan
  6. Output SAILOR-compatible summary.tsv

Usage:
    python3 baselines/b4_sa_llm_detect/run_b4.py \
        --project libtiff_f324415_vul \
        --dataset-root dataset/f324415/libtiff_f324415_vul \
        --sa-outputs-dir sa_outputs/libtiff_f324415_vul \
        --output-dir se_runs/b4/libtiff_f324415_vul
"""

import argparse
import json
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from baseline_utils import (
    call_llm,
    compile_with_asan,
    run_with_asan,
    dedup_bugs,
    write_summary_tsv,
    write_bug_report,
    get_token_counts,
    reset_token_counts,
)

# ── Constants ───────────────────────────────────────────────────────

# Max source chars per LLM call (to avoid exceeding context limits)
_MAX_SOURCE_CHARS = 40000

# Max findings per LLM call (if a single file has hundreds, chunk them)
_MAX_FINDINGS_PER_CALL = 80

# ── Prompts ──────────────────────────────────────────────────────────

BATCH_ASSESS_SYSTEM = """\
You are an expert C/C++ security analyst. You receive a batch of static \
analysis findings from CodeQL for a single source file, along with the \
file's source code.

Your task:
1. Review ALL findings together in context of the full source file.
2. TRIAGE each finding as true_positive, false_positive, or uncertain.
3. For each finding you assess as true_positive, identify the entry function \
   (public API) that reaches the vulnerable code and the crashing inputs.

Do NOT write standalone reproducers. Instead, provide structured information \
about how to trigger each bug through the library's real API.

Respond with a JSON object:
{
  "assessments": [
    {
      "finding_index": 0,
      "assessment": "true_positive" | "false_positive" | "uncertain",
      "confidence": "high" | "medium" | "low",
      "reasoning": "brief explanation",
      "vulnerable_function": "internal_func_name",
      "entry_function": "public_api_func_that_reaches_it",
      "call_chain": "public_api -> middle -> vulnerable_func",
      "crashing_inputs": {
        "arg1": "value or description",
        "struct_field": "value that triggers the bug"
      },
      "trigger_condition": "what input condition triggers the bug",
      "expected_bug_type": "heap-buffer-overflow | use-after-free | null-deref | ..."
    }
  ]
}

IMPORTANT:
- Return one assessment entry per finding, using the finding_index to match.
- Focus on findings most likely to be real vulnerabilities.
- It is OK to mark most findings as false_positive — precision matters.
- For true positives, identify the PUBLIC API entry point that reaches the bug.
- The entry_function must be a function declared in a public header file."""


# ── Finding Loading & Grouping ───────────────────────────────────────

def load_and_group_findings(sa_outputs_dir: Path) -> Dict[str, List[dict]]:
    """Load raw CodeQL findings and group them by source file.

    Returns dict mapping basename -> list of findings.
    """
    findings_file = sa_outputs_dir / "findings.json"
    if not findings_file.exists():
        print(f"[B4] findings.json not found at {findings_file}")
        return {}

    try:
        data = json.loads(findings_file.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[B4] Error reading findings.json: {e}")
        return {}

    raw_findings = data.get("results", data) if isinstance(data, dict) else data
    if not isinstance(raw_findings, list):
        print(f"[B4] Unexpected findings.json format")
        return {}

    # Group by source file basename
    grouped: Dict[str, List[dict]] = defaultdict(list)
    for idx, f in enumerate(raw_findings):
        src_file = f.get("file", "")
        basename = os.path.basename(src_file) if src_file else "unknown"
        f["_global_index"] = idx
        f["_basename"] = basename
        grouped[basename].append(f)

    return dict(grouped)


def _find_source_file(basename: str, dataset_root: Path) -> Optional[Path]:
    """Find a source file in the dataset by basename."""
    # Direct match
    direct = dataset_root / basename
    if direct.exists():
        return direct
    # Recursive search
    matches = list(dataset_root.rglob(basename))
    if matches:
        return matches[0]
    return None


def _read_source_truncated(path: Path, max_chars: int) -> str:
    """Read source file, truncating if too large."""
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return ""
    if len(text) > max_chars:
        lines = text[:max_chars].splitlines()
        return "\n".join(lines) + f"\n\n... [truncated at {max_chars} chars] ..."
    return text


def _format_findings_block(findings: List[dict]) -> str:
    """Format a batch of findings into a text block for the LLM prompt."""
    lines = []
    for i, f in enumerate(findings):
        rule = f.get("ruleId", "unknown")
        severity = f.get("severity", "")
        cwe_list = f.get("cwe", [])
        line = f.get("startLine", 0)
        message = f.get("message", "")[:300]
        code_flows = f.get("codeFlows", [])

        entry = (
            f"### Finding {i}\n"
            f"- **Rule**: {rule}\n"
            f"- **Line**: {line}\n"
            f"- **Severity**: {severity}\n"
        )
        if cwe_list:
            entry += f"- **CWE**: {', '.join(cwe_list)}\n"
        entry += f"- **Message**: {message}\n"

        if code_flows:
            flow_parts = []
            for cf in code_flows[:3]:
                cf_file = os.path.basename(cf.get("file", ""))
                cf_line = cf.get("startLine", "")
                if cf_file and cf_line:
                    flow_parts.append(f"{cf_file}:{cf_line}")
            if flow_parts:
                entry += f"- **Flow**: {' → '.join(flow_parts)}\n"

        lines.append(entry)
    return "\n".join(lines)


# ── Per-File Processing ──────────────────────────────────────────────

def process_file_findings(
    basename: str,
    findings: List[dict],
    dataset_root: Path,
    output_dir: Path,
) -> List[dict]:
    """Process all CodeQL findings for one source file in a single LLM call.

    Returns list of result dicts (one per finding).
    """
    # Find and read source file
    src_path = _find_source_file(basename, dataset_root)
    source_text = ""
    if src_path:
        source_text = _read_source_truncated(src_path, _MAX_SOURCE_CHARS)

    # Build prompt with ALL findings for this file
    findings_block = _format_findings_block(findings)

    user_msg = (
        f"## Source File: {basename}\n\n"
        f"Below are {len(findings)} CodeQL static analysis findings for this file, "
        f"followed by the source code.\n\n"
        f"{findings_block}\n\n"
        f"## Source Code\n\n"
        f"```c\n{source_text or '// Source file not found'}\n```\n\n"
        f"Assess each finding and provide crashing inputs for true positives."
    )

    file_dir = output_dir / "findings" / basename.replace(".", "_")
    file_dir.mkdir(parents=True, exist_ok=True)

    messages = [{"role": "user", "content": user_msg}]
    # Use higher token limit for batch responses
    result = call_llm(
        BATCH_ASSESS_SYSTEM,
        messages,
        tag=f"batch_{basename.replace('.', '_')}",
        log_dir=file_dir,
        max_tokens_override=65536,
    )

    if "error" in result:
        print(f"  [!] LLM error: {result['error']}")
        return [
            _make_result(f, "LLM_ERROR", "FP", "", 0)
            for f in findings
        ]

    # Parse batch assessments
    assessments = result.get("assessments", [])

    # Build index map for quick lookup
    assess_map: Dict[int, dict] = {}
    for a in assessments:
        idx = a.get("finding_index", -1)
        if 0 <= idx < len(findings):
            assess_map[idx] = a

    # Process each finding's assessment
    all_results = []
    for i, finding in enumerate(findings):
        assessment = assess_map.get(i, {})
        verdict = assessment.get("assessment", "uncertain")
        repro_code = assessment.get("reproducer_code", "")
        expected_type = assessment.get("expected_bug_type", "")

        vuln_file = finding.get("file", "")
        vuln_line = finding.get("startLine", 0)
        cwe_list = finding.get("cwe", [])
        rule = finding.get("ruleId", "unknown").replace("/", "-")
        stem = f"{finding['_global_index']:04d}_{basename.replace('.', '_')}_{vuln_line}_{rule}"

        if verdict == "false_positive" or not repro_code:
            all_results.append(_make_result(
                finding, "LLM_FP", "FP", expected_type, 0, stem=stem
            ))
            continue

        # Compile and validate replay driver
        repro_dir = file_dir / f"repro_{i:03d}_{vuln_line}"
        repro_dir.mkdir(parents=True, exist_ok=True)

        # Save assessment
        write_bug_report(repro_dir / "llm_assessment.json", assessment)

        reproducer_c = repro_dir / "reproducer.c"
        reproducer_c.write_text(repro_code, encoding="utf-8")

        binary = str(repro_dir / "reproducer")
        include_dirs = [str(dataset_root)]
        for sub in ["libtiff", "include", "."]:
            inc = dataset_root / sub
            if inc.is_dir():
                include_dirs.append(str(inc))

        extra_flags = []
        for lib_path in [dataset_root / "build" / ".libs",
                         dataset_root / ".libs",
                         dataset_root / "build"]:
            if lib_path.is_dir():
                extra_flags.extend(["-L", str(lib_path),
                                    f"-Wl,-rpath,{lib_path}"])

        ok, err = compile_with_asan(
            [str(reproducer_c)], binary,
            include_dirs=include_dirs,
            extra_flags=extra_flags,
        )

        if not ok:
            (repro_dir / "compile_error.txt").write_text(err, encoding="utf-8")
            all_results.append(_make_result(
                finding, "REPRODUCER_BUILD_FAIL", "REPRODUCER_BUILD_FAIL",
                expected_type, 0, stem=stem
            ))
            continue

        # Run with ASan
        asan = run_with_asan(binary, timeout=30)
        if "output" in asan:
            (repro_dir / "asan_output.txt").write_text(
                asan["output"], encoding="utf-8"
            )

        if asan.get("asan_triggered"):
            if asan.get("is_harness_artifact"):
                status, v = "HARNESS_ARTIFACT", "HARNESS_ARTIFACT"
            else:
                status, v = "SE_DETECTED", "CONCRETE_CONFIRMED"
        elif asan.get("timeout"):
            status, v = "TIMEOUT", "TIMEOUT"
        else:
            status, v = "NOT_REPRODUCIBLE", "NOT_REPRODUCIBLE"

        all_results.append({
            "Spec": stem,
            "FinalStatus": status,
            "Verdict": v,
            "BugType": asan.get("error_type", expected_type),
            "BugFile": os.path.basename(asan.get("crash_file", vuln_file)),
            "BugLine": asan.get("crash_line", vuln_line),
            "BugFunc": asan.get("crash_function", ""),
            "CWE": cwe_list[0] if cwe_list else "",
            "Time": int(asan.get("elapsed", 0)),
            "Tokens": 0,
            "UniqueBugID": "",
            "IsDuplicate": "",
        })

    return all_results


def _make_result(
    finding: dict, status: str, verdict: str,
    bug_type: str, elapsed: int, stem: str = ""
) -> dict:
    """Create a result dict from a finding."""
    vuln_file = finding.get("file", "")
    cwe_list = finding.get("cwe", [])
    if not stem:
        basename = finding.get("_basename", "unknown")
        vuln_line = finding.get("startLine", 0)
        rule = finding.get("ruleId", "unknown").replace("/", "-")
        stem = f"{finding['_global_index']:04d}_{basename.replace('.', '_')}_{vuln_line}_{rule}"
    return {
        "Spec": stem,
        "FinalStatus": status,
        "Verdict": verdict,
        "BugType": bug_type,
        "BugFile": os.path.basename(vuln_file),
        "BugLine": finding.get("startLine", 0),
        "BugFunc": "",
        "CWE": cwe_list[0] if cwe_list else "",
        "Time": elapsed,
        "Tokens": 0,
        "UniqueBugID": "",
        "IsDuplicate": "",
    }


# ── Main Pipeline ────────────────────────────────────────────────────

def run_b4(args):
    dataset_root = Path(args.dataset_root).resolve()
    sa_outputs_dir = Path(args.sa_outputs_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[B4] Project:     {args.project}")
    print(f"[B4] Dataset:     {dataset_root}")
    print(f"[B4] SA Outputs:  {sa_outputs_dir}")
    print(f"[B4] Output:      {output_dir}")

    total_start = time.time()
    reset_token_counts()

    # 1. Load and group findings by file
    grouped = load_and_group_findings(sa_outputs_dir)
    total_findings = sum(len(v) for v in grouped.values())
    print(f"[B4] Loaded {total_findings} findings across {len(grouped)} files")

    if not grouped:
        write_summary_tsv(output_dir / "summary.tsv", [])
        print("[B4] No findings to process. Done.")
        return

    # Sort files by number of findings (descending) for progress reporting
    file_order = sorted(grouped.keys(), key=lambda k: len(grouped[k]), reverse=True)

    # 2. Process each file (all its findings in one LLM call)
    all_results = []
    findings_processed = 0

    for f_idx, basename in enumerate(file_order):
        findings = grouped[basename]

        # Chunk if too many findings for one call
        chunks = []
        if len(findings) > _MAX_FINDINGS_PER_CALL:
            for start in range(0, len(findings), _MAX_FINDINGS_PER_CALL):
                chunks.append(findings[start:start + _MAX_FINDINGS_PER_CALL])
        else:
            chunks = [findings]

        for c_idx, chunk in enumerate(chunks):
            chunk_label = f" (chunk {c_idx+1}/{len(chunks)})" if len(chunks) > 1 else ""
            print(f"\n[B4] [{f_idx+1}/{len(file_order)}] {basename}: "
                  f"{len(chunk)} findings{chunk_label}")

            results = process_file_findings(
                basename, chunk, dataset_root, output_dir
            )
            all_results.extend(results)

            # Print per-file summary
            tp = sum(1 for r in results if r["FinalStatus"] == "SE_DETECTED")
            fp = sum(1 for r in results if r["FinalStatus"] == "LLM_FP")
            bf = sum(1 for r in results if r["FinalStatus"] == "REPRODUCER_BUILD_FAIL")
            nr = sum(1 for r in results if r["FinalStatus"] == "NOT_REPRODUCIBLE")
            other = len(results) - tp - fp - bf - nr

            status_parts = []
            if tp: status_parts.append(f"{tp} confirmed")
            if fp: status_parts.append(f"{fp} FP")
            if bf: status_parts.append(f"{bf} build-fail")
            if nr: status_parts.append(f"{nr} not-repro")
            if other: status_parts.append(f"{other} other")
            print(f"  → {', '.join(status_parts)}")

            findings_processed += len(chunk)

    total_elapsed = time.time() - total_start
    tokens = get_token_counts()

    # 3. Deduplicate confirmed bugs
    confirmed = [r for r in all_results if r["FinalStatus"] == "SE_DETECTED"]
    if confirmed:
        bugs_for_dedup = [
            {"bug_file": r["BugFile"], "bug_line": r["BugLine"],
             "bug_type": r["BugType"], **r}
            for r in confirmed
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
    per_file_tokens = tokens["total"] // max(len(file_order), 1)
    for r in all_results:
        r["Tokens"] = per_file_tokens

    # 4. Write summary
    write_summary_tsv(output_dir / "summary.tsv", all_results)

    (output_dir / "token_stats.json").write_text(
        json.dumps(tokens, indent=2), encoding="utf-8"
    )

    # 5. Print report
    n_llm_fp = sum(1 for r in all_results if r["FinalStatus"] == "LLM_FP")
    n_build_fail = sum(1 for r in all_results
                       if r["FinalStatus"] == "REPRODUCER_BUILD_FAIL")
    n_not_repro = sum(1 for r in all_results
                      if r["FinalStatus"] == "NOT_REPRODUCIBLE")
    n_harness_art = sum(1 for r in all_results
                        if r["FinalStatus"] == "HARNESS_ARTIFACT")
    n_llm_err = sum(1 for r in all_results if r["FinalStatus"] == "LLM_ERROR")

    print(f"\n[B4] ═══ Summary ═══")
    print(f"  Files processed:     {len(file_order)}")
    print(f"  Findings processed:  {findings_processed}")
    print(f"  LLM assessed FP:     {n_llm_fp}")
    print(f"  Confirmed bugs:      {len(confirmed)}")
    print(f"  Unique bugs:         {len(unique_bugs)}")
    print(f"  Duplicates:          {n_dups}")
    print(f"  Build failures:      {n_build_fail}")
    print(f"  Not reproducible:    {n_not_repro}")
    print(f"  Harness artifacts:   {n_harness_art}")
    print(f"  LLM errors:          {n_llm_err}")
    print(f"  LLM tokens:          {tokens['total']:,}")
    print(f"  Wall-clock time:     {total_elapsed:.1f}s")
    print(f"  Results:             {output_dir / 'summary.tsv'}")


def main():
    parser = argparse.ArgumentParser(
        description="B4: Raw CodeQL + LLM Detection (file-level batching)"
    )
    parser.add_argument("--project", required=True)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--sa-outputs-dir", required=True,
                        help="Path to sa_outputs/<project>/ with findings.json")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    run_b4(args)


if __name__ == "__main__":
    main()
