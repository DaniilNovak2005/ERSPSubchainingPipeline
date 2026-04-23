#!/usr/bin/env python3
"""B5: Agentic LLM Vulnerability Detection (No Static Analysis).

An autonomous Claude Code agent that freely explores the source code and
identifies memory safety vulnerabilities — with no static analysis guidance.
The agent outputs structured crashing inputs (entry function, argument values,
trigger condition); the infrastructure builds replay drivers and validates
with ASan.

Pipeline:
  1. For each target (source file batch), launch Claude Code in headless mode
  2. The agent can read files, grep for patterns, navigate the codebase
  3. Agent identifies vulnerabilities and outputs crashing inputs.
     The agent decides its own exploration strategy.
  4. Infrastructure compiles replay drivers against project .a and validates with ASan
  5. Output SAILOR-compatible summary.tsv

Usage:
    python3 baselines/b5_agentic_llm/run_b5.py \
        --project libtiff_f324415_vul \
        --dataset-root dataset/f324415/libtiff_f324415_vul \
        --output-dir se_runs/b5/libtiff_f324415_vul \
        [--max-targets 50] [--timeout 600] [--jobs 4]
"""

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from baseline_utils import (
    compile_with_asan,
    run_with_asan,
    dedup_bugs,
    write_summary_tsv,
    write_bug_report,
    find_source_files,
)

# ── Constants ───────────────────────────────────────────────────────

# Number of source files to include per agent target
FILES_PER_TARGET = 10

# Maximum targets (source file batches) to process
DEFAULT_MAX_TARGETS = 50

# Wall-clock timeout per target (seconds)
DEFAULT_TIMEOUT = 600

# Parallel agent workers
DEFAULT_JOBS = 4

# ── Agent Prompt ────────────────────────────────────────────────────

AGENT_PROMPT_TEMPLATE = """\
You are a security researcher analyzing C/C++ source code for memory safety \
vulnerabilities. Your goal is to find REAL, exploitable bugs and write \
standalone C programs that trigger them.

## Project
Source root: {dataset_root}

## Target files to start from
{file_list}

## Instructions

1. **Explore**: Read the target files and any related code (headers, callers, \
callees). Use grep/read to understand data flow and find vulnerability patterns.

2. **Identify**: Look for these vulnerability classes:
   - Buffer overflow (heap/stack): CWE-122, CWE-121, CWE-787, CWE-120
   - Out-of-bounds read: CWE-125
   - Use-after-free / double-free: CWE-416, CWE-415
   - NULL pointer dereference: CWE-476
   - Integer overflow leading to memory corruption: CWE-190

3. **Analyze**: For each vulnerability, identify how to trigger it through \
the library's public API:
   - Find the PUBLIC API function (declared in a header file) that reaches \
     the vulnerable internal function
   - Trace the call chain from public API → vulnerable function
   - Determine the specific input values (arguments, struct fields, buffer \
     sizes) that trigger the bug
   - Save a JSON report to: {output_dir}/bug_report_NNN.json (NNN = 001, 002, ...)

Do NOT write standalone reproducers or re-implement library code. \
Only provide the entry point and crashing inputs.

4. **Report**: After analyzing all vulnerabilities, output a JSON summary to stdout:
```json
{{
  "findings": [
    {{
      "vulnerable_function": "internal_func",
      "vulnerable_file": "source_file.c",
      "vulnerable_line": 123,
      "entry_function": "public_api_func",
      "entry_header": "header.h",
      "call_chain": "public_api -> middle -> internal_func",
      "crashing_inputs": {{
        "arg1": "value",
        "buffer_size": "10 (smaller than expected 64)"
      }},
      "trigger_condition": "when buffer_size < required_size",
      "bug_type": "heap-buffer-overflow",
      "cwe": "CWE-122",
      "explanation": "brief description"
    }}
  ]
}}
```

Focus on REAL bugs with concrete exploitation paths. Quality over quantity.
Do NOT report speculative issues. Only report bugs you are confident about.
"""

# ── Agent Execution ─────────────────────────────────────────────────


def _find_claude_cmd():
    """Find the claude CLI command."""
    # Check if claude is on PATH
    for cmd in ["claude"]:
        try:
            subprocess.run(
                [cmd, "--version"],
                capture_output=True, timeout=10,
                env={**os.environ, "NVM_DIR": os.path.expanduser("~/.nvm")},
            )
            return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Check nvm-installed location
    nvm_claude = os.path.expanduser("~/.nvm/versions/node/")
    if os.path.isdir(nvm_claude):
        for node_ver in sorted(os.listdir(nvm_claude), reverse=True):
            candidate = os.path.join(nvm_claude, node_ver, "bin", "claude")
            if os.path.isfile(candidate):
                return candidate

    raise FileNotFoundError(
        "claude CLI not found. Install with: npm install -g @anthropic-ai/claude-code"
    )


def run_agent_for_target(
    target_id: str,
    file_paths: list[str],
    dataset_root: str,
    output_dir: str,
    timeout: int,
) -> dict:
    """Run Claude Code agent for a batch of source files.

    Returns dict with agent output and metadata.
    """
    target_dir = os.path.join(output_dir, target_id)
    os.makedirs(target_dir, exist_ok=True)

    # Build file list for prompt
    file_list = "\n".join(f"- {f}" for f in file_paths)

    prompt = AGENT_PROMPT_TEMPLATE.format(
        dataset_root=dataset_root,
        file_list=file_list,
        output_dir=target_dir,
    )

    # Save prompt
    with open(os.path.join(target_dir, "agent_prompt.txt"), "w") as f:
        f.write(prompt)

    start = time.time()
    try:
        claude_cmd = _find_claude_cmd()

        # Run Claude Code in headless mode
        env = {**os.environ}
        # Ensure nvm is loaded
        nvm_dir = os.path.expanduser("~/.nvm")
        if os.path.isdir(nvm_dir):
            env["NVM_DIR"] = nvm_dir
            env["PATH"] = (
                os.path.dirname(claude_cmd) + ":" + env.get("PATH", "")
            )

        result = subprocess.run(
            [
                claude_cmd,
                "--print",
                "--output-format", "json",
                "--model", "claude-opus-4-6",
                "--max-turns", "0",  # unlimited turns within timeout
                "--permission-mode", "bypassPermissions",
                "--add-dir", target_dir,
                "-p", prompt,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 30,  # grace period beyond agent timeout
            cwd=dataset_root,
            env=env,
        )

        elapsed = time.time() - start

        # Save raw output
        with open(os.path.join(target_dir, "agent_stdout.txt"), "w") as f:
            f.write(result.stdout or "")
        with open(os.path.join(target_dir, "agent_stderr.txt"), "w") as f:
            f.write(result.stderr or "")

        # Try to parse JSON findings from output
        findings = _extract_findings(result.stdout)

        return {
            "target_id": target_id,
            "files": file_paths,
            "findings": findings,
            "elapsed": elapsed,
            "returncode": result.returncode,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        return {
            "target_id": target_id,
            "files": file_paths,
            "findings": [],
            "elapsed": elapsed,
            "returncode": -1,
            "error": f"Agent timed out after {timeout}s",
        }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "target_id": target_id,
            "files": file_paths,
            "findings": [],
            "elapsed": elapsed,
            "returncode": -1,
            "error": str(e),
        }


def _extract_findings(stdout: str) -> list[dict]:
    """Extract findings JSON from agent output."""
    if not stdout:
        return []

    # Try parsing the full output as JSON (--output-format json)
    try:
        data = json.loads(stdout)
        # Claude Code JSON output has a "result" field
        text = data.get("result", stdout)
    except (json.JSONDecodeError, TypeError):
        text = stdout

    # Look for JSON block with "findings" key
    # Try to find it in markdown code blocks first
    import re
    json_blocks = re.findall(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
    for block in json_blocks:
        try:
            parsed = json.loads(block)
            if "findings" in parsed:
                return parsed["findings"]
        except json.JSONDecodeError:
            continue

    # Try to find bare JSON
    start = text.find('{"findings"')
    if start == -1:
        start = text.find('"findings"')
        if start != -1:
            # Find enclosing brace
            brace = text.rfind("{", 0, start)
            if brace != -1:
                start = brace
    if start != -1:
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(text[start : i + 1])
                        return parsed.get("findings", [])
                    except json.JSONDecodeError:
                        break

    return []


# ── Validation ──────────────────────────────────────────────────────


def validate_reproducers(
    target_dir: str,
    findings: list[dict],
    dataset_root: str,
    upstream_libs: list[str] = None,
    extra_include_dirs: list[str] = None,
    extra_link_flags: list[str] = None,
) -> list[dict]:
    """Compile and run each reproducer with ASan, linked against real .a."""
    results = []
    target_path = Path(target_dir)
    ds_root = Path(dataset_root)

    # Also scan for any reproducer files the agent may have created
    repro_files = sorted(target_path.glob("reproducer_*.c"))

    # Map findings to reproducer files
    finding_map = {}
    for f in findings:
        repro_name = f.get("reproducer_file", "")
        if repro_name:
            finding_map[repro_name] = f

    # If agent created files but didn't report them, still validate
    all_repros = set()
    for rf in repro_files:
        all_repros.add(rf.name)
    for f in findings:
        rname = f.get("reproducer_file", "")
        if rname:
            all_repros.add(rname)

    for repro_name in sorted(all_repros):
        repro_path = target_path / repro_name
        if not repro_path.exists():
            continue

        finding = finding_map.get(repro_name, {})
        repro_dir = target_path / f"validate_{repro_path.stem}"
        repro_dir.mkdir(exist_ok=True)

        # Copy reproducer to validation dir
        repro_c = repro_dir / "reproducer.c"
        repro_c.write_text(repro_path.read_text(errors="replace"))

        # Compile against real .a library
        binary = str(repro_dir / "reproducer")
        include_dirs = [str(ds_root)]
        for sub in ["include", ".", "src", "source", "lib"]:
            inc = ds_root / sub
            if inc.is_dir():
                include_dirs.append(str(inc))
        include_dirs.extend(extra_include_dirs or [])

        # Copy stubs if agent wrote them
        stubs_files = []
        for sf in target_path.glob("stubs*.c"):
            stubs_files.append(str(sf))

        sources = [str(repro_c)] + stubs_files
        all_extra = list(upstream_libs or []) + (extra_link_flags or [])

        ok, err = compile_with_asan(
            sources, binary,
            include_dirs=include_dirs,
            extra_flags=all_extra,
        )

        if not ok:
            (repro_dir / "compile_error.txt").write_text(err)
            results.append(_make_result(
                finding, repro_name, "REPRODUCER_BUILD_FAIL", "REPRODUCER_BUILD_FAIL"
            ))
            continue

        # Run
        asan = run_with_asan(binary, timeout=30)
        if "output" in asan:
            (repro_dir / "asan_output.txt").write_text(asan["output"])

        if asan.get("asan_triggered"):
            if asan.get("is_harness_artifact"):
                status, verdict = "HARNESS_ARTIFACT", "HARNESS_ARTIFACT"
            else:
                status, verdict = "SE_DETECTED", "CONCRETE_CONFIRMED"
        elif asan.get("timeout"):
            status, verdict = "TIMEOUT", "TIMEOUT"
        else:
            status, verdict = "NOT_REPRODUCIBLE", "NOT_REPRODUCIBLE"

        result = {
            "Spec": f"{Path(target_dir).name}_{repro_path.stem}",
            "FinalStatus": status,
            "Verdict": verdict,
            "BugType": asan.get("error_type", finding.get("bug_type", "")),
            "BugFile": os.path.basename(
                asan.get("crash_file", finding.get("file", ""))
            ),
            "BugLine": asan.get("crash_line", finding.get("line", 0)),
            "BugFunc": asan.get("crash_function", finding.get("function", "")),
            "CWE": finding.get("cwe", ""),
            "Time": int(asan.get("elapsed", 0)),
            "Tokens": 0,
            "UniqueBugID": "",
            "IsDuplicate": "",
        }
        results.append(result)

    return results


def _make_result(finding: dict, repro_name: str, status: str, verdict: str) -> dict:
    return {
        "Spec": repro_name,
        "FinalStatus": status,
        "Verdict": verdict,
        "BugType": finding.get("bug_type", ""),
        "BugFile": os.path.basename(finding.get("file", "")),
        "BugLine": finding.get("line", 0),
        "BugFunc": finding.get("function", ""),
        "CWE": finding.get("cwe", ""),
        "Time": 0,
        "Tokens": 0,
        "UniqueBugID": "",
        "IsDuplicate": "",
    }


# ── Target Batching ─────────────────────────────────────────────────


def create_targets(
    dataset_root: Path, max_targets: int, files_per_target: int,
) -> list[tuple[str, list[str]]]:
    """Create exploration targets by batching source files."""
    src_files = find_source_files(dataset_root, extensions=(".c",))

    # Sort by size (largest first — more likely to have bugs)
    src_files.sort(key=lambda f: f.stat().st_size, reverse=True)

    targets = []
    for i in range(0, len(src_files), files_per_target):
        batch = src_files[i : i + files_per_target]
        if not batch:
            break

        rel_paths = [str(f.relative_to(dataset_root)) for f in batch]
        target_id = f"target_{len(targets):04d}"
        targets.append((target_id, rel_paths))

        if len(targets) >= max_targets:
            break

    return targets


# ── Main Pipeline ────────────────────────────────────────────────────


def run_b5(args):
    dataset_root = Path(args.dataset_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[B5] Project:     {args.project}")
    print(f"[B5] Dataset:     {dataset_root}")
    print(f"[B5] Output:      {output_dir}")
    print(f"[B5] Timeout:     {args.timeout}s per target")
    print(f"[B5] Jobs:        {args.jobs}")

    total_start = time.time()

    # 1. Create exploration targets
    targets = create_targets(dataset_root, args.max_targets, FILES_PER_TARGET)
    print(f"[B5] Created {len(targets)} exploration targets")

    if not targets:
        write_summary_tsv(output_dir / "summary.tsv", [])
        print("[B5] No targets. Done.")
        return

    # 2. Run agents (parallel)
    all_results = []
    total_findings = 0

    with ProcessPoolExecutor(max_workers=args.jobs) as executor:
        futures = {}
        for target_id, file_paths in targets:
            fut = executor.submit(
                run_agent_for_target,
                target_id,
                file_paths,
                str(dataset_root),
                str(output_dir / "targets"),
                args.timeout,
            )
            futures[fut] = target_id

        for fut in as_completed(futures):
            target_id = futures[fut]
            try:
                agent_result = fut.result()
            except Exception as e:
                print(f"  [!] {target_id}: worker exception: {e}")
                continue

            n_findings = len(agent_result.get("findings", []))
            elapsed = agent_result.get("elapsed", 0)
            error = agent_result.get("error")

            if error:
                print(f"  [{target_id}] ERROR ({elapsed:.0f}s): {error}")
            else:
                print(f"  [{target_id}] {n_findings} findings ({elapsed:.0f}s)")

            # 3. Validate reproducers against real .a library
            target_dir = str(output_dir / "targets" / target_id)
            validated = validate_reproducers(
                target_dir,
                agent_result.get("findings", []),
                str(dataset_root),
                upstream_libs=args.upstream_libs,
                extra_include_dirs=args.extra_include_dirs,
                extra_link_flags=args.extra_link_flags,
            )

            confirmed = [r for r in validated if r["FinalStatus"] == "SE_DETECTED"]
            if confirmed:
                print(f"    → {len(confirmed)} CONFIRMED bugs!")

            all_results.extend(validated)
            total_findings += n_findings

    total_elapsed = time.time() - total_start

    # 4. Deduplicate
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

    # 5. Write summary
    write_summary_tsv(output_dir / "summary.tsv", all_results)

    # Save run metadata
    meta = {
        "baseline": "B5",
        "project": args.project,
        "targets": len(targets),
        "timeout_per_target": args.timeout,
        "jobs": args.jobs,
        "total_findings_reported": total_findings,
        "total_validated": len(all_results),
        "confirmed": len(confirmed),
        "unique": len(unique_bugs),
        "elapsed": total_elapsed,
    }
    (output_dir / "run_meta.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )

    print(f"\n[B5] ═══ Summary ═══")
    print(f"  Targets explored:    {len(targets)}")
    print(f"  Agent findings:      {total_findings}")
    print(f"  Reproducers tested:  {len(all_results)}")
    print(f"  Confirmed bugs:      {len(confirmed)}")
    print(f"  Unique bugs:         {len(unique_bugs)}")
    print(f"  Wall-clock time:     {total_elapsed:.1f}s")
    print(f"  Results:             {output_dir / 'summary.tsv'}")


def main():
    parser = argparse.ArgumentParser(
        description="B5: Agentic LLM Vulnerability Detection (No SA)"
    )
    parser.add_argument("--project", required=True)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-targets", type=int, default=DEFAULT_MAX_TARGETS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="Wall-clock timeout per target in seconds")
    parser.add_argument("--jobs", type=int, default=DEFAULT_JOBS,
                        help="Parallel agent workers")
    parser.add_argument("--upstream-libs", type=str, default="",
                        help="Comma-separated upstream .a library paths")
    parser.add_argument("--extra-include-dirs", type=str, default="",
                        help="Comma-separated extra include directories")
    parser.add_argument("--extra-link-flags", type=str, default="-lm,-lpthread,-ldl",
                        help="Comma-separated extra linker flags")
    args = parser.parse_args()

    # Parse comma-separated into lists
    args.upstream_libs = [x for x in args.upstream_libs.split(",") if x] if args.upstream_libs else []
    args.extra_include_dirs = [x for x in args.extra_include_dirs.split(",") if x] if args.extra_include_dirs else []
    args.extra_link_flags = [x for x in args.extra_link_flags.split(",") if x] if args.extra_link_flags else ["-lm", "-lpthread", "-ldl"]

    run_b5(args)


if __name__ == "__main__":
    main()
