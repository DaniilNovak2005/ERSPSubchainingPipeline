#!/usr/bin/env python3
"""Single-shot LLM + KLEE engine.

NOTE: As of 2026-03, this module is only used by A1 (run_a1.py imports
scan_source_for_targets). B2 was rewritten as a project-level harness
generator and A2 was dropped. The with_sa=True code path is unused.

Implements the full pipeline per spec:
  1. Load spec → read source context (40-80 lines around target)
  2. Build LLM prompt (with or without SA context based on `with_sa` flag)
  3. Single LLM call → generates harness.c, driver.c, stubs.c as JSON
  4. Write files to harness/ directory
  5. Compile .c → .bc → llvm-link → combined.bc
  6. Run KLEE once (same flags as SAILOR)
  7. Parse .err files for crashes, classify harness vs real
  8. Report result in SAILOR-compatible summary.tsv format

Used by:
  - A1 (via scan_source_for_targets): LLM-based target discovery
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_COMMON_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_COMMON_DIR))
from baseline_utils import (
    call_llm,
    dedup_bugs,
    find_function_at_line,
    find_source_files,
    get_token_counts,
    read_source_context,
    reset_token_counts,
    write_bug_report,
    write_summary_tsv,
)

# ── System Prompts ──────────────────────────────────────────────────

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

# Map CWE numbers to human-readable vulnerability descriptions
CWE_DESCRIPTIONS = {
    "120": "Buffer Overflow",
    "121": "Stack-based Buffer Overflow",
    "122": "Heap-based Buffer Overflow",
    "123": "Write-what-where Condition",
    "125": "Out-of-bounds Read",
    "190": "Integer Overflow",
    "191": "Integer Underflow",
    "369": "Divide by Zero",
    "415": "Double Free",
    "416": "Use-After-Free",
    "476": "NULL Pointer Dereference",
    "562": "Return of Stack Variable Address",
    "674": "Uncontrolled Recursion",
    "787": "Out-of-bounds Write",
    "823": "Use of Out-of-range Pointer Offset",
}


def _extract_cwe_from_spec(spec: dict) -> Tuple[str, str]:
    """Extract CWE number and description from a spec's rule_id.

    Returns (cwe_number, description) e.g. ("125", "Out-of-bounds Read").
    Returns ("", "") if no CWE can be extracted.
    """
    rule_id = spec.get("rule_id", "")
    stem = spec.get("_stem", "")

    # Try rule_id first, then stem
    for text in [rule_id, stem]:
        m = re.search(r'cwe-(\d+)', text, re.IGNORECASE)
        if m:
            cwe_num = m.group(1)
            desc = CWE_DESCRIPTIONS.get(cwe_num, f"CWE-{cwe_num}")
            return cwe_num, desc

    # Try pattern-based inference from rule_id keywords
    rule_lower = rule_id.lower()
    if "unbounded-write" in rule_lower or "overflow" in rule_lower:
        return "120", "Buffer Overflow"
    if "oob-read" in rule_lower:
        return "125", "Out-of-bounds Read"
    if "oob-write" in rule_lower:
        return "787", "Out-of-bounds Write"
    if "use-after" in rule_lower or "lifecycle" in rule_lower or "stale-reference" in rule_lower:
        return "416", "Use-After-Free"
    if "null" in rule_lower or "unchecked" in rule_lower:
        return "476", "NULL Pointer Dereference"
    if "type-confusion" in rule_lower:
        return "125", "Out-of-bounds Read"

    return "", ""


HARNESS_GEN_SYSTEM = """\
You are an expert C security engineer specializing in symbolic execution \
with KLEE. Your task is to generate a KLEE harness that exercises a \
specific code location to detect potential memory safety vulnerabilities.

""" + TARGET_VULNERABILITY_TYPES + """
You must produce THREE files:

1. **harness.c**: Contains the target function(s) and required type \
definitions, extracted/adapted from the library source. Include only the \
code needed to reach the target location. Re-declare structs, typedefs, \
enums, and function signatures as needed to make the harness self-contained.

2. **driver.c**: Contains `main()` that:
   - Uses `klee_make_symbolic()` to create symbolic inputs
   - Calls the target function with those inputs
   - Places `klee_assert(0)` at strategic points to verify reachability
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

Respond with a JSON object:
{
  "harness_c": "// harness.c content",
  "driver_c": "// driver.c content",
  "stubs_c": "// stubs.c content (or just a comment if none needed)",
  "entry_function": "name of the function called in main()",
  "reasoning": "brief explanation of approach"
}"""


def _build_user_prompt_no_sa(
    spec: dict, source_context: str, function_name: str
) -> str:
    """Build the user prompt for B2: no SA context, just raw source + vuln type."""
    vuln_file = spec.get("file", "")
    vuln_line = spec.get("line", 0)

    cwe_num, cwe_desc = _extract_cwe_from_spec(spec)

    prompt = (
        f"## Target Location\n\n"
        f"**File**: `{os.path.basename(vuln_file)}`\n"
        f"**Line**: {vuln_line}\n"
        f"**Function**: `{function_name}`\n"
    )

    if cwe_num:
        prompt += f"**Vulnerability type to detect**: {cwe_desc} (CWE-{cwe_num})\n"

    prompt += (
        f"\nGenerate a KLEE harness that exercises line {vuln_line} in "
        f"`{os.path.basename(vuln_file)}` to detect a potential "
        f"{cwe_desc + ' vulnerability' if cwe_desc else 'memory safety issue'}.\n\n"
        f"## Source Context\n\n"
        f"```c\n{source_context}\n```\n"
    )

    return prompt


def _load_vulnerability_summary(
    sailor_runs_dir: Optional[Path], spec_stem: str
) -> Optional[dict]:
    """Load pre-computed vulnerability_summary.json from SAILOR's runs.

    SAILOR generates enriched context per spec in:
      se_runs/sailor_engine/<project>/<spec_stem>/sa_context/vulnerability_summary.json
    """
    if not sailor_runs_dir or not sailor_runs_dir.is_dir():
        return None

    # The spec directory name matches the spec stem
    vs_path = sailor_runs_dir / spec_stem / "sa_context" / "vulnerability_summary.json"
    if not vs_path.exists():
        # Try partial match (spec stems can vary slightly)
        for d in sailor_runs_dir.iterdir():
            if d.is_dir() and spec_stem in d.name:
                candidate = d / "sa_context" / "vulnerability_summary.json"
                if candidate.exists():
                    vs_path = candidate
                    break

    if vs_path.exists():
        try:
            return json.loads(vs_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


def _format_enriched_source_context(vs: dict) -> str:
    """Format the enriched source context from vulnerability_summary.json."""
    sc = vs.get("source_context", {})
    lines_dict = sc.get("lines", {})
    if not lines_dict:
        return ""

    # Sort by line number and format
    numbered = []
    target_line = int(vs.get("target_line", 0))
    for line_no in sorted(lines_dict.keys(), key=lambda x: int(x)):
        marker = ">>>" if int(line_no) == target_line else "   "
        numbered.append(f"{marker} {int(line_no):5d}: {lines_dict[line_no]}")
    return "\n".join(numbered)


def _build_user_prompt_with_sa(
    spec: dict,
    source_context: str,
    function_name: str,
    vuln_summary: Optional[dict] = None,
) -> str:
    """Build the user prompt for A2: includes SA context + enriched SAILOR context."""
    vuln_file = spec.get("file", "")
    vuln_line = spec.get("line", 0)
    message = spec.get("message", "")
    rule_id = spec.get("rule_id", "")
    facts = spec.get("facts", {})
    hints = spec.get("llm_hints", {})

    cwe_num, cwe_desc = _extract_cwe_from_spec(spec)

    prompt = (
        f"## Static Analysis Finding\n\n"
        f"**Rule**: `{rule_id}`\n"
        f"**File**: `{os.path.basename(vuln_file)}`\n"
        f"**Line**: {vuln_line}\n"
        f"**Function**: `{function_name}`\n"
        f"**Message**: {message[:500]}\n"
    )

    if cwe_num:
        prompt += f"**Vulnerability type**: {cwe_desc} (CWE-{cwe_num})\n"

    prompt += "\n"

    # Add SA-derived facts
    if facts.get("suspect_calls"):
        prompt += f"**Suspect calls**: {', '.join(facts['suspect_calls'])}\n"
    if facts.get("pointer_vars"):
        prompt += f"**Pointer variables**: {', '.join(facts['pointer_vars'])}\n"
    if facts.get("length_vars"):
        prompt += f"**Length/bounds variables**: {', '.join(facts['length_vars'])}\n"
    if facts.get("bounds_hints"):
        hints_str = "; ".join(
            f"{h.get('var', '?')} {h.get('relation', '?')}"
            for h in facts["bounds_hints"][:5]
        )
        prompt += f"**Bounds hints**: {hints_str}\n"

    # Add entrypoint candidates from SA
    ep = hints.get("entrypoint", {})
    if ep.get("candidates"):
        prompt += f"**Entry point candidates**: {', '.join(ep['candidates'])}\n"

    # Add assertion hints
    assertions = hints.get("assertions", {})
    if assertions.get("presence_assertion_hint"):
        prompt += f"**Assertion hint**: {assertions['presence_assertion_hint']}\n"

    # Add notes
    if hints.get("notes"):
        prompt += f"**Notes**: {'; '.join(hints['notes'][:3])}\n"

    # Enriched context from SAILOR's pre-computed vulnerability_summary.json
    if vuln_summary:
        entry_fn = vuln_summary.get("entry_function", "unknown")
        spine = vuln_summary.get("spine", [])
        vuln_fn = vuln_summary.get("vulnerable_function", "unknown")

        if entry_fn and entry_fn != "unknown":
            prompt += f"**Entry function**: `{entry_fn}`\n"
        if vuln_fn and vuln_fn != "unknown":
            prompt += f"**Vulnerable function**: `{vuln_fn}`\n"
        if spine and spine != ["unknown"]:
            prompt += f"**Call spine**: {' → '.join(spine)}\n"

        # Add struct/type info from relevant findings
        for finding in vuln_summary.get("relevant_findings", [])[:3]:
            extra_suspects = finding.get("suspect_calls", [])
            extra_ptrs = finding.get("pointer_vars", [])
            if extra_suspects and extra_suspects != facts.get("suspect_calls", []):
                prompt += f"**Related suspect calls**: {', '.join(extra_suspects)}\n"
            if extra_ptrs and extra_ptrs != facts.get("pointer_vars", []):
                prompt += f"**Related pointer vars**: {', '.join(extra_ptrs)}\n"

        # Use enriched source context if available (broader than our read_source_context)
        enriched_ctx = _format_enriched_source_context(vuln_summary)
        if enriched_ctx:
            source_context = enriched_ctx

    prompt += (
        f"\nGenerate a KLEE harness that exercises line {vuln_line} in "
        f"`{os.path.basename(vuln_file)}` to detect the reported "
        f"{cwe_desc + ' vulnerability' if cwe_desc else 'vulnerability'}.\n\n"
        f"## Source Context\n\n"
        f"```c\n{source_context}\n```\n"
    )

    return prompt


# ── Spec Loading ────────────────────────────────────────────────────

def load_specs(specs_dir: Path) -> List[dict]:
    """Load all spec JSON files from the specs directory."""
    specs = []
    for f in sorted(specs_dir.glob("*.json")):
        if f.name in ("triage.json", "triage_stats.json", "triage_order.txt"):
            continue
        try:
            spec = json.loads(f.read_text(encoding="utf-8"))
            spec["_stem"] = f.stem
            spec["_path"] = str(f)
            specs.append(spec)
        except Exception:
            continue
    return specs


# ── LLM-Based Target Discovery (for no-SA approaches) ──────────────

SCAN_SYSTEM = """\
You are an expert C/C++ security auditor. Your task is to identify \
memory safety vulnerabilities in C source code.

""" + TARGET_VULNERABILITY_TYPES + """
For each vulnerability, report the exact line, function, bug type, CWE, \
and a brief explanation. Only report real bugs with concrete exploitation \
paths — do NOT report speculative issues, coding style problems, or \
potential issues that require unusual conditions.

Respond with a JSON object:
{
  "vulnerabilities": [
    {
      "line": 123,
      "function": "func_name",
      "bug_type": "heap-buffer-overflow",
      "cwe": "CWE-122",
      "confidence": "high|medium",
      "explanation": "brief description"
    }
  ]
}

If no vulnerabilities are found, return {"vulnerabilities": []}."""

# Maximum source lines to send per file chunk
_SCAN_MAX_LINES_PER_CHUNK = 500
# Maximum files to scan
_SCAN_MAX_FILES = 50


def scan_source_for_targets(
    dataset_root: Path,
    max_files: int = _SCAN_MAX_FILES,
    tag: str = "B2",
) -> List[dict]:
    """Scan source files with LLM to discover potential vulnerability targets.

    Returns a list of spec-like dicts with _stem, file, line, etc. suitable
    for process_spec(). No SA context — pure LLM file scanning.
    """
    src_files = find_source_files(dataset_root, extensions=(".c",))
    if not src_files:
        print(f"[{tag}] No source files found in {dataset_root}")
        return []

    if len(src_files) > max_files:
        src_files = src_files[:max_files]

    print(f"[{tag}] Scanning {len(src_files)} source files for vulnerabilities...")

    targets = []
    target_idx = 0

    for f_idx, src_file in enumerate(src_files):
        try:
            content = src_file.read_text(errors="replace")
        except Exception:
            continue

        lines = content.splitlines()
        if len(lines) < 5:
            continue

        rel_path = str(src_file.relative_to(dataset_root))
        print(f"[{tag}] Scanning [{f_idx+1}/{len(src_files)}]: {rel_path}")

        # Process in chunks for large files
        for chunk_start in range(0, len(lines), _SCAN_MAX_LINES_PER_CHUNK):
            chunk_end = min(chunk_start + _SCAN_MAX_LINES_PER_CHUNK, len(lines))
            chunk_lines = lines[chunk_start:chunk_end]
            numbered = "\n".join(
                f"{chunk_start + i + 1:5d}: {line}"
                for i, line in enumerate(chunk_lines)
            )

            messages = [{
                "role": "user",
                "content": (
                    f"Analyze this C source file for memory safety vulnerabilities.\n"
                    f"File: {rel_path}\n"
                    f"Lines {chunk_start+1}-{chunk_end} of {len(lines)}:\n\n"
                    f"```c\n{numbered}\n```"
                ),
            }]

            result = call_llm(SCAN_SYSTEM, messages, tag=f"scan_{src_file.stem}_{chunk_start}")
            if "error" in result:
                continue

            vulns = result.get("vulnerabilities", [])
            if vulns:
                print(f"  [+] Found {len(vulns)} potential vulnerability(ies)")

            for v in vulns:
                vuln_line = v.get("line", 0)
                vuln_func = v.get("function", "unknown")
                cwe = v.get("cwe", "")
                bug_type = v.get("bug_type", "")

                target_idx += 1
                stem = f"{target_idx:03d}_{src_file.stem}_{vuln_line}_llm-scan"

                targets.append({
                    "_stem": stem,
                    "_path": str(src_file),
                    "schema": "llmse.vul_spec.v1",
                    "id": stem,
                    "rule_id": f"llm-scan/{bug_type}",
                    "family": "GENERIC",
                    "file": str(src_file),
                    "line": vuln_line,
                    "column": 0,
                    "end_line": vuln_line,
                    "end_column": 0,
                    "message": v.get("explanation", "LLM-identified vulnerability"),
                    "context": {},
                    "target_statement": {},
                    "facts": {
                        "suspect_calls": [],
                        "pointer_vars": [],
                        "length_vars": [],
                        "bounds_hints": [],
                    },
                    "llm_hints": {
                        "entrypoint": {"strategy": "LLM_INFER", "candidates": []},
                        "assertions": {
                            "presence_assertion_hint": "",
                            "reachability_assertion": "klee_assert(0);",
                        },
                        "notes": [],
                    },
                    # Preserve scan metadata
                    "_scan_cwe": cwe,
                    "_scan_bug_type": bug_type,
                    "_scan_confidence": v.get("confidence", ""),
                    "_scan_function": vuln_func,
                })

    print(f"[{tag}] Discovered {len(targets)} target locations from {len(src_files)} files")
    return targets


# ── LLVM Tool Discovery ────────────────────────────────────────────

def _find_llvm14(name: str) -> str:
    """Find LLVM-14 tool binary."""
    for p in [f"/usr/lib/llvm-14/bin/{name}", f"{name}-14", name]:
        if shutil.which(p):
            return p
    return name


# ── Bitcode Compilation ────────────────────────────────────────────

def _compile_to_bitcode(
    harness_dir: Path,
    dataset_root: Path,
    project_bc: Optional[Path] = None,
) -> Tuple[bool, Path, str]:
    """Compile harness/driver/stubs to a single LLVM bitcode file.

    No auto-fix retry: if compilation fails, it's a BUILD_ERROR.
    """
    clang = _find_llvm14("clang")
    llvm_link = _find_llvm14("llvm-link")

    base_flags = [
        "-emit-llvm", "-c", "-g", "-O0", "-fno-inline",
        "-Wno-everything", "-D__KLEE__",
    ]

    # Build include flags
    inc_flags = ["-isystem", "/usr/include"]
    inc_flags.extend(["-I", str(harness_dir)])
    inc_flags.extend(["-I", str(dataset_root)])
    for sub in ["include", "libtiff", "libxml2", "."]:
        inc = dataset_root / sub
        if inc.is_dir():
            inc_flags.extend(["-I", str(inc)])

    # Try to find and auto-include config.h
    for cfg in ["config.h", "tiffconf.h", "xmlversion.h"]:
        cfg_path = dataset_root / cfg
        if not cfg_path.exists():
            cfg_path = dataset_root / "build" / cfg
        if cfg_path.exists():
            inc_flags.extend(["-include", str(cfg_path)])
            break

    # Auto-detect IN_LIBFOO macro
    lib_name = dataset_root.name.split("_")[0].upper()
    if lib_name.startswith("LIB"):
        base_flags.append(f"-DIN_{lib_name}")

    bc_files = []

    # Compile each .c file in harness_dir (except driver.c, which includes harness.c)
    for c_file in sorted(harness_dir.glob("*.c")):
        if c_file.name == "harness.c":
            continue  # included by driver.c via #include
        bc_out = harness_dir / f"{c_file.stem}.bc"
        cmd = [clang] + base_flags + inc_flags + [str(c_file), "-o", str(bc_out)]
        rc, stdout, stderr = _run_simple(cmd, timeout=60)
        if rc != 0:
            return False, Path(), f"Compile {c_file.name} failed: {stderr[:1000]}"
        bc_files.append(bc_out)

    if not bc_files:
        return False, Path(), "No .c files compiled successfully"

    # Link all bitcode files (+ optional project.bc)
    combined_bc = harness_dir / "combined.bc"
    link_cmd = [llvm_link] + [str(b) for b in bc_files]
    if project_bc and project_bc.exists():
        link_cmd.append(str(project_bc))
    link_cmd.extend(["-o", str(combined_bc)])

    rc, stdout, stderr = _run_simple(link_cmd, timeout=120)
    if rc != 0:
        return False, Path(), f"llvm-link failed: {stderr[:1000]}"

    return True, combined_bc, ""


def _run_simple(cmd: List[str], timeout: int = 120) -> Tuple[int, str, str]:
    """Run a command and return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


# ── KLEE Execution ─────────────────────────────────────────────────

def _run_klee(
    bc_path: Path,
    output_dir: Path,
    timeout: int = 300,
) -> dict:
    """Run KLEE on a bitcode file and parse results."""
    klee_bin = _find_llvm14("klee") if not shutil.which("klee") else "klee"
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

    start = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 60
        )
        elapsed = time.time() - start
        full_log = proc.stdout + "\n" + proc.stderr
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        full_log = "TIMEOUT (subprocess)"
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

            crash_file = m_file.group(1).strip() if m_file else ""
            crash_basename = os.path.basename(crash_file)

            crash = {
                "err_file": str(ef),
                "crash_type": err_type,
                "crash_file": crash_file,
                "crash_basename": crash_basename,
                "crash_line": int(m_line.group(1)) if m_line else 0,
                "ktest_file": str(ef).replace(".err", ".ktest"),
            }

            # Classify: skip crashes in harness infrastructure files
            crash["is_harness_crash"] = crash_basename in (
                "driver.c", "stubs.c", "klee_driver.c", "replay_driver.c",
            )
            crashes.append(crash)

    # Parse KLEE stats
    stats = {
        "elapsed": elapsed,
        "total_crashes": len(crashes),
        "crashes": crashes,
        "klee_log_tail": full_log[-500:] if full_log else "",
    }
    for pattern, key in [
        (r"KLEE: done: total instructions = (\d+)", "total_instructions"),
        (r"KLEE: done: completed paths = (\d+)", "completed_paths"),
        (r"KLEE: done: generated tests = (\d+)", "generated_tests"),
    ]:
        m = re.search(pattern, full_log)
        if m:
            stats[key] = int(m.group(1))

    return stats


# ── Single Spec Pipeline ───────────────────────────────────────────

def _parse_llm_files(result: dict) -> Tuple[str, str, str]:
    """Extract harness.c, driver.c, stubs.c from LLM JSON response."""
    harness = result.get("harness_c", "")
    driver = result.get("driver_c", "")
    stubs = result.get("stubs_c", "// No stubs needed\n")

    # Fallback: if the LLM returned code in a single field
    if not harness and not driver:
        raw = result.get("raw_text", "")
        if raw:
            # Try to extract code blocks
            blocks = re.findall(r"```c\n(.*?)```", raw, re.DOTALL)
            if len(blocks) >= 2:
                harness = blocks[0]
                driver = blocks[1]
                stubs = blocks[2] if len(blocks) >= 3 else "// No stubs\n"

    return harness, driver, stubs


def process_spec(
    spec: dict,
    dataset_root: Path,
    output_dir: Path,
    with_sa: bool,
    klee_timeout: int = 300,
    project_bc: Optional[Path] = None,
    sailor_runs_dir: Optional[Path] = None,
) -> dict:
    """Process a single spec through the single-shot pipeline.

    Args:
        sailor_runs_dir: Path to SAILOR's completed runs for this project
            (e.g. se_runs/sailor_engine/libtiff_f324415_vul).
            Used by A2 to load pre-computed vulnerability_summary.json
            for enriched context (entry function, spine, struct defs).

    Returns a dict with SAILOR-compatible summary fields.
    """
    stem = spec["_stem"]
    vuln_file = spec.get("file", "")
    vuln_line = spec.get("line", 0)

    finding_dir = output_dir / "findings" / stem
    finding_dir.mkdir(parents=True, exist_ok=True)

    start_time = time.time()

    # 1. Read source context
    src_path = Path(vuln_file)
    if not src_path.exists():
        # Try relative resolution
        for base in [dataset_root]:
            candidate = base / os.path.basename(vuln_file)
            if candidate.exists():
                src_path = candidate
                break
            for f in base.rglob(os.path.basename(vuln_file)):
                src_path = f
                break

    source_context = ""
    function_name = "unknown"
    if src_path.exists():
        source_context = read_source_context(src_path, vuln_line, context=40)
        try:
            src_text = src_path.read_text(errors="replace")
            function_name = find_function_at_line(src_text, vuln_line)
        except Exception:
            pass

    if not source_context:
        return _make_result(
            stem, vuln_file, vuln_line, "NO_SOURCE", start_time
        )

    # 2. Build LLM prompt
    if with_sa:
        # Load pre-computed enriched context from SAILOR runs (if available)
        vuln_summary = _load_vulnerability_summary(sailor_runs_dir, stem)
        user_content = _build_user_prompt_with_sa(
            spec, source_context, function_name, vuln_summary=vuln_summary
        )
    else:
        user_content = _build_user_prompt_no_sa(spec, source_context, function_name)

    messages = [{"role": "user", "content": user_content}]

    # 3. Single LLM call
    llm_result = call_llm(
        HARNESS_GEN_SYSTEM,
        messages,
        tag=f"harness_{stem}",
        log_dir=finding_dir,
    )

    if "error" in llm_result:
        return _make_result(
            stem, vuln_file, vuln_line, "LLM_ERROR", start_time
        )

    # Save LLM response
    (finding_dir / "llm_response.json").write_text(
        json.dumps(llm_result, indent=2, default=str), encoding="utf-8"
    )

    # 4. Parse and write harness files
    harness_c, driver_c, stubs_c = _parse_llm_files(llm_result)

    if not harness_c or not driver_c:
        return _make_result(
            stem, vuln_file, vuln_line, "LLM_ERROR", start_time,
            detail="LLM did not generate harness/driver code"
        )

    harness_dir = finding_dir / "harness"
    harness_dir.mkdir(parents=True, exist_ok=True)
    (harness_dir / "harness.c").write_text(harness_c, encoding="utf-8")
    (harness_dir / "driver.c").write_text(driver_c, encoding="utf-8")
    (harness_dir / "stubs.c").write_text(stubs_c, encoding="utf-8")

    # 5. Compile to bitcode
    ok, combined_bc, err_msg = _compile_to_bitcode(
        harness_dir, dataset_root, project_bc=project_bc
    )

    if not ok:
        (finding_dir / "compile_error.txt").write_text(err_msg, encoding="utf-8")
        return _make_result(
            stem, vuln_file, vuln_line, "BUILD_ERROR", start_time,
            detail=err_msg[:200]
        )

    # 6. Run KLEE
    klee_stats = _run_klee(combined_bc, finding_dir, timeout=klee_timeout)

    # Save KLEE stats
    (finding_dir / "klee_stats.json").write_text(
        json.dumps(
            {k: v for k, v in klee_stats.items() if k != "crashes"},
            indent=2, default=str,
        ),
        encoding="utf-8",
    )

    # 7. Classify crashes
    real_crashes = [
        c for c in klee_stats["crashes"]
        if not c["is_harness_crash"]
    ]

    if not real_crashes:
        status = "NO_BUG"
        if not klee_stats["crashes"]:
            # KLEE found nothing at all
            status = "NO_BUG"
        else:
            # Only harness/stub crashes
            status = "HARNESS_ARTIFACT"
            # Return first harness crash for diagnostics
            hc = klee_stats["crashes"][0]
            return _make_result(
                stem, vuln_file, vuln_line, status, start_time,
                bug_type=hc["crash_type"],
                bug_file=hc["crash_basename"],
                bug_line=hc["crash_line"],
                klee_time=klee_stats["elapsed"],
            )
        return _make_result(
            stem, vuln_file, vuln_line, status, start_time,
            klee_time=klee_stats["elapsed"],
        )

    # Take the first real crash as the representative
    crash = real_crashes[0]
    return _make_result(
        stem, vuln_file, vuln_line, "SE_DETECTED", start_time,
        bug_type=crash["crash_type"],
        bug_file=crash["crash_basename"],
        bug_line=crash["crash_line"],
        klee_time=klee_stats["elapsed"],
    )


def _make_result(
    spec_stem: str,
    vuln_file: str,
    vuln_line: int,
    status: str,
    start_time: float,
    bug_type: str = "",
    bug_file: str = "",
    bug_line: int = 0,
    detail: str = "",
    klee_time: float = 0,
) -> dict:
    """Create a SAILOR-compatible result row."""
    elapsed = time.time() - start_time
    verdict_map = {
        "SE_DETECTED": "TP",
        "HARNESS_ARTIFACT": "HARNESS_ARTIFACT",
        "BUILD_ERROR": "FP",
        "LLM_ERROR": "FP",
        "NO_BUG": "FP",
        "NO_SOURCE": "FP",
        "TIMEOUT": "TIMEOUT",
    }
    return {
        "Spec": spec_stem,
        "FinalStatus": status,
        "Verdict": verdict_map.get(status, "FP"),
        "BugType": bug_type,
        "BugFile": bug_file or os.path.basename(vuln_file),
        "BugLine": bug_line or vuln_line,
        "BugFunc": "",
        "CWE": "",
        "Time": int(klee_time or elapsed),
        "Tokens": 0,
        "UniqueBugID": "",
        "IsDuplicate": "",
    }


# ── Main Entry Point ───────────────────────────────────────────────

def run_single_shot_klee(
    project: str,
    dataset_root: Path,
    output_dir: Path,
    with_sa: bool,
    specs_dir: Optional[Path] = None,
    max_specs: int = 0,
    max_files: int = _SCAN_MAX_FILES,
    klee_timeout: int = 300,
    jobs: int = 1,
    sailor_runs_dir: Optional[Path] = None,
) -> None:
    """Run the single-shot LLM + KLEE pipeline.

    Two modes:
      - with_sa=True (A2): Load specs from specs_dir (SA-derived locations).
      - with_sa=False (B2): Scan source files with LLM to discover targets.

    Args:
        project: Project slug (e.g. libtiff_f324415_vul)
        dataset_root: Path to project source tree
        output_dir: Path to write results
        with_sa: If True, use SA specs + enriched context (A2).
                 If False, LLM scans files to discover targets (B2).
        specs_dir: Path to CodeQL spec JSON files (required if with_sa=True)
        max_specs: Max specs to process when with_sa=True (0 = all)
        max_files: Max source files to scan when with_sa=False (default 50)
        klee_timeout: KLEE timeout per spec in seconds
        jobs: Number of parallel workers (currently sequential)
        sailor_runs_dir: Path to SAILOR's completed runs for this project.
            Used by A2 to load pre-computed vulnerability_summary.json.
            Auto-resolved from se_runs/sailor_engine/<project> if not given.
    """
    tag = "A2" if with_sa else "B2"

    dataset_root = dataset_root.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    # Auto-resolve SAILOR runs dir for A2 enriched context
    if with_sa and sailor_runs_dir is None:
        repo_root = Path(__file__).resolve().parent.parent.parent
        candidate = repo_root / "se_runs" / "sailor_engine" / project
        if candidate.is_dir():
            sailor_runs_dir = candidate

    print(f"[{tag}] Project:     {project}")
    print(f"[{tag}] Dataset:     {dataset_root}")
    if with_sa and specs_dir:
        print(f"[{tag}] Specs:       {specs_dir}")
    print(f"[{tag}] Output:      {output_dir}")
    print(f"[{tag}] With SA:     {with_sa}")
    print(f"[{tag}] KLEE timeout: {klee_timeout}s")
    if sailor_runs_dir:
        print(f"[{tag}] SAILOR runs: {sailor_runs_dir}")

    total_start = time.time()
    reset_token_counts()

    # Find project.bc if available
    project_bc = None
    for p in [dataset_root / "project.bc", dataset_root / "build" / "project.bc"]:
        if p.exists():
            project_bc = p
            break
    if project_bc:
        print(f"[{tag}] Project BC:  {project_bc}")

    # 1. Load targets
    if with_sa:
        # A2: Use SA-derived specs (CodeQL locations)
        if not specs_dir:
            print(f"[{tag}] ERROR: --specs-dir required for with_sa=True")
            return
        specs_dir = specs_dir.resolve()
        specs = load_specs(specs_dir)
        if max_specs and len(specs) > max_specs:
            specs = specs[:max_specs]
        print(f"[{tag}] Loaded {len(specs)} specs from SA")
    else:
        # B2: Scan source files with LLM to discover targets (no SA)
        specs = scan_source_for_targets(dataset_root, max_files=max_files, tag=tag)

    if not specs:
        write_summary_tsv(output_dir / "summary.tsv", [])
        print(f"[{tag}] No specs to process. Done.")
        return

    # 2. Process each spec (sequential — KLEE is CPU-bound)
    all_results = []
    for s_idx, spec in enumerate(specs):
        stem = spec["_stem"]
        print(f"\n[{tag}] [{s_idx+1}/{len(specs)}] {stem}")

        result = process_spec(
            spec=spec,
            dataset_root=dataset_root,
            output_dir=output_dir,
            with_sa=with_sa,
            klee_timeout=klee_timeout,
            project_bc=project_bc,
            sailor_runs_dir=sailor_runs_dir,
        )
        all_results.append(result)

        status = result["FinalStatus"]
        print(f"  [{status}] {result['BugType']} "
              f"at {result['BugFile']}:{result['BugLine']}")

    total_elapsed = time.time() - total_start
    tokens = get_token_counts()

    # 3. Deduplicate confirmed bugs
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

    # Update token counts in results
    per_spec_tokens = tokens["total"] // max(len(specs), 1)
    for r in all_results:
        r["Tokens"] = per_spec_tokens

    # 4. Write summary
    write_summary_tsv(output_dir / "summary.tsv", all_results)

    # Write token stats
    (output_dir / "token_stats.json").write_text(
        json.dumps(tokens, indent=2), encoding="utf-8"
    )

    # 5. Print report
    n_build_err = sum(1 for r in all_results if r["FinalStatus"] == "BUILD_ERROR")
    n_harness = sum(1 for r in all_results if r["FinalStatus"] == "HARNESS_ARTIFACT")
    n_no_bug = sum(1 for r in all_results if r["FinalStatus"] == "NO_BUG")
    n_llm_err = sum(1 for r in all_results if r["FinalStatus"] == "LLM_ERROR")

    print(f"\n[{tag}] ═══ Summary ═══")
    print(f"  Specs processed:     {len(specs)}")
    print(f"  SE_DETECTED:         {len(se_detected)}")
    print(f"  Unique bugs:         {len(unique_bugs)}")
    print(f"  Duplicates:          {n_dups}")
    print(f"  Build errors:        {n_build_err}")
    print(f"  Harness artifacts:   {n_harness}")
    print(f"  No bug / FP:         {n_no_bug}")
    print(f"  LLM errors:          {n_llm_err}")
    print(f"  LLM tokens:          {tokens['total']:,}")
    print(f"  Wall-clock time:     {total_elapsed:.1f}s")
    print(f"  Results:             {output_dir / 'summary.tsv'}")
