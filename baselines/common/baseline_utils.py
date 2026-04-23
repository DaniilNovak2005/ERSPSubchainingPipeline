#!/usr/bin/env python3
"""Shared utilities for all SAILOR baselines.

Provides common functions for:
- LLM interaction (OpenAI-compatible API)
- ASan compilation and replay
- Bug deduplication
- Result summarization in SAILOR-compatible TSV format
"""

import csv
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add sailor_engine to path for asan_utils
_ENGINE_DIR = Path(__file__).resolve().parent.parent.parent / "sailor_engine"
sys.path.insert(0, str(_ENGINE_DIR))
from asan_utils import parse_asan_frames, is_harness_crash, is_stub_free_uaf

# ── Token tracking ────────────────────────────────────────────────────

_TOKEN_TOTAL = 0
_TOKEN_PROMPT = 0
_TOKEN_COMPLETION = 0


def get_token_counts() -> Dict[str, int]:
    return {
        "total": _TOKEN_TOTAL,
        "prompt": _TOKEN_PROMPT,
        "completion": _TOKEN_COMPLETION,
    }


def reset_token_counts():
    global _TOKEN_TOTAL, _TOKEN_PROMPT, _TOKEN_COMPLETION
    _TOKEN_TOTAL = _TOKEN_PROMPT = _TOKEN_COMPLETION = 0


# ── LLM Interface ────────────────────────────────────────────────────

def call_llm(
    system: str,
    messages: List[Dict],
    tag: str = "",
    log_dir: Optional[Path] = None,
    max_retries: int = 5,
    max_tokens_override: Optional[int] = None,
) -> Dict:
    """Call LLM with OpenAI-compatible API. Returns parsed JSON dict.

    Args:
        max_tokens_override: If set, overrides the LLM_MAX_TOKENS env var.
            Useful for requests that need larger output (e.g. multi-harness generation).
    """
    global _TOKEN_TOTAL, _TOKEN_PROMPT, _TOKEN_COMPLETION
    import openai

    client = openai.OpenAI(
        api_key=os.environ.get("LLM_API_KEY", os.environ.get("OPENAI_API_KEY", "")),
        base_url=os.environ.get("LLM_API_BASE", ""),
    )
    model = os.environ.get("LLM_MODEL", "gpt-5")
    max_tokens = max_tokens_override or int(os.environ.get("LLM_MAX_TOKENS", "8192"))
    temperature = float(os.environ.get("LLM_TEMPERATURE", "0.2"))

    _restricted = any(k in model for k in ("o1", "o3", "gpt-5"))
    kwargs: Dict = {}
    if _restricted:
        kwargs["max_completion_tokens"] = max_tokens
    else:
        kwargs["max_tokens"] = max_tokens
        kwargs["temperature"] = temperature
        kwargs["response_format"] = {"type": "json_object"}

    def _try_parse(text: str) -> Optional[Dict]:
        clean = text.strip()
        if "```json" in clean:
            clean = clean.split("```json")[1].split("```")[0]
        elif "```" in clean:
            clean = clean.split("```")[1].split("```")[0]
        s, e = clean.find("{"), clean.rfind("}")
        if s != -1 and e != -1:
            try:
                return json.loads(clean[s : e + 1])
            except Exception:
                pass
        return None

    last_err = None
    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": system}] + messages,
                **kwargs,
            )
            u = getattr(resp, "usage", None)
            if u:
                _TOKEN_PROMPT += getattr(u, "prompt_tokens", 0)
                _TOKEN_COMPLETION += getattr(u, "completion_tokens", 0)
                _TOKEN_TOTAL = _TOKEN_PROMPT + _TOKEN_COMPLETION

            raw = resp.choices[0].message.content or ""
            if log_dir and tag:
                log_dir.mkdir(parents=True, exist_ok=True)
                # Save prompt (system + messages)
                prompt_data = json.dumps(
                    {"system": system, "messages": messages, "model": model},
                    indent=2, default=str,
                )
                (log_dir / f"{tag}_prompt.json").write_text(prompt_data, encoding="utf-8")
                # Save raw response
                (log_dir / f"{tag}_raw.txt").write_text(raw, encoding="utf-8")

            parsed = _try_parse(raw)
            if parsed is not None:
                return parsed
            # Return raw text in a wrapper if JSON parse fails
            return {"raw_text": raw}

        except Exception as e:
            last_err = e
            err_str = str(e).lower()
            if "insufficient_quota" in err_str or "billing" in err_str:
                return {"error": f"LLM quota exhausted: {e}"}
            if "response_format" in err_str or "unsupported parameter" in err_str:
                kwargs.pop("response_format", None)
                continue
            is_rate = "rate" in err_str and "limit" in err_str or "429" in err_str
            delay = min(60 * (2 ** attempt), 120) if is_rate else min(2 ** (attempt + 1), 30)
            print(f"  [!] LLM attempt {attempt+1}/{max_retries} failed: {e}; retrying in {delay}s")
            time.sleep(delay)

    return {"error": f"LLM call failed after {max_retries} retries: {last_err}"}


def call_llm_text(system: str, messages: List[Dict], **kwargs) -> str:
    """Call LLM and return raw text response."""
    result = call_llm(system, messages, **kwargs)
    if "raw_text" in result:
        return result["raw_text"]
    if "error" in result:
        return f"ERROR: {result['error']}"
    return json.dumps(result, indent=2)


# ── Compilation & Execution ──────────────────────────────────────────

def run_cmd(
    cmd: List[str], timeout: int = 120, cwd: Optional[str] = None, env=None
) -> Tuple[int, str, str, float]:
    """Run a shell command. Returns (rc, stdout, stderr, elapsed)."""
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
        elapsed = time.time() - start
        return proc.returncode, proc.stdout, proc.stderr, elapsed
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s", time.time() - start
    except Exception as e:
        return -1, "", str(e), time.time() - start


def compile_with_asan(
    sources: List[str],
    output: str,
    include_dirs: List[str] = None,
    libs: List[str] = None,
    extra_flags: List[str] = None,
    cwd: Optional[str] = None,
) -> Tuple[bool, str]:
    """Compile C source(s) with ASan. Returns (success, error_message)."""
    cmd = [
        "clang",
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-g",
        "-O0",
        "-w",
    ]
    for d in include_dirs or []:
        cmd.extend(["-I", d])
    cmd.extend(sources)
    cmd.extend(["-o", output])
    cmd.extend(extra_flags or [])
    for lib in libs or []:
        cmd.append(f"-l{lib}")

    rc, stdout, stderr, _ = run_cmd(cmd, cwd=cwd)
    if rc != 0:
        return False, stderr[:2000]
    return True, ""


def run_with_asan(
    binary: str,
    args: List[str] = None,
    timeout: int = 30,
    stdin_data: bytes = None,
) -> Dict:
    """Run an ASan-instrumented binary and parse the output."""
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:print_stacktrace=1"

    cmd = [binary] + (args or [])
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            env=env,
            input=stdin_data,
        )
        combined = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return {"asan_triggered": False, "timeout": True, "elapsed": time.time() - start}
    except Exception as e:
        return {"asan_triggered": False, "error": str(e), "elapsed": time.time() - start}

    elapsed = time.time() - start
    result = {
        "asan_triggered": "AddressSanitizer" in combined,
        "exit_code": proc.returncode,
        "elapsed": elapsed,
        "output": combined[:5000],
    }

    if result["asan_triggered"]:
        m_type = re.search(r"ERROR: AddressSanitizer:\s*(\S+)", combined)
        m_loc = re.search(r"#0\s+\S+\s+in\s+(\S+)\s+(\S+):(\d+)", combined)
        if m_type:
            result["error_type"] = m_type.group(1)
        if m_loc:
            result["crash_function"] = m_loc.group(1)
            result["crash_file"] = m_loc.group(2)
            result["crash_line"] = int(m_loc.group(3))
        frames = parse_asan_frames(combined)
        result["frames"] = frames
        result["is_harness_artifact"] = is_harness_crash(frames)

    return result


# ── Bug Deduplication ────────────────────────────────────────────────

def dedup_bugs(bugs: List[Dict]) -> Tuple[List[Dict], int]:
    """Deduplicate bugs by (BugFile, BugLine, BugType).

    Returns (unique_bugs_with_ids, total_duplicates).
    Each bug gets a 'UniqueBugID' field.
    """
    clusters: Dict[Tuple, List[Dict]] = defaultdict(list)
    for bug in bugs:
        sig = (
            os.path.basename(bug.get("bug_file", "")),
            str(bug.get("bug_line", "")),
            bug.get("bug_type", ""),
        )
        clusters[sig].append(bug)

    unique = []
    bug_id = 0
    total_dups = 0
    for sig, members in sorted(clusters.items()):
        bug_id += 1
        rep = members[0]
        rep["UniqueBugID"] = f"BUG-{bug_id:03d}"
        rep["duplicates"] = len(members) - 1
        unique.append(rep)
        total_dups += len(members) - 1

    return unique, total_dups


# ── Result TSV Writing ───────────────────────────────────────────────

SUMMARY_HEADER = [
    "Spec",
    "FinalStatus",
    "Verdict",
    "BugType",
    "BugFile",
    "BugLine",
    "BugFunc",
    "CWE",
    "Time",
    "Tokens",
    "UniqueBugID",
    "IsDuplicate",
]


def write_summary_tsv(path: Path, rows: List[Dict]):
    """Write results in SAILOR-compatible summary.tsv format."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=SUMMARY_HEADER, delimiter="\t", extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def write_bug_report(path: Path, bug: Dict):
    """Write a per-finding bug_report.json."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bug, indent=2, default=str), encoding="utf-8")


# ── Source File Helpers ──────────────────────────────────────────────

def find_source_files(src_root: Path, extensions: Tuple[str, ...] = (".c", ".h")) -> List[Path]:
    """Find all source files in a project tree, excluding test/tool dirs."""
    skip_dirs = {"test", "tests", "tools", "doc", "docs", "examples", "fuzz", ".git", "build"}
    results = []
    for f in src_root.rglob("*"):
        if f.is_file() and f.suffix in extensions:
            parts = set(f.relative_to(src_root).parts)
            if not parts & skip_dirs:
                results.append(f)
    return sorted(results)


def read_source_context(src_file: Path, line: int, context: int = 30) -> str:
    """Read source code context around a specific line."""
    try:
        lines = src_file.read_text(errors="replace").splitlines()
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        numbered = []
        for i in range(start, end):
            marker = ">>>" if i + 1 == line else "   "
            numbered.append(f"{marker} {i+1:5d}: {lines[i]}")
        return "\n".join(numbered)
    except Exception:
        return f"(could not read {src_file}:{line})"


def find_function_at_line(src_text: str, line: int) -> str:
    """Find the function name containing a given line number."""
    func_re = re.compile(
        r"^(?:static\s+|inline\s+|extern\s+|const\s+)*"
        r"(?:\w+[\s*]+)*(\w+)\s*\([^;]*$",
        re.MULTILINE,
    )
    best_name = "unknown"
    best_start = 0
    for m in func_re.finditer(src_text):
        m_line = src_text[: m.start()].count("\n") + 1
        if m_line <= line and m_line > best_start:
            name = m.group(1)
            if name not in ("if", "while", "for", "switch", "return"):
                best_name = name
                best_start = m_line
    return best_name


# ── KLEE Compilation & Execution Helpers ─────────────────────────

def find_llvm14(name: str) -> str:
    """Find LLVM-14 tool binary."""
    for p in [f"/usr/lib/llvm-14/bin/{name}", f"{name}-14", name]:
        if shutil.which(p):
            return p
    return name


def compile_harness_to_bitcode(
    harness_dir: Path,
    dataset_root: Path,
    project_bc: Optional[Path] = None,
    extra_cflags: Optional[List[str]] = None,
) -> Tuple[bool, Path, str]:
    """Compile .c files in harness_dir to LLVM bitcode and link with project.bc.

    Expects harness_dir to contain driver.c (which #includes harness.c) and
    optionally stubs.c. Returns (success, combined_bc_path, error_message).
    """
    clang = find_llvm14("clang")
    llvm_link = find_llvm14("llvm-link")

    base_flags = [
        "-emit-llvm", "-c", "-g", "-O0", "-fno-inline",
        "-Wno-everything", "-D__KLEE__",
    ]
    base_flags.extend(extra_cflags or [])

    # Build include flags
    inc_flags = ["-isystem", "/usr/include"]
    inc_flags.extend(["-I", str(harness_dir)])
    inc_flags.extend(["-I", str(dataset_root)])
    for sub in ["include", "libtiff", "libxml2", "."]:
        inc = dataset_root / sub
        if inc.is_dir():
            inc_flags.extend(["-I", str(inc)])

    # Auto-include config headers
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
    for c_file in sorted(harness_dir.glob("*.c")):
        if c_file.name == "harness.c":
            continue  # included by driver.c via #include
        bc_out = harness_dir / f"{c_file.stem}.bc"
        cmd = [clang] + base_flags + inc_flags + [str(c_file), "-o", str(bc_out)]
        rc, _, stderr, _ = run_cmd(cmd, timeout=60)
        if rc != 0:
            return False, Path(), f"Compile {c_file.name} failed: {stderr[:1000]}"
        bc_files.append(bc_out)

    if not bc_files:
        return False, Path(), "No .c files compiled successfully"

    combined_bc = harness_dir / "combined.bc"
    link_cmd = [llvm_link] + [str(b) for b in bc_files]
    if project_bc and project_bc.exists():
        link_cmd.append(str(project_bc))
    link_cmd.extend(["-o", str(combined_bc)])

    rc, _, stderr, _ = run_cmd(link_cmd, timeout=120)
    if rc != 0:
        return False, Path(), f"llvm-link failed: {stderr[:1000]}"

    return True, combined_bc, ""


def run_klee(
    bc_path: Path,
    output_dir: Path,
    timeout: int = 300,
) -> dict:
    """Run KLEE on a bitcode file and parse crash results.

    Returns dict with keys: elapsed, total_crashes, crashes (list),
    plus KLEE stats (total_instructions, completed_paths, generated_tests).
    """
    klee_bin = find_llvm14("klee") if not shutil.which("klee") else "klee"
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
                "is_harness_crash": crash_basename in (
                    "driver.c", "stubs.c", "klee_driver.c", "replay_driver.c",
                ),
            }
            crashes.append(crash)

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
