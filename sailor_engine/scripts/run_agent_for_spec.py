#!/usr/bin/env python3
"""SAILOR v6.0 — Sliced Symbolic Execution for Bug Verification.
Pipeline:
  Phase 0: Load spec + SA data
  Phase 1: Frozen analysis (identify spine, assertion, compile flags)
  Phase 2: Agent loop (WriteDriver → CompileSlice → iterate)
  Phase 3: Export findings
  Phase 5: Concrete validation (ASan replay)
"""
import argparse, datetime, json, os, re, shlex, shutil, subprocess, sys, time, textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Shared ASan harness-artifact detection (sailor_engine/asan_utils.py)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from asan_utils import parse_asan_frames, is_harness_crash

SAILOR_AGENT_VERSION = "v6.1-se-config"

# ---------------------------------------------------------------------------
# SE Config — Analyst Knowledge Injection
# ---------------------------------------------------------------------------
# The se_config/ folder lets analysts inject domain knowledge, bug
# reproduction data, or manual verification hints into the SAILOR pipeline
# WITHOUT modifying the engine itself.
#
# Structure:
#   se_config/
#     config.json          — structured settings (KLEE flags, timeouts, mode)
#     analyst_notes.md     — freeform instructions for the LLM agent
#     constraints.json     — klee_assume hints, struct field values, entry overrides
#     seed_driver.c        — analyst-written driver.c (replaces auto-generated)
#     seed_stubs.c         — analyst-written stubs
#     seed_harness.c       — analyst-written harness (sliced spine code)
#     crash_output.txt     — ASan/fuzzer crash log for stack trace analysis
#     poc_input.bin        — proof-of-concept input for concrete replay
#     extra_stubs.c        — additional stubs (merged, not replaced)
# ---------------------------------------------------------------------------

def load_se_config(se_config_dir: str) -> Dict:
    """Load analyst-provided se_config/ folder into a structured dict.

    All files are optional. Missing files are silently skipped.
    Returns a dict with all loaded data, ready to be threaded through the pipeline.
    """
    d = Path(se_config_dir) if se_config_dir else None
    cfg = {
        # --- From config.json ---
        "mode": "discover",          # "discover" (find bugs) or "verify" (reproduce known bug)
        "klee_flags": [],            # extra KLEE CLI flags
        "klee_timeout": 0,           # override KLEE timeout (0 = use default)
        "max_turns": 0,              # override agent turn limit (0 = use default)
        "extra_cflags": [],          # extra clang flags for compilation
        "extra_includes": [],        # extra -I paths
        "search_strategy": "",       # KLEE search: dfs, bfs, random-path, etc.
        # --- From constraints.json ---
        "entry_override": "",        # override the entry function
        "spine_override": [],        # override the spine
        "struct_field_values": {},   # {field: value} — concrete values to set in driver
        "klee_assumes": [],          # ["sym_len > 64", "instate == 7"] — agent injects these
        "stub_returns": {},          # {func: "symbolic"/"0"/"-1"/...} — stub return policy
        # --- From files ---
        "analyst_notes": "",         # freeform markdown text for agent
        "crash_output": "",          # ASan/fuzzer output for stack trace
        "poc_input_path": "",        # path to PoC input binary
        "seed_driver": "",           # analyst driver.c source
        "seed_stubs": "",            # analyst stubs.c source
        "seed_harness": "",          # analyst harness source
        "extra_stubs": "",           # additional stubs (merged into stubs.c)
        # --- Meta ---
        "se_config_dir": str(d) if d else "",
        "loaded_files": [],          # which files were actually loaded
    }

    if not d or not d.is_dir():
        return cfg

    print(f"  [SE-Config] Loading from: {d}")

    # --- config.json ---
    config_path = d / "config.json"
    if config_path.exists():
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
            for key in ["mode", "search_strategy", "entry_override"]:
                if key in raw and isinstance(raw[key], str):
                    cfg[key] = raw[key]
            for key in ["klee_timeout", "max_turns"]:
                if key in raw:
                    cfg[key] = int(raw[key])
            for key in ["klee_flags", "extra_cflags", "extra_includes", "spine_override", "klee_assumes"]:
                if key in raw and isinstance(raw[key], list):
                    cfg[key] = raw[key]
            for key in ["struct_field_values", "stub_returns"]:
                if key in raw and isinstance(raw[key], dict):
                    cfg[key] = raw[key]
            cfg["loaded_files"].append("config.json")
            print(f"    [+] config.json: mode={cfg['mode']}, klee_timeout={cfg['klee_timeout']}, "
                  f"{len(cfg['klee_flags'])} klee_flags, {len(cfg['klee_assumes'])} assumes")
        except Exception as e:
            print(f"    [!] config.json parse error: {e}")

    # --- constraints.json (alternative/supplement to config.json for constraints) ---
    constraints_path = d / "constraints.json"
    if constraints_path.exists():
        try:
            raw = json.loads(constraints_path.read_text(encoding="utf-8"))
            if "entry_override" in raw and not cfg["entry_override"]:
                cfg["entry_override"] = raw["entry_override"]
            if "spine_override" in raw and not cfg["spine_override"]:
                cfg["spine_override"] = raw["spine_override"]
            for key in ["struct_field_values", "stub_returns"]:
                if key in raw and isinstance(raw[key], dict):
                    cfg[key].update(raw[key])
            if "klee_assumes" in raw and isinstance(raw["klee_assumes"], list):
                cfg["klee_assumes"].extend(raw["klee_assumes"])
            cfg["loaded_files"].append("constraints.json")
            print(f"    [+] constraints.json: {len(cfg['struct_field_values'])} field values, "
                  f"{len(cfg['klee_assumes'])} assumes, {len(cfg['stub_returns'])} stub overrides")
        except Exception as e:
            print(f"    [!] constraints.json parse error: {e}")

    # --- Text / binary files ---
    text_files = {
        "analyst_notes.md": "analyst_notes",
        "crash_output.txt": "crash_output",
        "seed_driver.c":    "seed_driver",
        "seed_stubs.c":     "seed_stubs",
        "seed_harness.c":   "seed_harness",
        "extra_stubs.c":    "extra_stubs",
    }
    for fname, cfg_key in text_files.items():
        fpath = d / fname
        if fpath.exists():
            try:
                cfg[cfg_key] = fpath.read_text(encoding="utf-8")
                cfg["loaded_files"].append(fname)
                lines = cfg[cfg_key].count('\n') + 1
                print(f"    [+] {fname}: {lines} lines")
            except Exception as e:
                print(f"    [!] {fname} read error: {e}")

    # --- PoC input binary ---
    poc_path = d / "poc_input.bin"
    if poc_path.exists():
        cfg["poc_input_path"] = str(poc_path)
        cfg["loaded_files"].append("poc_input.bin")
        print(f"    [+] poc_input.bin: {poc_path.stat().st_size} bytes")

    # Summarize
    if cfg["loaded_files"]:
        print(f"  [SE-Config] Loaded {len(cfg['loaded_files'])} files: {', '.join(cfg['loaded_files'])}")
        if cfg["mode"] == "verify":
            print(f"  [SE-Config] MODE: VERIFY — agent will try to reproduce a known bug")
        elif cfg["analyst_notes"]:
            print(f"  [SE-Config] Analyst notes will be injected into agent context")
    else:
        print(f"  [SE-Config] Directory exists but no recognized files found")

    return cfg

# ---------------------------------------------------------------------------
# Globals & Helpers
# ---------------------------------------------------------------------------
_TOKEN_TOTAL = 0
_TOKEN_PROMPT = 0
_TOKEN_COMPLETION = 0

def _update_tokens(resp):
    global _TOKEN_TOTAL, _TOKEN_PROMPT, _TOKEN_COMPLETION
    u = getattr(resp, "usage", None)
    if u:
        _TOKEN_PROMPT += getattr(u, "prompt_tokens", 0)
        _TOKEN_COMPLETION += getattr(u, "completion_tokens", 0)
        _TOKEN_TOTAL = _TOKEN_PROMPT + _TOKEN_COMPLETION

def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True); return p

def read_json(path: Path) -> Any:
    try: return json.loads(path.read_text(encoding="utf-8"))
    except: return None

def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")

def run_cmd(cmd, cwd=None, timeout=120, env=None, stream=False) -> Tuple[int, str, str, float]:
    t0 = time.time()
    try:
        if stream:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=cwd, env=env, bufsize=1
            )
            lines = []
            try:
                for line in proc.stdout:
                    lines.append(line)
                    stripped = line.strip()
                    if stripped and any(k in stripped for k in [
                        "KLEE:", "SAILOR_PROBE", "SAILOR_TRAP", "SAILOR_SUSPECT",
                        "memory error", "Error:", "WARNING"
                    ]):
                        print(f"    {stripped}")
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return -1, "".join(lines), "TIMEOUT", time.time() - t0
            finally:
                # Properly close pipes to avoid sys.unraisablehook exceptions
                try:
                    if proc.stdout:
                        proc.stdout.close()
                    if proc.stderr:
                        proc.stderr.close()
                except Exception:
                    pass
            return proc.returncode, "".join(lines), "", time.time() - t0
        else:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env)
            return r.returncode, r.stdout, r.stderr, time.time() - t0
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT", time.time() - t0
    except Exception as e:
        return -1, "", str(e), time.time() - t0

def find_llvm14_tool(name: str) -> str:
    for p in [f"/usr/lib/llvm-14/bin/{name}", f"{name}-14", name]:
        if shutil.which(p): return p
    return name

# ---------------------------------------------------------------------------
# Build Header Generation — fix missing configure-produced headers
# ---------------------------------------------------------------------------
def _generate_build_headers(src_root: Path) -> None:
    """Generate missing headers from .h.in / .h.cmake.in templates.

    Many C projects produce headers via configure/cmake (e.g. xmlversion.h).
    When we copy the raw source tree these are absent, breaking compilation.
    This generates *good-enough* headers for KLEE by substituting safe defaults.
    """
    templates_found = 0
    headers_generated = 0

    # Collect all template files
    templates: List[Path] = []
    for pat in ("**/*.h.in", "**/*.h.cmake.in"):
        templates.extend(src_root.glob(pat))

    for tpl in templates:
        templates_found += 1
        # Compute output path: strip .cmake.in or .in suffix
        rel = tpl.relative_to(src_root)
        rel_str = str(rel)
        if rel_str.endswith(".cmake.in"):
            out_rel = rel_str[: -len(".cmake.in")]
        elif rel_str.endswith(".h.in"):
            out_rel = rel_str[: -len(".in")]
        else:
            continue

        out_path = src_root / out_rel
        if out_path.exists():
            continue  # already present — don't overwrite

        try:
            content = tpl.read_text(errors="replace")
        except Exception:
            continue

        # --- Substitutions ---
        # 1) #cmakedefine01 HAVE_XXX  →  #define HAVE_XXX 0
        content = re.sub(
            r'^[ \t]*#\s*cmakedefine01\s+(\w+)',
            r'#define \1 0',
            content, flags=re.MULTILINE,
        )
        # 2) #cmakedefine HAVE_XXX ...  →  /* #undef HAVE_XXX */
        content = re.sub(
            r'^[ \t]*#\s*cmakedefine\s+(\w+).*',
            r'/* #undef \1 */',
            content, flags=re.MULTILINE,
        )
        # 3) Known version variables
        content = content.replace("@VERSION@", '"0.0.0"')
        content = content.replace("@PACKAGE_VERSION@", '"0.0.0"')
        content = content.replace("@PACKAGE_NAME@", '"project"')
        content = content.replace("@PACKAGE_STRING@", '"project 0.0.0"')
        content = content.replace("@PACKAGE_TARNAME@", '"project"')
        content = content.replace("@PACKAGE_URL@", '""')
        content = content.replace("@PACKAGE_BUGREPORT@", '""')
        # Numeric version tokens (common in libxml2, etc.)
        content = content.replace("@LIBXML_VERSION_NUMBER@", "0")
        content = content.replace("@LIBXML_MAJOR_VERSION@", "0")
        content = content.replace("@LIBXML_MINOR_VERSION@", "0")
        content = content.replace("@LIBXML_MICRO_VERSION@", "0")
        # 4) Catch-all: remaining @VAR@ → empty string
        content = re.sub(r'@[A-Za-z_][A-Za-z0-9_]*@', '""', content)

        # Write the generated header
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8")
        headers_generated += 1
        print(f"    [i] Generated header: {out_rel} (from {rel})")

    if templates_found:
        print(f"  [i] Build headers: {templates_found} templates found, {headers_generated} headers generated")


# ---------------------------------------------------------------------------
# LLM Interface
# ---------------------------------------------------------------------------
def call_llm(system: str, messages: List[Dict], out_dir: Path, tag: str) -> Dict:
    import openai
    client = openai.OpenAI(
        api_key=os.environ.get("LLM_API_KEY", os.environ.get("OPENAI_API_KEY", "")),
        base_url=os.environ.get("LLM_API_BASE", ""),
    )
    model = os.environ.get("LLM_MODEL", "")
    max_tokens = int(os.environ.get("LLM_MAX_TOKENS", "8192"))
    temperature = float(os.environ.get("LLM_TEMPERATURE", "0.2"))
    max_retries = int(os.environ.get("LLM_MAX_RETRIES", "5"))

    # Newer OpenAI models (o1, o3, gpt-5) have restricted parameters
    _restricted_model = any(k in model for k in ("o1", "o3", "gpt-5"))
    _extra_kwargs: Dict = {}
    if _restricted_model:
        _extra_kwargs["max_completion_tokens"] = max_tokens
        # These models only support temperature=1; omit the parameter
    else:
        _extra_kwargs["max_tokens"] = max_tokens
        _extra_kwargs["temperature"] = temperature
        # Request JSON output for models that support it (reduces parse failures)
        _extra_kwargs["response_format"] = {"type": "json_object"}

    def _try_parse_json(text: str) -> Optional[Dict]:
        """Attempt to extract a JSON object from LLM response text."""
        clean = text.strip()
        if "```json" in clean: clean = clean.split("```json")[1].split("```")[0]
        elif "```" in clean: clean = clean.split("```")[1].split("```")[0]
        s, e = clean.find('{'), clean.rfind('}')
        if s != -1 and e != -1:
            json_str = clean[s:e+1]
            try: return json.loads(json_str)
            except: pass
            # Fallback: escape unescaped control characters in string values
            try:
                fixed = re.sub(r'(?<=": ")(.*?)(?="[,}\s])',
                    lambda m: m.group().replace('\n', '\\n').replace('\t', '\\t').replace('\r', '\\r'),
                    json_str)
                return json.loads(fixed)
            except: pass
        return None

    last_err = None
    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=model, messages=[{"role": "system", "content": system}] + messages,
                **_extra_kwargs,
            )
            _update_tokens(resp)
            raw = resp.choices[0].message.content or ""
            try:
                ensure_dir(out_dir)
                (out_dir / f"{tag}_raw.txt").write_text(raw, encoding="utf-8")
            except Exception:
                pass  # Non-fatal: don't crash if we can't save debug output

            # --- Inner retry loop for JSON parse failures ---
            # Up to 3 attempts (original + 2 retries) within the same API turn
            cur_raw = raw
            cur_messages = list(messages)
            for json_retry in range(3):
                parsed = _try_parse_json(cur_raw)
                if parsed is not None:
                    return parsed

                # JSON parse failed — retry with explicit instruction
                if json_retry < 2:
                    print(f"  [!] JSON parse failed (attempt {json_retry+1}/3), retrying...")
                    cur_messages = cur_messages + [
                        {"role": "assistant", "content": cur_raw},
                        {"role": "user", "content": (
                            "ERROR: Your response was not valid JSON. "
                            "Respond ONLY with a JSON object: "
                            '{"thought": "...", "tool": "ToolName", "args": {...}}'
                        )},
                    ]
                    resp = client.chat.completions.create(
                        model=model,
                        messages=[{"role": "system", "content": system}] + cur_messages,
                        **_extra_kwargs,
                    )
                    _update_tokens(resp)
                    cur_raw = resp.choices[0].message.content or ""
                    try:
                        (out_dir / f"{tag}_retry{json_retry+1}_raw.txt").write_text(cur_raw, encoding="utf-8")
                    except Exception:
                        pass
                    continue

                # All retries exhausted
                return {"error": "No valid JSON found", "raw": cur_raw[:500]}

        except Exception as e:
            last_err = e
            err_str = str(e).lower()

            # Quota exhaustion — abort immediately, don't waste turns
            if "insufficient_quota" in err_str or "billing" in err_str:
                print(f"  [!] LLM quota exhausted — aborting: {e}")
                return {"error": f"LLM quota exhausted: {e}"}

            # response_format not supported — retry without it
            if "response_format" in err_str or "unsupported parameter" in err_str:
                _extra_kwargs.pop("response_format", None)
                print(f"  [!] response_format not supported by {model}, retrying without it...")
                continue

            # Rate-limit (429) — longer adaptive backoff
            is_rate_limit = (
                "rate" in err_str and "limit" in err_str
                or "429" in err_str
                or "too many requests" in err_str
                or (hasattr(e, "status_code") and getattr(e, "status_code", 0) == 429)
            )
            if is_rate_limit:
                delay = min(60 * (2 ** attempt), 120)  # 60s, 120s, 120s, ...
                print(f"  [!] LLM rate-limited (attempt {attempt+1}/{max_retries}); backing off {delay}s...")
            else:
                delay = min(2 ** (attempt + 1), 30)
                print(f"  [!] LLM call attempt {attempt+1}/{max_retries} failed: {e}; retrying in {delay}s...")
            time.sleep(delay)

    return {"error": f"LLM call failed after {max_retries} retries: {last_err}"}

# ---------------------------------------------------------------------------
# KLEE Runtime Crash Resolution
# ---------------------------------------------------------------------------
# KLEE's Freestanding runtime reimplements memcpy/memset/memmove.  When an OOB
# access happens inside one of these wrappers the .err file reports the crash in
# e.g. runtime/Freestanding/memcpy.c:17 — not in the actual source caller.  The
# stack trace in the .err file *does* contain the real caller, so we parse it and
# resolve the crash location to the first non-runtime, non-driver frame.

_KLEE_RUNTIME_DIRS = {"runtime", "Freestanding"}
_KLEE_RUNTIME_FILES = {"memcpy.c", "memset.c", "memmove.c", "memcmp.c",
                       "strlen.c", "strncmp.c", "strcmp.c", "strnlen.c"}
_HARNESS_SKIP_FILES = {"driver.c", "stubs.c", "smart_stubs.c", "auto_stubs.c"}

def _is_klee_runtime_crash(crash_file: str) -> bool:
    """Return True if the crash file is a KLEE runtime wrapper."""
    parts = crash_file.replace("\\", "/").split("/")
    basename = parts[-1] if parts else ""
    return (basename in _KLEE_RUNTIME_FILES or
            any(d in parts for d in _KLEE_RUNTIME_DIRS))


def _resolve_runtime_caller(err_content: str) -> tuple:
    """Parse the .err stack trace to find the first real source-code caller.

    Returns (caller_file, caller_line) or ("", 0) if not found.
    The stack trace looks like:
        #000000134 in memcpy(...) at runtime/Freestanding/memcpy.c:17
        #100000042 in av_adts_header_parse(...) at adts_parser.c:54
        #200000069 in entry_func(...) at adts_parser.c:71
        #300000098 in main() at driver.c:17
    We want frame #1 (first non-runtime, non-driver frame).
    """
    stack_re = re.compile(
        r'#\d+\s+in\s+\S+\(.*?\)\s+at\s+(\S+):(\d+)'
    )
    frames = stack_re.findall(err_content)
    for src, line in frames:
        basename = os.path.basename(src)
        if basename in _KLEE_RUNTIME_FILES or basename in _HARNESS_SKIP_FILES:
            continue
        # Skip frames in runtime directories
        if _is_klee_runtime_crash(src):
            continue
        return src, int(line)
    return "", 0


# KLEE Runner & Diagnosis
# ---------------------------------------------------------------------------
def run_klee(bc_path: Path, klee_bin: str, flags: List[str], timeout: int,
             log_dir: Path, run_id: int, frozen: Dict = None, harness_dir: Path = None) -> Dict:
    out_dir = log_dir / f"klee_run_{run_id}"
    if out_dir.exists(): shutil.rmtree(out_dir)
    
    flag_str = " ".join(flags)
    defaults = [
        f"--output-dir={out_dir}",
        f"--max-time={timeout}s",
        "--write-kqueries",
        "--write-smt2s",
        "--optimize",
        "--search=random-path", "--search=dfs",
        "--only-output-states-covering-new",
        "--external-calls=all",
        "--check-overshift",
        "--max-depth=1000",  # Limit path depth to prevent infinite loop explosion
    ]
    if "--max-memory" not in flag_str:
        defaults.append("--max-memory=2048")
    
    cmd = [klee_bin] + defaults + flags + [str(bc_path)]
    
    print(f"    [KLEE] Running: timeout={timeout}s")
    print(f"    [KLEE] Command: {' '.join(cmd)}")
    rc, stdout, stderr, elapsed = run_cmd(cmd, timeout=timeout + 30, stream=True)
    full_log = stdout + "\n" + stderr
    ensure_dir(log_dir)
    (log_dir / f"klee_{run_id}.log").write_text(full_log, encoding="utf-8")
    
    print(f"    [KLEE] Exit code: {rc}, Elapsed: {elapsed:.1f}s")
    print(f"    [KLEE] Log saved: {log_dir / f'klee_{run_id}.log'}")
    
    stats = {"rc": rc, "elapsed": elapsed, "out_dir": str(out_dir), "bug_found": False}
    
    # --- Parse .err files (KLEE-detected crashes) ---
    err_files = sorted(out_dir.glob("*.err")) if out_dir.exists() else []
    if err_files:
        stats["bug_found"] = True
        stats["total_errors"] = len(err_files)
        
        # --- PRIORITIZE: real code crashes > driver/stubs crashes ---
        # Parse ALL .err files, classify each, pick the best primary crash.
        # Priority: 1. crash in harness source (real bug)
        #           2. crash from assert (sink reached)
        #           3. crash in driver.c/stubs.c (harness bug)
        all_crashes = []
        for ef in err_files:
            ec = ef.read_text(errors="replace")
            stem_parts = ef.stem.split(".")
            ctype = stem_parts[-1] if len(stem_parts) > 1 else "unknown"
            mf = re.search(r'File:\s*(\S+)', ec)
            ml = re.search(r'Line:\s*(\d+)', ec)
            crash_file = mf.group(1).strip() if mf else ""
            crash_line = int(ml.group(1)) if ml else 0
            crash_basename = os.path.basename(crash_file)

            # If crash is in KLEE runtime (memcpy/memset/memmove), resolve
            # to the actual source-level caller via the stack trace.
            resolved_from_runtime = False
            if _is_klee_runtime_crash(crash_file) and ctype in ("ptr", "div", "free"):
                caller_file, caller_line = _resolve_runtime_caller(ec)
                if caller_file:
                    print(f"    [KLEE] Resolved runtime crash {crash_basename}:{crash_line}"
                          f" → {os.path.basename(caller_file)}:{caller_line}")
                    crash_file = caller_file
                    crash_line = caller_line
                    crash_basename = os.path.basename(crash_file)
                    resolved_from_runtime = True

            # Classify priority
            if crash_basename in _HARNESS_SKIP_FILES:
                priority = 3  # lowest — harness/driver bug
            elif ctype == "assert":
                priority = 1  # assertion (sink reached)
            elif ctype in ("ptr", "div", "free"):
                priority = 0  # highest — real memory error in source
            else:
                priority = 2

            all_crashes.append({
                "err_file": ef, "content": ec, "crash_type": ctype,
                "crash_file": crash_file, "crash_line": crash_line,
                "crash_basename": crash_basename, "priority": priority,
                "resolved_from_runtime": resolved_from_runtime,
            })
        
        # Sort by priority (lowest number = highest priority)
        all_crashes.sort(key=lambda x: (x["priority"], x["err_file"].name))
        primary = all_crashes[0]
        
        stats["crash_type"] = primary["crash_type"]
        stats["error_file"] = primary["crash_file"]
        stats["error_line"] = primary["crash_line"]
        stats["ktest_file"] = str(primary["err_file"]).replace(".err", ".ktest")
        stats["diagnosis"] = f"CRASH: {primary['crash_type']} at {primary['crash_file']}:{primary['crash_line']}"
        
        # Log if we deprioritized a driver crash in favor of a real crash
        if all_crashes[0]["priority"] < 3 and any(c["priority"] == 3 for c in all_crashes):
            driver_crashes = [c for c in all_crashes if c["priority"] == 3]
            print(f"    [KLEE] Note: {len(driver_crashes)} driver crash(es) deprioritized in favor of real crash at {primary['crash_file']}:{primary['crash_line']}")
        
        # Store all crashes for comprehensive reporting
        stats["all_crashes"] = all_crashes
    
    # --- Parse counters from KLEE log ---
    for pattern, key in [
        (r'KLEE: done: total instructions = (\d+)', 'total_instructions'),
        (r'KLEE: done: completed paths = (\d+)', 'completed_paths'),
        (r'KLEE: done: generated tests = (\d+)', 'generated_tests'),
    ]:
        m = re.search(pattern, full_log)
        if m: stats[key] = int(m.group(1))
    
    # --- Parse warnings.txt (SAILOR probes + external calls) ---
    warns = ""
    warns_path = out_dir / "warnings.txt"
    if warns_path.exists():
        warns = warns_path.read_text(errors="replace")
    
    # --- Parse messages.txt ---
    msgs = ""
    msgs_path = out_dir / "messages.txt"
    if msgs_path.exists():
        msgs = msgs_path.read_text(errors="replace")
    
    # Combine warns + msgs for probe detection (not full_log which duplicates KLEE output)
    probe_text = warns + "\n" + msgs
    
    # --- SINK DETECTION: 3-STATE MODEL ---
    # State 1: SITE_REACHED — klee_assert(SAILOR_SINK_REACHED) fired
    #   → Proves the vulnerability site is reachable, but no crash occurred
    #   → The vulnerable statement DIDN'T trigger a bug (possible FP)
    #   → klee_assert fires AFTER the vulnerable statement, so if we get here
    #     it means the statement executed WITHOUT crashing
    #
    # State 2: BUG_TRIGGERED — KLEE .ptr.err/.div.err near the SAILOR_SINK_REACHED line
    #   → The vulnerable statement CRASHED before reaching klee_assert
    #   → This is the actual bug! Send to concrete validation.
    #   → Detection: .err file at harness line within ±10 of the assert line
    #
    # State 3: NOT_REACHED — neither signal fired
    #   → Fix driver/stubs to reach the vulnerability site
    #
    # NOTE on klee_check_memory_access: REMOVED. It requires constant (non-symbolic)
    # args and fails with "requires constant args" when pointer is symbolic.
    # Instead, the actual vulnerable statement (e.g., cur[0], cur[1]) triggers
    # KLEE's native OOB detection, which works with symbolic pointers.
    
    probe_text = warns + "\n" + msgs
    all_text = warns + "\n" + msgs + "\n" + full_log
    
    probe_hits = {
        "SINK": probe_text.count("SAILOR_PROBE_SINK"),
        "RUNG_1": probe_text.count("SAILOR_PROBE_RUNG_1"),
        "RUNG_2": probe_text.count("SAILOR_PROBE_RUNG_2"),
        "TRAP": probe_text.count("SAILOR_TRAP"),
        "SUSPECT_HIT": probe_text.count("SAILOR_SUSPECT_HIT"),
    }
    
    # --- Locate the SAILOR_SINK_REACHED assert line in the harness ---
    # harness_dir is passed directly from HarnessTools (no guessing needed)
    sink_assert_line = 0
    if harness_dir and Path(harness_dir).exists():
        for hf in sorted(Path(harness_dir).glob("*.c")):
            if hf.name in ("driver.c", "stubs.c", "smart_stubs.c", "auto_stubs.c"):
                continue
            try:
                for i, line in enumerate(hf.read_text(errors="replace").split('\n'), 1):
                    if 'SAILOR_SINK_REACHED' in line:
                        sink_assert_line = i
                        break
            except Exception:
                pass
            if sink_assert_line:
                break
    
    # --- State 1: SITE_REACHED (klee_assert fired) ---
    site_reached = False
    sink_assert_hit = "SAILOR_SINK_REACHED" in all_text
    if not sink_assert_hit and out_dir.exists():
        for assert_err in out_dir.glob("*.assert.err"):
            try:
                content = assert_err.read_text(errors="replace")
                if "SAILOR_SINK_REACHED" in content:
                    sink_assert_hit = True
                    break
            except Exception:
                pass
    if sink_assert_hit:
        site_reached = True
    
    # --- State 2: BUG_TRIGGERED (KLEE crash near the sink assert line) ---
    bug_triggered = False
    bug_triggered_details = ""
    if out_dir.exists() and sink_assert_line > 0:
        # Determine which file contains the sink assertion (the harness spine file)
        sink_file = ""
        if harness_dir:
            vul_file_base = os.path.basename(frozen.get("vul_file", "")) if frozen else ""
            if vul_file_base:
                sink_file = vul_file_base
        
        for err_pattern in ("*.ptr.err", "*.div.err", "*.free.err"):
            for ef in out_dir.glob(err_pattern):
                try:
                    content = ef.read_text(errors="replace")
                    m_line = re.search(r'Line:\s*(\d+)', content)
                    m_file = re.search(r'File:\s*(\S+)', content)
                    if m_line:
                        err_line = int(m_line.group(1))
                        err_file_full = m_file.group(1).strip() if m_file else ""
                        err_file = os.path.basename(err_file_full)

                        # If crash is in KLEE runtime (memcpy/memset/memmove),
                        # resolve to the actual caller in harness source
                        if _is_klee_runtime_crash(err_file_full):
                            caller_file, caller_line = _resolve_runtime_caller(content)
                            if caller_file:
                                err_file = os.path.basename(caller_file)
                                err_line = caller_line

                        # Must be in the HARNESS file (not driver.c/stubs.c)
                        if err_file in _HARNESS_SKIP_FILES:
                            continue

                        # If we know the sink file, check it matches
                        if sink_file and err_file and err_file != sink_file:
                            continue

                        # Crash within ±10 lines of the sink assert = bug triggered
                        if abs(err_line - sink_assert_line) <= 10:
                            err_type = ef.suffix.replace('.err', '').replace('.', '')
                            bug_triggered = True
                            bug_triggered_details = f"KLEE {err_type} error at line {err_line} (sink assert at {sink_assert_line})"
                            break
                except Exception:
                    pass
            if bug_triggered:
                break
    
    # Also check: if no sink_assert_line found, fall back to resolve_vul_line
    if not bug_triggered and out_dir.exists() and not sink_assert_line:
        # Fallback 1: Search for SAILOR markers
        try:
            for hf in (Path(harness_dir) if harness_dir else Path("/dev/null")).glob("*.c"):
                if hf.name in ("driver.c", "stubs.c", "smart_stubs.c"):
                    continue
                hsrc = hf.read_text(errors="replace")
                for marker in ['SAILOR_PROBE_SINK', 'SAILOR_SUSPECT_HIT']:
                    for i, line in enumerate(hsrc.split('\n'), 1):
                        if marker in line:
                            sink_assert_line = i
                            break
                    if sink_assert_line:
                        break
                if sink_assert_line:
                    break
        except Exception:
            pass
        
        # Fallback 2: No markers at all — use frozen plan to identify the crash
        # as being at the vulnerability site. Match .err crash lines against
        # the harness code near vulnerability keywords from frozen plan.
        if not sink_assert_line and frozen:
            try:
                vul_func = frozen.get("vul_func", "")
                src_ctx = frozen.get("source_context", "")
                goto_targets = frozen.get("goto_targets", [])
                
                # Build set of distinctive code patterns from the vulnerability
                vuln_patterns = set()
                if src_ctx:
                    for ctx_line in src_ctx.split('\n'):
                        stripped = re.sub(r'^\d+:\s*', '', ctx_line).strip()
                        if stripped and len(stripped) > 10 and not stripped.startswith(('//', '/*', '*')):
                            vuln_patterns.add(stripped)
                for gt in (goto_targets if isinstance(goto_targets, list) else []):
                    label = gt if isinstance(gt, str) else gt.get("label", "")
                    if label:
                        vuln_patterns.add(f"{label}:")
                
                # Read the harness and find lines matching vulnerability patterns
                vuln_region_lines = set()  # harness line numbers in vuln region
                if harness_dir:
                    for hf in Path(harness_dir).glob("*.c"):
                        if hf.name in ("driver.c", "stubs.c", "smart_stubs.c"):
                            continue
                        hlines = hf.read_text(errors="replace").split('\n')
                        for i, hl in enumerate(hlines, 1):
                            stripped = hl.strip()
                            for pat in vuln_patterns:
                                if pat in stripped:
                                    # Mark ±15 lines as vulnerability region
                                    for j in range(max(1, i-15), min(len(hlines)+1, i+16)):
                                        vuln_region_lines.add(j)
                                    break
                
                # Check if any .err crash line falls in the vulnerability region
                if vuln_region_lines:
                    for err_pattern in ("*.ptr.err", "*.div.err", "*.free.err"):
                        for ef in out_dir.glob(err_pattern):
                            try:
                                content = ef.read_text(errors="replace")
                                m_line = re.search(r'Line:\s*(\d+)', content)
                                m_file2 = re.search(r'File:\s*(\S+)', content)
                                if m_line:
                                    err_line = int(m_line.group(1))
                                    err_file2 = m_file2.group(1).strip() if m_file2 else ""
                                    # Resolve KLEE runtime crashes
                                    if _is_klee_runtime_crash(err_file2):
                                        cf, cl = _resolve_runtime_caller(content)
                                        if cf:
                                            err_line = cl
                                    if err_line in vuln_region_lines:
                                        err_type = ef.suffix.replace('.err', '').replace('.', '')
                                        bug_triggered = True
                                        bug_triggered_details = f"KLEE {err_type} error at line {err_line} (in vulnerability region, pattern-matched from frozen plan)"
                                        print(f"    [KLEE] *** BUG TRIGGERED (pattern match) — {bug_triggered_details} ***")
                                        break
                            except Exception:
                                pass
                        if bug_triggered:
                            break
            except Exception:
                pass
        
        # Retry with found marker line
        if not bug_triggered and sink_assert_line > 0:
            for err_pattern in ("*.ptr.err", "*.div.err", "*.free.err"):
                for ef in out_dir.glob(err_pattern):
                    try:
                        content = ef.read_text(errors="replace")
                        m_line = re.search(r'Line:\s*(\d+)', content)
                        m_file3 = re.search(r'File:\s*(\S+)', content)
                        if m_line:
                            err_line = int(m_line.group(1))
                            err_file3 = m_file3.group(1).strip() if m_file3 else ""
                            # Resolve KLEE runtime crashes
                            if _is_klee_runtime_crash(err_file3):
                                cf, cl = _resolve_runtime_caller(content)
                                if cf:
                                    err_line = cl
                            if abs(err_line - sink_assert_line) <= 10:
                                err_type = ef.suffix.replace('.err', '').replace('.', '')
                                bug_triggered = True
                                bug_triggered_details = f"KLEE {err_type} error at line {err_line} (sink marker at {sink_assert_line})"
                                break
                    except Exception:
                        pass
                if bug_triggered:
                    break
    
    # --- Legacy: SAILOR_PROBE_SINK warning ---
    if probe_hits["SINK"] > 0:
        site_reached = True
    
    # --- Populate stats ---
    stats["probe_hits"] = probe_hits
    stats["site_reached"] = site_reached or bug_triggered
    stats["bug_triggered"] = bug_triggered
    stats["bug_triggered_details"] = bug_triggered_details
    stats["sink_assert_line"] = sink_assert_line
    # Keep sink_reached for backward compat (= site_reached OR bug_triggered)
    stats["sink_reached"] = site_reached or bug_triggered
    
    # Print results
    active_probes = {k: v for k, v in probe_hits.items() if v > 0}
    if active_probes:
        print(f"    [KLEE] SAILOR probes: {active_probes}")
    if bug_triggered:
        print(f"    [KLEE] *** BUG TRIGGERED — {bug_triggered_details} ***")
        print(f"    [KLEE] Send to concrete validation.")
    elif site_reached:
        print(f"    [KLEE] Site reached (klee_assert fired) but NO crash at vulnerable statement.")
        print(f"    [KLEE] The vulnerable code executed without error — possible FP or needs different input.")
    if stats["bug_found"]:
        print(f"    [KLEE] Crash: {stats.get('diagnosis', 'unknown')}")
    
    # --- Build diagnostics ---
    diagnostics = []
    
    if bug_triggered:
        diagnostics.append(f"BUG TRIGGERED: {bug_triggered_details}")
    elif site_reached:
        diagnostics.append(f"SITE REACHED (klee_assert fired) but no crash at vulnerable statement.")
    
    if probe_hits["RUNG_1"] or probe_hits["RUNG_2"]:
        diagnostics.append(f"Probe ladder: RUNG_1={probe_hits['RUNG_1']}, RUNG_2={probe_hits['RUNG_2']}")
    
    if "external call" in warns:
        missing = set(re.findall(r'calling external: (\w+)', warns))
        diagnostics.append(f"EXTERNAL CALLS (needs stubs): {', '.join(sorted(missing)[:15])}")
    
    if "memory error" in msgs or "memory error" in full_log:
        diagnostics.append("MEMORY ERROR detected by KLEE.")
    
    if not stats["bug_found"] and not stats["sink_reached"]:
        if stats.get("completed_paths", 0) == 0:
            diagnostics.append("CRITICAL: 0 paths explored. Driver likely exits before reaching target.")
        if rc != 0:
            diagnostics.append("KLEE EXIT ERROR (non-zero rc).")
    
    stats["diagnostics_summary"] = "; ".join(diagnostics)
    stats["warnings_text"] = warns[:2000]
    stats["messages_text"] = msgs[:2000]
    
    # --- SPINE COVERAGE ANALYSIS (from instrumented probes) ---
    # The spine functions have klee_warning_once("SPINE_PROBE:func:EVENT") probes.
    # These appear in warnings.txt when KLEE actually executes them.
    # This is 100% reliable — no istats parsing needed.
    if frozen and out_dir.exists():
        spine = frozen.get("spine", [])
        vul_func = frozen.get("vul_func", "")
        
        # Collect all SPINE_PROBE hits from warnings.txt and KLEE log
        all_text = warns + "\n" + msgs + "\n" + full_log
        probe_re = re.compile(r'SPINE_PROBE:(\w+):(\w+)')
        spine_hits = {}  # func -> set of events
        for m in probe_re.finditer(all_text):
            fn, event = m.group(1), m.group(2)
            spine_hits.setdefault(fn, set()).add(event)
        
        if spine_hits or spine:
            cov_parts = []
            for fn in spine:
                if fn in spine_hits:
                    events = sorted(spine_hits[fn])
                    cov_parts.append(f"{fn}: REACHED [{', '.join(events)}]")
                else:
                    cov_parts.append(f"{fn}: NOT REACHED")
            
            cov_msg = f"SPINE COVERAGE: {' | '.join(cov_parts)}"
            stats["spine_coverage"] = spine_hits
            diagnostics.append(cov_msg)
            print(f"    [KLEE] {cov_msg}")
            
            # Specific guidance based on what was/wasn't reached
            reached_funcs = [fn for fn in spine if fn in spine_hits]
            not_reached = [fn for fn in spine if fn not in spine_hits]
            
            if not_reached:
                if vul_func in not_reached:
                    if stats.get("bug_triggered"):
                        # Bug was actually triggered (ptr.err near sink) — probe just didn't fire
                        diagnostics.append(
                            f"NOTE: Spine probe for {vul_func} didn't fire, but "
                            f"bug_triggered=True. KLEE crashed at the vulnerable statement "
                            f"before the probe could execute.")
                    elif stats.get("site_reached") and not stats.get("bug_triggered"):
                        # SINK ASSERT FIRED but vul_func probe didn't fire AND no bug triggered.
                        # This means the assert fired from a WRONG PATH — not the vulnerable code.
                        # Common causes:
                        # 1. Assert placed at end of function, fired from fall-through (loop skipped)
                        # 2. Assert in auto-generated intermediate skeleton, not in vul_func
                        # 3. Neutralized code has unsatisfiable guards (e.g., hashValue=0 contradiction)
                        diagnostics.append(
                            f"WARNING: SINK ASSERT FIRED but {vul_func} spine probe did NOT fire. "
                            f"This means klee_assert fired from a WRONG CODE PATH — the vulnerable "
                            f"statement was NOT actually executed. "
                            f"LIKELY CAUSES: (1) A loop/if guard in your harness has concrete values "
                            f"that make the vulnerable branch unsatisfiable (e.g., a variable is 0 but "
                            f"the loop requires it non-zero). (2) The sink assert is at the end of the "
                            f"function and fires from the fall-through/skip path, not the vulnerable path. "
                            f"FIX: Make loop/branch guard variables SYMBOLIC (not hardcoded concrete) so "
                            f"KLEE can explore the path into the vulnerable code. Ensure the sink assert "
                            f"is placed INSIDE the vulnerable branch, not after the function's closing brace.")
                    elif reached_funcs:
                        last = reached_funcs[-1]
                        events = sorted(spine_hits.get(last, set()))
                        
                        # Determine WHERE the call chain breaks
                        # Find the next spine function that should be called
                        last_idx = spine.index(last) if last in spine else -1
                        next_func = spine[last_idx + 1] if last_idx >= 0 and last_idx + 1 < len(spine) else vul_func
                        
                        diagnostics.append(
                            f"BLOCKED: Reached {last} ({', '.join(events)}) "
                            f"but {vul_func} NOT REACHED.")
                        diagnostics.append(
                            f"The call chain breaks at {last} → {next_func}. "
                            f"LIKELY CAUSE: The harness 'neutralized' {last} too aggressively, "
                            f"removing the call to {next_func}. "
                            f"FIX: In WriteHarness, ensure {last} CALLS {next_func}. "
                            f"Neutralization must KEEP calls to spine functions "
                            f"(remove only off-path code, NOT the call to the next spine function). "
                            f"Check the harness .c file for a call to {next_func}().")
                    else:
                        diagnostics.append(
                            f"TARGET {vul_func} NOT REACHED and no spine functions entered. "
                            f"Check driver — is it calling {spine[0] if spine else 'entry'}?")
            
            # Check if we reached the right switch case
            if vul_func in spine_hits:
                vf_events = spine_hits[vul_func]
                cases = [e for e in vf_events if e.startswith('CASE_')]
                labels = [e for e in vf_events if e.startswith('LABEL_')]
                
                # Get the required case and labels from the vulnerability summary
                sa_dir = out_dir.parent.parent / "sa_context"
                required_case = None
                required_labels = []
                try:
                    vs_path = sa_dir / "vulnerability_summary.json"
                    if vs_path.exists():
                        import json
                        vs = json.loads(vs_path.read_text(errors="replace"))
                        required_case = vs.get("enclosing_switch_case")
                        for gs in vs.get("goto_sources", []):
                            lbl = gs.get("label", "")
                            if lbl and lbl not in required_labels:
                                required_labels.append(lbl)
                except Exception:
                    pass
                
                if 'ENTRY' in vf_events and not cases and not labels:
                    diagnostics.append(
                        f"Entered {vul_func} but no switch cases or labels reached. "
                        f"KLEE is stuck at the function's early checks or while-loop guard.")
                    if required_case:
                        diagnostics.append(
                            f"REQUIRED: Set ctxt->instate = {required_case} to reach the vulnerable case.")
                elif cases:
                    reached_case_names = [c[5:] for c in cases]
                    
                    # Check if we reached the RIGHT case
                    if required_case and f"CASE_{required_case}" not in cases:
                        diagnostics.append(
                            f"WRONG CASE: Reached {', '.join(reached_case_names)} "
                            f"but vulnerability requires {required_case}. "
                            f"Fix driver: int sym_instate; klee_make_symbolic(&sym_instate, sizeof(sym_instate), \"instate\"); "
                            f"klee_assume(sym_instate == {required_case}); ctxt->instate = sym_instate;")
                    
                    # Check if we reached the vulnerability label
                    if required_labels:
                        reached_label_names = [l[6:] for l in labels]
                        missing_labels = [l for l in required_labels if l not in reached_label_names]
                        if missing_labels:
                            # Check if 'done' was reached (common early-exit label)
                            reached_label_names = [l[6:] for l in labels]
                            if 'done' in reached_label_names or 'xmldecl_done' in reached_label_names:
                                exit_label = [l for l in reached_label_names if 'done' in l][0]
                                diagnostics.append(
                                    f"EARLY EXIT: Reached '{exit_label}' label (early return) "
                                    f"but NOT '{', '.join(missing_labels)}' (vulnerability). "
                                    f"This means a condition BEFORE the vulnerability path failed. "
                                    f"Common causes:\n"
                                    f"  - input->end not set → avail = end - cur is garbage → early exit\n"
                                    f"  - Buffer too small → avail < threshold → goto done\n"
                                    f"  - Stub returns wrong value → branch goes to done instead of target\n"
                                    f"FIX: 1) Set input->end = content + buf_size in driver. "
                                    f"2) Make stub returns SYMBOLIC so KLEE can find triggering values.")
                            elif labels:
                                diagnostics.append(
                                    f"Reached label(s) {', '.join(reached_label_names)} "
                                    f"but NOT '{', '.join(missing_labels)}'. "
                                    f"Check stubs: functions on the path must return values "
                                    f"that trigger 'goto {missing_labels[0]}'. "
                                    f"COMMON FIX: Make the stub return SYMBOLIC (klee_make_symbolic) "
                                    f"instead of a hardcoded value, so KLEE can find the triggering value. "
                                    f"Also verify driver sets ALL pointer fields (especially input->end).")
                            else:
                                diagnostics.append(
                                    f"In case {', '.join(reached_case_names)} but no labels reached. "
                                    f"Need to reach '{', '.join(missing_labels)}'. "
                                    f"Check stubs: make critical stub returns SYMBOLIC, not hardcoded. "
                                    f"Also check driver: is input->end set? Is buffer large enough?")
                        elif required_labels and all(l in reached_label_names for l in required_labels):
                            diagnostics.append(
                                f"GOOD: Reached vulnerability label '{', '.join(required_labels)}'. "
                                f"But sink_reached=False — check if klee_assert probe is present.")
                    elif not labels:
                        diagnostics.append(
                            f"Reached case(s) {', '.join(reached_case_names)} in {vul_func} "
                            f"but no labels reached. Check stubs for correct return values.")
            
            stats["diagnostics_summary"] = "; ".join(diagnostics)
    
    # Print summary to console
    probe_hits = stats["probe_hits"]
    print(f"    [KLEE] Results: bug_found={stats['bug_found']}, sink_reached={stats['sink_reached']}, "
          f"paths={stats.get('completed_paths', 0)}, tests={stats.get('generated_tests', 0)}")
    if any(v > 0 for v in probe_hits.values()):
        print(f"    [KLEE] Probes: SINK={probe_hits['SINK']}, RUNG_1={probe_hits['RUNG_1']}, "
              f"RUNG_2={probe_hits['RUNG_2']}, TRAP={probe_hits['TRAP']}")
    if stats.get("bug_found"):
        print(f"    [KLEE] Crash: {stats.get('diagnosis', 'unknown')}")
    if diagnostics:
        print(f"    [KLEE] Diagnostics: {'; '.join(diagnostics)}")
    
    return stats

# ---------------------------------------------------------------------------
# Source Analysis Helpers  
# ---------------------------------------------------------------------------
def find_source_file(src_root: Path, name: str) -> Optional[Path]:
    for f in src_root.rglob(name):
        if ".git" not in str(f): return f
    base = os.path.basename(name)
    for f in src_root.rglob(base):
        if ".git" not in str(f): return f
    return None

def find_function_span(source: str, func_name: str) -> Optional[Tuple[int, int, int]]:
    type_pat = r'(?:static\s+|inline\s+|extern\s+|const\s+)*(?:\w+[\s*]+)*'
    pat = re.compile(rf'(?:^|\n)\s*{type_pat}{re.escape(func_name)}\s*\([^)]*\)\s*\{{', re.MULTILINE)
    m = pat.search(source)
    if not m: return None
    sig_start = m.start()
    if sig_start > 0 and source[sig_start] == '\n': sig_start += 1
    brace_start = source.index('{', m.start())
    depth, pos = 1, brace_start + 1
    while pos < len(source) and depth > 0:
        if source[pos] == '{': depth += 1
        elif source[pos] == '}': depth -= 1
        pos += 1
    return (sig_start, brace_start, pos)

def find_definition(src_root: Path, symbol: str) -> Optional[str]:
    """Find struct/union/enum definition in source tree. Returns definition text or None."""
    search_names = [symbol]
    if not symbol.startswith("_"):
        search_names.append(f"_{symbol}")
    else:
        search_names.append(symbol.lstrip("_"))
    
    for name in search_names:
        cmd = ["grep", "-rE", "-l", "--include=*.h", "--include=*.c",
               rf"(struct|union|enum)\s+{name}\s*\{{", str(src_root)]
        rc, out, _, _ = run_cmd(cmd, timeout=10)
        if rc == 0 and out:
            fpath = Path(out.strip().split('\n')[0])
            try:
                src_lines = fpath.read_text(errors="replace").splitlines()
                pat = re.compile(rf'(struct|union|enum)\s+{name}\s*\{{')
                for i, line in enumerate(src_lines):
                    if pat.search(line):
                        end = min(len(src_lines), i + 40)
                        return '\n'.join(src_lines[i:end])
            except Exception:
                pass
    return None

_SKIP_CALLS = frozenset({'if', 'while', 'for', 'switch', 'return', 'sizeof', 'typeof', 'case', 'goto', 'int', 'char', 'void', 'unsigned', 'long', 'short', 'float', 'double', 'struct', 'enum', 'union', 'const', 'static', 'inline', 'extern', 'klee_make_symbolic', 'klee_assume', 'klee_assert', 'main', 'memcpy', 'memset', 'memmove', 'strlen', 'strcmp', 'strncmp', 'strcpy', 'strncpy', 'malloc', 'calloc', 'realloc', 'free', 'printf', 'fprintf', 'snprintf', 'sprintf', 'abort', 'exit'})

def scan_function_calls(source_text: str, skip_funcs: set = None) -> List[str]:
    skip = _SKIP_CALLS | (skip_funcs or set())
    calls = set()
    for m in re.finditer(r'\b([a-zA-Z_]\w+)\s*\(', source_text):
        name = m.group(1)
        if name not in skip and (not name.startswith('_') or name.startswith('__')):
            calls.add(name)
    return sorted(calls)

def extract_compile_flags(sa_data: Dict, vul_file: str) -> Tuple[List[str], str]:
    """Extract compile flags AND build directory from compile_commands.json.
    Returns (flags_list, build_directory)."""
    cc = sa_data.get("compile_commands", [])
    vul_base = os.path.basename(vul_file)
    for entry in cc:
        if vul_base in (entry.get("file") or ""):
            args_list = entry.get("arguments") or []
            if not args_list and entry.get("command"): args_list = shlex.split(entry["command"])
            build_dir = entry.get("directory", "")
            flags = []
            skip_next = False
            for i, a in enumerate(args_list):
                if skip_next:
                    skip_next = False; continue
                # Skip: compiler binary, source file, -c, -o <output>, warning flags, optimization
                if i == 0: continue  # compiler binary
                if a == "-c" or a == "-fPIC": continue
                if a == "-o":
                    skip_next = True; continue
                if a.startswith(("-W", "-pedantic", "-O")): continue
                if a.endswith(".c") or a.endswith(".o"): continue
                # Keep: -D, -I, -include, -std, and anything else useful
                if a.startswith(("-I", "-D", "-include", "-std")):
                    # Resolve relative -I paths against build_dir
                    if a.startswith("-I") and len(a) > 2 and build_dir and not os.path.isabs(a[2:]):
                        a = "-I" + os.path.join(build_dir, a[2:])
                    elif a == "-I" and i + 1 < len(args_list):
                        val = args_list[i+1]
                        if build_dir and not os.path.isabs(val):
                            val = os.path.join(build_dir, val)
                        flags.extend(["-I", val])
                        skip_next = True
                        continue
                    flags.append(a)
            return flags, build_dir
    return [], ""

def build_source_file_index(sa_data: Dict, src_root: Path) -> List[str]:
    """Build a list of source/header files from compile_commands.json.
    This limits grep to only project-relevant files instead of rglob-ing the tree."""
    cc = sa_data.get("compile_commands", [])
    files = set()
    for entry in cc:
        f = entry.get("file", "")
        d = entry.get("directory", "")
        if f:
            fp = f if os.path.isabs(f) else os.path.join(d, f) if d else str(src_root / f)
            files.add(fp)
    return sorted(files)

def discover_include_paths(src_root: Path, sa_data: Dict = None) -> List[str]:
    """Get include paths. Use compile_commands -I flags first, rglob as fallback."""
    paths = set()
    # Priority 1: Extract -I paths from compile_commands (exact, fast)
    cc = (sa_data or {}).get("compile_commands", [])
    for entry in cc:
        args_list = entry.get("arguments") or []
        if not args_list and entry.get("command"):
            args_list = shlex.split(entry["command"])
        build_dir = entry.get("directory", "")
        for i, a in enumerate(args_list):
            if a.startswith("-I"):
                p = a[2:] if len(a) > 2 else (args_list[i+1] if i+1 < len(args_list) else "")
                if p:
                    if not os.path.isabs(p) and build_dir:
                        p = os.path.join(build_dir, p)
                    if os.path.isdir(p):
                        paths.add(p)
    
    if paths:
        return sorted(paths)[:20]
    
    # Fallback: rglob (slow but works when no compile_commands)
    for h in src_root.resolve().rglob("*.h"):
        if ".git" not in str(h): paths.add(str(h.parent.resolve()))
    return sorted(paths)[:20]

def load_spec(spec_path: str) -> Dict:
    """Load spec JSON to get SA-computed entry, spine, types, CWE."""
    if not spec_path or not Path(spec_path).exists():
        return {}
    spec = read_json(Path(spec_path))
    if spec:
        print(f"  [i] Spec loaded: {os.path.basename(spec_path)}")
    return spec or {}

def run_frozen_analysis(ctx: Dict, src_root: Path, spec: Dict = None) -> Dict:
    vul_file = ctx["vul_file"]
    vul_line = int(ctx["vul_line"])
    sa_data = ctx.get("sa_data", {})
    spec = spec or {}
    
    # Parse fact_pack — facts can be list OR dict depending on schema version
    fp = sa_data.get("fact_pack") or {}
    raw_facts = fp.get("facts", {})
    build_ctx = fp.get("build_context", {})
    
    # Normalize: if facts is a list of findings, index them by file/line
    facts_dict = {}  # keyed lookup
    facts_list = []  # raw list
    if isinstance(raw_facts, list):
        facts_list = raw_facts
        print(f"  [SA] fact_pack: {len(facts_list)} findings (list format)")
        # Extract any call chain / data flow info from findings
        for finding in facts_list:
            if isinstance(finding, dict):
                # Common SARIF-like fields
                for key in ["message", "path", "call_chain", "dataFlow", "codeFlows"]:
                    if key in finding:
                        facts_dict.setdefault(key, []).append(finding[key])
    elif isinstance(raw_facts, dict):
        facts_dict = raw_facts
        print(f"  [SA] fact_pack: dict format, keys={list(raw_facts.keys())[:10]}")
    
    # Also try to load findings.json (separate file with CodeQL results)
    findings_data = sa_data.get("findings", {})
    if isinstance(findings_data, list):
        for finding in findings_data:
            if isinstance(finding, dict) and finding.get("file") and finding.get("line"):
                facts_list.append(finding)
    
    # 1. Find vul_func from source
    vul_func = "unknown"
    src_file = find_source_file(src_root, vul_file)
    func_spans = {}
    if src_file:
        src = src_file.read_text(errors="replace")
        for m in re.finditer(r'^(\w+)\s*\(', src, re.MULTILINE):
            candidate = m.group(1)
            if candidate in ("if", "while", "for", "switch", "return"): continue
            span = find_function_span(src, candidate)
            if span:
                s_line = src[:span[0]].count("\n") + 1
                e_line = src[:span[2]].count("\n") + 1
                func_spans[candidate] = (s_line, e_line)
        for name, (s, e) in func_spans.items():
            if s <= vul_line <= e:
                vul_func = name
                break
    
    print(f"  [i] Vulnerable function: {vul_func}")
    
    # 2. Get spine from SA data (spec > fact_pack > source scan)
    spine = []
    entry = ""
    
    # Try spec JSON first
    for key in ["spine", "call_chain", "path"]:
        v = spec.get(key, [])
        if isinstance(v, list) and v:
            spine = v; break
    for key in ["entry", "entry_func", "entry_point"]:
        v = spec.get(key, "")
        if v: entry = v; break
    
    # Try facts_dict call graph (only if facts was a dict)
    if not entry and isinstance(facts_dict, dict):
        for key in ["call_graph", "calls", "callGraph"]:
            cg = facts_dict.get(key, None)
            if cg is None: continue
            if isinstance(cg, dict):
                for caller, callees in cg.items():
                    if isinstance(callees, list) and vul_func in callees:
                        entry = caller
                        print(f"  [SA] Entry from call graph: {entry}")
                        break
            elif isinstance(cg, list):
                for edge in cg:
                    if isinstance(edge, dict):
                        if edge.get("callee") == vul_func or edge.get("to") == vul_func:
                            entry = edge.get("caller") or edge.get("from", "")
                            if entry:
                                print(f"  [SA] Entry from call graph: {entry}")
                                break
            if entry: break
    
    # Try to extract entry from findings that match our vul_line
    if not entry and facts_list:
        for finding in facts_list:
            if not isinstance(finding, dict): continue
            fline = finding.get("line") or finding.get("startLine", 0)
            if int(fline) == vul_line or abs(int(fline) - vul_line) < 5:
                # This finding is about our vulnerability
                for key in ["caller", "entry", "enclosingFunction", "function"]:
                    v = finding.get(key, "")
                    if v and v != vul_func:
                        entry = v
                        print(f"  [SA] Entry from finding: {entry}")
                        break
            if entry: break
    
    # Fallback: source scan for callers
    if not entry and src_file and vul_func != "unknown":
        src = src_file.read_text(errors="replace")
        for fname, (s, e) in func_spans.items():
            if fname == vul_func: continue
            func_span = find_function_span(src, fname)
            if func_span:
                body = src[func_span[1]:func_span[2]]
                if re.search(rf'\b{re.escape(vul_func)}\s*\(', body):
                    entry = fname
                    print(f"  [i] Entry from source scan: {entry}")
                    break
    
    if not entry: entry = vul_func
    if not spine: spine = [entry, vul_func] if entry != vul_func else [vul_func]
    seen = set()
    spine = [x for x in spine if not (x in seen or seen.add(x))]
    
    # --- CRITICAL: Ensure entry point is PUBLIC (non-static) ---
    # A static entry function can't be called from driver.c across translation units.
    # If the entry is static, walk UP the call chain to find the closest public caller.
    if src_file and src_file.exists():
        src_text = src_file.read_text(errors="replace")
        
        def _is_static(func_name, src):
            """Check if a function is declared static in the source."""
            # Match: static [qualifiers] return_type func_name(
            pat = re.compile(
                rf'^\s*static\s+[\w\s\*]*\b{re.escape(func_name)}\s*\(',
                re.MULTILINE
            )
            return bool(pat.search(src))
        
        if _is_static(entry, src_text):
            print(f"  [!] Entry '{entry}' is static — searching for public caller")
            
            # Build a simple caller map: for each function, who calls it?
            callers_of = {}  # func -> list of callers
            for fname, (s, e) in func_spans.items():
                fspan = find_function_span(src_text, fname)
                if fspan:
                    body = src_text[fspan[1]:fspan[2]]
                    for other_fname in func_spans:
                        if other_fname != fname:
                            if re.search(rf'\b{re.escape(other_fname)}\s*\(', body):
                                callers_of.setdefault(other_fname, []).append(fname)
            
            # BFS upward from entry to find closest public caller
            visited = set()
            queue = [entry]
            public_entry = None
            path_to_public = []  # track the chain
            
            # BFS with parent tracking
            parent = {entry: None}
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                
                # Check if current is public (non-static) and NOT the original entry
                if current != entry and not _is_static(current, src_text):
                    public_entry = current
                    # Reconstruct path from public_entry down to original entry
                    # BFS walked UP (callee→caller), so tracing parent gives
                    # public_entry → ... → original_entry (already top-down)
                    path_to_public = []
                    node = current
                    while node is not None:
                        path_to_public.append(node)
                        node = parent.get(node)
                    # path is [public_entry, ..., original_entry] — already top-down
                    break
                
                # Add callers to queue
                for caller in callers_of.get(current, []):
                    if caller not in visited:
                        parent[caller] = current
                        queue.append(caller)
            
            if public_entry:
                print(f"  [✓] Found public entry: {public_entry}")
                
                # Rebuild spine: public_entry → ... → old_entry → vul_func
                # The path trace goes from public_entry back to original entry (top-down)
                new_spine = list(path_to_public)
                if vul_func not in new_spine:
                    new_spine.append(vul_func)
                print(f"  [✓] New spine: {' → '.join(new_spine)}")
                if vul_func not in new_spine:
                    new_spine.append(vul_func)
                # Deduplicate preserving order
                seen2 = set()
                spine = [x for x in new_spine if not (x in seen2 or seen2.add(x))]
                entry = public_entry
            else:
                print(f"  [!] No public caller found — keeping static entry '{entry}'")
                print(f"  [!] A public trampoline will be generated at compile time")
    
    # 3. Get stub candidates, type defs, signatures from SA (only if dict format)
    sa_stubs = []
    sa_types = {}
    sa_sigs = {}
    
    if isinstance(facts_dict, dict):
        spine_set = set(spine)
        for key in ["call_graph", "calls", "callGraph"]:
            cg = facts_dict.get(key, None)
            if isinstance(cg, dict):
                for func in spine:
                    callees = cg.get(func, [])
                    if isinstance(callees, list):
                        sa_stubs.extend([c for c in callees if c not in spine_set and c not in _SKIP_CALLS])
                break
        sa_stubs = sorted(set(sa_stubs))
        
        for key in ["types", "type_defs", "structs", "typedefs"]:
            td = facts_dict.get(key, None)
            if isinstance(td, dict) and td:
                sa_types = td
                print(f"  [SA] Type definitions: {len(sa_types)} types loaded")
                break
        
        for key in ["signatures", "func_signatures", "functions"]:
            sigs = facts_dict.get(key, None)
            if isinstance(sigs, dict) and sigs:
                sa_sigs = sigs
                print(f"  [SA] Function signatures: {len(sa_sigs)} loaded")
                break
    
    if sa_stubs:
        print(f"  [SA] Stub candidates: {', '.join(sa_stubs[:15])}")
    
    compile_flags, build_dir = extract_compile_flags(sa_data, vul_file)
    if compile_flags:
        print(f"  [SA] Compile flags from compile_commands: {len(compile_flags)} flags, build_dir={build_dir}")
    source_files = build_source_file_index(sa_data, src_root)
    
    return {
        "vul_func": vul_func, "spine": spine, "entry": spine[0],
        "vul_file": vul_file,
        "compile_flags": compile_flags,
        "build_dir": build_dir,
        "include_paths": discover_include_paths(src_root, sa_data),
        "sa_stubs": sa_stubs,
        "sa_types": sa_types,
        "sa_sigs": sa_sigs,
        "source_files": source_files,
        "struct_groom": groom_structs(src_root, spine, vul_func, src_file),
    }


def groom_structs(src_root: Path, spine: list, vul_func: str, src_file: Path = None) -> Dict:
    """Analyze spine functions to build a path map and stub prescriptions.
    
    For each function in the spine, determines:
    - The target statement (call to next spine function, or SINK marker)
    - Guard conditions (early returns that define struct init requirements)
    - Calls that need specific stub return values to stay on path
    - Buffer size constants that constrain symbolic input size
    """
    if not src_file or not src_file.exists():
        return {}
    
    src = src_file.read_text(errors="replace")
    
    # Collect #define constants
    constants = {}
    for line in src.split('\n'):
        m = re.match(r'#define\s+(\w+)\s+(\d+)', line)
        if m:
            constants[m.group(1)] = int(m.group(2))
    
    # Build path analysis for each spine function
    path_map = {}
    for i, func_name in enumerate(spine):
        target = spine[i + 1] if i + 1 < len(spine) else None
        analysis = _analyze_function_path(src, func_name, target, vul_func, constants)
        if analysis:
            path_map[func_name] = analysis
    
    # Also analyze the target function for sink path
    sink_info = _analyze_sink_path(src, vul_func, constants)
    
    # Build init template and stub prescriptions
    init_lines, stub_prescriptions = _build_prescriptions(path_map, sink_info, constants)
    
    important_constants = {k: v for k, v in constants.items() if any(
        kw in k for kw in ["BUFFER", "SIZE", "MAX", "MIN", "PARSER", "CHUNK", "INPUT", "LOOKUP"])}
    
    result = {
        "path_map": path_map,
        "sink_info": sink_info,
        "stub_prescriptions": stub_prescriptions,
        "constants": important_constants,
        "init_template": '\n'.join(init_lines),
    }
    
    n_guards = sum(len(p.get("guards", [])) for p in path_map.values())
    n_stubs = len(stub_prescriptions)
    print(f"  [i] Struct groom: {n_guards} guards, {n_stubs} stub prescriptions, {len(important_constants)} constants")
    
    return result


def _analyze_function_path(src: str, func_name: str, call_target: str, vul_func: str, constants: dict) -> Dict:
    """Analyze one function to find path from entry to call_target (or SINK)."""
    span = find_function_span(src, func_name)
    if not span:
        return {}
    
    func_body = src[span[1]:span[2]]
    lines = func_body.split('\n')
    
    # Determine what we're looking for in this function
    if call_target:
        target_pattern = rf'\b{re.escape(call_target)}\s*\('
    else:
        target_pattern = r'SAILOR_PROBE_SINK'
    
    # Find target line
    target_line = -1
    for i, line in enumerate(lines):
        if re.search(target_pattern, line):
            target_line = i
            break
    
    if target_line < 0:
        return {}
    
    # Classify each statement before the target line
    guards = []           # Early return conditions
    on_path_calls = []    # Function calls between start and target
    branch_skips = []     # Branches NOT containing target (can be sliced)
    field_inits = {}      # Required field values
    
    i = 0
    brace_depth_at_start = 0
    while i < target_line:
        line = lines[i]
        stripped = line.strip()
        
        # Skip blanks, comments
        if not stripped or stripped.startswith(('/*', '//', '*', '#', '{', '}')):
            i += 1
            continue
        
        # Detect guard: if (COND) return(VALUE);
        guard = _detect_guard(lines, i)
        if guard:
            guards.append(guard)
            i = guard["end_line"] + 1
            continue
        
        # Detect branch blocks
        if re.match(r'if\s*\(', stripped) and '{' in '\n'.join(lines[i:i+3]):
            block_info = _scan_block(lines, i, target_line, target_pattern)
            if block_info["contains_target"]:
                # Target is inside — we'll keep this block
                i += 1
                continue
            else:
                # Target NOT inside — record as skippable
                calls_in_block = block_info.get("calls", [])
                branch_skips.append({
                    "start": i,
                    "end": block_info["end"],
                    "condition": stripped,
                    "calls": calls_in_block,
                })
                i = block_info["end"] + 1
                continue
        
        # Detect function calls
        call_m = re.match(r'(?:(\w+)\s*=\s*)?(\w+)\s*\(', stripped)
        if call_m and call_m.group(2) not in ('if', 'while', 'for', 'return', 'sizeof', 'switch'):
            ret_var = call_m.group(1)
            called_func = call_m.group(2)
            
            # Check if return value is used in a branch condition
            stub_type = "trivial"
            constraint = None
            if ret_var:
                # Look ahead for: if (ret_var < 0) return/goto
                for j in range(i+1, min(i+5, target_line)):
                    fwd = lines[j].strip()
                    # Pattern: if (var < 0) { ... return/goto ... }
                    branch_m = re.match(rf'if\s*\(\s*{re.escape(ret_var)}\s*(<|>|==|!=|<=|>=)\s*(\w+)', fwd)
                    if branch_m:
                        op, val = branch_m.group(1), branch_m.group(2)
                        resolved = constants.get(val, val)
                        # Does this branch lead AWAY from our target (return/error)?
                        if 'return' in fwd or 'goto' in fwd:
                            # We need to AVOID this branch → constrain return value
                            stub_type = "constrained"
                            constraint = {"var": ret_var, "avoid_op": op, "avoid_val": str(resolved)}
                        break
            
            on_path_calls.append({
                "func": called_func,
                "ret_var": ret_var,
                "stub_type": stub_type,
                "constraint": constraint,
                "line": i,
            })
        
        i += 1
    
    return {
        "target": call_target or "SINK",
        "target_line": target_line,
        "guards": guards,
        "on_path_calls": on_path_calls,
        "branch_skips": branch_skips,
    }


def _detect_guard(lines, i):
    """Detect if lines[i] starts a guard pattern: if (COND) return(...);"""
    stripped = lines[i].strip()
    
    # Inline: if (cond) return(val);
    m = re.match(r'if\s*\((.+)\)\s*return\s*\(', stripped)
    if m:
        return {"condition": m.group(1).strip(), "start_line": i, "end_line": i,
                "inits": _parse_guard_inits(m.group(1).strip())}
    
    # Multi-line: if (cond)\n    return(val);
    m = re.match(r'if\s*\((.+)\)\s*$', stripped)
    if m:
        cond = m.group(1).strip()
        for j in range(i+1, min(i+4, len(lines))):
            next_s = lines[j].strip()
            if not next_s or next_s == '{':
                continue
            if next_s.startswith('return'):
                return {"condition": cond, "start_line": i, "end_line": j,
                        "inits": _parse_guard_inits(cond)}
            break
    return None


def _parse_guard_inits(cond: str) -> list:
    """Parse guard condition into field init requirements."""
    inits = []
    parts = re.split(r'\s*&&\s*', cond)
    for part in parts:
        part = part.strip().strip('()')
        # field == NULL → must be non-NULL
        m = re.match(r'(\w+(?:->\w+)*)\s*==\s*NULL', part)
        if m:
            inits.append({"field": m.group(1), "must": "non-NULL", "action": "allocate"})
            continue
        # field == VALUE → must NOT be VALUE
        m = re.match(r'(\w+(?:->\w+)*)\s*==\s*(\w+)', part)
        if m:
            inits.append({"field": m.group(1), "must": f"not {m.group(2)}", "avoid": m.group(2)})
            continue
        # field != VALUE → must BE VALUE
        m = re.match(r'(\w+(?:->\w+)*)\s*!=\s*(\w+)', part)
        if m:
            inits.append({"field": m.group(1), "must": m.group(2), "set_to": m.group(2)})
    return inits


def _scan_block(lines, start, target_line, target_pattern):
    """Scan a braced block starting at 'start', return info about it."""
    brace_depth = 0
    contains_target = False
    calls = []
    end = start
    
    for j in range(start, min(len(lines), target_line + 10)):
        brace_depth += lines[j].count('{') - lines[j].count('}')
        if re.search(target_pattern, lines[j]):
            contains_target = True
        for cm in re.finditer(r'(\w+)\s*\(', lines[j]):
            if cm.group(1) not in ('if', 'while', 'for', 'return', 'sizeof', 'switch'):
                calls.append(cm.group(1))
        if brace_depth <= 0 and j > start:
            end = j
            break
    
    return {"contains_target": contains_target, "end": end, "calls": list(set(calls))}


def _analyze_sink_path(src: str, vul_func: str, constants: dict) -> Dict:
    """Find what conditions in the target function lead to the SINK."""
    span = find_function_span(src, vul_func)
    if not span:
        return {}
    
    func_body = src[span[1]:span[2]]
    
    sink_labels = []
    sink_conditions = []
    buffer_reqs = []
    
    # Find labels that contain SAILOR_PROBE_SINK
    for m in re.finditer(r'^(\w+):', func_body, re.MULTILINE):
        label = m.group(1)
        pos = m.end()
        snippet = func_body[pos:pos+1500]
        if 'SAILOR_PROBE_SINK' in snippet:
            next_label = re.search(r'^\w+:', snippet, re.MULTILINE)
            if not next_label or 'SAILOR_PROBE_SINK' in snippet[:next_label.start()]:
                sink_labels.append(label)
    
    sink_labels = list(set(sink_labels))
    
    # For each sink label, find goto statements and their conditions
    for label in sink_labels:
        for m in re.finditer(rf'goto\s+{re.escape(label)}\s*;', func_body):
            before = func_body[max(0, m.start()-500):m.start()]
            before_lines = before.split('\n')[-10:]
            for bline in reversed(before_lines):
                cond_m = re.match(r'\s*if\s*\((.+?)\)', bline.strip())
                if cond_m:
                    cond = cond_m.group(1).strip()
                    # Extract the function call whose return drives this condition
                    call_m = re.search(r'(\w+)\s*\(', cond)
                    sink_conditions.append({
                        "label": label,
                        "condition": cond,
                        "trigger_func": call_m.group(1) if call_m else None,
                    })
                    break
    
    # Find buffer size checks that skip to "done" (bypass the sink path)
    for m in re.finditer(r'(\w+)\s*<\s*(\w+)', func_body):
        field, const_name = m.group(1), m.group(2)
        if const_name in constants:
            after = func_body[m.end():m.end()+200]
            if 'goto done' in after or 'goto ' in after:
                buffer_reqs.append({
                    "field": field, "min_value": constants[const_name],
                    "constant": const_name, 
                    "reason": f"{field} must be >= {constants[const_name]} ({const_name})"
                })
    
    return {"sink_labels": sink_labels, "sink_conditions": sink_conditions, "buffer_requirements": buffer_reqs}


def _build_prescriptions(path_map, sink_info, constants):
    """Build init template and stub prescriptions from path analysis."""
    lines = []
    lines.append("/* === PATH-SENSITIVE INITIALIZATION TEMPLATE ===")
    lines.append(" * Generated from backward analysis: sink → target → entry → driver */")
    lines.append("")
    
    stub_prescriptions = {}  # func_name -> {type, return_value, reason}
    
    # Process each function in the path
    for func_name, analysis in path_map.items():
        target = analysis.get("target", "?")
        guards = analysis.get("guards", [])
        on_path_calls = analysis.get("on_path_calls", [])
        
        if guards:
            lines.append(f"// === {func_name} → {target}: Guards ===")
            for g in guards:
                lines.append(f"//  if ({g['condition']}) return → to PASS:")
                for init in g.get("inits", []):
                    if init.get("action") == "allocate":
                        lines.append(f"//    {init['field']} = calloc(1, sizeof(*{init['field']}));")
                    elif init.get("set_to"):
                        lines.append(f"//    {init['field']} = {init['set_to']};")
                    elif init.get("avoid"):
                        lines.append(f"//    {init['field']}: anything EXCEPT {init['avoid']}")
            lines.append("")
        
        if on_path_calls:
            lines.append(f"// === {func_name} → {target}: Calls needing stubs ===")
            for call in on_path_calls:
                fn = call["func"]
                st = call["stub_type"]
                constraint = call.get("constraint")
                
                if st == "constrained" and constraint:
                    op = constraint["avoid_op"]
                    val = constraint["avoid_val"]
                    # Invert the condition to find safe return value
                    if op == '<' and val == '0':
                        safe = "0"
                        reason = f"return >= 0 to avoid error branch"
                    elif op == '==' and val == 'NULL':
                        safe = "(void*)1"
                        reason = f"return non-NULL to avoid error branch"
                    else:
                        safe = "0"
                        reason = f"return value must not satisfy: {constraint['var']} {op} {val}"
                    
                    stub_prescriptions[fn] = {"type": "constrained", "return": safe, "reason": reason}
                    lines.append(f"//  {fn}() → STUB returns {safe}  ({reason})")
                else:
                    stub_prescriptions[fn] = {"type": "trivial", "return": "0", "reason": "not on critical path"}
                    lines.append(f"//  {fn}() → trivial stub (return 0)")
            lines.append("")
    
    # Sink conditions — the call that MUST return a specific value to REACH the sink
    if sink_info:
        for sc in sink_info.get("sink_conditions", []):
            trigger = sc.get("trigger_func")
            cond = sc["condition"]
            if trigger:
                # This function's return value must satisfy the condition to reach sink
                # e.g., "tmp < 0" where tmp = xmlCheckCdataPush(...) → must return < 0
                m = re.match(r'(\w+)\s*(<|>|==|!=|<=|>=)\s*(\w+)', cond)
                if m:
                    var, op, val = m.group(1), m.group(2), m.group(3)
                    if op == '<' and val == '0':
                        stub_prescriptions[trigger] = {"type": "sink_trigger", "return": "-1",
                            "reason": f"MUST return < 0 to trigger goto {sc['label']} (reaching sink)"}
                    elif op == '>' and val == '0':
                        stub_prescriptions[trigger] = {"type": "sink_trigger", "return": "1",
                            "reason": f"MUST return > 0 to trigger goto {sc['label']}"}
                    elif op == '==' and val == '0':
                        stub_prescriptions[trigger] = {"type": "sink_trigger", "return": "0",
                            "reason": f"MUST return == 0 to trigger goto {sc['label']}"}
                    lines.append(f"// *** {trigger}() → SINK TRIGGER: return makes ({cond}) true → goto {sc['label']}")
        
        for br in sink_info.get("buffer_requirements", []):
            lines.append(f"// *** BUFFER: {br['reason']}")
        
        # Compute recommended buffer size
        max_buf = max((br["min_value"] for br in sink_info.get("buffer_requirements", [])), default=0)
        if max_buf:
            lines.append(f"// → Symbolic buffer must be >= {max_buf + 100} bytes")
        lines.append("")
    
    return lines, stub_prescriptions

class SliceTools:
    def __init__(self, ctx, frozen, src_root, harness_dir, logs_dir, clang, llvm_link, klee, klee_flags, timeout, start_time, extra_cflags=None, se_config=None):
        self.ctx = ctx
        self.frozen = frozen
        self.src_root = Path(src_root).resolve()
        self.harness_dir = ensure_dir(harness_dir).resolve()
        self.logs_dir = ensure_dir(logs_dir)
        self.clang = clang
        self.llvm_link = llvm_link
        self.klee = klee
        self.klee_flags = klee_flags
        self.timeout = timeout
        self.start_time = start_time
        self.iteration = 0
        self.last_klee_stats = None
        self.harness_line_map = {}  # harness_file -> {harness_line -> {orig_file, orig_line, code}}
        self._sliced = False  # guard: neutralize only once
        self.se_config = se_config or {}
        self.project_cflags = self.frozen.get("compile_flags", [])
        self.extra_cflags = (extra_cflags or []) + self.se_config.get("extra_cflags", [])
        self.include_paths = self.frozen.get("include_paths", []) + self.se_config.get("extra_includes", [])
        self.klee_include = str(Path(klee).resolve().parent.parent / "include")
        # Cache: original source lines around vul_line for fingerprinting
        self._vul_fingerprints = self._build_vul_fingerprints()

    def _build_vul_fingerprints(self) -> List[str]:
        """Extract distinctive code lines near vul_line from original source for matching."""
        src_file = find_source_file(self.src_root, self.ctx['vul_file'])
        if not src_file:
            return []
        src_lines = src_file.read_text(errors="replace").splitlines()
        vul_line = int(self.ctx.get("vul_line", 0))
        if vul_line <= 0 or vul_line > len(src_lines):
            return []
        # Collect distinctive lines in a window around vul_line (skip blanks, comments, probes)
        fingerprints = []
        for offset in range(0, 15):  # search forward from vul_line
            idx = vul_line - 1 + offset
            if idx >= len(src_lines):
                break
            line = src_lines[idx].strip()
            # Skip non-distinctive lines
            if not line or line.startswith(('/*', '//', '*', '#', 'SAILOR', 'klee_')):
                continue
            if line in ('{', '}', 'break;'):
                continue
            fingerprints.append(line)
            if len(fingerprints) >= 3:
                break
        return fingerprints

    def resolve_vul_line(self) -> Dict:
        """Dynamically find the vulnerability line in the CURRENT harness file.
        Returns {"harness_file", "harness_line", "context"} or empty dict."""
        # Strategy 1: Search for SAILOR_PROBE_SINK or SAILOR_SINK_REACHED
        sink_markers = ["SAILOR_PROBE_SINK", "SAILOR_SINK_REACHED"]
        for harness_file in self.harness_dir.glob("*.c"):
            content = harness_file.read_text(errors="replace")
            lines = content.splitlines()
            
            candidates = []
            for i, line in enumerate(lines):
                if not any(m in line for m in sink_markers):
                    continue
                stripped = line.strip()
                if stripped.startswith('#define'):
                    continue
                if stripped.startswith(('/*', '//', '*')):
                    continue
                if i > 0 and lines[i-1].strip().startswith('#define') and lines[i-1].strip().endswith('\\'):
                    continue
                candidates.append(i)
            
            if not candidates:
                continue
            
            best = candidates[-1]
            
            ctx_start = max(0, best - 2)
            ctx_end = min(len(lines), best + 8)
            context = '\n'.join(f"{j+1}: {lines[j]}" for j in range(ctx_start, ctx_end))
            
            # For SAILOR_SINK_REACHED, the vulnerable statement is the line BEFORE
            # the assertion, not the assertion itself
            marker_found = "SAILOR_PROBE_SINK"
            if "SAILOR_SINK_REACHED" in lines[best] and "SAILOR_PROBE_SINK" not in lines[best]:
                marker_found = "SAILOR_SINK_REACHED"
                # Return the line BEFORE the assertion as the vulnerability line
                if best > 0:
                    best = best - 1
            
            return {
                "harness_file": harness_file.name,
                "harness_line": best + 1,
                "marker": marker_found,
                "context": context,
            }

        # Strategy 2: Match fingerprint lines from original source
        if self._vul_fingerprints:
            for harness_file in self.harness_dir.glob("*.c"):
                content = harness_file.read_text(errors="replace")
                lines = content.splitlines()
                for i, line in enumerate(lines):
                    if self._vul_fingerprints[0] in line.strip():
                        # Verify with additional fingerprints
                        matched = 1
                        for fp in self._vul_fingerprints[1:]:
                            window = '\n'.join(lines[i:min(len(lines), i+10)])
                            if fp in window:
                                matched += 1
                        if matched >= min(2, len(self._vul_fingerprints)):
                            ctx_start = max(0, i - 2)
                            ctx_end = min(len(lines), i + 8)
                            context = '\n'.join(f"{j+1}: {lines[j]}" for j in range(ctx_start, ctx_end))
                            return {
                                "harness_file": harness_file.name,
                                "harness_line": i + 1,
                                "marker": "fingerprint",
                                "context": context,
                            }
        return {}
    
    def build_line_map(self) -> Dict:
        """Build a line map for all harness .c files: harness_line → original source line.
        
        Strategy: for each harness .c file (excluding driver.c, stubs.c),
        match distinctive code lines against the original source file.
        Only maps lines that have actual C code (skips blank, comments, probes).
        
        Returns: {harness_file: {harness_line: {"orig_file": str, "orig_line": int, "code": str}}}
        """
        vul_file = self.frozen.get("vul_file", "")
        src_file = find_source_file(self.src_root, vul_file)
        if not src_file:
            return {}
        
        orig_lines = src_file.read_text(errors="replace").splitlines()
        # Build a lookup: stripped code → list of (orig_line_num) 
        orig_lookup = {}
        for i, line in enumerate(orig_lines):
            stripped = line.strip()
            if stripped and not stripped.startswith(('/*', '//', '*', '#define SAILOR', 'klee_')):
                orig_lookup.setdefault(stripped, []).append(i + 1)
        
        result = {}
        skip_files = {"driver.c", "stubs.c", "smart_stubs.c", "auto_stubs.c"}
        
        # Build a normalized lookup for fuzzy matching
        # Normalize: strip variable prefixes, collapse whitespace, remove casts
        def normalize_code(s):
            """Normalize code for fuzzy matching — strip variable name differences."""
            s = s.strip()
            # Remove common variable prefixes/renames agents use
            # e.g., ctxt_ptr->field becomes ctxt->field
            s = re.sub(r'\b\w+_ptr\b', 'PTR', s)
            s = re.sub(r'\b\w+_arg\b', 'PTR', s)
            # Collapse multiple spaces
            s = re.sub(r'\s+', ' ', s)
            # Remove casts like (void*), (char*), (xmlParserCtxtPtr)
            s = re.sub(r'\(\s*\w[\w\s\*]*\s*\)\s*', '', s)
            return s
        
        # Build normalized lookup from original source
        norm_lookup = {}
        for i, line in enumerate(orig_lines):
            stripped = line.strip()
            if stripped and not stripped.startswith(('/*', '//', '*', '#define SAILOR', 'klee_')):
                normed = normalize_code(stripped)
                if len(normed) > 10:  # skip trivial lines
                    norm_lookup.setdefault(normed, []).append(i + 1)
        
        for hf in self.harness_dir.glob("*.c"):
            if hf.name in skip_files:
                continue
            h_lines = hf.read_text(errors="replace").splitlines()
            fmap = {}
            last_orig = 0
            
            for h_idx, h_line in enumerate(h_lines):
                stripped = h_line.strip()
                if not stripped or stripped.startswith(('/*', '//', '*', 'klee_warning', 'klee_assert', 'SPINE_PROBE')):
                    continue
                if 'SAILOR_SINK_REACHED' in stripped or 'SPINE_PROBE' in stripped:
                    continue
                
                # Check for ORIG_LINE tag (from auto-generated harness)
                orig_tag = re.search(r'/\*\s*ORIG_LINE:(\d+)\s*\*/', h_line)
                if orig_tag:
                    tagged_line = int(orig_tag.group(1))
                    code = re.sub(r'\s*/\*\s*ORIG_LINE:\d+\s*\*/', '', h_line).strip()
                    fmap[h_idx + 1] = {
                        "orig_file": vul_file,
                        "orig_line": tagged_line,
                        "code": code,
                        "match_type": "tagged",
                    }
                    last_orig = tagged_line + 1
                    continue
                
                # Try exact match first
                if stripped in orig_lookup:
                    candidates = orig_lookup[stripped]
                    if last_orig > 0:
                        best = min(candidates, key=lambda x: abs(x - last_orig))
                    else:
                        best = candidates[0]
                    
                    fmap[h_idx + 1] = {
                        "orig_file": vul_file,
                        "orig_line": best,
                        "code": stripped,
                    }
                    last_orig = best + 1
                    continue
                
                # Try normalized/fuzzy match
                normed = normalize_code(stripped)
                if len(normed) > 10 and normed in norm_lookup:
                    candidates = norm_lookup[normed]
                    if last_orig > 0:
                        best = min(candidates, key=lambda x: abs(x - last_orig))
                    else:
                        best = candidates[0]
                    
                    fmap[h_idx + 1] = {
                        "orig_file": vul_file,
                        "orig_line": best,
                        "code": stripped,
                        "match_type": "fuzzy",
                    }
                    last_orig = best + 1
            
            if fmap:
                result[hf.name] = fmap
        
        self.harness_line_map = result
        
        # Save to disk for later use
        map_path = self.harness_dir / "line_map.json"
        write_json(map_path, result)
        
        n_mapped = sum(len(v) for v in result.values())
        print(f"    [+] Line map: {n_mapped} harness lines mapped to original source")
        return result
    
    def lookup_original_line(self, harness_file: str, harness_line: int) -> Dict:
        """Look up the original source line for a harness line number.
        
        Returns: {"orig_file": str, "orig_line": int, "code": str} or {}
        """
        if not self.harness_line_map:
            self.build_line_map()
        
        fmap = self.harness_line_map.get(harness_file, {})
        
        # Exact match
        if harness_line in fmap:
            return fmap[harness_line]
        
        # Nearest match within ±5 lines
        for offset in range(1, 6):
            for candidate in [harness_line - offset, harness_line + offset]:
                if candidate in fmap:
                    entry = fmap[candidate].copy()
                    entry["offset"] = offset
                    return entry
        
        # --- FALLBACK: vulnerability site mapping ---
        # When the agent rewrites the vulnerable statement (e.g., simplifies snprintf),
        # textual matching fails. But if the crash is near the SINK assertion,
        # we KNOW it's at the vulnerability site. Map directly to vul_line.
        vul_file_base = os.path.basename(self.frozen.get("vul_file", ""))
        if harness_file == vul_file_base:
            vul_loc = self.resolve_vul_line()
            if vul_loc:
                sink_line = int(vul_loc.get("harness_line", 0))
                if sink_line > 0 and abs(harness_line - sink_line) <= 15:
                    vul_line = int(self.ctx.get("vul_line", 0))
                    if vul_line > 0:
                        return {
                            "orig_file": self.frozen.get("vul_file", ""),
                            "orig_line": vul_line,
                            "code": f"(vulnerability site — mapped via sink proximity, offset={abs(harness_line - sink_line)})",
                            "match_type": "vul_site_fallback",
                        }
        
        return {}
    
    def concrete_validate(self, klee_out_dir: str = "") -> Dict:
        """Concrete validation: replay KLEE test cases with ASan + produce bug report.
        
        Runs for ALL KLEE crashes (not just the target bug):
        - Target bugs: crash at/near the vulnerability site → validate with ASan
        - Non-target bugs: crash elsewhere → report as "surprise findings"
        - Harness bugs: crash in driver.c/stubs.c → skip (artifact)
        
        Returns: full bug report dict with original line mappings
        """
        print("  [Phase 5] Concrete validation (ASan replay)")
        
        # Find KLEE output directory
        if not klee_out_dir:
            last = self.last_klee_stats or {}
            klee_out_dir = last.get("out_dir", "")
        out_dir = Path(klee_out_dir) if klee_out_dir else None
        
        if not out_dir or not out_dir.exists():
            for d in sorted(self.logs_dir.glob("klee_run_*"), reverse=True):
                if d.is_dir() and list(d.glob("*.ktest")):
                    out_dir = d
                    break
            if not out_dir or not out_dir.exists():
                print("    [!] No KLEE output directory found")
                return {"validated": False, "error": "No KLEE output directory found"}
        
        print(f"    [i] KLEE output: {out_dir}")
        
        # --- Step 1: Collect ALL .err + .ktest pairs ---
        err_ktests = []
        for ef in sorted(out_dir.glob("*.err")):
            # KLEE .err files: test000002.ptr.err, test000001.user.err
            # Corresponding .ktest: test000002.ktest (base name before first dot)
            # ef.with_suffix(".ktest") is WRONG: gives test000002.ptr.ktest
            ktest_name = ef.name.split(".")[0] + ".ktest"  # test000002.ktest
            ktest = ef.parent / ktest_name
            err_content = ef.read_text(errors="replace")
            # Parse err_type from filename: test000001.ptr.err → "ptr"
            err_type = ef.stem.split(".")[-1] if "." in ef.stem else "unknown"
            m_file = re.search(r'File:\s*(.+)', err_content)
            m_line = re.search(r'Line:\s*(\d+)', err_content)
            
            entry = {
                "ktest": str(ktest) if ktest.exists() else "",
                "err_file": str(ef),
                "err_type": err_type,
                "crash_file": m_file.group(1).strip() if m_file else "",
                "crash_line": int(m_line.group(1)) if m_line else 0,
                "err_content": err_content[:500],
            }
            
            # If crash is in KLEE runtime (memcpy/memset/memmove), resolve
            # to the actual source-level caller via the stack trace.
            if _is_klee_runtime_crash(entry["crash_file"]) and err_type in ("ptr", "div", "free"):
                caller_file, caller_line = _resolve_runtime_caller(err_content)
                if caller_file:
                    print(f"    [i] Resolved runtime crash {os.path.basename(entry['crash_file'])}:{entry['crash_line']}"
                          f" → {os.path.basename(caller_file)}:{caller_line}")
                    entry["runtime_crash_file"] = entry["crash_file"]
                    entry["runtime_crash_line"] = entry["crash_line"]
                    entry["crash_file"] = caller_file
                    entry["crash_line"] = caller_line

            # Classify: harness bug vs real bug
            crash_basename = os.path.basename(entry["crash_file"])
            if crash_basename in _HARNESS_SKIP_FILES:
                entry["classification"] = "harness"
            else:
                entry["classification"] = "real"
            
            err_ktests.append(entry)
            print(f"    [i] {ef.name}: {err_type} at {crash_basename}:{entry['crash_line']} [{entry['classification']}]")
        
        if not err_ktests:
            print("    [!] No .err files found in KLEE output")
            return {"validated": False, "error": "No error files found"}
        
        real_crashes = [kt for kt in err_ktests if kt["classification"] == "real"]
        print(f"    [i] Found {len(err_ktests)} total errors, {len(real_crashes)} real (non-harness)")
        
        if not real_crashes:
            print("    [!] All crashes are in harness code (driver.c/stubs.c)")
            return {"validated": False, "error": "All crashes in harness code"}
        
        # --- Step 2: Decode ktest files ---
        for kt in real_crashes:
            if not kt["ktest"]:
                kt["decoded"] = "(no .ktest file)"
                kt["objects"] = []
                print(f"    [!] No .ktest file for {os.path.basename(kt.get('err_file', ''))}")
                continue
            rc, out, stderr_out, _ = run_cmd(["ktest-tool", kt["ktest"]], timeout=10)
            if rc == 0:
                kt["decoded"] = out
                objects = []
                # ktest-tool outputs EACH field on its own line:
                #   object 0: name: b'sym_name'
                #   object 0: size: 4
                #   object 0: data: b'\xfb\xff\xff\xff'
                # Parse by collecting fields per object index.
                obj_fields = {}  # index → {name, size, data}
                for line in out.splitlines():
                    m = re.match(r'\s*object\s+(\d+):\s*(\w+):\s*(.*)', line)
                    if m:
                        idx = int(m.group(1))
                        field = m.group(2).strip()
                        value = m.group(3).strip()
                        if idx not in obj_fields:
                            obj_fields[idx] = {}
                        obj_fields[idx][field] = value
                
                for idx in sorted(obj_fields.keys()):
                    fields = obj_fields[idx]
                    name_raw = fields.get("name", "")
                    # name is like b'sym_name' — strip b'' wrapper
                    nm = re.match(r"b'([^']*)'", name_raw)
                    name = nm.group(1) if nm else name_raw.strip("'\"")
                    
                    size_str = fields.get("size", "0")
                    try:
                        size = int(size_str)
                    except ValueError:
                        size = 0
                    
                    data = fields.get("data", "")
                    
                    if name:
                        objects.append({
                            "index": idx,
                            "name": name,
                            "size": size,
                            "data": data,
                        })
                
                kt["objects"] = objects
                print(f"    [i] Decoded {kt['ktest']}: {len(objects)} symbolic objects")
            else:
                kt["decoded"] = f"(ktest-tool failed: rc={rc})"
                kt["objects"] = []
                print(f"    [!] ktest-tool failed for {kt['ktest']}: {stderr_out[:200]}")
        
        # --- Step 3: Map ALL crashes to original source ---
        if not self.harness_line_map:
            self.build_line_map()
        
        for kt in real_crashes:
            crash_file_base = os.path.basename(kt.get("crash_file", ""))
            crash_line = kt.get("crash_line", 0)
            orig = self.lookup_original_line(crash_file_base, crash_line)
            if orig:
                kt["orig_file"] = orig["orig_file"]
                kt["orig_line"] = orig["orig_line"]
                kt["orig_code"] = orig["code"]
                print(f"    [✓] Mapped: harness {crash_file_base}:{crash_line} → {orig['orig_file']}:{orig['orig_line']}")
                print(f"        Code: {orig['code'][:100]}")
            else:
                kt["orig_file"] = ""
                kt["orig_line"] = 0
                kt["orig_code"] = ""
                print(f"    [!] No mapping for harness {crash_file_base}:{crash_line}")
        
        # --- Step 4: ASan replay on REAL library source ---
        asan_result = {"success": False, "asan_triggered": False}
        try:
            asan_result = self._asan_replay_real_library(real_crashes)
        except Exception as e:
            print(f"    [!] Real-library ASan replay failed: {e}")
            asan_result = {"success": False, "error": str(e)}
        
        # --- Step 5: Build bug report ---
        report = self._build_bug_report(real_crashes, asan_result)
        
        # Save report
        report_path = self.harness_dir.parent / "bug_report.json"
        write_json(report_path, report)
        print(f"    [✓] Bug report saved: {report_path}")
        
        # Print summary
        print(f"    [SUMMARY] Verdict: {report['summary']['verdict']}")
        for crash in report.get("all_crashes", []):
            orig_info = f" → {crash['original_file']}:{crash['original_line']}" if crash.get('original_line') else ""
            print(f"    [SUMMARY] {crash['error_type']} at harness {crash['harness_file']}:{crash['harness_line']}{orig_info}")
        
        return report
    
    def _asan_replay_real_library(self, err_ktests: List[Dict]) -> Dict:
        """Compile the REAL source file with ASan and replay.

        Compiles the ACTUAL vulnerable source file from the original project with ASan
        and links it with a concrete driver to confirm the bug exists in the
        real code, not just our simplified slice.
        """
        replay_dir = ensure_dir(self.harness_dir.parent / "asan_real")
        
        build_dir = self.frozen.get("build_dir", "")
        vul_file = self.frozen.get("vul_file", "")
        entry_func = self.frozen.get("entry", "")

        if not vul_file:
            return {"success": False, "error": "Missing vul_file for real replay"}

        # Use src_root as fallback build_dir (configure/Makefile often live there)
        if not build_dir:
            build_dir = str(self.src_root)
            print(f"    [ASan-Real] No build_dir in frozen, using src_root: {build_dir}")
        
        # Find the real source file
        real_src = find_source_file(self.src_root, vul_file)
        if not real_src or not os.path.exists(real_src):
            return {"success": False, "error": f"Real source not found: {vul_file}"}
        
        print(f"    [ASan-Real] Source: {real_src}")
        
        # Parse ktest objects for concrete values
        primary_ktest = err_ktests[0] if err_ktests else {}
        obj_map = {obj["name"]: obj for obj in primary_ktest.get("objects", [])}
        
        # Generate a minimal driver with concrete ktest values
        # Read the harness driver.c to get the structure
        driver_path = self.harness_dir / "driver.c"
        driver_src = driver_path.read_text(errors="replace") if driver_path.exists() else ""
        
        replay_driver = self._generate_replay_driver(err_ktests[0], driver_src)
        if not replay_driver:
            return {"success": False, "error": "Could not generate replay driver for real library"}
        
        replay_driver_path = replay_dir / "replay_driver.c"
        replay_driver_path.write_text(replay_driver, encoding="utf-8")
        
        # Build include flags from project
        # -isystem /usr/include first to prevent project headers shadowing libc
        inc_flags = ["-isystem", "/usr/include"]
        for ip in self.include_paths:
            if os.path.isdir(ip):
                # -idirafter: searched AFTER -isystem, so project headers like
                # include/private/string.h don't shadow /usr/include/string.h
                inc_flags.extend(["-idirafter", ip])
        inc_flags.extend(["-I", str(self.src_root), "-I", str(self.harness_dir)])
        if build_dir and os.path.isdir(build_dir):
            inc_flags.extend(["-I", build_dir])
        
        # Auto-include config.h (same logic as compile_slice)
        config_h = None
        search_roots = [Path(build_dir)] if build_dir and os.path.isdir(build_dir) else []
        search_roots.append(self.src_root)
        for root in search_roots:
            for rel in ["config.h", "include/config.h"]:
                candidate = root / rel
                if candidate.exists():
                    config_h = candidate
                    break
            if config_h:
                break
            for candidate in root.glob("**/config.h"):
                if ".git" not in str(candidate) and "test" not in str(candidate).lower():
                    config_h = candidate
                    break
            if config_h:
                break
        if config_h:
            inc_flags.extend(["-include", str(config_h)])
            # Also add the directory containing config.h to -I so that
            # #include "config.h" in source files can find it
            config_dir = str(config_h.parent)
            if config_dir not in [f for i, f in enumerate(inc_flags) if i > 0 and inc_flags[i-1] == "-I"]:
                inc_flags.extend(["-I", config_dir])
            print(f"    [ASan-Real] Auto-including {config_h} (-I {config_dir})")
        
        # Auto-detect IN_LIBFOO macros (e.g., -DIN_LIBXML)
        for hfile in self.src_root.rglob("lib*.h"):
            stem = hfile.stem.upper()
            inc_flags.append(f"-D{f'IN_{stem}'}")
            print(f"    [ASan-Real] Auto-adding -DIN_{stem}")
            break
        
        # Project cflags (skip -c, -emit-llvm, optimization)
        proj_cflags = []
        for cf in self.project_cflags:
            if cf not in ('-emit-llvm', '-c', '-o') and not cf.startswith('-O'):
                proj_cflags.append(cf)
        # Add extra cflags (auto-fixed macros like -DXML_HIDDEN=)
        for cf in self.extra_cflags:
            if cf not in proj_cflags:
                proj_cflags.append(cf)
        
        # Strategy: compile the real source + our replay driver + stubs
        # Copy stubs from harness (they provide the stubbed functions)
        c_files = [str(replay_driver_path)]
        
        # Copy and clean stubs (remove klee references)
        for stub_name in ["stubs.c", "smart_stubs.c", "auto_stubs.c"]:
            stub_path = self.harness_dir / stub_name
            if stub_path.exists():
                src = stub_path.read_text(errors="replace")
                clean = re.sub(r'#include\s*[<"]klee/klee\.h[>"]', '// klee removed', src)
                clean = re.sub(r'\bklee_warning_once\([^)]*\)\s*;', '', clean)
                clean = re.sub(r'\bklee_warning\([^)]*\)\s*;', '', clean)
                clean = re.sub(r'\bklee_assert\([^)]*\)\s*;', '', clean)
                clean = re.sub(r'\bklee_make_symbolic\s*\(((?:[^()]|\([^()]*\))+)\)',
                               r'memset(\1) /* stub */;', clean)
                clean = re.sub(r'\bklee_assume\([^)]*\)\s*;', '', clean)
                clean_path = replay_dir / stub_name
                clean_path.write_text(clean, encoding="utf-8")
                c_files.append(str(clean_path))
        
        # Try to compile the REAL source file with ASan
        asan_flags = ["-fsanitize=address", "-fno-omit-frame-pointer", "-g", "-O0", "-w"]
        out_bin = replay_dir / "replay_real_bin"
        rc = 1  # initialize to failure
        stdout, stderr = "", ""
        
        # === APPROACH 1: Rebuild project with ASan using make ===
        # The right way: use the project's own build system with ASan flags injected.
        # This handles all dependencies, configure options, and struct definitions.
        build_path = Path(build_dir)
        build_cmd = self.ctx.get("build_cmd", "")
        
        asan_lib = None
        asan_build_dir = ensure_dir(replay_dir / "asan_build")

        # === CHECK SHARED ASan CACHE ===
        # Avoid rebuilding the entire project for every spec — cache ASan-built
        # libraries in a shared directory at the project level.
        asan_cache_dir = self.src_root.parent / ".asan_cache"
        asan_cache_lock = asan_cache_dir / ".building"
        cached_libs = []
        if asan_cache_dir.exists() and not asan_cache_lock.exists():
            for ext in ["*.a", "*.so"]:
                cached_libs.extend(asan_cache_dir.glob(ext))
            if cached_libs:
                project_name = self.src_root.name.split("_")[0]
                matched = [f for f in cached_libs if project_name.lower() in f.name.lower()]
                asan_lib = matched[0] if matched else cached_libs[0]
                print(f"    [ASan-Real] Using cached ASan library: {asan_lib}")

        # === APPROACH 1A: Build project with ASan (mirrors build_project_bc.sh) ===
        # Copy source to avoid modifying the original, then build with gcc + ASan.
        if not asan_lib and (build_cmd or build_path.exists()):
            asan_cflags = "-fsanitize=address -fno-omit-frame-pointer -g -O0 -w"
            # Stub out KLEE functions that may have been injected into the original source
            klee_stubs = (
                "-Dklee_warning(x)= "
                "-Dklee_warning_once(x)= "
                "-Dklee_assert(x)= "
                "-Dklee_make_symbolic(a,b,c)= "
                "-Dklee_assume(x)= "
                "-Dklee_report_error(a,b,c,d)= "
                "-Dklee_get_obj_size(x)=0 "
                "-Dklee_check_memory_access(a,b)= "
            )
            asan_cflags_full = f"{asan_cflags} {klee_stubs}"
            asan_ldflags = "-fsanitize=address"
            
            asan_env = dict(os.environ)
            asan_env["CC"] = "gcc"
            asan_env["CXX"] = "g++"
            asan_env["CFLAGS"] = asan_cflags_full
            asan_env["CXXFLAGS"] = asan_cflags_full
            asan_env["LDFLAGS"] = asan_ldflags
            # Remove wllvm env vars that might interfere
            for k in ["LLVM_COMPILER", "LLVM_CC_NAME", "LLVM_CXX_NAME"]:
                asan_env.pop(k, None)
            
            # Copy source tree to avoid modifying the original
            # Copy from ORIGINAL source (not working copy which may have KLEE probes injected)
            asan_src = replay_dir / "asan_src"
            if asan_src.exists():
                shutil.rmtree(str(asan_src), ignore_errors=True)
            original_src = Path(self.ctx.get("src_root_original", str(self.src_root)))
            print(f"    [ASan-Real] Copying source tree from {original_src} to {asan_src}...")
            shutil.copytree(str(original_src), str(asan_src), symlinks=True,
                           ignore=shutil.ignore_patterns('*.o', '*.bc', '*.bca', 'asan_build', 'asan_replay'))
            
            cmake_file = asan_src / "CMakeLists.txt"
            configure_script = asan_src / "configure"
            build_sh = asan_src / "build.sh"

            built_ok = False
            asan_build = None

            if build_sh.exists():
                # Project has a custom build.sh — use it with ASan env injected
                asan_build = asan_src
                print(f"    [ASan-Real] Using project build.sh with ASan env...")
                rc_bs, _, stderr_bs, _ = run_cmd(
                    ["bash", str(build_sh)], timeout=300, cwd=str(asan_src), env=asan_env)
                if rc_bs == 0:
                    built_ok = True
                else:
                    print(f"    [ASan-Real] build.sh errors: {stderr_bs[:300]}")
                    built_ok = True  # partial build may have produced libraries

            elif cmake_file.exists():
                # Mirror build_project_bc.sh: mkdir build; cd build; cmake ..
                asan_build = asan_src / "build"
                if asan_build.exists():
                    shutil.rmtree(str(asan_build), ignore_errors=True)
                asan_build.mkdir(parents=True, exist_ok=True)

                print(f"    [ASan-Real] CMake + ASan in {asan_build}...")
                # Step 1: Configure WITHOUT ASan (ASan breaks cmake compiler probes)
                clean_env = dict(os.environ)
                clean_env["CC"] = "gcc"
                clean_env["CXX"] = "g++"
                for k in ["LLVM_COMPILER", "LLVM_CC_NAME", "LLVM_CXX_NAME"]:
                    clean_env.pop(k, None)

                rc_cm, _, stderr_cm, _ = run_cmd([
                    "cmake", "..",
                    f"-DCMAKE_C_COMPILER=gcc",
                    f"-DCMAKE_CXX_COMPILER=g++",
                    f"-DBUILD_SHARED_LIBS=OFF",
                ], timeout=120, cwd=str(asan_build), env=clean_env)

                if rc_cm == 0:
                    # Step 2: Make WITH ASan flags (cmake probes already done)
                    print(f"    [ASan-Real] CMake configured, building with ASan...")
                    rc_mk, _, stderr_mk, _ = run_cmd(
                        ["make", "-j4",
                         f"CFLAGS={asan_cflags_full}",
                         f"CXXFLAGS={asan_cflags_full}",
                         f"LDFLAGS={asan_ldflags}"],
                        timeout=300, cwd=str(asan_build), env=asan_env)
                    if rc_mk == 0:
                        built_ok = True
                    else:
                        print(f"    [ASan-Real] Make errors: {stderr_mk[:300]}")
                        built_ok = True  # library might still exist from partial build
                else:
                    print(f"    [ASan-Real] CMake failed: {stderr_cm[:300]}")

            elif configure_script.exists():
                asan_build = asan_src  # autotools builds in-tree

                # Clean first (like build_project_bc.sh)
                print(f"    [ASan-Real] Cleaning previous build...")
                run_cmd(["make", "distclean"], timeout=60, cwd=str(asan_src))

                # Detect autotools vs custom configure by checking --help output
                rc_help, help_out, _, _ = run_cmd(
                    [str(configure_script), "--help"], timeout=10, cwd=str(asan_src))
                is_autotools = "disable-nls" in (help_out or "")

                if is_autotools:
                    configure_args = [
                        str(configure_script),
                        "--disable-shared", "--enable-static",
                        "--disable-nls", "--disable-werror",
                    ]
                else:
                    # Non-autotools (e.g., FFmpeg) — use minimal flags
                    configure_args = [
                        str(configure_script),
                        "--disable-shared", "--enable-static",
                    ]

                print(f"    [ASan-Real] configure ({'autotools' if is_autotools else 'custom'}) + ASan...")
                rc_cf, _, stderr_cf, _ = run_cmd(
                    configure_args, timeout=120, cwd=str(asan_src), env=asan_env)
                
                if rc_cf == 0:
                    print(f"    [ASan-Real] Configured, running make...")
                    rc_mk, _, stderr_mk, _ = run_cmd(
                        ["make", "-j4"], timeout=300, cwd=str(asan_src), env=asan_env)
                    if rc_mk == 0:
                        built_ok = True
                    else:
                        print(f"    [ASan-Real] Make errors: {stderr_mk[:300]}")
                        built_ok = True
                else:
                    print(f"    [ASan-Real] Configure failed: {stderr_cf[:300]}")
            
            if built_ok and asan_build:
                # Search for resulting .a/.so (mirror build_project_bc.sh: find . -name "*.a")
                for search_dir in [asan_build, asan_src]:
                    for ext in ["*.a", "*.so"]:
                        found = list(search_dir.rglob(ext))
                        found = [f for f in found if "CMakeFiles" not in str(f) and "asan_replay" not in str(f)]
                        if found:
                            project_name = self.src_root.name.split("_")[0]
                            matched = [f for f in found if project_name.lower() in f.name.lower()]
                            asan_lib = matched[0] if matched else found[0]
                            print(f"    [ASan-Real] Found ASan library: {asan_lib}")
                            break
                    if asan_lib:
                        break
                
                if not asan_lib:
                    # List what WAS built for debugging
                    all_built = list(asan_build.rglob("*.a")) + list(asan_build.rglob("*.so"))
                    all_built = [f for f in all_built if "CMakeFiles" not in str(f)]
                    if all_built:
                        print(f"    [ASan-Real] Libraries found but none matched: {[str(f) for f in all_built[:5]]}")
                    else:
                        print(f"    [ASan-Real] No .a/.so files produced by build")

            # Cache the ASan library for other specs to reuse
            if asan_lib and asan_lib.exists() and not asan_cache_dir.exists():
                try:
                    asan_cache_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(asan_lib), str(asan_cache_dir / asan_lib.name))
                    # Also copy any additional .a files (projects may have multiple libs)
                    if asan_build:
                        for lib in asan_build.rglob("*.a"):
                            if "CMakeFiles" not in str(lib) and lib != asan_lib:
                                shutil.copy2(str(lib), str(asan_cache_dir / lib.name))
                    print(f"    [ASan-Real] Cached ASan library to {asan_cache_dir}")
                except Exception as e:
                    print(f"    [ASan-Real] Cache save failed: {e}")

        # === APPROACH 1B: Make with ASan flags (if Makefile exists) ===
        if not asan_lib:
            makefile_exists = any((d / mf).exists() 
                                for d in [build_path, self.src_root] 
                                for mf in ["Makefile", "makefile"]
                                if d.exists())
            
            if makefile_exists:
                make_dir = build_path if (build_path / "Makefile").exists() or (build_path / "makefile").exists() else self.src_root
                asan_env = dict(os.environ)
                asan_cflags = "-fsanitize=address -fno-omit-frame-pointer -g -O0"
                asan_env["CFLAGS"] = asan_cflags
                asan_env["CXXFLAGS"] = asan_cflags
                asan_env["LDFLAGS"] = "-fsanitize=address"
                
                print(f"    [ASan-Real] Trying make with ASan in {make_dir}...")
                run_cmd(["make", "-C", str(make_dir), "clean"], timeout=60, env=asan_env)
                rc_make, _, stderr_make, _ = run_cmd(
                    ["make", "-C", str(make_dir), "-j4"], timeout=300, env=asan_env)
                if rc_make == 0:
                    for ext in ["*.a", "*.so"]:
                        lib_candidates = list(make_dir.rglob(ext))
                        if lib_candidates:
                            asan_lib = lib_candidates[0]
                            break
                    if asan_lib:
                        print(f"    [ASan-Real] Make succeeded: {asan_lib}")
                else:
                    print(f"    [ASan-Real] Make failed: {stderr_make[:200]}")
        
        # === APPROACH 2: Link replay driver against ASan-rebuilt library ===
        if asan_lib and asan_lib.exists():
            print(f"    [ASan-Real] Linking replay driver against {asan_lib.name}...")
            link_cmd = (["gcc"] + asan_flags + inc_flags + proj_cflags +
                        c_files + [str(asan_lib), "-o", str(out_bin), 
                        "-lm", "-lz", "-lpthread", "-ldl"])
            rc, stdout, stderr, _ = run_cmd(link_cmd, timeout=120)
            if rc != 0:
                link_cmd[0] = "clang"
                rc, stdout, stderr, _ = run_cmd(link_cmd, timeout=120)
        
        # === APPROACH 3: Link against existing (non-ASan) library ===
        # This still validates the REAL code paths (just without ASan instrumentation
        # in the library — crashes/SEGV will still be caught by the OS).
        if rc != 0:
            lib_files = []
            # Search broadly: build_dir, its parent, src_root, and common sub-paths
            search_dirs = set()
            for d in [Path(build_dir), Path(build_dir).parent, self.src_root]:
                if d.exists():
                    search_dirs.add(d)
            
            for sd in search_dirs:
                # Non-recursive: direct and .libs/
                for ext in ["*.a", "*.so", "*.so.*"]:
                    lib_files.extend(sd.glob(ext))
                    lib_files.extend(sd.glob(f".libs/{ext}"))
                # Recursive: find any .a/.so up to 3 levels deep
                if not lib_files:
                    for ext in ["*.a", "*.so"]:
                        lib_files.extend(sd.glob(f"*/{ext}"))
                        lib_files.extend(sd.glob(f"*/.libs/{ext}"))
                        lib_files.extend(sd.glob(f"*/*/{ext}"))
                        lib_files.extend(sd.glob(f"*/*/.libs/{ext}"))
                if lib_files:
                    break
            
            # Filter: prefer libxml2/libfoo matching the project name
            project_name = self.src_root.name.split("_")[0] if self.src_root.name else ""
            if lib_files and project_name:
                matched = [f for f in lib_files if project_name.lower() in f.name.lower()]
                if matched:
                    lib_files = matched
            
            if lib_files:
                lib_path = str(lib_files[0])
                print(f"    [ASan-Real] Linking against existing library {lib_path}...")
                cmd2 = (["gcc"] + asan_flags + proj_cflags + inc_flags +
                        c_files + [lib_path, "-o", str(out_bin), "-lm", "-lz", "-lpthread"])
                rc, stdout, stderr, _ = run_cmd(cmd2, timeout=120)
                if rc != 0:
                    cmd2[0] = "clang"
                    rc, stdout, stderr, _ = run_cmd(cmd2, timeout=120)
            else:
                all_searched = ', '.join(str(d) for d in search_dirs)
                print(f"    [ASan-Real] No .a/.so libraries found in: {all_searched}")
        
        # === APPROACH 4: Last resort — compile just the real source file directly ===
        # This rarely works for large files with complex dependencies.
        if rc != 0:
            print(f"    [ASan-Real] Last resort: compiling real source directly...")
            cmd = (["gcc"] + asan_flags + proj_cflags + inc_flags +
                   [str(real_src)] + c_files + ["-o", str(out_bin), "-lm"])
            rc, stdout, stderr, _ = run_cmd(cmd, timeout=120)
            if rc != 0:
                cmd[0] = "clang"
                rc, stdout, stderr, _ = run_cmd(cmd, timeout=120)
        
        if rc != 0:
            print(f"    [ASan-Real] All compilation approaches failed: {stderr[:300]}")
            return {"success": False, "error": f"Real ASan compile failed: {stderr[:300]}"}
        
        print(f"    [ASan-Real] Compiled: {out_bin}")
        
        # Run the replay binary
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:print_stacktrace=1"
        rc, stdout, stderr, elapsed = run_cmd([str(out_bin)], timeout=30, env=env)
        
        combined = stdout + "\n" + stderr
        asan_triggered = "AddressSanitizer" in combined or rc == 139  # SIGSEGV

        result = {
            "success": True,
            "asan_triggered": asan_triggered,
            "exit_code": rc,
            "output": combined[:3000],
            "elapsed": elapsed,
            "validation_type": "real_library",
            "harness_artifact": False,
        }

        if asan_triggered:
            m_type = re.search(r'ERROR: AddressSanitizer:\s*(\S+)', combined)
            m_loc = re.search(r'#0\s+\S+\s+in\s+(\S+)\s+(\S+):(\d+)', combined)
            if m_type:
                result["asan_error_type"] = m_type.group(1)
            if m_loc:
                result["asan_func"] = m_loc.group(1)
                result["asan_file"] = m_loc.group(2)
                result["asan_line"] = int(m_loc.group(3))

            # Check if crash is in harness code (not a real library bug)
            frames = parse_asan_frames(combined)
            if is_harness_crash(frames):
                result["asan_triggered"] = False
                result["harness_artifact"] = True
                crash_loc = f"{m_loc.group(1)} at {m_loc.group(2)}:{m_loc.group(3)}" if m_loc else "unknown"
                print(f"    [ASan-Real] HARNESS ARTIFACT — crash in harness code ({crash_loc}), not real library")
            else:
                print(f"    [ASan-Real] *** Bug CONFIRMED in real library! ***")
                if m_type:
                    print(f"    [ASan-Real] Error: {m_type.group(1)}")
                if m_loc:
                    print(f"    [ASan-Real] Location: {m_loc.group(1)} at {m_loc.group(2)}:{m_loc.group(3)}")
        else:
            print(f"    [ASan-Real] No ASan error on real library (exit code {rc})")

        return result
    
    def _generate_replay_driver(self, ktest_info: Dict, original_driver: str) -> str:
        """Generate a concrete replay driver from ktest decoded values.
        
        Takes the original symbolic driver and replaces klee_make_symbolic/klee_assume
        with concrete values from the ktest. This is used for ASan replay validation.
        
        Key: we inject the ACTUAL bytes from the ktest, not zeros.
        """
        if not original_driver:
            return ""
        
        replay = original_driver
        
        # Remove klee includes
        replay = re.sub(r'#include\s*[<"]klee/klee\.h[>"]', '// klee removed for replay', replay)
        
        # Parse ktest objects into a name→bytes map
        objects = ktest_info.get("objects", [])
        obj_map = {obj["name"]: obj for obj in objects}
        
        def replace_symbolic(m):
            """Replace klee_make_symbolic(ptr, size, "name") with concrete byte injection."""
            args_str = m.group(1)
            # Split on commas, handling nested parens
            parts = [p.strip() for p in args_str.split(',')]
            if len(parts) < 3:
                return f'memset({parts[0]}, 0, {parts[1] if len(parts) > 1 else "1"}); /* replay: parse error */'
            
            ptr = parts[0]
            size = parts[1]
            name = parts[2].strip('"').strip("'")
            
            if name in obj_map:
                obj = obj_map[name]
                data_str = obj.get("data", "")
                obj_size = obj.get("size", 0)
                
                # Parse the ktest data into actual bytes
                # ktest-tool outputs data in formats like:
                #   b'\x00\x01\x02...' or 0x00000001
                byte_values = self._parse_ktest_data(data_str, obj_size)
                
                if byte_values:
                    # Generate: unsigned char name_data[] = {0x00, 0x01, ...};
                    #           memcpy(ptr, name_data, size);
                    hex_vals = ', '.join(f'0x{b:02x}' for b in byte_values[:512])
                    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
                    lines = [
                        f'{{ /* replay: concrete values for "{name}" ({len(byte_values)} bytes) */',
                        f'  static const unsigned char {safe_name}_data[] = {{{hex_vals}}};',
                        f'  memcpy({ptr}, {safe_name}_data, ({size}) < {len(byte_values)} ? ({size}) : {len(byte_values)});',
                        f'}}',
                    ]
                    return '\n'.join(lines)
                else:
                    return f'memset({ptr}, 0, {size}); /* replay: "{name}" (could not parse ktest data) */'
            
            return f'memset({ptr}, 0, {size}); /* replay: "{name}" (not in ktest) */'
        
        # Updated regex to handle one level of nested parentheses (e.g., sizeof(...))
        replay = re.sub(r'klee_make_symbolic\s*\(((?:[^()]|\([^()]*\))+)\)', replace_symbolic, replay)
        
        # Remove klee_assume (constraints not needed — ASan catches the bug)
        replay = re.sub(r'klee_assume\([^)]+\)\s*;', '/* klee_assume removed for replay */', replay)
        
        # Remove klee_assert
        replay = re.sub(r'klee_assert\([^)]+\)\s*;', '/* klee_assert removed for replay */', replay)
        
        # Add header
        replay = f"""/* AUTO-GENERATED REPLAY DRIVER for concrete validation
 * Replaces symbolic inputs with concrete ktest values.
 * Compile with ASan: gcc -fsanitize=address -g -O0 replay_driver.c ... -o replay
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
""" + replay
        
        return replay
    
    @staticmethod
    def _parse_ktest_data(data_str: str, expected_size: int) -> List[int]:
        """Parse ktest-tool output data into a list of byte values.
        
        Handles formats:
          b'\\x00\\x01\\x02'  (Python bytes literal)
          b'\\x00\\x00\\x03\\xe8' 
          0x00000001           (hex integer)
        """
        byte_values = []
        
        if not data_str:
            return [0] * expected_size
        
        # Format 1: Python bytes literal b'...'
        if data_str.startswith("b'") or data_str.startswith('b"'):
            inner = data_str[2:-1]  # strip b' and '
            i = 0
            while i < len(inner):
                if inner[i] == '\\' and i + 1 < len(inner):
                    if inner[i+1] == 'x' and i + 3 < len(inner):
                        try:
                            byte_values.append(int(inner[i+2:i+4], 16))
                            i += 4
                            continue
                        except ValueError:
                            pass
                    elif inner[i+1] == '0':
                        byte_values.append(0)
                        i += 2
                        continue
                    elif inner[i+1] == 'n':
                        byte_values.append(10)
                        i += 2
                        continue
                    elif inner[i+1] == '\\':
                        byte_values.append(ord('\\'))
                        i += 2
                        continue
                byte_values.append(ord(inner[i]) if i < len(inner) else 0)
                i += 1
        
        # Format 2: hex integer 0x...
        elif data_str.startswith("0x"):
            try:
                val = int(data_str, 16)
                for i in range(expected_size):
                    byte_values.append((val >> (8 * (expected_size - 1 - i))) & 0xFF)
            except ValueError:
                byte_values = [0] * expected_size
        
        # Pad or truncate to expected size
        if len(byte_values) < expected_size:
            byte_values.extend([0] * (expected_size - len(byte_values)))
        elif len(byte_values) > expected_size:
            byte_values = byte_values[:expected_size]
        
        return byte_values
    
    def _build_bug_report(self, err_ktests: List[Dict], asan_result: Dict) -> Dict:
        """Build a comprehensive bug report with original line numbers."""
        
        vul_file = self.frozen.get("vul_file", "")
        vul_line = int(self.ctx.get("vul_line", 0))
        vul_func = self.frozen.get("vul_func", "")
        entry_func = self.frozen.get("entry", "")
        
        # Get original source context around the vulnerability
        src_file = find_source_file(self.src_root, vul_file)
        orig_context = ""
        orig_lines = []
        if src_file:
            orig_lines = src_file.read_text(errors="replace").splitlines()
            start = max(0, vul_line - 6)
            end = min(len(orig_lines), vul_line + 5)
            orig_context = '\n'.join(f"{i+1}: {orig_lines[i]}" for i in range(start, end))
        
        # CWE info
        spec_path = self.harness_dir.parent / "sa_context" / "spec.json"
        cwe_id = ""
        cwe_desc = ""
        rule_id = ""
        if spec_path.exists():
            try:
                spec = read_json(spec_path)
                cwe_id = str(spec.get("cwe_id", spec.get("cwe", "")))
                cwe_desc = spec.get("cwe_description", spec.get("title", ""))
                rule_id = spec.get("rule_id", spec.get("query_id", ""))
            except Exception:
                pass
        
        # WMI rule_id → CWE fallback (WMI rules may not have explicit CWE)
        if not cwe_id and rule_id:
            wmi_cwe_map = {
                "wmi-1": "416",  # Stale Reference → UAF
                "wmi-2": "416",  # Type Confusion Leak → UAF read
                "wmi-3": "416",  # Arbitrary Free → UAF/double-free
                "wmi-4": "416",  # Write-What-Where → UAF write
            }
            for prefix, cwe in wmi_cwe_map.items():
                if prefix in str(rule_id).lower():
                    cwe_id = cwe
                    cwe_desc = f"WMI pattern ({prefix})"
                    break
        
        # Primary crash (closest to vulnerability)
        primary = err_ktests[0] if err_ktests else {}
        
        # Get source context around the KLEE crash line in the ORIGINAL file
        klee_orig_context = ""
        klee_orig_line = primary.get("orig_line", 0)
        if klee_orig_line and orig_lines:
            start = max(0, klee_orig_line - 4)
            end = min(len(orig_lines), klee_orig_line + 3)
            klee_orig_context = '\n'.join(
                f"{'>>>' if (i+1) == klee_orig_line else '   '} {i+1}: {orig_lines[i]}" 
                for i in range(start, end)
            )
        
        # Get source context around ASan crash line (if ASan confirmed in a different file)
        asan_orig_context = ""
        asan_line = asan_result.get("asan_line", 0)
        asan_file = asan_result.get("asan_file", "")
        if asan_line and asan_file:
            # ASan crash may be in the replay_dir harness file — map it back
            asan_basename = os.path.basename(asan_file)
            asan_orig = self.lookup_original_line(asan_basename, asan_line)
            if asan_orig:
                asan_result["asan_orig_file"] = asan_orig["orig_file"]
                asan_result["asan_orig_line"] = asan_orig["orig_line"]
                asan_result["asan_orig_code"] = asan_orig["code"]
                if orig_lines:
                    al = asan_orig["orig_line"]
                    start = max(0, al - 3)
                    end = min(len(orig_lines), al + 2)
                    asan_orig_context = '\n'.join(
                        f"{'>>>' if (i+1) == al else '   '} {i+1}: {orig_lines[i]}"
                        for i in range(start, end)
                    )
        
        # --- Verdict: Check if ASAN crash is at/near the TARGET vulnerability ---
        # A "TP" requires the ASAN crash to be in the same function or within
        # ±30 lines of the original vulnerability. Otherwise it's a different
        # bug triggered by the same harness → "LIKELY_TP_DIFFERENT_CRASH".
        verdict = "LIKELY_TP"
        crash_relevance = "no_asan"
        
        if asan_result.get("asan_triggered"):
            asan_orig_line = asan_result.get("asan_orig_line", 0)
            asan_orig_file = asan_result.get("asan_orig_file", "")
            asan_crash_func = asan_result.get("asan_func", "")
            
            # Check 1: ASAN crash in the same function as the vulnerability
            same_func = (asan_crash_func == vul_func) if (asan_crash_func and vul_func) else False
            
            # Check 2: ASAN crash in the same file and within ±30 lines
            same_file = False
            if asan_orig_file and vul_file:
                same_file = (os.path.basename(asan_orig_file) == os.path.basename(vul_file)
                             or asan_orig_file == vul_file)
            near_target = same_file and asan_orig_line and vul_line and abs(asan_orig_line - vul_line) <= 30
            
            # Check 3: ASAN crash in a spine function (callee of target)
            spine = self.frozen.get("spine", [])
            in_spine = asan_crash_func in spine if asan_crash_func else False
            
            # Check 4: ASAN error type matches the CWE expectation
            asan_error = asan_result.get("asan_error_type", "").lower()
            cwe_match = False
            if cwe_id:
                cwe_to_asan = {
                    "125": ["heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow", "SEGV"],
                    "787": ["heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow"],
                    "416": ["heap-use-after-free"],
                    "415": ["double-free"],
                    "476": ["SEGV", "null"],
                    "122": ["heap-buffer-overflow"],
                    "121": ["stack-buffer-overflow"],
                    "120": ["heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow"],
                    "674": ["stack-overflow"],
                    "190": ["signed-integer-overflow", "unsigned-integer-overflow"],
                    "823": ["heap-buffer-overflow", "SEGV"],
                    "400": ["allocator-size-too-big", "out-of-memory"],
                }
                expected = cwe_to_asan.get(str(cwe_id), [])
                cwe_match = any(e.lower() in asan_error for e in expected)
            
            if same_func or near_target:
                verdict = "TP"
                crash_relevance = "exact_match"
            elif in_spine and (cwe_match or same_file):
                verdict = "TP"
                crash_relevance = "spine_match"
            elif same_file:
                verdict = "LIKELY_TP"
                crash_relevance = "same_file_different_location"
            elif in_spine:
                verdict = "LIKELY_TP"
                crash_relevance = "spine_different_file"
            else:
                verdict = "LIKELY_TP_DIFFERENT_CRASH"
                crash_relevance = "different_location"
            
            # SEGV at null page (address < 0x1000) with all-zero inputs is likely
            # a harness initialization problem, not the real bug
            asan_output = asan_result.get("output", "")
            null_segv = ("SEGV" in asan_error and 
                        re.search(r'SEGV on unknown address 0x0{3,}[0-9a-f]{1,4}\b', asan_output))
            if null_segv and not same_func and not near_target:
                verdict = "LIKELY_FP_NULL_DEREF"
                crash_relevance = "null_deref_likely_harness_bug"
                print(f"    [Report] WARNING: ASAN crash is a null-page SEGV, likely harness "
                      f"initialization issue (not the target vulnerability)")
            
            print(f"    [Report] Crash relevance: {crash_relevance} "
                  f"(asan={asan_crash_func}@{asan_orig_file}:{asan_orig_line}, "
                  f"target={vul_func}@{vul_file}:{vul_line})")
        
        report = {
            "summary": {
                "verdict": verdict,
                "asan_confirmed": asan_result.get("asan_triggered", False),
                "crash_relevance": crash_relevance,
                "cwe": f"CWE-{cwe_id}" if cwe_id else "unknown",
                "cwe_description": cwe_desc,
            },
            "vulnerability": {
                "original_file": vul_file,
                "original_line": vul_line,
                "function": vul_func,
                "entry_point": entry_func,
                "spine": self.frozen.get("spine", []),
                "original_context": orig_context,
            },
            "klee_crash": {
                "harness_file": os.path.basename(primary.get("crash_file", "")),
                "harness_line": primary.get("crash_line", 0),
                "original_file": primary.get("orig_file", ""),
                "original_line": primary.get("orig_line", 0),
                "original_code": primary.get("orig_code", ""),
                "original_context": klee_orig_context,
                "error_type": primary.get("err_type", ""),
                "error_details": primary.get("err_content", ""),
            },
            "concrete_inputs": [],
            "asan_result": {
                "triggered": asan_result.get("asan_triggered", False),
                "harness_artifact": asan_result.get("harness_artifact", False),
                "error_type": asan_result.get("asan_error_type", ""),
                "crash_function": asan_result.get("asan_func", ""),
                "crash_file": asan_result.get("asan_file", ""),
                "crash_line": asan_result.get("asan_line", 0),
                "original_file": asan_result.get("asan_orig_file", ""),
                "original_line": asan_result.get("asan_orig_line", 0),
                "original_code": asan_result.get("asan_orig_code", ""),
                "original_context": asan_orig_context,
                "output": asan_result.get("output", "")[:2000],
            },
            "line_map_file": str(self.harness_dir / "line_map.json"),
            "all_crashes": [],
            "all_asan_crashes": [],
        }
        
        # Add ALL confirmed ASAN crashes (not just the primary)
        for ar in asan_result.get("all_asan_crashes", []):
            # Map each ASAN crash back to original source
            ar_asan_file = ar.get("asan_file", "")
            ar_asan_line = ar.get("asan_line", 0)
            ar_orig_file = ""
            ar_orig_line = 0
            if ar_asan_file and ar_asan_line:
                ar_orig = self.lookup_original_line(os.path.basename(ar_asan_file), ar_asan_line)
                if ar_orig:
                    ar_orig_file = ar_orig["orig_file"]
                    ar_orig_line = ar_orig["orig_line"]
            
            # Classify relevance of this ASAN crash vs target
            ar_func = ar.get("asan_func", "")
            ar_same_func = (ar_func == vul_func) if ar_func and vul_func else False
            ar_same_file = False
            if ar_orig_file and vul_file:
                ar_same_file = os.path.basename(ar_orig_file) == os.path.basename(vul_file)
            ar_near = ar_same_file and ar_orig_line and vul_line and abs(ar_orig_line - vul_line) <= 30
            ar_in_spine = ar_func in self.frozen.get("spine", []) if ar_func else False
            
            if ar_same_func or ar_near:
                ar_relevance = "target_crash"
            elif ar_in_spine and ar_same_file:
                ar_relevance = "spine_crash"
            elif ar_same_file:
                ar_relevance = "same_file_crash"
            elif ar_in_spine:
                ar_relevance = "spine_crash"
            else:
                ar_relevance = "secondary_bug"
            
            report["all_asan_crashes"].append({
                "error_type": ar.get("asan_error_type", ""),
                "crash_function": ar.get("asan_func", ""),
                "crash_file": ar_asan_file,
                "crash_line": ar_asan_line,
                "original_file": ar_orig_file or ar.get("source_orig_file", ""),
                "original_line": ar_orig_line or ar.get("source_orig_line", 0),
                "relevance": ar_relevance,
                "source_ktest": ar.get("source_ktest", ""),
            })
        
        # Update summary counts
        report["summary"]["total_asan_crashes"] = len(report["all_asan_crashes"])
        report["summary"]["target_asan_crashes"] = len([
            c for c in report["all_asan_crashes"] 
            if c["relevance"] in ("target_crash", "spine_crash")
        ])
        report["summary"]["secondary_asan_crashes"] = len([
            c for c in report["all_asan_crashes"]
            if c["relevance"] not in ("target_crash", "spine_crash")
        ])
        
        # Add concrete inputs from ktest
        for kt in err_ktests:
            for obj in kt.get("objects", []):
                report["concrete_inputs"].append({
                    "name": obj["name"],
                    "size": obj["size"],
                    "data": obj["data"][:200],
                })
        
        # Add all crash info with original line mapping + relevance classification
        for kt in err_ktests:
            kt_orig_file = kt.get("orig_file", "")
            kt_orig_line = kt.get("orig_line", 0)
            kt_err_type = kt.get("err_type", "")
            
            # Classify this crash's relevance to the target vulnerability
            kt_same_func = False
            kt_near_target = False
            kt_in_spine = False
            
            # Check function: parse from err_content stack trace
            kt_crash_func = ""
            stack_m = re.search(r'in\s+(\w+)\s*\(', kt.get("err_content", ""))
            if stack_m:
                kt_crash_func = stack_m.group(1)
            
            if kt_crash_func and vul_func and kt_crash_func == vul_func:
                kt_same_func = True
            
            kt_same_file = False
            if kt_orig_file and vul_file:
                kt_same_file = (os.path.basename(kt_orig_file) == os.path.basename(vul_file)
                                or kt_orig_file == vul_file)
            kt_near_target = kt_same_file and kt_orig_line and vul_line and abs(kt_orig_line - vul_line) <= 30
            
            spine = self.frozen.get("spine", [])
            if kt_crash_func and kt_crash_func in spine:
                kt_in_spine = True
            
            if kt_same_func or kt_near_target:
                kt_relevance = "target_crash"
            elif kt_in_spine and kt_same_file:
                kt_relevance = "spine_crash"
            elif kt_same_file:
                kt_relevance = "same_file_crash"
            elif kt_in_spine:
                kt_relevance = "spine_different_file"
            else:
                kt_relevance = "secondary_bug"
            
            report["all_crashes"].append({
                "harness_file": os.path.basename(kt.get("crash_file", "")),
                "harness_line": kt.get("crash_line", 0),
                "original_file": kt_orig_file,
                "original_line": kt_orig_line,
                "error_type": kt_err_type,
                "crash_function": kt_crash_func,
                "relevance": kt_relevance,
                "ktest": kt.get("ktest", ""),
            })
        
        # Separate target-related vs secondary bugs for the summary
        target_crashes = [c for c in report["all_crashes"] 
                          if c["relevance"] in ("target_crash", "spine_crash")]
        secondary_bugs = [c for c in report["all_crashes"]
                          if c["relevance"] not in ("target_crash", "spine_crash")]
        
        report["summary"]["target_crashes"] = len(target_crashes)
        report["summary"]["secondary_bugs"] = len(secondary_bugs)
        
        if secondary_bugs:
            report["secondary_bugs"] = []
            for sb in secondary_bugs:
                report["secondary_bugs"].append({
                    "original_file": sb["original_file"],
                    "original_line": sb["original_line"],
                    "error_type": sb["error_type"],
                    "crash_function": sb.get("crash_function", ""),
                    "relevance": sb["relevance"],
                    "ktest": sb["ktest"],
                })
        
        # Print summary
        print(f"    [Report] Verdict: {report['summary']['verdict']}")
        print(f"    [Report] KLEE crash: harness {report['klee_crash']['harness_file']}:{report['klee_crash']['harness_line']}"
              f" → original {report['klee_crash']['original_file']}:{report['klee_crash']['original_line']}")
        if asan_result.get("asan_triggered"):
            print(f"    [Report] ASan: {report['asan_result']['error_type']} at "
                  f"{report['asan_result']['original_file']}:{report['asan_result']['original_line']}")
        if target_crashes:
            print(f"    [Report] Target crashes: {len(target_crashes)}")
        if secondary_bugs:
            print(f"    [Report] Secondary bugs found: {len(secondary_bugs)}")
            for sb in secondary_bugs[:5]:
                print(f"      - {sb['error_type']} at {sb['original_file']}:{sb['original_line']} "
                      f"({sb.get('crash_function', '?')}) [{sb['relevance']}]")
        
        # Print all ASAN-confirmed crashes
        if report["all_asan_crashes"]:
            print(f"    [Report] ASan-confirmed crashes: {len(report['all_asan_crashes'])}")
            for ac in report["all_asan_crashes"]:
                print(f"      - {ac['error_type']} in {ac.get('crash_function', '?')} "
                      f"→ {ac.get('original_file', '?')}:{ac.get('original_line', '?')} "
                      f"[{ac['relevance']}]")
        
        return report

    def smart_recon(self, target_func: str) -> str:
        if target_func == self.frozen['vul_func']:
            return f"Context: {target_func} is the target. It is called by {self.frozen['entry']}."
        f = find_source_file(self.src_root, self.ctx['vul_file'])
        if not f: return "Source file not found."
        cmd = ["grep", "-n", rf"^{target_func}\s*(", str(f)]
        rc, out, _, _ = run_cmd(cmd)
        if rc == 0: return f"Found definition in {f.name}:\n{out.strip()}\n"
        return "Definition not found via grep."
    
    def find_definition(self, symbol: str) -> str:
        print(f"  [Tool] FindDefinition: {symbol}")
        # Priority 1: SA type index
        sa_types = self.frozen.get("sa_types", {})
        for name in [symbol, f"_{symbol}", symbol.lstrip("_")]:
            if name in sa_types:
                return f"[SA] {name}:\n{sa_types[name][:1000]}"
        # Priority 2: grep *.h/*.c files, try both symbol and _symbol
        search_names = [symbol]
        if not symbol.startswith("_"):
            search_names.append(f"_{symbol}")
        else:
            search_names.append(symbol.lstrip("_"))
        
        for name in search_names:
            cmd = ["grep", "-rE", "-n", "--include=*.h", "--include=*.c",
                   rf"(struct|union|enum)\s+{name}\s*\{{", str(self.src_root)]
            rc, out, _, _ = run_cmd(cmd, timeout=10)
            if rc == 0 and out:
                # Show the definition with some context (up to 30 lines after the opening brace)
                first_match = out.strip().split('\n')[0]
                match_file, match_line = first_match.split(':', 1)[0], first_match.split(':')[1]
                try:
                    fpath = Path(first_match.split(':')[0])
                    lnum = int(first_match.split(':')[1])
                    src_lines = fpath.read_text(errors="replace").splitlines()
                    # Show up to 40 lines from the struct definition start
                    end = min(len(src_lines), lnum + 39)
                    context = '\n'.join(f"{i+1}: {src_lines[i]}" for i in range(lnum-1, end))
                    return f"Found '{name}' in {fpath.name}:\n{context[:2000]}"
                except:
                    return out[:1000]
        return f"No definition found for {symbol}"

    def grep_source(self, pattern: str, file_name: str = "") -> str:
        """Search for a pattern in source files. Much faster than ReadSource line-by-line."""
        print(f"  [Tool] GrepSource: '{pattern}' in {file_name or 'all files'}")
        if file_name:
            # Search in a specific file (harness or original)
            if file_name.startswith("original:"):
                f = find_source_file(self.src_root, file_name[9:])
            else:
                hf = self.harness_dir / os.path.basename(file_name)
                f = hf if hf.exists() else find_source_file(self.src_root, file_name)
            if not f: return "File not found."
            cmd = ["grep", "-n", "-i", pattern, str(f)]
        else:
            # Search across all source files
            cmd = ["grep", "-rn", "-i", "--include=*.c", "--include=*.h", pattern, str(self.src_root)]
        rc, out, _, _ = run_cmd(cmd, timeout=10)
        if rc == 0 and out:
            lines = out.strip().split('\n')
            if len(lines) > 30:
                return '\n'.join(lines[:25]) + f"\n... ({len(lines)-25} more matches)"
            return out[:2000]
        return f"No matches for '{pattern}'"

    def read_sa_context(self, file_name: str = "") -> str:
        """Read SA context files: spec, findings, vulnerability summary."""
        sa_dir = self.logs_dir.parent / "sa_context"
        if not sa_dir.exists():
            return "No SA context directory found."
        
        if not file_name:
            # List available files
            files = sorted(sa_dir.iterdir())
            listing = []
            for f in files:
                size = f.stat().st_size if f.is_file() else 0
                listing.append(f"  {f.name} ({size}B)")
            result = "SA context files available:\n" + "\n".join(listing)
            result += "\n\nUse ReadSAContext(file) to read a specific file."
            # Auto-show vulnerability summary if it exists
            summary_path = sa_dir / "vulnerability_summary.json"
            if summary_path.exists():
                summary = summary_path.read_text(errors="replace")
                result += f"\n\n--- vulnerability_summary.json ---\n{summary[:3000]}"
            return result
        
        fp = sa_dir / file_name
        if not fp.exists():
            return f"File '{file_name}' not found. Available: {[f.name for f in sa_dir.iterdir()]}"
        
        content = fp.read_text(errors="replace")
        
        # For compile_commands.json, filter to show only the vulnerable file's entry
        if file_name == "compile_commands.json":
            try:
                import json
                cc = json.loads(content)
                vul_file = self.frozen.get("vul_file", "")
                vul_base = os.path.basename(vul_file)
                relevant = [e for e in cc if os.path.basename(e.get("file", "")) == vul_base]
                if relevant:
                    content = (f"[Filtered to {vul_base} — {len(cc)} total entries]\n"
                              + json.dumps(relevant, indent=2))
                else:
                    content = (f"[No entry found for {vul_base} — showing compile_entry.json instead]\n"
                              + "Use ReadSAContext('compile_entry.json') for the vulnerable file's flags.")
            except Exception:
                pass  # fall through to normal display
        
        if len(content) > 5000:
            content = content[:2500] + "\n... (truncated) ...\n" + content[-2500:]
        return content

    def read_source(self, file_name: str, start_line: int, end_line: int) -> str:
        clean_name = os.path.basename(file_name)
        hf = self.harness_dir / clean_name
        # Allow reading original source with 'original:' prefix
        if file_name.startswith("original:"):
            f = find_source_file(self.src_root, file_name[9:])
            if not f: return "Original source file not found."
        else:
            f = hf if hf.exists() else find_source_file(self.src_root, file_name)
        if not f: return "File not found."
        lines = f.read_text(errors="replace").splitlines()
        total = len(lines)
        s, e = max(0, start_line-1), min(total, end_line)
        if s >= total:
            return f"File has {total} lines. Requested start ({start_line}) is beyond end of file."
        result = "\n".join([f"{i+1}: {lines[i]}" for i in range(s, e)])
        return f"[{f.name}: {total} lines total, showing {s+1}-{e}]\n{result}"
    
    def write_driver(self, code: str) -> str:
        print(f"  [Tool] WriteDriver: {len(code)} chars")
        (self.harness_dir / "driver.c").write_text(code, encoding="utf-8")
        return "OK: Written harness/driver.c"
    
    def write_types(self, code: str) -> str:
        (self.harness_dir / "types.h").write_text(code, encoding="utf-8")
        return "OK: Written harness/types.h"
    
    def write_stubs(self, code: str) -> str:
        print(f"  [Tool] WriteStubs: {len(code)} chars")
        (self.harness_dir / "stubs.c").write_text(code, encoding="utf-8")
        return "OK: Written harness/stubs.c"
    
    def extract_function(self, file_name: str, func_name: str) -> str:
        f = find_source_file(self.src_root, file_name)
        if not f: return f"Error: '{file_name}' not found."
        src = f.read_text(errors="replace")
        span = find_function_span(src, func_name)
        if not span: return f"Error: '{func_name}' not found in source."
        
        sig_start, _, body_end = span
        func_text = src[sig_start:body_end]
        # Keep 'static' qualifier — _ensure_public_entry() will add a public trampoline
        
        # Note: Smart slicing happens in compile_slice after ALL functions are extracted
        
        # --- SANITIZE SAILOR PROBES ---
        # Remove malformed SAILOR_SUSPECT_HIT probes inside function arguments
        probe_pattern = re.compile(
            r'/\*\s*SAILOR_INST_BEGIN:\w+\s*\*/\s*\n'
            r'\s*klee_warning\("SAILOR_SUSPECT_HIT"\);\s*\n'
            r'\s*/\*\s*SAILOR_INST_END:\w+\s*\*/\s*\n'
            r'(\s*/\*\s*SAILOR_INST:\w+\s*\*/\s*\n)?',
            re.MULTILINE
        )
        
        n_probes_removed = len(probe_pattern.findall(func_text))
        if n_probes_removed:
            func_text = probe_pattern.sub('', func_text)
            print(f"    [!] Sanitized {n_probes_removed} malformed SAILOR probe(s) from {func_name}")
        
        # --- UNIVERSAL ASSERTION INJECTION AT VULNERABILITY SITE ---
        # Algorithm: Always inject klee_assert(0 && "SAILOR_SINK_REACHED") at the
        # vulnerability line as a reachability probe. This works for ALL CWE types.
        # Optionally inject CWE-specific checks BEFORE the assert for richer evidence.
        #
        # Detection in run_klee:
        #   - .assert.err with SAILOR_SINK_REACHED → reachability proven
        #   - .ptr.err near vuln line → OOB/NULL deref (CWE-125/787/476)
        #   - .div.err near vuln line → divide by zero (CWE-369)
        #   - check_memory_access in log → our CWE-specific check triggered
        #   - SAILOR_PROBE_SINK in warnings → probe hit
        
        sink_markers = ['SAILOR_PROBE_SINK', 'SAILOR_SUSPECT_HIT', 'SAILOR_INST_BEGIN']
        has_sink = any(m in func_text for m in sink_markers)
        
        if has_sink:
            # Determine CWE type for optional specific checks
            spec_path = self.harness_dir.parent / "sa_context" / "spec.json"
            cwe_id = ""
            if spec_path.exists():
                try:
                    spec = read_json(spec_path)
                    cwe_id = str(spec.get("cwe_id", spec.get("cwe", "")))
                except Exception:
                    pass
            
            lines = func_text.split('\n')
            new_lines = []
            in_sink_zone = False
            check_done = False
            sink_indent = "\t"
            
            for i, line in enumerate(lines):
                stripped = line.strip()
                
                if any(m in stripped for m in ['SAILOR_PROBE_SINK', 'SAILOR_SUSPECT_HIT']):
                    in_sink_zone = True
                    sink_indent = re.match(r'^(\s*)', line).group(1) or "\t"
                    continue
                
                if 'SAILOR_INST_BEGIN' in stripped and not in_sink_zone:
                    in_sink_zone = True
                    sink_indent = re.match(r'^(\s*)', line).group(1) or "\t"
                    new_lines.append(line)
                    continue
                
                if in_sink_zone and not check_done:
                    if stripped.startswith(('/* SAILOR_INST', '* SAILOR_INST')):
                        continue
                    if 'klee_check_memory_access' in stripped:
                        continue
                
                if in_sink_zone and not check_done:
                    if (stripped and
                        not stripped.startswith(('/*', '//', '#', '*')) and
                        stripped not in ('{', '}')):
                        
                        # --- CWE-SPECIFIC CHECKS: REMOVED ---
                        # klee_check_memory_access requires constant args and fails
                        # with symbolic pointers. Instead, the actual vulnerable
                        # statement triggers KLEE's native OOB/.ptr.err detection.
                        
                        # --- UNIVERSAL REACHABILITY ASSERT (AFTER vulnerable statement) ---
                        # First, let the vulnerable statement execute (it may crash = bug)
                        # Then place the assert (reaching it = no crash = possible FP)
                        new_lines.append(line)  # the vulnerable statement itself
                        new_lines.append(f'{sink_indent}klee_assert(0 && "SAILOR_SINK_REACHED");')
                        print(f"    [+] Injected universal reachability probe AFTER vulnerable statement")
                        check_done = True
                        continue  # skip the normal append of line (already added)
                
                new_lines.append(line)
            
            if check_done:
                func_text = '\n'.join(new_lines)
        
        # Also sanitize the preamble (probes can be in other functions too)
        preamble_src = src[:sig_start]
        n_preamble_probes = len(probe_pattern.findall(preamble_src))
        if n_preamble_probes:
            preamble_src = probe_pattern.sub('', preamble_src)
            print(f"    [!] Sanitized {n_preamble_probes} malformed SAILOR probe(s) from preamble")
        
        # --- SPINE-BASED STUB DETECTION ---
        spine_set = set(self.frozen.get('spine', []))
        func_calls = set(re.findall(r'\b([a-zA-Z_]\w+)\s*\(', func_text)) - _SKIP_CALLS
        stub_candidates = sorted(func_calls - spine_set - {func_name})
        
        target = self.harness_dir / os.path.basename(file_name)
        func_marker = f"/* === Extracted {func_name} === */"
        
        if target.exists():
            content = target.read_text(errors="replace")
            if func_marker in content:
                return f"SKIP: {func_name} already extracted in {target.name}"
            # Check if function already exists in preamble (e.g. static function from same file)
            if find_function_span(content, func_name):
                return (f"SKIP: {func_name} already present in {target.name} "
                        f"(included in preamble from same source file). "
                        f"Do NOT extract it again — it will cause duplicate definitions.")
            # Append just the function (preamble already written from first extraction)
            target.write_text(content + f"\n{func_marker}\n{func_text}\n", encoding="utf-8")
        else:
            # --- BUILD PREAMBLE: everything before the target function ---
            preamble = preamble_src
            
            # FIX: Close any unclosed preprocessor conditionals.
            cond_depth = 0
            for line in preamble.splitlines():
                stripped = line.strip()
                if re.match(r'^#\s*(if|ifdef|ifndef)\b', stripped):
                    cond_depth += 1
                elif re.match(r'^#\s*endif\b', stripped):
                    cond_depth -= 1
            if cond_depth > 0:
                preamble += "\n" + ("#endif\n" * cond_depth)
                preamble += f"/* auto-closed {cond_depth} unclosed preprocessor conditional(s) at extraction boundary */\n"
            
            # Add klee header if not already present
            if "klee/klee.h" not in preamble:
                preamble += '\n#include <klee/klee.h>\n'
            
            preamble_lines = preamble.count('\n')
            new_content = (
                f"/* Extracted from {file_name} — preamble preserved ({preamble_lines} lines) */\n"
                f"{preamble}\n\n"
                f"{func_marker}\n{func_text}\n"
            )
            target.write_text(new_content, encoding="utf-8")
        
        # --- DYNAMIC LINE MAPPING ---
        # After writing, resolve the current vulnerability line in the harness file
        vul_line_info = ""
        vul_loc = self.resolve_vul_line()
        if vul_loc:
            vul_line_info = (
                f"\nVULNERABILITY SITE in harness/{vul_loc['harness_file']}:{vul_loc['harness_line']} "
                f"(found via {vul_loc['marker']}):"
                f"\n{vul_loc['context']}"
            )
            print(f"    [i] Vulnerability site: harness/{vul_loc['harness_file']}:{vul_loc['harness_line']}")
        
        print(f"  [Tool] ExtractFunction: {func_name} -> {target.name} ({len(stub_candidates)} stub candidates)")
        
        # Warn if file is bloated — agent should use GatherCode + WriteHarness instead
        n_lines = content.count('\n')
        bloat_warning = ""
        if n_lines > 500:
            bloat_warning = (
                f"\n\nWARNING: Extracted file is {n_lines} lines — this is TOO LARGE for KLEE. "
                f"ExtractFunction copies the ENTIRE file preamble ({n_lines - func_text.count(chr(10))} lines of includes/macros/types) "
                f"plus the function body. This will cause hundreds of undefined references and slow compilation. "
                f"RECOMMENDED: Use GatherCode to get just the function body, then WriteHarness "
                f"with ONLY the essential preamble and a NEUTRALIZED (sliced) version of the function."
            )
        
        stub_info = ""
        if stub_candidates:
            stub_info = f"\nStub candidates (not in spine): {', '.join(stub_candidates[:20])}"
        
        # Build line map for original↔harness correspondence
        self._post_harness_line_map()
        
        return f"OK: Extracted '{func_name}' to 'harness/{target.name}' ({n_lines} lines).{bloat_warning}{stub_info}{vul_line_info}"

    def gather_code(self, func_names: str, type_names: str = "") -> str:
        """Gather function bodies and type definitions from project source.
        
        For large functions (>200 lines), returns a SMART EXCERPT:
        - Function signature (first 10 lines)
        - The target switch case section (if known)
        - Goto label sections near the vulnerability
        - Skips all other code
        
        The agent should NOT call GatherCode repeatedly for the same function.
        Use the excerpt + vulnerability_summary to write the harness.
        """
        print(f"  [Tool] GatherCode(funcs={func_names}, types={type_names})")
        
        funcs = [f.strip() for f in func_names.split(",") if f.strip()]
        types = [t.strip() for t in type_names.split(",") if t.strip()] if type_names else []
        
        vul_file = self.frozen.get("vul_file", "")
        src_file = find_source_file(self.src_root, vul_file) if vul_file else None
        src = src_file.read_text(errors="replace") if src_file else ""
        
        # Load vulnerability context for smart truncation
        target_case = self.frozen.get("enclosing_switch_case", "")
        goto_labels = []
        vs_path = self.harness_dir.parent / "sa_context" / "vulnerability_summary.json"
        if vs_path.exists():
            vs = read_json(vs_path)
            target_case = target_case or vs.get("enclosing_switch_case", "")
            goto_labels = [gs.get("label", "") for gs in vs.get("goto_sources", []) if gs.get("label")]
        
        result_parts = []
        
        # Gather function bodies
        for func_name in funcs:
            found = False
            body = None
            source_name = vul_file
            
            if src:
                span = find_function_span(src, func_name)
                if span:
                    body = src[span[0]:span[2]]
                    found = True
            
            if not found:
                for other in self.src_root.rglob("*.c"):
                    try:
                        other_src = other.read_text(errors="replace")
                        span = find_function_span(other_src, func_name)
                        if span:
                            body = other_src[span[0]:span[2]]
                            source_name = str(other.relative_to(self.src_root))
                            found = True
                            break
                    except Exception:
                        continue
            
            if not found:
                result_parts.append(f"=== FUNCTION: {func_name} — NOT FOUND ===")
                continue
            
            n_lines = body.count('\n') + 1
            
            # Smart truncation for large functions
            if n_lines > 200:
                lines = body.split('\n')
                excerpt_parts = []
                
                # 1. Function signature (first 15 lines)
                excerpt_parts.append(f"=== FUNCTION: {func_name} ({n_lines} lines, from {source_name}) [SMART EXCERPT] ===")
                excerpt_parts.append("--- SIGNATURE (lines 1-15) ---")
                excerpt_parts.extend(lines[:15])
                
                # 2. Target switch case section
                if target_case:
                    case_pat = f"case {target_case}"
                    for i, line in enumerate(lines):
                        if case_pat in line:
                            start = max(0, i - 2)
                            # Find end of case (next case or closing brace at same depth)
                            end = min(len(lines), i + 80)
                            for j in range(i + 1, min(len(lines), i + 200)):
                                stripped = lines[j].strip()
                                if stripped.startswith('case ') and stripped != line.strip():
                                    end = j
                                    break
                            excerpt_parts.append(f"\n--- TARGET CASE: {target_case} (line {start+1}-{end}) ---")
                            excerpt_parts.extend(lines[start:end])
                            break
                
                # 3. Goto labels near vulnerability
                for label in goto_labels:
                    label_pat = f"{label}:"
                    for i, line in enumerate(lines):
                        if label_pat in line and not line.strip().startswith('//'):
                            start = max(0, i - 1)
                            end = min(len(lines), i + 25)
                            excerpt_parts.append(f"\n--- LABEL: {label} (line {start+1}-{end}) ---")
                            excerpt_parts.extend(lines[start:end])
                            break
                
                # 4. Last 5 lines (closing braces)
                excerpt_parts.append(f"\n--- END (lines {n_lines-5}-{n_lines}) ---")
                excerpt_parts.extend(lines[-5:])
                
                excerpt_parts.append(f"\n[NOTE: {n_lines}-line function truncated to relevant sections. "
                                     f"Do NOT call GatherCode again for this function. "
                                     f"Write your harness using this excerpt + vulnerability_summary.]")
                
                result_parts.append('\n'.join(excerpt_parts))
            else:
                result_parts.append(f"=== FUNCTION: {func_name} ({n_lines} lines, from {source_name}) ===\n{body}")
        
        # Gather type definitions
        for type_name in types:
            defn = find_definition(self.src_root, type_name)
            if defn:
                result_parts.append(f"=== TYPE: {type_name} ===\n{defn}")
            else:
                result_parts.append(f"=== TYPE: {type_name} — NOT FOUND ===")
        
        # Also provide the preamble (includes/macros/structs) from the source file
        if src and funcs:
            first_pos = len(src)
            for fn in funcs:
                span = find_function_span(src, fn)
                if span and span[0] < first_pos:
                    first_pos = span[0]
            
            # Extract preamble: everything before the first function.
            # Keep struct/union/enum definitions (they have braces but aren't functions).
            # Skip function BODIES (preceded by a function-like signature).
            preamble_src = src[:first_pos]
            preamble_lines = []
            in_func_body = False
            depth = 0
            lines = preamble_src.split('\n')
            
            for i, line in enumerate(lines):
                stripped = line.strip()
                
                # Detect function body start: line has '{' and previous non-empty line
                # looks like a function signature (has parens and return type)
                if stripped == '{' and not in_func_body and depth == 0:
                    # Look back for function signature
                    for j in range(i-1, max(i-5, -1), -1):
                        prev = lines[j].strip()
                        if prev and '(' in prev and ')' in prev and not prev.startswith(('#', '/', '*', 'typedef', 'struct', 'union', 'enum')):
                            in_func_body = True
                            break
                
                depth += line.count('{') - line.count('}')
                
                if in_func_body:
                    if depth <= 0:
                        in_func_body = False
                        depth = 0
                    continue
                
                if depth < 0:
                    depth = 0
                preamble_lines.append(line)
            
            preamble = '\n'.join(preamble_lines)
            if len(preamble) > 15000:
                preamble = preamble[:7000] + "\n...[TRUNCATED]...\n" + preamble[-7000:]
            result_parts.append(f"=== PREAMBLE ({len(preamble_lines)} lines, includes + structs + macros) ===\n{preamble}")
        
        return '\n\n'.join(result_parts)

    def write_harness(self, code: str) -> str:
        """Write the sliced harness file (spine functions with neutralized off-path code).
        
        This replaces ExtractFunction for the main harness. The agent should:
        1. Use GatherCode to get function bodies
        2. Slice them (keep only target path code)
        3. Include the preamble
        4. Write with this tool
        """
        vul_file = self.frozen.get("vul_file", "harness.c")
        target = self.harness_dir / os.path.basename(vul_file)
        
        target.write_text(code, encoding="utf-8")
        print(f"    [+] Wrote harness: {target.name} ({len(code.split(chr(10)))} lines)")
        
        # Auto-inject spine probes
        try:
            hsrc = target.read_text(errors="replace")
            fspans = {}
            for fn in self.frozen.get("spine", []):
                sp = find_function_span(hsrc, fn)
                if sp:
                    fspans[fn] = sp
            if fspans:
                hsrc = self._instrument_spine_probes(hsrc, fspans, 0, hsrc)
                target.write_text(hsrc, encoding="utf-8")
                print(f"    [+] Injected spine probes")
        except Exception as e:
            print(f"    [!] Probe injection error: {e}")
        
        # Build line map for original↔harness correspondence
        self._post_harness_line_map()
        
        # --- AUTO-GENERATE shared types header from harness preamble ---
        try:
            self._generate_harness_types_header(target)
        except Exception as e:
            print(f"    [!] harness_types.h generation error: {e}")
        
        # --- VERIFY & AUTO-FIX: spine call chain is intact ---
        # After writing, check that each spine function calls the next one.
        # If broken, AUTO-INJECT the missing call — don't rely on the agent to fix it.
        try:
            hsrc = target.read_text(errors="replace")
            spine = self.frozen.get("spine", [])
            chain_fixed = False
            for i in range(len(spine) - 1):
                caller = spine[i]
                callee = spine[i + 1]
                caller_span = find_function_span(hsrc, caller)
                if caller_span:
                    caller_body = hsrc[caller_span[1]:caller_span[2]]
                    if not re.search(rf'\b{re.escape(callee)}\s*\(', caller_body):
                        print(f"    [⚠] BROKEN CALL CHAIN: {caller} does NOT call {callee}!")
                        # AUTO-FIX: inject a call to callee at the START of caller's body
                        # Find the callee's signature to build a valid call
                        callee_span = find_function_span(hsrc, callee)
                        
                        # If callee doesn't exist in harness, AUTO-GENERATE a minimal skeleton
                        if not callee_span:
                            print(f"    [⚠] {callee} not defined in harness — auto-generating skeleton")
                            # Get callee signature from GatherCode/frozen data
                            callee_sig = ""
                            # Try to find signature from frozen gathered code
                            gathered = self.frozen.get("gathered_code", "")
                            sig_m = re.search(rf'(?:static\s+)?(?:const\s+)?\w[\w\s\*]*\b{re.escape(callee)}\s*\([^)]*\)', gathered)
                            if sig_m:
                                callee_sig = sig_m.group(0).strip()
                            else:
                                # Fallback: use void return type with caller's params
                                caller_sig = hsrc[caller_span[0]:caller_span[1]].strip()
                                cm = re.search(rf'{re.escape(caller)}\s*\(([^)]*)\)', caller_sig)
                                params = cm.group(1) if cm else "void"
                                callee_sig = f"void {callee}({params})"
                            
                            # Build skeleton with vulnerable statement from source_context
                            src_ctx = self.frozen.get("source_context", "")
                            vul_stmts = []
                            for ctx_line in src_ctx.split('\n'):
                                stripped = re.sub(r'^\d+:\s*', '', ctx_line).strip()
                                if stripped and not stripped.startswith(('/*', '//', '#', '{', '}')):
                                    vul_stmts.append(f"    {stripped}")
                            
                            # CRITICAL: Only inject sink assertion and source_context if this IS
                            # the vulnerable function. For intermediate spine functions, generate
                            # a pass-through skeleton — the call chain injector below will add
                            # the call to the next spine function.
                            vul_func_name = self.frozen.get("vul_func", "")
                            
                            if callee == vul_func_name:
                                # This IS the vulnerable function — include source context + sink
                                src_ctx = self.frozen.get("source_context", "")
                                vul_stmts = []
                                for ctx_line in src_ctx.split('\n'):
                                    stripped = re.sub(r'^\d+:\s*', '', ctx_line).strip()
                                    if stripped and not stripped.startswith(('/*', '//', '#', '{', '}')):
                                        vul_stmts.append(f"    {stripped}")
                                if not vul_stmts:
                                    vul_stmts = [f"    /* vulnerable function body — no source_context */"]
                                
                                skeleton = (
                                    f"\n/* AUTO-GENERATED: vulnerable function skeleton */\n"
                                    f"{callee_sig} {{\n"
                                    + "\n".join(vul_stmts) + "\n"
                                    f"    klee_assert(0 && \"SAILOR_SINK_REACHED\");\n"
                                    f"}}\n"
                                )
                            else:
                                # INTERMEDIATE spine function — just a pass-through body.
                                # Do NOT put source_context or klee_assert here — that kills
                                # the path before reaching the actual vulnerable function.
                                # Build actual pass-through that CALLS the next spine function.
                                # Find the next spine function's signature to build the call.
                                next_callee = spine[i + 2] if (i + 2) < len(spine) else ""
                                next_sig = ""
                                if next_callee:
                                    ns_m = re.search(
                                        rf'(?:static\s+)?(?:const\s+)?\w[\w\s\*]*\b{re.escape(next_callee)}\s*\([^)]*\)',
                                        gathered)
                                    if ns_m:
                                        next_sig = ns_m.group(0).strip()
                                
                                # Extract param names from callee_sig for variable declarations
                                pm_skel = re.search(rf'{re.escape(callee)}\s*\(([^)]*)\)', callee_sig)
                                skel_params = pm_skel.group(1) if pm_skel else ""
                                
                                # Build the function body with the spine probe
                                skel_body_lines = [
                                    f'    klee_warning_once("SPINE_PROBE:{callee}:ENTRY");',
                                ]
                                
                                # If there's a next spine function, build a call to it
                                if next_callee and next_sig:
                                    # Extract next callee's params
                                    nc_pm = re.search(rf'{re.escape(next_callee)}\s*\(([^)]*)\)', next_sig)
                                    if nc_pm:
                                        nc_params = nc_pm.group(1).strip()
                                        # Match params by name between current and next function
                                        cur_param_names = []
                                        for p in skel_params.split(','):
                                            toks = p.strip().split()
                                            if toks:
                                                cur_param_names.append(toks[-1].lstrip('*'))
                                        
                                        nc_args = []
                                        for p in nc_params.split(','):
                                            toks = p.strip().split()
                                            if toks:
                                                pname = toks[-1].lstrip('*')
                                                if pname in cur_param_names:
                                                    nc_args.append(pname)
                                                elif any(pname.lower() in cn.lower() for cn in cur_param_names):
                                                    match = [cn for cn in cur_param_names if pname.lower() in cn.lower()][0]
                                                    nc_args.append(match)
                                                else:
                                                    # Check type to provide reasonable default
                                                    ptype = ' '.join(toks[:-1])
                                                    if '*' in ptype or '*' in toks[-1]:
                                                        nc_args.append("NULL")
                                                    else:
                                                        nc_args.append("0")
                                        
                                        skel_body_lines.append(f"    {next_callee}({', '.join(nc_args)});")
                                
                                # Determine return type
                                ret_m = re.match(r'(.*?)\b' + re.escape(callee), callee_sig)
                                ret_type = ret_m.group(1).strip() if ret_m else "void"
                                ret_type = re.sub(r'\bstatic\b', '', ret_type).strip()
                                if ret_type and ret_type != "void":
                                    skel_body_lines.append(f"    return ({ret_type})0;")
                                
                                skeleton = (
                                    f"\n/* AUTO-GENERATED: intermediate spine pass-through */\n"
                                    f"{callee_sig} {{\n"
                                    + "\n".join(skel_body_lines) + "\n"
                                    f"}}\n"
                                )
                            # Append skeleton before the caller function
                            hsrc = hsrc[:caller_span[0]] + skeleton + "\n" + hsrc[caller_span[0]:]
                            print(f"    [✓] AUTO-GENERATED skeleton for {callee} ({len(vul_stmts)} lines)")
                            # Re-find spans after modification
                            caller_span = find_function_span(hsrc, caller)
                            callee_span = find_function_span(hsrc, callee)
                        
                        if callee_span:
                            callee_sig = hsrc[callee_span[0]:callee_span[1]].strip()
                            # Extract parameter names from callee signature
                            pm = re.search(rf'{re.escape(callee)}\s*\(([^)]*)\)', callee_sig)
                            if pm:
                                param_str = pm.group(1).strip()
                                # Build call with matching arg names from caller's params
                                caller_sig = hsrc[caller_span[0]:caller_span[1]].strip()
                                cm = re.search(rf'{re.escape(caller)}\s*\(([^)]*)\)', caller_sig)
                                caller_params = []
                                if cm:
                                    for p in cm.group(1).split(','):
                                        tokens = p.strip().split()
                                        if tokens:
                                            name = tokens[-1].lstrip('*')
                                            caller_params.append(name)
                                
                                # Build callee args: match by position or use caller's params + defaults
                                callee_params = []
                                for p in param_str.split(','):
                                    tokens = p.strip().split()
                                    if tokens:
                                        callee_params.append(tokens[-1].lstrip('*'))
                                
                                # Use caller's params where names match, else use 0/NULL
                                call_args = []
                                for cp in callee_params:
                                    if cp in caller_params:
                                        call_args.append(cp)
                                    elif any(cp.lower() in ca.lower() for ca in caller_params):
                                        match = [ca for ca in caller_params if cp.lower() in ca.lower()][0]
                                        call_args.append(match)
                                    else:
                                        call_args.append("0")
                                
                                inject_call = f"    {callee}({', '.join(call_args)});"
                                # Insert right after the opening brace of caller
                                insert_pos = caller_span[1] + 1  # +1 to get AFTER the '{'
                                hsrc = hsrc[:insert_pos] + f"\n{inject_call}  /* AUTO-INJECTED: spine call chain */\n" + hsrc[insert_pos:]
                                chain_fixed = True
                                print(f"    [✓] AUTO-FIX: Injected '{callee}(...)' into {caller}'s body")
                else:
                    if i == 0:
                        print(f"    [⚠] Entry function '{caller}' not found in harness!")
                        print(f"    [⚠] The harness must define all spine functions: {' → '.join(spine)}")
            
            if chain_fixed:
                target.write_text(hsrc, encoding="utf-8")
                print(f"    [✓] Harness call chain auto-fixed and saved")
        except Exception as e:
            print(f"    [!] Call chain verification error: {e}")
        
        # --- AUTO-INJECT SINK ASSERTION at the vulnerable statement ---
        # The agent often places klee_assert at the function END instead of
        # right after the vulnerable statement. Auto-fix this.
        try:
            hsrc = target.read_text(errors="replace")
            vul_func = self.frozen.get("vul_func", "")
            vul_line = int(self.ctx.get("vul_line", 0))
            src_ctx = self.frozen.get("source_context", "")
            
            if vul_func and vul_line > 0:
                vul_span = find_function_span(hsrc, vul_func)
                if vul_span:
                    # Check if there's already a correctly-placed SAILOR_SINK_REACHED
                    func_body = hsrc[vul_span[1]:vul_span[2]]
                    
                    # Extract the vulnerable statement from source_context
                    # source_context has lines like "541: memcmp(entry->name, name, len)"
                    vul_stmt_patterns = []
                    for ctx_line in src_ctx.split('\n'):
                        ctx_stripped = re.sub(r'^\d+:\s*', '', ctx_line).strip()
                        if ctx_stripped and not ctx_stripped.startswith(('/*', '//', '#', '{', '}')):
                            # Normalize: remove extra spaces
                            normalized = re.sub(r'\s+', ' ', ctx_stripped).strip()
                            if len(normalized) > 10:
                                vul_stmt_patterns.append(normalized)
                    
                    # Also use the line map to find harness lines near vul_line
                    vul_harness_lines = []
                    if self.harness_line_map:
                        for h_line, orig in self.harness_line_map.items():
                            if isinstance(orig, dict) and abs(orig.get("orig_line", 0) - vul_line) <= 5:
                                vul_harness_lines.append(h_line)
                            elif isinstance(orig, int) and abs(orig - vul_line) <= 5:
                                vul_harness_lines.append(h_line)
                    
                    # Find the vulnerable statement in the harness by text matching
                    hlines = hsrc.split('\n')
                    best_vul_hline = 0
                    
                    # Method 1: line map
                    if vul_harness_lines:
                        best_vul_hline = max(vul_harness_lines)  # last matching line
                    
                    # Method 2: text match against source_context
                    if not best_vul_hline and vul_stmt_patterns:
                        for i, hline in enumerate(hlines):
                            hn = re.sub(r'\s+', ' ', hline).strip()
                            for pat in vul_stmt_patterns:
                                # Check if key identifiers from vuln statement appear
                                key_tokens = re.findall(r'\b\w+\b', pat)
                                important_tokens = [t for t in key_tokens if len(t) > 2 and t not in (
                                    'int', 'char', 'void', 'const', 'unsigned', 'return', 'if', 'for', 'while')]
                                if important_tokens:
                                    matches = sum(1 for t in important_tokens if t in hn)
                                    if matches >= len(important_tokens) * 0.6:
                                        best_vul_hline = i + 1
                    
                    if best_vul_hline > 0:
                        # Check if there's already a SINK assertion within 3 lines after it
                        has_nearby_sink = False
                        for j in range(best_vul_hline, min(best_vul_hline + 4, len(hlines))):
                            if 'SAILOR_SINK_REACHED' in hlines[j]:
                                has_nearby_sink = True
                                break
                        
                        if not has_nearby_sink:
                            # Remove any existing SAILOR_SINK_REACHED that's far away
                            new_hlines = []
                            removed = 0
                            for i, hl in enumerate(hlines):
                                if 'SAILOR_SINK_REACHED' in hl:
                                    removed += 1
                                else:
                                    new_hlines.append(hl)
                            
                            indent = re.match(r'^(\s*)', hlines[best_vul_hline - 1]).group(1)
                            
                            # --- CWE-125/787: inject bounds check BEFORE vulnerable statement ---
                            # KLEE's heap OOB detection is unreliable with symbolic indices.
                            # Use klee_get_obj_size() to explicitly check bounds.
                            spec_path_for_cwe = self.harness_dir.parent / "sa_context" / "spec.json"
                            cwe_id = ""
                            if spec_path_for_cwe.exists():
                                try:
                                    spec_data = read_json(spec_path_for_cwe)
                                    cwe_id = str(spec_data.get("cwe_id", spec_data.get("cwe", "")))
                                except Exception:
                                    pass
                            if not cwe_id:
                                spec_name_cwe = os.path.basename(self.ctx.get("spec_path", ""))
                                cwe_m = re.search(r'cwe-(\d+)', spec_name_cwe, re.IGNORECASE)
                                cwe_id = cwe_m.group(1) if cwe_m else ""
                            
                            bounds_check_lines = []
                            if cwe_id in ("125", "787", "119", "122", "121"):
                                # Find pointer and length in the vulnerable statement
                                vul_text = hlines[best_vul_hline - 1].strip()
                                # Common patterns: memcmp(ptr, x, len), memcpy(dst, src, len), ptr[idx]
                                # Extract pointer+length from memcmp/memcpy/memmove/strncmp etc.
                                mem_m = re.search(r'(memcmp|memcpy|memmove|strncmp|strncpy|memset)\s*\(\s*([^,]+),\s*[^,]+,\s*([^)]+)\)', vul_text)
                                idx_m = re.search(r'(\w+(?:->\w+)*(?:\.\w+)*)\s*\[\s*(\w+)\s*\]', vul_text)
                                
                                if mem_m:
                                    ptr_expr = mem_m.group(2).strip()
                                    len_expr = mem_m.group(3).strip()
                                    bounds_check_lines = [
                                        f'{indent}/* SAILOR: CWE-{cwe_id} bounds check */',
                                        f'{indent}if (klee_get_obj_size((void*){ptr_expr}) < (size_t)({len_expr}))',
                                        f'{indent}  klee_report_error(__FILE__, {vul_line}, "SAILOR OOB: buffer too small for access length", "sailor.ptr.err");',
                                    ]
                                    print(f"    [+] Injected CWE-{cwe_id} bounds check: klee_get_obj_size({ptr_expr}) < {len_expr}")
                                elif idx_m:
                                    arr_expr = idx_m.group(1).strip()
                                    idx_expr = idx_m.group(2).strip()
                                    bounds_check_lines = [
                                        f'{indent}/* SAILOR: CWE-{cwe_id} bounds check */',
                                        f'{indent}if ((size_t)({idx_expr}) >= klee_get_obj_size((void*){arr_expr}))',
                                        f'{indent}  klee_report_error(__FILE__, {vul_line}, "SAILOR OOB: index exceeds buffer size", "sailor.ptr.err");',
                                    ]
                                    print(f"    [+] Injected CWE-{cwe_id} bounds check: {idx_expr} >= klee_get_obj_size({arr_expr})")
                            
                            # Insert: bounds check BEFORE vuln stmt, sink assertion AFTER
                            sink_line = f'{indent}klee_assert(0 && "SAILOR_SINK_REACHED");'
                            # Re-find the line in new_hlines
                            vul_text = hlines[best_vul_hline - 1].strip()
                            insert_idx = best_vul_hline - removed  # approximate
                            for idx, nl in enumerate(new_hlines):
                                if nl.strip() == vul_text:
                                    insert_idx = idx + 1
                                    break
                            
                            # Insert bounds check BEFORE the vulnerable statement
                            if bounds_check_lines:
                                for bc_idx, bc_line in enumerate(bounds_check_lines):
                                    new_hlines.insert(insert_idx - 1 + bc_idx, bc_line)
                                insert_idx += len(bounds_check_lines)
                            
                            # Insert sink assertion AFTER the vulnerable statement
                            new_hlines.insert(insert_idx, sink_line)
                            hsrc = '\n'.join(new_hlines)
                            target.write_text(hsrc, encoding="utf-8")
                            if removed:
                                print(f"    [✓] Moved SINK assertion: removed {removed} misplaced, injected after harness line {insert_idx + 1} (near vul_line {vul_line})")
                            else:
                                print(f"    [+] Injected SINK assertion after harness line {insert_idx + 1} (near vul_line {vul_line})")
        except Exception as e:
            print(f"    [!] Sink assertion injection error: {e}")
        
        types_hint = ""
        types_path = self.harness_dir / "harness_types.h"
        if types_path.exists():
            types_hint = (
                "\n\nIMPORTANT: harness_types.h has been auto-generated with the real struct "
                "definitions from the harness preamble. Your driver.c MUST start with:\n"
                '  #include "harness_types.h"\n'
                "This gives you the correct struct layouts. Do NOT redefine these structs in driver.c."
            )
        
        return f"OK: Wrote harness/{target.name}{types_hint}"
    
    def _generate_harness_types_header(self, harness_path: Path):
        """Extract struct/typedef/enum definitions from harness into harness_types.h."""
        hsrc = harness_path.read_text(errors="replace")
        preamble_end = len(hsrc)
        for marker in ['/* SAILOR_FUNC:', '/* --- SPINE FUNCTION', '/* Spine function']:
            idx = hsrc.find(marker)
            if idx >= 0:
                preamble_end = min(preamble_end, idx)
        lines = hsrc.splitlines()
        brace_depth = 0
        in_struct = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.match(r'^(typedef\s+)?(struct|enum|union)\s', stripped):
                in_struct = True
            if in_struct:
                brace_depth += stripped.count('{') - stripped.count('}')
                if brace_depth <= 0:
                    in_struct = False
                    brace_depth = 0
                continue
            if not in_struct and '{' in stripped:
                prev_text = " ".join(lines[max(0, i-3):i+1])
                if re.search(r'\w+\s*\([^)]*\)\s*\{?\s*$', prev_text) and \
                   not re.match(r'^\s*(if|while|for|switch|do|else)\b', prev_text.strip()):
                    preamble_end = sum(len(lines[k]) + 1 for k in range(max(0, i-1)))
                    break
        preamble = hsrc[:preamble_end]
        if len(preamble.strip()) < 20:
            return
        header_lines = ["/* AUTO-GENERATED from harness preamble */", "#pragma once", ""]
        # Filter: keep structs, typedefs, enums, #defines, and blank lines
        # EXCLUDE: function prototypes/declarations (they break driver.c compilation)
        for l in preamble.splitlines():
            stripped = l.strip()
            # Skip klee includes
            if 'klee/klee.h' in l:
                continue
            # Skip function prototypes: lines that look like "type funcname(params);"
            # but are NOT typedef, struct, enum, union, or #define
            if stripped.endswith(';') and '(' in stripped and ')' in stripped:
                # Check if it's a function prototype (not a typedef or struct field)
                if not stripped.startswith(('typedef', 'struct', 'union', 'enum', '#')):
                    # Check if it looks like a function declaration
                    if re.match(r'^(?:static\s+|inline\s+|extern\s+|const\s+)*\w[\w\s\*]*\w+\s*\([^)]*\)\s*;', stripped):
                        continue  # Skip function prototype
            # Skip static declarations entirely (they cause "invalid storage class" in headers)
            if stripped.startswith('static ') and ';' in stripped and '=' not in stripped:
                continue
            header_lines.append(l)
        types_path = self.harness_dir / "harness_types.h"
        types_path.write_text('\n'.join(header_lines) + '\n', encoding="utf-8")
        n_structs = len(re.findall(r'\bstruct\s+\w+\s*\{', preamble))
        n_typedefs = preamble.count('typedef')
        print(f"    [+] Generated harness_types.h ({len(header_lines)} lines, {n_structs} structs, {n_typedefs} typedefs)")
        print(f"    [i] Driver MUST: #include \"harness_types.h\" for correct struct layouts")
    
    def _post_harness_line_map(self):
        """Build line map after any harness file is written/modified."""
        try:
            self.build_line_map()
        except Exception as e:
            print(f"    [!] Line map build failed: {e}")

    def compile_slice(self) -> Dict:
        """Pure compiler — no preprocessing, no extraction, no slicing.
        
        The agent is responsible for writing harness files BEFORE calling this.
        This just compiles whatever .c files exist in the harness directory.
        """
        print("  [Tool] CompileSlice")
        
        # --- AUTO-INJECT harness_types.h into driver.c/stubs.c if missing ---
        # Only inject if: (1) harness_types.h exists, (2) file doesn't already include it,
        # (3) file doesn't define its own struct types (to avoid redefinition errors),
        # (4) file doesn't have an explicit NO_HARNESS_TYPES opt-out marker
        types_h = self.harness_dir / "harness_types.h"
        for fname in ("driver.c", "stubs.c"):
            fpath = self.harness_dir / fname
            if types_h.exists() and fpath.exists():
                fsrc = fpath.read_text(errors="replace")
                if 'harness_types.h' not in fsrc:
                    # Check for explicit opt-out marker
                    if '// NO_HARNESS_TYPES' in fsrc or '/* NO_HARNESS_TYPES */' in fsrc:
                        print(f"    [i] Skipped harness_types.h injection into {fname} (NO_HARNESS_TYPES marker)")
                    else:
                        # Don't inject if file already defines structs (would cause redefinition)
                        has_own_structs = bool(re.search(r'\bstruct\s+_?\w+\s*\{', fsrc))
                        if not has_own_structs:
                            fsrc = '#include "harness_types.h"\n' + fsrc
                            fpath.write_text(fsrc, encoding="utf-8")
                            print(f"    [i] Auto-injected #include \"harness_types.h\" into {fname}")
                        else:
                            print(f"    [i] Skipped harness_types.h injection into {fname} (has own struct defs)")
        
        # --- Public trampoline for static entry functions ---
        # If the entry function is declared static in the harness, driver.c can't call it.
        # Instead of removing static (which breaks header compat), we:
        # 1. Keep the static function as-is
        # 2. Append a public trampoline to the SAME .c file
        # 3. Rewrite driver.c to call the trampoline
        self._ensure_public_entry()
        
        # Auto-generate smart stubs on first compile
        if self.iteration == 0:
            self._write_smart_stubs({})
        c_files = sorted([f for f in self.harness_dir.glob("*.c")])
        if not c_files: return {"success": False, "error": "No .c files"}
        
        # Include paths: harness dir, source root, build dir, discovered paths, klee
        # IMPORTANT: -isystem /usr/include FIRST so <string.h> etc. resolve to real
        # libc headers, not project shadows (e.g. libxml2's include/private/string.h)
        inc_flags = ["-isystem", "/usr/include",
                     "-I", str(self.harness_dir), "-I", str(self.src_root)]
        build_dir = self.frozen.get("build_dir", "")
        if build_dir and os.path.isdir(build_dir):
            inc_flags.extend(["-I", build_dir])
        
        # Auto-include config.h — search build_dir, src_root, and common subdirectories
        config_h = None
        search_roots = [Path(build_dir)] if build_dir and os.path.isdir(build_dir) else []
        search_roots.append(self.src_root)
        for root in search_roots:
            # Check common locations first (fast)
            for rel in ["config.h", "include/config.h", "include/lib*/config.h", "src/config.h"]:
                candidate = root / rel
                if candidate.exists():
                    config_h = candidate
                    break
            if config_h:
                break
            # Fallback: recursive search (limited depth)
            if not config_h:
                for candidate in root.glob("**/config.h"):
                    if ".git" not in str(candidate) and "test" not in str(candidate).lower():
                        config_h = candidate
                        break
            if config_h:
                break
        if config_h:
            inc_flags.extend(["-include", str(config_h)])
            print(f"    [i] Auto-including {config_h}")
        
        # -idirafter: searched AFTER -isystem /usr/include, so project headers like
        # include/private/string.h don't shadow /usr/include/string.h
        for p in self.include_paths: inc_flags.extend(["-idirafter", p])
        if os.path.exists(self.klee_include): inc_flags.extend(["-I", self.klee_include])
        
        base_flags = ["-emit-llvm", "-c", "-g", "-O0", "-fno-inline", "-Wno-everything", "-D__KLEE__", "-DATTRIBUTE_UNUSED=__attribute__((unused))"]
        
        # Auto-detect project-level macros needed for internal headers
        # Many projects require IN_LIBFOO (e.g., IN_LIBXML, IN_LIBCURL, IN_OPENSSL)
        # before including internal headers. Scan for lib*.h patterns.
        for hfile in self.src_root.rglob("lib*.h"):
            # Extract library name: libxml.h → IN_LIBXML, libcurl.h → IN_LIBCURL
            stem = hfile.stem.upper()  # LIBXML, LIBCURL, etc.
            macro = f"IN_{stem}"
            base_flags.append(f"-D{macro}")
            print(f"    [i] Auto-adding -D{macro} (found {hfile.relative_to(self.src_root)})")
            break  # only add one
        
        bc_files = []
        
        for sf in c_files:
            bf = sf.with_suffix(".bc")
            cmd = [self.clang] + base_flags + self.project_cflags + self.extra_cflags + inc_flags + [str(sf), "-o", str(bf)]
            
            # Try up to 3 times: compile → auto-fix → retry
            compiled = False
            for attempt in range(3):
                rc, _, err, _ = run_cmd(cmd, cwd=self.harness_dir, timeout=60)
                if rc == 0:
                    bc_files.append(bf)
                    print(f"    [+] {sf.name} -> OK" + (f" (after {attempt} auto-fix)" if attempt else ""))
                    compiled = True
                    break
                
                # --- Auto-fix attempt (only for non-driver harness files) ---
                if sf.name in ("driver.c", "stubs.c") or attempt >= 2:
                    break
                
                err_str = err or ""
                fixed = self._auto_fix_compile_error(sf, err_str)
                if not fixed:
                    break
                print(f"    [~] Auto-fix applied to {sf.name}, retrying...")
            
            if not compiled:
                diag = f"Compile error in {sf.name}:\n{err[:1500]}"
                
                # --- AUTO-FIX: common undefined macros ---
                # Many project headers use visibility/attribute macros that aren't
                # in config.h. Auto-define them so the agent doesn't waste turns.
                err_str = err or ""
                undefined_macros = re.findall(r"use of undeclared identifier '(\w+)'", err_str)
                undefined_macros += re.findall(r"'(\w+)' undeclared", err_str)
                undefined_macros += re.findall(r"unknown type name '(\w+)'", err_str)
                
                # Common macros that should be empty/0
                # Covers visibility macros, attribute macros, calling conventions
                common_macro_fixes = {
                    "ATTRIBUTE_UNUSED": "",
                    "ATTRIBUTE_NO_SANITIZE_INTEGER": "",
                    "ATTRIBUTE_NO_SANITIZE": "",
                    "ATTRIBUTE_PRINTF": "",
                    "ATTRIBUTE_DESTRUCTOR": "",
                }
                
                # Pattern-based: any macro matching these patterns is likely a
                # visibility/attribute macro that should be defined empty
                visibility_patterns = [
                    r'^.*_HIDDEN$',       # XML_HIDDEN, SSL_HIDDEN, etc.
                    r'^.*PUBFUN$',        # XMLPUBFUN, SSLPUBFUN, etc. 
                    r'^.*PUBVAR$',        # XMLPUBVAR, etc.
                    r'^.*CALL$',          # XMLCALL, APICALL, etc.
                    r'^.*CDECL$',         # XMLCDECL, etc.
                    r'^.*PUBLIC$',        # XMLPUBLIC, etc.
                    r'^.*DEPRECATED$',    # XML_DEPRECATED, etc.
                    r'^.*ATTR_FORMAT$',   # LIBXML_ATTR_FORMAT, etc.
                    r'^.*ATTR_ALLOC_SIZE$',
                    r'^.*_EXPORT$',       # API_EXPORT, LIB_EXPORT, etc.
                    r'^.*_IMPORT$',       # API_IMPORT, etc.
                    r'^.*_API$',          # PUBLIC_API, CURL_API, etc.
                    r'^__.*attribute__$',  # compiler attributes
                ]
                
                auto_defs = []
                for macro in set(undefined_macros):
                    if macro in common_macro_fixes:
                        val = common_macro_fixes[macro]
                        auto_defs.append(f"#ifndef {macro}\n#define {macro} {val}\n#endif")
                    elif any(re.match(pat, macro) for pat in visibility_patterns):
                        auto_defs.append(f"#ifndef {macro}\n#define {macro}\n#endif")
                
                if auto_defs:
                    # Auto-inject as COMPILE FLAGS so they apply to ALL files
                    # (including auto-generated smart_stubs.c)
                    new_flags = []
                    for macro in set(undefined_macros):
                        if macro in common_macro_fixes:
                            val = common_macro_fixes[macro]
                            flag = f"-D{macro}={val}" if val else f"-D{macro}="
                        elif any(re.match(pat, macro) for pat in visibility_patterns):
                            flag = f"-D{macro}="
                        else:
                            continue
                        if flag not in self.extra_cflags:
                            self.extra_cflags.append(flag)
                            new_flags.append(macro)
                    
                    if new_flags:
                        diag += f"\n\n[AUTO-FIX] Added compile flags for {len(new_flags)} macros: {', '.join(new_flags)}"
                        diag += "\nRetry CompileSlice."
                        return {"success": False, "error": diag}
                
                if sf.name == "stubs.c":
                    # Auto-detect conflicting types and look up real prototypes
                    conflicts = re.findall(r"conflicting types for '(\w+)'", err or "")
                    if conflicts:
                        diag += "\n\n[DIAGNOSIS] CONFLICTING TYPES in stubs.c. Your stub signatures don't match the headers."
                        diag += "\nREAL PROTOTYPES (from project headers):"
                        for sym in set(conflicts[:5]):
                            # Grep the real prototype from headers
                            grep_cmd = ["grep", "-rn", "--include=*.h",
                                       rf"\b{sym}\s*\(", str(self.src_root)]
                            grc, gout, _, _ = run_cmd(grep_cmd, timeout=5)
                            if grc == 0 and gout:
                                proto_lines = gout.strip().split('\n')[:2]
                                for pl in proto_lines:
                                    diag += f"\n  {pl.strip()}"
                            else:
                                diag += f"\n  {sym}: not found in headers — remove this stub and let KLEE auto-stub it"
                        diag += "\n\nFIX: Either match these exact prototypes or REMOVE the conflicting stubs (KLEE auto-stubs return 0 which is usually fine)."
                    elif "incomplete type" in (err or "") or "incomplete definition" in (err or ""):
                        incomplete = re.findall(r"incomplete (?:type|definition of) '(?:struct )?(\w+)'", err or "")
                        if incomplete:
                            diag += "\n\n[DIAGNOSIS] INCOMPLETE TYPE."
                            for sym in set(incomplete[:3]):
                                # Auto-lookup the definition and provide it directly
                                defn = find_definition(self.src_root, sym)
                                if defn:
                                    defn_short = defn[:500]
                                    diag += f"\n\n[AUTO-FOUND] {sym} definition:\n{defn_short}"
                                    diag += f"\n\nFIX: Add this struct definition to your harness .c file BEFORE the functions that use it."
                                else:
                                    diag += f"\n  {sym}: not found. Try adding 'typedef struct _{sym} {sym};' or allocating as opaque (char[1024])."
                    else:
                        diag += "\n\n[DIAGNOSIS] stubs.c failed. Simplify: keep ONLY the essential stubs (xmlCreatePushParserCtxt etc). Remove any stubs that conflict with headers — KLEE auto-stubs them fine."
                elif sf.name != "driver.c":
                    # --- Diagnose neutralization artifacts ---
                    # The smart slicer neutralizes off-path code by:
                    #   - Replacing if(condition) with if(0) — dead branch
                    #   - Prepending break; to off-path switch case bodies
                    #   - Prepending return(0); after post-target code
                    # These can fail on macro-expanded code or preprocessor patterns.
                    
                    err_str = err or ""
                    
                    if "extraneous ')'" in err_str or "expected expression" in err_str:
                        line_m = re.search(rf'{re.escape(sf.name)}:(\d+):\d+: error:', err_str)
                        err_line = int(line_m.group(1)) if line_m else 0
                        diag += f"\n\n[DIAGNOSIS] NEUTRALIZATION ARTIFACT — extra parentheses near line {err_line}."
                        diag += f"\nAuto-fix was attempted but may not have fully resolved the issue."
                        diag += f"\nFIX: ReadSource('{sf.name}', {max(1,err_line-3)}, {err_line+3})"
                        diag += f"\nThen ReplaceCode('{sf.name}', <broken if(0 line>, 'if (0) {{')"
                    
                    elif "expected '}'" in err_str or "function definition is not allowed" in err_str:
                        # Likely: unbalanced braces from switch case neutralization
                        # or an if/else chain where braces were disrupted
                        diag += f"\n\n[DIAGNOSIS] BRACE MISMATCH — likely from switch/if neutralization."
                        diag += f"\nThe smart slicer prepends break; or if(0) to neutralize off-path code."
                        diag += f"\nIf braces are unbalanced, read the error line and look for:"
                        diag += f"\n  1. A case body where break; was prepended but inner {{}} got disrupted"
                        diag += f"\n  2. An if/else chain where the condition replacement lost a brace"
                        diag += f"\nFIX: Read 20 lines around the error. Add/remove the missing brace."
                        diag += f"\nCommon fix: add a }} before the next function definition."
                    
                    elif "redefinition of" in err_str:
                        redef = re.findall(r"redefinition of '(\w+)'", err_str)
                        diag += f"\n\n[DIAGNOSIS] REDEFINITION — likely duplicate extraction."
                        if redef:
                            diag += f"\nDuplicate symbol(s): {', '.join(set(redef[:5]))}"
                        diag += f"\nThe function was already included in the preamble (everything before"
                        diag += f" the first extracted function). Do NOT extract it again."
                        diag += f"\nFIX: The function is already available. Skip the ExtractFunction call."
                    
                    else:
                        diag += f"\n\n[DIAGNOSIS] Extracted source failed to compile."
                        diag += f"\nThe smart slicer may have introduced artifacts. Read the error lines"
                        diag += f" in harness/{sf.name} and fix with ReplaceCode."
                        diag += f"\nCommon patterns: if(0) with extra parens, unbalanced braces, macro issues."
                else:
                    # Parse specific error types for targeted advice
                    if "undeclared" in (err or "") or "use of undeclared" in (err or ""):
                        # Extract the undefined symbol
                        m = re.search(r"use of undeclared identifier '(\w+)'", err)
                        if not m:
                            m = re.search(r"'(\w+)' undeclared", err)
                        sym = m.group(1) if m else "unknown"
                        diag += f"\n\n[DIAGNOSIS] Undefined symbol: '{sym}'. "
                        diag += "This usually means a project header macro is missing. "
                        diag += "The extracted parser.c compiles fine because its preamble has all includes. "
                        diag += "In driver.c, copy the same includes from parser.c preamble: "
                        diag += "the project guard macro (check the spine preamble with GrepSource), then the project internal header. "
                        diag += "Use GrepSource(pattern='#include', file='parser.c') to see what parser.c includes."
                    else:
                        diag += "\n\n[DIAGNOSIS] driver.c failed. Do NOT #include parser.c. "
                        diag += "Use GrepSource(pattern='#include', file='parser.c') to see what includes the extracted parser.c uses, then copy the same includes to driver.c."
                return {"success": False, "error": diag}
        
        linked = self.harness_dir / "slice.bc"
        cmd = [self.llvm_link] + [str(f) for f in bc_files] + ["-o", str(linked)]
        rc, _, err, _ = run_cmd(cmd, timeout=30)

        if rc != 0:
             return {"success": False, "error": f"Link error:\n{err[:500]}"}

        # --- AUTO-STUB POLICY ---
        # Scan driver.c for constructor calls (functions that return pointers stored in variables).
        # If these functions aren't defined in any harness .c file, they'll be auto-stubbed
        # by KLEE to return NULL/0, which always crashes. Generate proper stubs preemptively.
        self._auto_stub_constructors(bc_files, linked)

        self.iteration += 1
        klee_timeout = int(os.environ.get("KLEE_TIMEOUT", 300))
        stats = run_klee(linked, self.klee, self.klee_flags, klee_timeout, self.logs_dir, self.iteration, self.frozen, harness_dir=self.harness_dir)
        self.last_klee_stats = stats
        return {"success": True, "klee_stats": stats}


    def _ensure_public_entry(self):
        """Ensure the entry function is callable from driver.c.
        
        If the entry function is `static` in the harness, driver.c can't call it
        across translation units. Instead of removing `static` (which can break
        header compatibility), we:
        1. Keep the static function intact
        2. Append a non-static trampoline to the SAME .c file
        3. Rewrite driver.c to call the trampoline name
        
        The trampoline is in the same translation unit → can call static functions.
        """
        entry = self.frozen.get("entry", "")
        if not entry:
            return
        
        vul_file = os.path.basename(self.frozen.get("vul_file", ""))
        harness_file = self.harness_dir / vul_file if vul_file else None
        if not harness_file or not harness_file.exists():
            return
        
        hsrc = harness_file.read_text(errors="replace")
        
        # Check if entry function is static
        # Match: static [qualifiers] return_type entry_name(params)
        static_pat = re.compile(
            rf'^(\s*)static\s+((?:inline\s+)?[\w\s\*]+\b{re.escape(entry)}\s*)\(([^)]*)\)',
            re.MULTILINE
        )
        m = static_pat.search(hsrc)
        if not m:
            # Entry is not static — no trampoline needed
            return
        
        trampoline_marker = f"__sailor_entry_{entry}"
        if trampoline_marker in hsrc:
            # Already have a trampoline
            return
        
        # Parse the signature
        sig_prefix = m.group(2).strip()  # e.g., "const xmlChar * xmlDictLookupInternal"
        params_str = m.group(3).strip()  # e.g., "xmlDictPtr dict, const xmlChar *name, int len, ..."
        
        # Extract return type from sig_prefix by removing the function name
        # sig_prefix = "const xmlChar * xmlDictLookupInternal"
        # return_type = "const xmlChar *"
        name_pos = sig_prefix.rfind(entry)
        if name_pos < 0:
            return
        return_type = sig_prefix[:name_pos].strip()
        if not return_type:
            return_type = "int"  # fallback
        
        # Parse parameter names from params_str
        # "xmlDictPtr dict, const xmlChar *name, int len" → "dict, name, len"
        param_names = []
        if params_str and params_str != "void":
            for param in params_str.split(','):
                param = param.strip()
                if not param:
                    continue
                # Last word (possibly with * prefix) is the param name
                # Handle: "const xmlChar *name" → "name", "int len" → "len"
                tokens = re.findall(r'[*]?(\w+)', param)
                if tokens:
                    param_names.append(tokens[-1])
        
        call_args = ", ".join(param_names)
        
        # Build trampoline
        trampoline = f"""
/* Public entry point — calls static {entry} from driver.c */
{return_type} {trampoline_marker}({params_str}) {{
    return {entry}({call_args});
}}
"""
        # Append trampoline to harness file
        hsrc += trampoline
        harness_file.write_text(hsrc, encoding="utf-8")
        print(f"    [+] Added public trampoline: {trampoline_marker}()")
        
        # Rewrite driver.c to call the trampoline
        driver_path = self.harness_dir / "driver.c"
        if driver_path.exists():
            dsrc = driver_path.read_text(errors="replace")
            # Replace calls: entry(args) → trampoline(args)
            # Also replace extern declarations
            new_dsrc = dsrc.replace(entry, trampoline_marker)
            if new_dsrc != dsrc:
                driver_path.write_text(new_dsrc, encoding="utf-8")
                print(f"    [+] Rewrote driver.c: {entry} → {trampoline_marker}")
    
    def _write_smart_stubs(self, prescriptions):
        """Generate smart stubs for external functions.
        Only runs once — does NOT regenerate on subsequent CompileSlice calls.
        """
        stub_path = self.harness_dir / "smart_stubs.c"
        
        # Don't regenerate if already exists (agent's ReplaceCode fixes would be lost)
        if stub_path.exists() and stub_path.stat().st_size > 100:
            return
        
        print("    [i] Generating smart stubs...")
        """Generate smart_stubs.c from stub prescriptions.
        
        Stub types generated:
        - symbolic_constrained: klee_make_symbolic + klee_assume(constraint)
        - symbolic: klee_make_symbolic (no constraint)
        - sink_trigger: hardcoded return value that satisfies branch to sink
        - constrained: hardcoded return value that avoids error exit
        - trivial: return 0
        
        Also includes PROACTIVE stubs for common functions that cause KLEE
        to concretize symbolic data when auto-stubbed (strstr, strlen, etc.)
        """
        lines = []
        lines.append("/* Smart stubs — auto-generated from path + vulnerability analysis */")
        lines.append("/* Symbolic stubs model the environment: KLEE explores return values */")
        lines.append("/* that both REACH the sink AND TRIGGER the vulnerability */")
        lines.append("#include <stdlib.h>")
        lines.append("#include <string.h>")
        lines.append("#include <klee/klee.h>")
        lines.append("")
        
        # --- PROACTIVE STUBS ---
        # Auto-detect ALL external functions called in the spine source but not
        # defined there. Generate stubs to prevent KLEE concretization.
        # This is project-agnostic: works for libxml2, openssl, curl, sqlite, etc.
        
        # Well-known libc functions that need specific stub signatures
        _LIBC_STUBS = {
            "strstr": "char *strstr(const char *h, const char *n) { (void)h; (void)n; return NULL; }",
            "strchr": "char *strchr(const char *s, int c) { (void)s; (void)c; return NULL; }",
            "strrchr": "char *strrchr(const char *s, int c) { (void)s; (void)c; return NULL; }",
            "memchr": "void *memchr(const void *s, int c, unsigned long n) { (void)s; (void)c; (void)n; return NULL; }",
            "strcmp": "int strcmp(const char *a, const char *b) { (void)a; (void)b; return 1; }",
            "strncmp": "int strncmp(const char *a, const char *b, unsigned long n) { (void)a; (void)b; (void)n; return 1; }",
            "strlen": "unsigned long strlen(const char *s) { (void)s; return 0; }",
            "memcmp": "int memcmp(const void *a, const void *b, unsigned long n) { (void)a; (void)b; (void)n; return 1; }",
            "snprintf": "int snprintf(char *s, unsigned long n, const char *fmt, ...) { (void)s; (void)n; (void)fmt; if(n>0) s[0]=0; return 0; }",
            "fprintf": "int fprintf(void *f, const char *fmt, ...) { (void)f; (void)fmt; return 0; }",
            "printf": "int printf(const char *fmt, ...) { (void)fmt; return 0; }",
        }
        
        # Skip list: functions KLEE handles natively or shouldn't be stubbed
        _SKIP_STUB = frozenset({
            'if', 'while', 'for', 'switch', 'return', 'sizeof', 'typeof',
            'case', 'goto', 'int', 'char', 'void', 'unsigned', 'long',
            'short', 'float', 'double', 'struct', 'enum', 'union', 'const',
            'static', 'inline', 'extern', 'register', 'volatile',
            'klee_make_symbolic', 'klee_assume', 'klee_assert',
            'klee_warning', 'klee_warning_once', 'klee_check_memory_access',
            'klee_int', 'klee_silent_exit', 'klee_prefer_cex',
            'main', 'calloc', 'malloc', 'free', 'realloc',
            'memset', 'memcpy', 'memmove', 'abort', 'exit', '_exit',
            # Common C macros that look like function calls
            'defined', 'offsetof', 'NULL', 'assert', 'va_start', 'va_end', 'va_arg',
            # Common attribute macros (libxml2, etc.)
            'LIBXML_ATTR_FORMAT', 'ATTRIBUTE_UNUSED', '__attribute__',
            'XMLPUBFUN', 'XMLPUBVAR', 'XMLCALL', 'XMLCDECL',
        })
        
        # Scan spine source for called vs defined functions
        called_funcs = set()
        defined_funcs = set()
        
        for sf in self.harness_dir.glob("*.c"):
            if sf.name == "smart_stubs.c":
                continue  # don't scan ourselves
            try:
                src = sf.read_text(errors="replace")
                # Collect function DEFINITIONS from ALL files (including stubs.c)
                for m in re.finditer(r'\n\w[\w\s\*]*\b(\w+)\s*\([^)]*\)\s*\{', src):
                    defined_funcs.add(m.group(1))
                # Collect function CALLS only from spine files (not driver/stubs)
                if sf.name not in ("driver.c", "stubs.c"):
                    for m in re.finditer(r'\b(\w+)\s*\(', src):
                        fn = m.group(1)
                        if fn in _SKIP_STUB:
                            continue
                        # Skip numeric tokens ("2"), single chars, ALL_CAPS macros
                        if not fn[0].isalpha() and fn[0] != '_':
                            continue  # starts with digit
                        if len(fn) <= 1:
                            continue  # single char
                        if fn.isupper() and '_' in fn:
                            continue  # ALL_CAPS_MACRO
                        if fn.isupper() and len(fn) <= 4:
                            continue  # short uppercase (likely macro like NXT, CUR)
                        called_funcs.add(fn)
            except Exception:
                pass
        
        # External = called but not defined in harness and not in prescriptions
        external_funcs = called_funcs - defined_funcs - set(prescriptions.keys())
        
        n_proactive = 0
        for func_name in sorted(external_funcs):
            # Validate: must be a valid C identifier
            if not re.match(r'^[a-zA-Z_]\w*$', func_name):
                continue  # skip numeric tokens, macro artifacts, etc.
            if len(func_name) > 100:
                continue  # absurdly long — likely a parsing artifact
            if func_name in _LIBC_STUBS:
                lines.append(f"/* PROACTIVE: {func_name} (libc — prevents KLEE concretization) */")
                lines.append(_LIBC_STUBS[func_name])
            else:
                # Generic stub for unknown project functions: return 0
                lines.append(f"/* PROACTIVE: {func_name} (auto-detected external) */")
                lines.append(f"int {func_name}() {{ return 0; }}")
            lines.append("")
            n_proactive += 1
        
        # Counter for unique symbolic variable names
        sym_counter = 0
        
        for func, info in sorted(prescriptions.items()):
            stype = info.get("type", "trivial")
            reason = info.get("reason", "")
            var_name = info.get("var_name", "ret")
            
            if stype == "symbolic_constrained":
                # Return value is symbolic WITH constraint — models the function's
                # contract while letting KLEE find the exact triggering value
                constraint = info["constraint"]
                sym_name = f"{func}_ret"
                
                lines.append(f"/* ⚡SYMBOLIC+CONSTRAINED {func}: {reason} */")
                lines.append(f"/* The return value controls the branch AND flows into the vulnerability. */")
                lines.append(f"/* KLEE will find the exact value that triggers the OOB/UAF/etc. */")
                lines.append(f"int {func}() {{")
                lines.append(f"    int {var_name};")
                lines.append(f"    klee_make_symbolic(&{var_name}, sizeof({var_name}), \"{sym_name}\");")
                lines.append(f"    klee_assume({constraint});")
                lines.append(f"    return {var_name};")
                lines.append(f"}}")
                lines.append("")
            
            elif stype == "symbolic":
                # Return value flows into vulnerability — fully symbolic
                sym_name = f"{func}_ret"
                
                lines.append(f"/* 🔍SYMBOLIC {func}: {reason} */")
                lines.append(f"/* Value flows into vulnerability expression — KLEE explores all values */")
                lines.append(f"int {func}() {{")
                lines.append(f"    int {var_name};")
                lines.append(f"    klee_make_symbolic(&{var_name}, sizeof({var_name}), \"{sym_name}\");")
                lines.append(f"    return {var_name};")
                lines.append(f"}}")
                lines.append("")
            
            elif stype == "sink_trigger":
                # Hardcoded value to reach sink (return doesn't affect vulnerability itself)
                ret_val = info["return"]
                
                # Determine return type
                if ret_val in ("NULL", "(void*)1"):
                    ret_type = "void *"
                else:
                    ret_type = "int"
                
                lines.append(f"/* ⚡SINK_TRIGGER {func}: {reason} */")
                lines.append(f"{ret_type} {func}() {{ return {ret_val}; }}")
                lines.append("")
            
            elif stype == "constrained":
                # Hardcoded value to avoid error exit
                ret_val = info["return"]
                
                if ret_val in ("NULL", "(void*)1"):
                    ret_type = "void *"
                else:
                    ret_type = "int"
                
                lines.append(f"/* → CONSTRAINED {func}: {reason} */")
                lines.append(f"{ret_type} {func}() {{ return {ret_val}; }}")
                lines.append("")
            
            else:
                # Trivial
                lines.append(f"/* {func}: trivial stub */")
                lines.append(f"int {func}() {{ return 0; }}")
                lines.append("")
        
        stubs_path = self.harness_dir / "smart_stubs.c"
        stubs_path.write_text('\n'.join(lines), encoding="utf-8")
        
        n_sym = sum(1 for p in prescriptions.values() if 'symbolic' in p.get('type', ''))
        n_hard = len(prescriptions) - n_sym
        print(f"    [i] SmartStubs: {n_sym} symbolic + {n_hard} hardcoded + {n_proactive} proactive → smart_stubs.c")

    def _auto_fix_compile_error(self, sf, err_str):
        """Try to automatically fix neutralization artifacts in a harness .c file.
        
        Returns True if a fix was applied (caller should retry compilation).
        """
        try:
            hlines = sf.read_text(errors="replace").split('\n')
        except Exception:
            return False
        
        fixed = False
        
        # Pattern 1: Extra parentheses from multi-line macro neutralization
        # e.g. "if (0\n   )) {"  or  "if (0\n   ) && (stuff)) {"
        if "extraneous ')'" in err_str or "expected expression" in err_str:
            # Find ALL error lines
            for m in re.finditer(rf'{re.escape(sf.name)}:(\d+):\d+: error:', err_str):
                err_line = int(m.group(1))
                if err_line < 1 or err_line > len(hlines):
                    continue
                # Look backwards for the if(0 that caused this
                for k in range(err_line - 1, max(0, err_line - 6), -1):
                    if re.match(r'\s*if\s*\(0\s*$', hlines[k]):
                        # Found: if (0 on line k, leftover )) on err_line
                        # Find the { that should follow
                        brace = ""
                        for j in range(k, min(len(hlines), err_line + 2)):
                            if '{' in hlines[j]:
                                brace = " {"; break
                        indent = re.match(r'^(\s*)', hlines[k]).group(1)
                        hlines[k] = f"{indent}if (0){brace}"
                        # Blank the leftover condition lines
                        for j in range(k + 1, min(err_line + 1, len(hlines))):
                            s = hlines[j].strip()
                            if s and (s.startswith(')') or s.startswith('&&') or s.startswith('||')):
                                hlines[j] = re.match(r'^(\s*)', hlines[j]).group(1)
                        fixed = True
                        print(f"    [auto-fix] Fixed extra parens at line {err_line} (if(0) at {k+1})")
                        break
        
        if fixed:
            sf.write_text('\n'.join(hlines), encoding='utf-8')
        return fixed
    
    def _instrument_spine_probes(self, body: str, func_spans: dict, first_func_start: int, full_src: str) -> str:
        """Insert klee_warning coverage probes at key spine checkpoints.
        
        Probes inserted:
        1. FUNC_ENTRY — first line after opening brace of each spine function
        2. SWITCH_CASE — first line of each non-neutralized switch case
        3. GOTO_LABEL — at labels near the vulnerability (encoding_error, etc.)
        
        This gives concrete coverage feedback via KLEE's warnings.txt,
        replacing unreliable run.istats parsing.
        """
        lines = body.split('\n')
        new_lines = []
        n_probes = 0
        
        # Build a map of body-relative line offsets for each function
        # func_spans are in full_src coordinates; body starts at first_func_start
        func_line_ranges = {}
        for fn, (sig_start, brace_start, body_end) in func_spans.items():
            # Convert to body-relative line numbers
            fn_start_line = full_src[:sig_start].count('\n') - full_src[:first_func_start].count('\n')
            fn_end_line = full_src[:body_end].count('\n') - full_src[:first_func_start].count('\n')
            func_line_ranges[fn] = (fn_start_line, fn_end_line)
        
        # Track which function we're in as we iterate
        def get_current_func(line_idx):
            for fn, (s, e) in func_line_ranges.items():
                if s <= line_idx <= e:
                    return fn
            return None
        
        # Find the opening brace lines for each function (for FUNC_ENTRY probes)
        func_entry_lines = set()
        for fn, (sig_start, brace_start, _) in func_spans.items():
            brace_line = full_src[:brace_start].count('\n') - full_src[:first_func_start].count('\n')
            func_entry_lines.add((brace_line, fn))
        
        func_entry_injected = set()
        
        for i, line in enumerate(lines):
            new_lines.append(line)
            stripped = line.strip()
            current_func = get_current_func(i)
            
            # 1. FUNC_ENTRY: inject after opening brace of each spine function
            for brace_line, fn in func_entry_lines:
                if i == brace_line and fn not in func_entry_injected:
                    indent = "    "
                    new_lines.append(f'{indent}klee_warning_once("SPINE_PROBE:{fn}:ENTRY");')
                    func_entry_injected.add(fn)
                    n_probes += 1
            
            # 2. SWITCH_CASE: inject after case labels inside spine functions
            if current_func:
                case_match = re.match(r'^(\s*)case\s+(\w+)\s*:', stripped)
                if case_match:
                    # Only probe non-neutralized cases (next line is NOT "break;")
                    next_stripped = lines[i+1].strip() if i+1 < len(lines) else ""
                    if not next_stripped.startswith('break;'):
                        case_val = case_match.group(2)
                        indent = re.match(r'^(\s*)', line).group(1)
                        new_lines.append(f'{indent}    klee_warning_once("SPINE_PROBE:{current_func}:CASE_{case_val}");')
                        n_probes += 1
            
            # 3. GOTO_LABEL: inject at labels near vulnerability site
            if current_func:
                label_match = re.match(r'^(\w+)\s*:\s*$', stripped)
                if label_match:
                    label_name = label_match.group(1)
                    if label_name not in ('default', 'case'):
                        indent = "    "
                        new_lines.append(f'{indent}klee_warning_once("SPINE_PROBE:{current_func}:LABEL_{label_name}");')
                        n_probes += 1
        
        if n_probes > 0:
            print(f"    [+] Inserted {n_probes} spine coverage probes")
        
        # --- UNIVERSAL SINK ASSERTION ---
        # Ensure klee_assert(0 && "SAILOR_SINK_REACHED") is always present
        # at the vulnerability site. This must work regardless of whether the
        # agent included any markers.
        result = '\n'.join(new_lines)
        if 'SAILOR_SINK_REACHED' not in result:
            result_lines = result.split('\n')
            injected = False
            
            # Strategy 1: Find existing SAILOR_PROBE_SINK / SUSPECT_HIT markers
            for i, line in enumerate(result_lines):
                if ('SAILOR_PROBE_SINK' in line or 'SAILOR_SUSPECT_HIT' in line) and not injected:
                    indent = re.match(r'^(\s*)', line).group(1) or "    "
                    result_lines.insert(i + 1, f'{indent}klee_assert(0 && "SAILOR_SINK_REACHED");')
                    injected = True
                    print(f"    [+] Injected sink assert after SAILOR marker at line {i+1}")
                    break
            
            # Strategy 2: No markers — find vulnerability site from frozen plan
            if not injected:
                vul_func = self.frozen.get("vul_func", "")
                
                # Build search patterns from frozen plan
                search_patterns = []
                
                # a) Exact code snippets from source_context around the vuln line
                src_ctx = self.frozen.get("source_context", "")
                vul_line = int(self.frozen.get("vul_line", 0))
                if src_ctx:
                    for ctx_line in src_ctx.split('\n'):
                        # Strip line numbers like "12080: code..."
                        stripped_ctx = re.sub(r'^\d+:\s*', '', ctx_line).strip()
                        if stripped_ctx and len(stripped_ctx) > 15 and not stripped_ctx.startswith(('//', '/*', '*')):
                            search_patterns.append(stripped_ctx)
                
                # b) Goto labels from frozen plan (encoding_error, error, oom, etc.)
                goto_targets = self.frozen.get("goto_targets", [])
                if isinstance(goto_targets, list):
                    for gt in goto_targets:
                        if isinstance(gt, str):
                            search_patterns.append(f"{gt}:")
                        elif isinstance(gt, dict):
                            label = gt.get("label", "")
                            if label:
                                search_patterns.append(f"{label}:")
                
                # c) Vulnerability summary keywords
                vuln_summary = self.frozen.get("vulnerability_summary", "")
                if vuln_summary:
                    # Extract key expressions mentioned in the summary
                    # e.g., "cur[0]", "memcmp(entry->name, name, len)"
                    for pat in re.findall(r'(\w+\[\d+\]|\w+->\w+\[\d+\]|memcmp\([^)]+\)|snprintf\([^)]+\))', vuln_summary):
                        search_patterns.append(pat)
                
                # d) Common vulnerability patterns for the CWE type
                cwe_id = ""
                spec_path = self.harness_dir.parent / "sa_context" / "spec.json"
                if spec_path.exists():
                    try:
                        spec = read_json(spec_path)
                        cwe_id = str(spec.get("cwe_id", spec.get("cwe", "")))
                    except Exception:
                        pass
                
                # Search for vulnerability site in the harness
                best_line = -1
                best_score = 0
                
                # Check if the harness is in the vul_func
                in_vul_func = False
                func_depth = 0
                
                for i, line in enumerate(result_lines):
                    stripped = line.strip()
                    
                    # Track if we're inside the vulnerable function
                    if vul_func and re.match(rf'.*\b{re.escape(vul_func)}\b\s*\(', stripped):
                        in_vul_func = True
                    if in_vul_func:
                        func_depth += stripped.count('{') - stripped.count('}')
                        if func_depth < 0:
                            in_vul_func = False
                            func_depth = 0
                    
                    # Score this line against search patterns
                    score = 0
                    for pat in search_patterns:
                        if pat in stripped or pat in line:
                            score += 1
                    
                    # Bonus: in the vulnerable function
                    if in_vul_func and score > 0:
                        score += 2
                    
                    # Bonus: goto label match
                    if any(f"{gt}" in stripped for gt in goto_targets if isinstance(gt, str)):
                        score += 3
                    
                    if score > best_score:
                        best_score = score
                        best_line = i
                
                # If we found a good match, inject after it
                if best_line >= 0 and best_score >= 1:
                    indent = re.match(r'^(\s*)', result_lines[best_line]).group(1) or "    "
                    result_lines.insert(best_line + 1, f'{indent}klee_assert(0 && "SAILOR_SINK_REACHED");')
                    injected = True
                    print(f"    [+] Injected sink assert after vuln-site match at line {best_line+1} (score={best_score})")
                
                # Strategy 2b: For CWE-125/787, find memcmp/memcpy/array-access inside
                # vul_func and inject bounds check + assert BEFORE the vulnerable call.
                # This works even when the agent rewrote the code and source_context
                # patterns don't match exactly.
                if not injected and vul_func:
                    # Determine CWE
                    cwe_for_2b = cwe_id
                    if not cwe_for_2b:
                        spec_name_2b = os.path.basename(self.ctx.get("spec_path", ""))
                        cwe_m_2b = re.search(r'cwe-(\d+)', spec_name_2b, re.IGNORECASE)
                        cwe_for_2b = cwe_m_2b.group(1) if cwe_m_2b else ""
                    
                    if cwe_for_2b in ("125", "787", "119", "122", "121"):
                        in_vf = False
                        vf_depth = 0
                        vul_line_num = int(self.frozen.get("vul_line", 0))
                        
                        for i, line in enumerate(result_lines):
                            stripped = line.strip()
                            if re.match(rf'.*\b{re.escape(vul_func)}\b\s*\(', stripped):
                                in_vf = True
                            if in_vf:
                                vf_depth += stripped.count('{') - stripped.count('}')
                                if vf_depth <= 0 and i > 0:
                                    break
                                
                                # Look for memcmp/memcpy/memmove/strncmp(ptr, x, len)
                                mem_m = re.search(
                                    r'(memcmp|memcpy|memmove|strncmp|strncpy|memset)\s*\(\s*([^,]+),\s*[^,]+,\s*([^)]+)\)',
                                    stripped
                                )
                                if mem_m:
                                    ptr_expr = mem_m.group(2).strip()
                                    len_expr = mem_m.group(3).strip()
                                    line_indent = re.match(r'^(\s*)', line).group(1) or "        "
                                    
                                    # Insert bounds check + assert BEFORE the memcmp line
                                    inject_lines = [
                                        f'{line_indent}/* SAILOR: CWE-{cwe_for_2b} bounds check — injected before vulnerable call */',
                                        f'{line_indent}if (klee_get_obj_size((void*){ptr_expr}) < (size_t)({len_expr}))',
                                        f'{line_indent}  klee_report_error(__FILE__, {vul_line_num}, "SAILOR OOB: buffer too small for access length", "sailor.ptr.err");',
                                        f'{line_indent}klee_assert(0 && "SAILOR_SINK_REACHED");',
                                    ]
                                    for j, il in enumerate(inject_lines):
                                        result_lines.insert(i + j, il)
                                    injected = True
                                    print(f"    [+] Injected CWE-{cwe_for_2b} bounds check + sink BEFORE {mem_m.group(1)}() at line {i+1}")
                                    break
                                
                                # Look for ptr[idx] patterns
                                idx_m = re.search(r'(\w+(?:->\w+)*)\s*\[\s*(\w+)\s*\]', stripped)
                                if idx_m and not idx_m.group(2).isdigit():
                                    arr_expr = idx_m.group(1).strip()
                                    idx_expr = idx_m.group(2).strip()
                                    line_indent = re.match(r'^(\s*)', line).group(1) or "        "
                                    
                                    inject_lines = [
                                        f'{line_indent}/* SAILOR: CWE-{cwe_for_2b} bounds check — injected before vulnerable access */',
                                        f'{line_indent}if ((size_t)({idx_expr}) >= klee_get_obj_size((void*){arr_expr}))',
                                        f'{line_indent}  klee_report_error(__FILE__, {vul_line_num}, "SAILOR OOB: index exceeds buffer size", "sailor.ptr.err");',
                                        f'{line_indent}klee_assert(0 && "SAILOR_SINK_REACHED");',
                                    ]
                                    for j, il in enumerate(inject_lines):
                                        result_lines.insert(i + j, il)
                                    injected = True
                                    print(f"    [+] Injected CWE-{cwe_for_2b} bounds check + sink BEFORE {arr_expr}[{idx_expr}] at line {i+1}")
                                    break
                
                # Strategy 3: Last resort — find any klee_warning PROBE_SINK or just the
                # last line of vul_func
                if not injected and vul_func:
                    last_func_line = -1
                    in_func = False
                    depth = 0
                    for i, line in enumerate(result_lines):
                        stripped = line.strip()
                        if re.match(rf'.*\b{re.escape(vul_func)}\b\s*\(', stripped):
                            in_func = True
                        if in_func:
                            depth += stripped.count('{') - stripped.count('}')
                            if depth > 0:
                                last_func_line = i
                            if depth <= 0 and last_func_line > 0:
                                break
                    
                    if last_func_line > 0:
                        indent = "    "
                        result_lines.insert(last_func_line, f'{indent}klee_assert(0 && "SAILOR_SINK_REACHED");')
                        injected = True
                        print(f"    [+] Injected sink assert at end of {vul_func} (line {last_func_line})")
            
            if injected:
                result = '\n'.join(result_lines)
            else:
                print(f"    [!] WARNING: Could not inject SAILOR_SINK_REACHED — no vulnerability site found")
        
        # =====================================================================
        # ALWAYS-RUN: CWE-125/787 bounds check injection
        # Runs REGARDLESS of whether SAILOR_SINK_REACHED was already present.
        # Scans vul_func for memcmp/memcpy/ptr[idx] and injects klee_get_obj_size
        # checks that produce .sailor.ptr.err for bug_triggered detection.
        # =====================================================================
        cwe_bc = ""
        spec_p_bc = self.harness_dir.parent / "sa_context" / "spec.json"
        if spec_p_bc.exists():
            try:
                sp_data = read_json(spec_p_bc)
                cwe_bc = str(sp_data.get("cwe_id", sp_data.get("cwe", "")))
            except Exception:
                pass
        if not cwe_bc:
            sn_bc = os.path.basename(self.ctx.get("spec_path", ""))
            cm_bc = re.search(r'cwe-(\d+)', sn_bc, re.IGNORECASE)
            cwe_bc = cm_bc.group(1) if cm_bc else ""
        
        if cwe_bc in ("125", "787", "119", "122", "121"):
            vf_bc = self.frozen.get("vul_func", "")
            vl_bc = int(self.frozen.get("vul_line", 0))
            if vf_bc and "klee_get_obj_size" not in result:
                bc_lines = result.split('\n')
                in_vf = False
                vf_d = 0
                bc_done = False
                
                for i, line in enumerate(bc_lines):
                    stripped = line.strip()
                    if re.match(rf'.*\b{re.escape(vf_bc)}\b\s*\(', stripped):
                        in_vf = True
                    if in_vf:
                        vf_d += stripped.count('{') - stripped.count('}')
                        if vf_d <= 0 and i > 0:
                            break
                        
                        li = re.match(r'^(\s*)', line).group(1) or "        "
                        
                        mem_m = re.search(
                            r'(memcmp|memcpy|memmove|strncmp|strncpy|memset)\s*\(\s*([^,]+),\s*[^,]+,\s*([^)]+)\)',
                            stripped)
                        if mem_m and not bc_done:
                            pe = mem_m.group(2).strip()
                            le = mem_m.group(3).strip()
                            check = (f'{li}if (klee_get_obj_size((void*){pe}) < (size_t)({le})) '
                                     f'klee_report_error(__FILE__, {vl_bc}, '
                                     f'"SAILOR OOB: buffer too small", "sailor.ptr.err");')
                            bc_lines.insert(i, check)
                            bc_done = True
                            print(f"    [+] CWE-{cwe_bc} bounds check: klee_get_obj_size({pe}) < {le}")
                            break
                        
                        idx_m = re.search(r'(\w+(?:->\w+)*)\s*\[\s*(\w+)\s*\]', stripped)
                        if idx_m and not mem_m and not bc_done and not idx_m.group(2).isdigit():
                            ae = idx_m.group(1).strip()
                            ie = idx_m.group(2).strip()
                            check = (f'{li}if ((size_t)({ie}) >= klee_get_obj_size((void*){ae})) '
                                     f'klee_report_error(__FILE__, {vl_bc}, '
                                     f'"SAILOR OOB: index exceeds buffer", "sailor.ptr.err");')
                            bc_lines.insert(i, check)
                            bc_done = True
                            print(f"    [+] CWE-{cwe_bc} bounds check: {ie} >= klee_get_obj_size({ae})")
                            break
                
                if bc_done:
                    result = '\n'.join(bc_lines)
        
        # =====================================================================
        # ALWAYS-RUN: CWE-416/415 UAF/double-free detection
        # For UAF specs, ensure free() stubs actually call free() and that
        # KLEE's native .free.err detection can trigger. If the harness has
        # a free() call inside vul_func, verify the sink assertion is AFTER
        # a dereference of the freed pointer, not just after the free.
        # =====================================================================
        if cwe_bc in ("416", "415"):
            vf_uaf = self.frozen.get("vul_func", "")
            if vf_uaf and "SAILOR_SINK_REACHED" in result:
                uaf_lines = result.split('\n')
                in_vf_uaf = False
                vf_uaf_d = 0
                has_free = False
                has_deref_after_free = False
                
                for i, line in enumerate(uaf_lines):
                    stripped = line.strip()
                    if re.match(rf'.*\b{re.escape(vf_uaf)}\b\s*\(', stripped):
                        in_vf_uaf = True
                    if in_vf_uaf:
                        vf_uaf_d += stripped.count('{') - stripped.count('}')
                        if vf_uaf_d <= 0 and i > 0:
                            break
                        # Detect free() calls
                        if re.search(r'\b(free|kfree|kfree_rcu|kmem_cache_free|kvfree)\s*\(', stripped):
                            has_free = True
                        # Detect dereference after free (ptr->field or *ptr)
                        if has_free and re.search(r'->|\*\s*\w+', stripped) and 'SAILOR' not in stripped:
                            has_deref_after_free = True
                
                if has_free and has_deref_after_free:
                    print(f"    [+] CWE-{cwe_bc} UAF pattern: free() + dereference found in {vf_uaf}")
                elif has_free and not has_deref_after_free:
                    print(f"    [!] CWE-{cwe_bc} WARNING: free() found but no dereference after it in {vf_uaf}")
                    print(f"         KLEE needs a dereference AFTER free to generate .free.err")
        
        return result
    

    def _auto_generate_driver(self) -> str:
        """Auto-generate a correct driver when the agent's driver keeps crashing.
        
        Uses frozen plan data (entry func, struct groom, driver hint) to produce
        a driver with CONCRETE allocations and proper symbolic content.
        """
        entry = self.frozen.get("entry", "")
        vul_func = self.frozen.get("vul_func", "")
        if not entry:
            return ""
        
        # Get struct groom info for allocation sizes
        groom = self.frozen.get("struct_groom", {})
        guards = groom.get("guards", {})
        constants = groom.get("constants", {})
        sub_structs = groom.get("sub_structs", {})
        
        # Get entry function signature from harness
        entry_sig = ""
        for hf in self.harness_dir.glob("*.c"):
            if hf.name in ("driver.c", "stubs.c", "smart_stubs.c"):
                continue
            hsrc = hf.read_text(errors="replace")
            # Look for entry function signature
            m = re.search(rf'(\w[\w\s\*]*)\b{re.escape(entry)}\s*\(([^)]*)\)', hsrc)
            if m:
                entry_sig = m.group(0)
                break
        
        # Get driver hint from SA context
        driver_hint = ""
        sa_dir = self.harness_dir.parent / "sa_context"
        hint_file = sa_dir / "vulnerability_summary.json"
        if hint_file.exists():
            try:
                summary = read_json(hint_file)
                driver_hint = summary.get("driver_hint", "")
            except Exception:
                pass
        
        # Build the driver
        lines = []
        lines.append("/* AUTO-GENERATED DRIVER — concrete allocations, symbolic content */")
        lines.append("#include <stdlib.h>")
        lines.append("#include <string.h>")
        lines.append("#include <klee/klee.h>")
        lines.append("")
        
        # Add project includes from harness preamble
        for hf in self.harness_dir.glob("*.c"):
            if hf.name in ("driver.c", "stubs.c", "smart_stubs.c"):
                continue
            for line in hf.read_text(errors="replace").split('\n')[:50]:
                if line.strip().startswith('#include') and 'klee' not in line.lower():
                    lines.append(line)
            break
        
        lines.append("")
        
        # Declare entry function if signature found
        if entry_sig:
            lines.append(f"extern {entry_sig};")
        else:
            lines.append(f"extern int {entry}();")
        
        lines.append("")
        lines.append("int main() {")
        
        # Determine parameter types from signature
        # For now, generate a generic driver that works for most cases
        # Key rule: ALL sizes are CONCRETE, content is SYMBOLIC
        
        # Allocate main context struct with concrete size
        lines.append("    // Step 1: Concrete struct allocations")
        lines.append("    // Using char arrays to avoid incomplete type issues")
        
        # Generic parameter setup
        # If we have guard info, use it to set up fields
        if guards or constants:
            lines.append("    // Struct with space for fields (from SA analysis)")
            lines.append("    char ctx_buf[4096];")
            lines.append("    memset(ctx_buf, 0, sizeof(ctx_buf));")
            lines.append("    void *ctx = (void*)ctx_buf;")
            lines.append("")
            
            # Set guard values at known offsets
            for field, val in guards.items():
                lines.append(f"    // Guard: {field} = {val}")
            for name, val in constants.items():
                lines.append(f"    // Constant: {name} = {val}")
        
        lines.append("")
        lines.append("    // Step 2: Symbolic input buffers (CONCRETE size, SYMBOLIC content)")
        lines.append("    char sym_name[256];")
        lines.append("    klee_make_symbolic(sym_name, sizeof(sym_name), \"name\");")
        lines.append("    sym_name[255] = '\\0';  // null-terminate")
        lines.append("")
        lines.append("    int sym_len;")
        lines.append("    klee_make_symbolic(&sym_len, sizeof(sym_len), \"len\");")
        lines.append("    klee_assume(sym_len > 0 && sym_len < 256);")
        lines.append("")
        
        # Sub-struct allocations
        if sub_structs:
            lines.append("    // Step 3: Sub-struct allocations (from SA groom)")
            for var, subs in sub_structs.items():
                for sub, fields in subs.items():
                    lines.append(f"    // {var}->{sub}: fields {', '.join(fields[:5])}")
                    lines.append(f"    char {sub}_buf[1024];")
                    lines.append(f"    memset({sub}_buf, 0, sizeof({sub}_buf));")
            lines.append("")
        
        # Call entry function
        lines.append("    // Step 4: Call entry function")
        lines.append(f"    {entry}(sym_name, sym_len);")
        
        lines.append("")
        lines.append("    return 0;")
        lines.append("}")
        
        return '\n'.join(lines)

    def _auto_stub_constructors(self, bc_files, linked_bc):
        """Auto-generate stubs for constructor functions called in driver.c but not defined in harness.
        
        Policy: scan driver.c for 'TypePtr var = func(...)' patterns. For each func not
        already in the harness, generate a stub that includes the same project headers
        (so signatures match) and returns calloc'd memory.
        """
        driver_path = self.harness_dir / "driver.c"
        if not driver_path.exists():
            return
        driver_src = driver_path.read_text(errors="replace")
        
        # Find constructor calls: lines matching "SomeType var = someFunc(...)"
        # where the return is stored (implies pointer/struct return that needs allocation)
        constructor_info = {}  # func_name -> return_type from call site
        for line in driver_src.split('\n'):
            stripped = line.strip()
            # Match: TypeName [*] varname = funcname(
            m = re.match(r'(\w+(?:\s*\*)?)\s+\w+\s*=\s*(\w+)\s*\(', stripped)
            if not m:
                continue
            ret_type = m.group(1).strip()
            func_name = m.group(2).strip()
            # Skip standard lib, klee, and trivial functions
            if func_name in ('malloc', 'calloc', 'realloc', 'klee_make_symbolic',
                            'memset', 'memcpy', 'memmove', 'strdup', 'strndup',
                            'fopen', 'tmpfile', 'sizeof', 'if', 'while', 'for',
                            'atoi', 'atol', 'strtol', 'strtoul', 'getenv'):
                continue
            constructor_info[func_name] = ret_type
        
        if not constructor_info:
            return
        
        # Check which functions are already defined in harness .c files (including stubs.c)
        for cfile in self.harness_dir.glob("*.c"):
            if cfile.name == "auto_stubs.c":
                continue
            src = cfile.read_text(errors="replace")
            for func in list(constructor_info.keys()):
                # Check for function definition (body with {) OR just presence in stubs.c
                if re.search(rf'^\s*(?:\w+[\s\*]+)+{re.escape(func)}\s*\([^)]*\)\s*\{{', src, re.MULTILINE):
                    del constructor_info[func]
                elif cfile.name == "stubs.c" and func in src:
                    # Agent wrote this function in stubs.c — don't auto-stub it
                    del constructor_info[func]
        
        if not constructor_info:
            return
        
        # Generate auto_stubs.c — deliberately NO project headers to avoid conflicting prototypes.
        # We just define functions that return calloc'd memory. LLVM linker resolves by name.
        auto_stubs = []
        auto_stubs.append("/* Auto-generated constructor stubs — no project headers to avoid conflicts */")
        auto_stubs.append("#include <stdlib.h>")
        auto_stubs.append("")
        
        for func, ret_type in sorted(constructor_info.items()):
            # Use void* return and let the linker handle type matching
            auto_stubs.append(f"/* Auto-stub for {func} — allocates zeroed memory */")
            auto_stubs.append(f"void * {func}() {{")
            auto_stubs.append(f"    return calloc(1, 4096);")
            auto_stubs.append(f"}}")
            auto_stubs.append("")
            print(f"    [i] Auto-stub: {func} -> calloc(4096)")
        
        # Write auto_stubs.c
        auto_stubs_path = self.harness_dir / "auto_stubs.c"
        auto_stubs_path.write_text('\n'.join(auto_stubs), encoding="utf-8")
        
        # Compile with MINIMAL flags — no project headers, just stdlib
        bf = auto_stubs_path.with_suffix(".bc")
        cmd = [self.clang, "-emit-llvm", "-c", "-g", "-O0", "-Wno-everything",
               str(auto_stubs_path), "-o", str(bf)]
        rc, _, err, _ = run_cmd(cmd, cwd=self.harness_dir, timeout=30)
        if rc == 0:
            print(f"    [+] auto_stubs.c -> OK")
            # Re-link with auto_stubs included
            bc_files_with_auto = list(bc_files) + [bf]
            cmd = [self.llvm_link] + [str(f) for f in bc_files_with_auto] + ["-o", str(linked_bc)]
            rc2, _, err2, _ = run_cmd(cmd, timeout=30)
            if rc2 != 0:
                print(f"    [!] Re-link with auto_stubs failed: {err2[:200]}")
        else:
            print(f"    [!] auto_stubs.c compile failed: {err[:200]}")
            auto_stubs_path.unlink(missing_ok=True)

    def explore_klee_output(self, file_name=""):
        if not self.last_klee_stats: return "No KLEE runs yet."
        out_dir = Path(self.last_klee_stats.get("out_dir", ""))
        if not out_dir.exists(): return "KLEE output directory not found."
        
        if not file_name:
            # List all files with sizes
            files = sorted(out_dir.iterdir())
            listing = []
            for f in files:
                size = f.stat().st_size if f.is_file() else 0
                listing.append(f"{f.name} ({size}B)")
            
            # Auto-show err files + their path constraints
            err_files = sorted(out_dir.glob("*.err"))
            err_summary = ""
            if err_files:
                for ef in err_files[:3]:
                    content = ef.read_text(errors="replace")
                    err_summary += f"\n--- {ef.name} ---\n{content}\n"
                    
                    # Auto-show path constraints for this crash
                    test_id = ef.stem  # e.g., "test000001"
                    for ext in [".kquery", ".smt2"]:
                        constraint_file = out_dir / (test_id + ext)
                        if constraint_file.exists():
                            ctext = constraint_file.read_text(errors="replace")
                            if len(ctext) > 3000:
                                ctext = ctext[:1500] + "\n... (truncated) ...\n" + ctext[-1500:]
                            err_summary += f"\n--- {test_id}{ext} (path constraints) ---\n{ctext}\n"
                            break  # prefer .kquery, fallback to .smt2
            
            return f"Files in {out_dir.name}:\n{', '.join(listing)}\n{err_summary}"
        
        fp = out_dir / file_name
        if not fp.exists(): return f"File '{file_name}' not found. Available: {[f.name for f in out_dir.iterdir()]}"
        
        # For .ktest files, try to decode with ktest-tool
        if file_name.endswith(".ktest"):
            rc, out, _, _ = run_cmd(["ktest-tool", str(fp)], timeout=5)
            if rc == 0: return out[:3000]
            return f"(ktest-tool not available, raw binary file of {fp.stat().st_size} bytes)"
        
        # For .kquery/.smt2 files, show with a header explaining the format
        if file_name.endswith((".kquery", ".smt2")):
            content = fp.read_text(errors="replace")
            fmt = "KQuery" if file_name.endswith(".kquery") else "SMT-LIB2"
            header = f"[{fmt} path constraints for {fp.stem}]\n"
            header += "These are the symbolic conditions that led to this test case/crash.\n"
            header += "Variables like 'buf' are the symbolic inputs from klee_make_symbolic().\n\n"
            if len(content) > 4000:
                content = content[:2000] + "\n... (truncated) ...\n" + content[-2000:]
            return header + content
        
        return fp.read_text(errors="replace")[:3000]

    def replace_code(self, file_name, search, replace):
        # Accept both "parser.c" and "harness/parser.c"
        clean = file_name.replace("harness/", "") if file_name else file_name
        fp = self.harness_dir / clean
        if not fp.exists(): return f"File not found: {clean} (available: {', '.join(f.name for f in self.harness_dir.glob('*.c'))})"
        c = fp.read_text()
        if search in c:
            fp.write_text(c.replace(search, replace))
            return "OK"
        return "Search text not found"

# ---------------------------------------------------------------------------
# System Prompt & Agent Loop
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = r"""You are a symbolic execution engineer. Your job is to BUILD a minimal KLEE harness that reaches and triggers a specific vulnerability.

ARCHITECTURE — YOU drive the whole process:
1. Read the vulnerability model (ReadSAContext → vulnerability_summary.json)
2. Design a harness: identify what functions/types are needed
3. Gather code from source (GatherCode, GrepSource)
4. Write a MINIMAL sliced harness (WriteHarness) + driver (WriteDriver)
5. Compile and iterate (CompileSlice)
6. Run KLEE, diagnose, fix, repeat

TOOLS:
  ReadSAContext(file) — read SA context:
    no arg → list files + auto-show vulnerability summary
    vulnerability_summary.json → source context, goto_sources, driver_hint, struct defs
    spec.json → CWE, description, data flows
  GatherCode(functions, types) — find function bodies and type definitions from project source:
    functions: comma-separated names → returns full function source + file preamble
    types: comma-separated struct/type names → returns definitions
  WriteHarness(code) — write the sliced spine file (preamble + neutralized functions)
  WriteDriver(code) — write driver.c (main with symbolic input)
  WriteStubs(code) — write stubs.c (stub functions)
  CompileSlice() — compile all .c in harness/, link, run KLEE
  GrepSource(pattern, file) — search source files for patterns
  ReadSource(file, start_line, end_line) — read specific lines
  FindDefinition(symbol) — find struct/type/function definition
  ExtractFunction(file, func) — extract a function with full preamble (for helpers not in spine)
  ReplaceCode(file, search, replace) — fix code in harness files
  ExploreKleeOutput(file) — examine KLEE results
  Done(verdict, details) — report result

STEP-BY-STEP APPROACH — HARD TURN LIMITS:

STEP 1 (Turn 1-2) — UNDERSTAND THE VULNERABILITY:
  ReadSAContext() → get vulnerability model. This has EVERYTHING you need:
  entry_func, vul_func, enclosing_switch_case, goto_sources, driver_hint,
  struct_definitions, source_context. Read it ONCE, do not re-read.

STEP 2 (Turn 3) — GATHER CODE:
  GatherCode(functions="entry_func,vul_func", types="struct1,struct2")
  Call this ONCE. For large functions (2000+ lines), you'll get a SMART EXCERPT
  showing: signature, target switch case, goto labels. That's all you need.
  DO NOT call GatherCode again for the same function.

STEP 3 (Turn 4) — WRITE HARNESS:
  WriteHarness with neutralized code. Use the excerpt + vulnerability_summary.
  If you don't have the full function body, THAT'S OK — you only need the
  target case and labels anyway. Write the neutralized version from what you have.
  
  CRITICAL — ENTRY FUNCTION MUST BE A SIMPLE PASS-THROUGH:
  The entry function MUST be written as a direct call to the vulnerable function
  with NO guards, NO NULL checks, NO early returns:
    ReturnType entry_func(params...) {
        vul_func(matching_params);  // DIRECT call, no guards
        return 0;
    }
  Do NOT add if-conditions, NULL checks, early returns, or any other guards
  before the call to the vulnerable function. Guards cause KLEE to take
  alternative paths and NEVER reach the vulnerability. Strip ALL guards.
  The driver already ensures inputs are valid — guards are unnecessary.

STEP 4 (Turn 5) — WRITE DRIVER + STUBS:
  WriteDriver (symbolic-first) + WriteStubs (symbolic returns).
  Define any missing macros LOCALLY — do NOT search for them:
    #ifndef SOME_BUFFER_SIZE
    #define SOME_BUFFER_SIZE 300
    #endif
  Include project headers for type definitions.

STEP 5 (Turn 6+) — COMPILE AND ITERATE:
  CompileSlice → fix errors → CompileSlice → KLEE → diagnose → fix → retry.
  
  BUDGET: You must have your FIRST KLEE run by turn 10.
  If you're still doing GrepSource/GatherCode/FindDefinition after turn 8,
  you are WASTING TURNS. Write code and compile — errors are faster to fix
  than researching every detail upfront.

PRAGMATIC RULES:
  - If a macro value is unknown, DEFINE IT LOCALLY with a reasonable guess.
    #define SOME_BUFFER_SIZE 300
    #define SOME_ERROR_OK 0
    #define SOME_STATE_EOF -1
    You can always fix the value later if KLEE shows wrong behavior.
  - If a struct is opaque, allocate a char[1024] and cast.
  - If GatherCode truncates a function, DON'T retry. Use the excerpt.
  - If you need a type definition, check vulnerability_summary first.
    Only use FindDefinition/GatherCode if the summary doesn't have it.
  - NEVER call GatherCode more than twice total.
  - NEVER call GrepSource more than 5 times total.
  - Compile errors are NORMAL. Fix them one at a time. Don't research — just fix.
  Using the gathered code, write a MINIMAL harness file with WriteHarness.
  The harness must contain ONLY the code needed to reach the vulnerability.
  A good harness is 100-300 lines. If yours is over 500 lines, you're doing it wrong.
  
  DO NOT copy entire functions verbatim. NEUTRALIZE them:
  
  For the ENTRY function:
    - Keep: function signature ONLY
    - Keep: the CALL to vul_func
    - After the call to vul_func: just "return 0;"
    - REMOVE EVERYTHING ELSE: NO NULL checks, NO error guards, NO if-conditions
    - DO NOT add "if (ptr == NULL) return" — this causes KLEE to skip the call!
    - The driver handles input validity. Entry function = pure pass-through.
    
    Example (neutralized entry — MANDATORY pattern):
    ```c
    int entry_func(ContextType *ctx, const char *data, int size, int flag) {
        vul_func(ctx, flag);
        return 0;
    }
    ```
  
  For the VUL function:
    - Keep: function signature, variable declarations
    - If there's a switch(): keep the switch header
    - ONLY the target case body — all other cases: just "break;"
    - Convert while(1)/for(;;) enclosing the switch to if(1)
    - Keep: goto labels that lead to the vulnerability
    - At the vulnerability site, add the UNIVERSAL SINK ASSERTION (see below)
    - REMOVE: all function calls not on the direct path
    
    UNIVERSAL SINK ASSERTION — add at the vulnerability line in EVERY harness:
    Place klee_assert AFTER the vulnerable statement (not before!).
    If the statement crashes → KLEE generates .ptr.err = BUG TRIGGERED (auto-TP).
    If statement doesn't crash → klee_assert fires = site reachable but no bug.
    
    ```c
    // The vulnerable statement itself (KLEE catches crashes natively):
    result = ptr[index];  // or memcpy, snprintf, etc.
    // AFTER — reachability probe (only fires if statement didn't crash):
    klee_assert(0 && "SAILOR_SINK_REACHED");
    ```
    
    DO NOT use klee_check_memory_access — it fails with symbolic pointers.
    KLEE's native .ptr.err/.div.err detection works with symbolic values.
    
    Example (neutralized switch):
    ```c
    if (1) {  // was while(1)
        switch (ctx->state) {
            case STATE_A: break;
            case STATE_B: break;
            // ... all other cases: just break;
            case TARGET_STATE:
                // KEEP ONLY THIS CASE BODY — the path to vulnerability
                ...original code for this case...
                break;
        }
    }
    ```

  DO NOT use ExtractFunction for spine functions — it creates 12,000+ line files
  with the entire file preamble. Use GatherCode + WriteHarness instead.
  ExtractFunction is ONLY for small helper functions from other files.

STEP 4 — WRITE DRIVER:
  WriteDriver with symbolic input setup:
  - Allocate context structs using real types from preamble
  - Make input data symbolic (klee_make_symbolic on LOCAL variable, then assign)
  - Set switch variable to target case (symbolic + klee_assume)
  - Call the entry function

STEP 5 — COMPILE AND RUN:
  CompileSlice() → compiles + runs KLEE
  React to diagnostics:
  - Compile errors → ReplaceCode or rewrite
  - KLEE: "X NOT REACHED" → fix stubs/driver
  - KLEE: sink_reached=True → Done(verdict='TP')
  - KLEE: crashes in target function → Done(verdict='TP')

COMPILATION:
- Each .c in harness/ is compiled SEPARATELY to .bc, then linked
- harness file and driver.c are separate translation units
- Smart stubs are AUTO-GENERATED for undefined external functions
- Include project headers for real type definitions
- harness_types.h is auto-injected into driver.c/stubs.c for struct definitions.
  If harness_types.h causes compilation issues (e.g., missing xmlversion.h or
  header chain errors), you may opt out by adding `// NO_HARNESS_TYPES` as the
  first line of driver.c or stubs.c. Define the needed types manually in that
  file instead.

STUB GUIDELINES — SYMBOLIC, NOT HARDCODED:
  Stub functions that control the path to the vulnerability must return SYMBOLIC values,
  not hardcoded constants. KLEE needs freedom to find the triggering value.
  
  BAD (hardcoded — KLEE has no freedom):
    int some_check_func(...) { return -300; }
  
  GOOD (symbolic — KLEE finds the right value):
    int some_check_func(const char *data, int len, int flag) {
        int ret;
        klee_make_symbolic(&ret, sizeof(ret), "check_ret");
        klee_assume(ret < 0);  // constrain only if needed for path direction
        return ret;
    }
  
  This lets KLEE choose the exact value that triggers the vulnerability path
  (e.g., a negative return that causes a pointer offset to go out of bounds).
  
  RULE: If the vulnerability depends on a stub's return value (e.g., it controls
  a pointer offset, array index, or branch condition near the sink), make it SYMBOLIC.
  Only hardcode returns for stubs that just need to "not crash" (e.g., init/setup helpers).

DRIVER PHILOSOPHY — OVERAPPROXIMATE FIRST:
  Start with EVERYTHING symbolic. Add klee_assume constraints ONLY where needed
  to pass guards. This gives KLEE maximum freedom to find the vulnerability.
  
  WRONG approach (concrete-first — misses bugs):
    ctx->error_code = 0;          // hardcoded
    ctx->state = 7;               // hardcoded
    int size = 300;               // hardcoded
    some_check_func() { return -300; }  // hardcoded
  
  RIGHT approach (symbolic-first — KLEE finds the bug):
    // Make ALL struct fields symbolic
    klee_make_symbolic(ctx, sizeof(*ctx), "ctx");
    
    // Constrain ONLY what's needed to pass guards
    klee_assume(ctx->error_code == 0);       // pass error guard
    klee_assume(ctx->flags != DISABLED);     // pass flag guard
    klee_assume(ctx->state == TARGET_STATE); // target case
    
    // Re-set pointer fields (symbolic overwrote them — pointers must be valid)
    ctx->input = calloc(1, sizeof(*ctx->input));
    klee_make_symbolic(ctx->input, sizeof(*ctx->input), "input");
    
    // Buffer: allocate real memory, make content symbolic
    char *buf = malloc(512);
    klee_make_symbolic(buf, 512, "buffer");
    ctx->input->base = buf;
    ctx->input->cur = buf;        // or buf + symbolic_offset
    ctx->input->end = buf + 512;  // MUST be set!
    
    // Stubs: return SYMBOLIC values
    int some_check_func(...) {
        int ret; klee_make_symbolic(&ret, sizeof(ret), "check_ret");
        return ret;  // KLEE explores all return values
    }

  PATTERN: symbolic struct → klee_assume for guards → concrete pointers → symbolic buffers

DRIVER CHECKLIST:
  Before CompileSlice, verify:
  ✓ All guard fields symbolic with klee_assume (error codes, flags, state, etc.)
  ✓ Switch variable constrained to target case
  ✓ Pointer fields are real allocations (not symbolic garbage)
  ✓ End/limit pointers are SET (= buffer + size). If NULL → bounds checks fail → early exit
  ✓ base, cur, end all point into the SAME buffer allocation
  ✓ Buffer content is symbolic (klee_make_symbolic on the buffer bytes)
  ✓ Stubs on the path return SYMBOLIC values, not hardcoded constants

=== CWE-416/415 USE-AFTER-FREE & DOUBLE-FREE (WMI patterns) ===

  UAF vulnerabilities require a DIFFERENT driver strategy than OOB bugs:
  The driver must create a TWO-PHASE lifecycle: allocate → free → use.
  
  HARNESS STRATEGY for CWE-416 (UAF):
  The vul_func should contain BOTH the free AND the subsequent use of the pointer.
  If free and use are in different functions, the harness must keep both on the path.
  
  DRIVER PATTERN for CWE-416:
    1. Allocate the target struct concretely
    2. Set up fields so the free-path is reachable
    3. Call the entry function (which should free the object internally)
    4. The vul_func then dereferences the freed pointer → KLEE detects .free.err
  
  Example driver for UAF:
  ```c
  int main() {
      // Allocate container that holds the target pointer
      Container *ctx = calloc(1, sizeof(Container));
      Target *target = calloc(1, sizeof(Target));
      klee_make_symbolic(target, sizeof(Target), "target");
      ctx->target_ptr = target;  // back-pointer that becomes stale
      
      // Set fields to reach the free path first, then the use path
      klee_make_symbolic(&ctx->state, sizeof(ctx->state), "state");
      
      // Call: entry_func will free target, then dereference target_ptr (UAF)
      entry_func(ctx);
      return 0;
  }
  ```
  
  CRITICAL FOR UAF — SLICING FIDELITY RULES:
  - The free() stub MUST actually call free() — not return symbolic
  - The NEUTRALIZED vul_func must keep BOTH the free AND the use
  - Do NOT remove the free() call during neutralization
  - The sink assertion goes AFTER the use-after-free dereference

  SLICING FIDELITY — DO NOT INJECT SYNTHETIC UAF:
  - NEVER insert volatile dereferences (e.g., `volatile unsigned char v = *ptr;`)
    after free() calls to "materialize" a UAF. If the real code does NOT
    dereference a freed pointer, that means the bug does NOT exist.
  - NEVER replace a sub-field free (e.g., `free(obj->buffer)`) with a
    whole-struct free (`free(obj)`) — this changes the UAF semantics.
  - NEVER add free() calls to stubs that don't exist in the real function.
  - The free AND the dereference must BOTH come from the REAL source code
    at the locations identified by the static analysis finding.
  - If the real code nullifies a pointer after freeing (e.g., `free(p); p = NULL;`),
    the harness MUST preserve that nullification — do NOT remove it.
  - If you cannot find a genuine free→use path in the real source code,
    report this in your analysis rather than synthesizing one. Not every
    static analysis finding is a real bug.

  HARNESS PATTERN for UAF:
  ```c
  void vul_func(Container *ctx) {
      Target *t = ctx->target_ptr;
      // Phase 1: Free happens here — MUST match real source
      free(t);  // or kfree(t) in kernel code
      // Phase 2: Dereference — MUST exist in real source code
      int val = t->field;  // UAF! t is freed — this line must be from real code
      klee_assert(0 && "SAILOR_SINK_REACHED");
  }
  ```

  KLEE DETECTION: KLEE natively detects UAF as .free.err when it sees a
  dereference of a freed pointer. This produces a test case automatically.
  
  WMI (Weird Machine Instruction) PATTERNS:
  WMI specs detect exploitation chain building blocks. They have rule IDs like
  "sailor/wmi-1-*" through "sailor/wmi-4-*" or tags containing "wmi".

  WMI-1 (Stale Reference): free(A) without nullifying B->ptr_to_A
    → Harness: Keep the free, keep the non-nullified back-pointer
    → Driver: Set up A and B with cross-reference, call free function
    → FIDELITY: The back-pointer dereference MUST exist in real code

  WMI-2 (Type Confusion Leak): Read field through stale pointer after realloc
    → Harness: free(old_obj), alloc(new_obj) at same address, read via stale ptr
    → Driver: malloc→free→malloc pattern to force reuse, then read
    → FIDELITY: The realloc and stale read MUST both exist in real code

  WMI-3 (Arbitrary Free): Traversal through stale pointer frees controlled address
    → Harness: Keep linked-list traversal + free loop
    → Driver: Set up fake linked list, trigger destructor

  WMI-4 (Write-What-Where): Reclaim freed memory, overwrite function pointer
    → Harness: free→reclaim→write pattern
    → Driver: alloc→free→alloc→write→call pattern

  WMI FIDELITY: All WMI patterns MUST reflect real code behavior. Do NOT
  inject synthetic dereferences, artificial free() calls, or volatile reads
  to materialize a pattern that doesn't exist in the original source.

STUB PHILOSOPHY — SAME PRINCIPLE:
  Stubs should OVERAPPROXIMATE the real function's behavior.
  Return symbolic values so KLEE explores all possible behaviors.
  Add klee_assume ONLY if unconstrained values cause infinite paths.
  
  // Good: KLEE explores all return values
  int some_check_func(...) {
      int ret; klee_make_symbolic(&ret, sizeof(ret), "ret");
      return ret;
  }
  
  // Also good: constrain when needed to avoid path explosion
  int some_size_func(void *obj) {
      int ret; klee_make_symbolic(&ret, sizeof(ret), "size_ret");
      klee_assume(ret >= 0 && ret < 10000);  // reasonable range
      return ret;
  }
  
  // Bad: hardcoded → KLEE has ONE path, can't find the bug
  int some_check_func(...) { return -300; }

BUG CLASSIFICATION — THREE CATEGORIES:
  When KLEE finds a crash (bug_found=True), classify it:

  A) HARNESS BUG (crash in driver.c / stubs.c / smart_stubs.c):
     YOUR code is broken. Fix immediately:
     → ExploreKleeOutput to see the .err file
     → Fix the driver (NULL struct, wrong allocation) or stubs (bad return)
     → CompileSlice to retry

  B) NON-TARGET REAL BUG (crash in spine source, but NOT at vulnerability line):
     This is a REAL bug — a surprise finding! It will be saved automatically
     for concrete validation. But it's not the target, so BYPASS it:
     → ExploreKleeOutput to understand the crash
     → Stub/neutralize the crashing statement with ReplaceCode
     → Or add a guard to skip past it
     → CompileSlice to retry — KLEE continues toward the real target
     All surprise findings are included in the final Done() report.

  C) TARGET BUG (crash at/near vulnerability line, ±15 lines):
     This IS the vulnerability. Save for concrete validation:
     → Done(verdict='TP') — include crash details

  NEVER call Done(TP) for category A or B crashes.
  ALWAYS call ExploreKleeOutput() for ANY crash to classify it.

CRITICAL — AFTER EVERY KLEE RUN:
  If bug_found=True:
    1. ALWAYS call ExploreKleeOutput() FIRST — read .err and .kquery files
    2. Check which FILE and LINE the crash is in
    3. Classify as A (harness), B (non-target real), or C (target)
    4. Follow the appropriate action for that category
  
  If 0 paths explored:
    Driver exits immediately. Fix struct allocation in WriteDriver.
  
  If BLOCKED (entry reached but vul func NOT REACHED):
    Entry function guards failing. Fix driver setup.

ANTI-PATTERNS:
- NEVER call Done(verdict='TP') when the crash is in driver.c or stubs.c
- NEVER call Done(verdict='TP') for a crash at a different line than the vulnerability
- NEVER skip ExploreKleeOutput when KLEE finds a bug
- Do NOT extract entire 12000-line files. Use GatherCode for specific functions.
- Do NOT make entire structs symbolic. Only specific fields.

CRITICAL — VULNERABLE STATEMENT MUST BE VERBATIM:
  When writing the harness, COPY the vulnerable statement EXACTLY from the original source
  (as shown in vulnerability_summary source_context). Do NOT simplify, rewrite, or abbreviate it.
  For example, if the original is:
    snprintf(buffer, 149, "Bytes: 0x%%02X 0x%%02X\\n", ctxt->input->cur[0], ctxt->input->cur[1]);
  then your harness MUST contain that EXACT line, not a simplified version like:
    snprintf(buffer, 149, "%%02X", cur[0], cur[1]);
  The line mapping system matches harness lines against the original source by text.
  Rewriting the vulnerable statement breaks this mapping and prevents bug detection.

RESPONSE FORMAT: {"thought": "...", "tool": "ToolName", "args": {...}}
"""

def _generate_baseline_driver(frozen, func_sigs, src_root) -> str:
    """Auto-generate a baseline driver.c from frozen plan data.
    
    Uses entry function signature and struct groom data to produce a driver
    with CONCRETE allocations and symbolic content. This avoids the common
    agent mistake of using symbolic values for malloc sizes.
    """
    entry = frozen.get("entry", "")
    vul_func = frozen.get("vul_func", "")
    if not entry:
        return ""
    
    groom = frozen.get("struct_groom", {})
    constants = groom.get("constants", {})
    
    # Get entry signature
    entry_sig = func_sigs.get(entry, "")
    
    # Parse parameters from signature
    params = []
    if entry_sig:
        m = re.search(rf'{re.escape(entry)}\s*\(([^)]*)\)', entry_sig)
        if m:
            param_str = m.group(1).strip()
            if param_str and param_str != "void":
                for p in param_str.split(','):
                    p = p.strip()
                    # Extract type and name: "const xmlChar *name" → ("const xmlChar *", "name")
                    tokens = p.rsplit(None, 1)
                    if len(tokens) == 2:
                        ptype, pname = tokens
                        # Handle pointer in name: "*name" → type="...*", name="name"
                        while pname.startswith('*'):
                            ptype += '*'
                            pname = pname[1:]
                        params.append((ptype.strip(), pname.strip()))
                    elif tokens:
                        params.append((tokens[0], f"arg{len(params)}"))
    
    lines = []
    lines.append("/* AUTO-GENERATED baseline driver — concrete sizes, symbolic content */")
    lines.append("#include <stdlib.h>")
    lines.append("#include <string.h>")
    lines.append("#include <klee/klee.h>")
    lines.append("")
    
    # Add project header includes from the harness source
    vul_file = frozen.get("vul_file", "")
    src_file = find_source_file(src_root, vul_file) if vul_file else None
    if src_file:
        for line in src_file.read_text(errors="replace").split('\n')[:30]:
            stripped = line.strip()
            if stripped.startswith('#include') and 'klee' not in stripped.lower():
                lines.append(stripped)
                break  # just one project include is enough
    
    lines.append("")
    
    # Forward declare entry
    if entry_sig:
        # Clean the signature for extern declaration
        clean_sig = re.sub(r'\bstatic\s+', '', entry_sig).strip()
        if not clean_sig.endswith(';'):
            clean_sig += ';'
        lines.append(f"extern {clean_sig}")
    
    lines.append("")
    lines.append("int main(void) {")
    lines.append("    /* All allocations use CONCRETE sizes */")
    lines.append("")
    
    # Generate parameter setup based on types
    call_args = []
    for ptype, pname in params:
        if '*' in ptype and ('char' in ptype.lower() or 'xmlchar' in ptype.lower() or 'byte' in ptype.lower()):
            # String/buffer parameter: allocate concrete, make symbolic
            lines.append(f"    /* {ptype} {pname} — symbolic string buffer */")
            lines.append(f"    char {pname}_buf[256];")
            lines.append(f"    klee_make_symbolic({pname}_buf, sizeof({pname}_buf), \"{pname}\");")
            lines.append(f"    {pname}_buf[255] = '\\0';")
            call_args.append(f"(void*){pname}_buf")
        elif '*' in ptype:
            # Pointer to struct: allocate concrete
            lines.append(f"    /* {ptype} {pname} — concrete struct allocation */")
            lines.append(f"    char {pname}_mem[4096];")
            lines.append(f"    memset({pname}_mem, 0, sizeof({pname}_mem));")
            lines.append(f"    klee_make_symbolic({pname}_mem, 512, \"{pname}\");")
            call_args.append(f"(void*){pname}_mem")
        elif 'int' in ptype.lower() or 'size' in ptype.lower() or 'len' in ptype.lower():
            # Integer parameter: symbolic with constraints
            lines.append(f"    /* {ptype} {pname} — symbolic integer */")
            lines.append(f"    int {pname}_val;")
            lines.append(f"    klee_make_symbolic(&{pname}_val, sizeof({pname}_val), \"{pname}\");")
            lines.append(f"    klee_assume({pname}_val > 0 && {pname}_val < 256);")
            call_args.append(f"{pname}_val")
        else:
            # Default: symbolic
            lines.append(f"    /* {ptype} {pname} */")
            lines.append(f"    {ptype} {pname}_val;")
            lines.append(f"    klee_make_symbolic(&{pname}_val, sizeof({pname}_val), \"{pname}\");")
            call_args.append(f"{pname}_val")
        lines.append("")
    
    # Call entry
    lines.append(f"    /* Call entry function */")
    lines.append(f"    {entry}({', '.join(call_args)});")
    lines.append("")
    lines.append("    return 0;")
    lines.append("}")
    
    return '\n'.join(lines)


def run_agent(ctx, frozen, tools, out_dir, max_turns, timeout, start_time, spec=None):
    spec = spec or {}
    history = []
    findings = []
    
    # --- GET FUNCTION SIGNATURES FOR AGENT ---
    func_sigs = {}
    src_file = find_source_file(tools.src_root, ctx['vul_file'])
    entry_preconditions = ""
    if src_file:
        src_text = src_file.read_text(errors="replace")
        for func in [frozen['entry'], frozen['vul_func']]:
            span = find_function_span(src_text, func)
            if span:
                sig = src_text[span[0]:span[1]].strip()
                sig = re.sub(r'\s+', ' ', sig).strip()
                func_sigs[func] = sig
        
        # --- EXTRACT ENTRY FUNCTION PRECONDITIONS ---
        # Read the first ~40 lines of the entry function to find early-return checks.
        # These tell the agent what fields the stub must initialize.
        entry_span = find_function_span(src_text, frozen['entry'])
        if entry_span:
            entry_body = src_text[entry_span[1]:entry_span[2]]
            # Get first 40 lines (the guard/precondition region)
            early_lines = entry_body.split('\n')[:40]
            # Find NULL checks, field comparisons, early returns
            guards = []
            for line in early_lines:
                stripped = line.strip()
                if not stripped or stripped.startswith(('/*', '//', '*', '#', '{', '}')): continue
                # Lines with NULL checks, field accesses, or returns
                if ('== NULL' in stripped or '!= NULL' in stripped or 
                    'return' in stripped or '-> ' in stripped.replace('->', '-> ') or
                    '->' in stripped):
                    guards.append(stripped)
            if guards:
                entry_preconditions = f"""
    ENTRY FUNCTION PRECONDITIONS ({frozen['entry']}):
    The entry function has these early checks before reaching the target.
    Your stub for context creation MUST satisfy these to avoid early returns:
"""
                for g in guards[:15]:
                    entry_preconditions += f"      {g}\n"
                entry_preconditions += """
    This means the stub must allocate a properly-sized struct and initialize
    fields that are checked (e.g., errNo=0, input=non-NULL, instate=valid).
    The stub should also allocate sub-structs (e.g., input->buf, input->cur)
    so pointer dereferences don't crash.
"""
    
    sig_hint = ""
    if func_sigs:
        sig_lines = "\n".join(f"    {name}: {sig}" for name, sig in func_sigs.items())
        sig_hint = f"\n    FUNCTION SIGNATURES (from source):\n{sig_lines}\n"
    
    sa_stubs = frozen.get("sa_stubs", [])
    stub_hint = ""
    if sa_stubs:
        stub_hint = f"\n    AUTO-STUBBED FUNCTIONS: {', '.join(sa_stubs[:20])}\n"
    
    # --- VULNERABILITY CONTEXT FROM SPEC ---
    vuln_context = ""
    spec_name = os.path.basename(ctx.get("spec_path", ""))
    # Extract CWE and pattern from spec filename (format: NNN_file_line_type_cwe-NNN-description.json)
    cwe_match = re.search(r'cwe-(\d+)', spec_name, re.IGNORECASE)
    if cwe_match:
        cwe_id = cwe_match.group(1)
        # Extract the pattern description after the CWE
        pattern_match = re.search(r'cwe-\d+-(.+)\.json$', spec_name, re.IGNORECASE)
        pattern_desc = pattern_match.group(1).replace('-', ' ') if pattern_match else ""
        vuln_context = f"\n    VULNERABILITY INFO:\n"
        vuln_context += f"    - CWE-{cwe_id}: "
        cwe_names = {"125": "Out-of-bounds Read", "787": "Out-of-bounds Write", "416": "Use After Free",
                     "119": "Buffer Overflow", "476": "NULL Pointer Dereference", "190": "Integer Overflow",
                     "122": "Heap Buffer Overflow", "121": "Stack Buffer Overflow", "415": "Double Free"}
        vuln_context += cwe_names.get(cwe_id, f"CWE-{cwe_id}") + "\n"
        if pattern_desc:
            vuln_context += f"    - Pattern: {pattern_desc}\n"
        vuln_context += f"    - The vulnerability is at {ctx['vul_file']}:{ctx['vul_line']} inside {frozen['vul_func']}\n"
        vuln_context += f"    - Use GrepSource(pattern='SAILOR_PROBE_SINK', file='parser.c') to find the exact sink location\n"
        vuln_context += f"    - Use GrepSource(pattern='goto encoding_error\\|goto oom\\|goto error', file='parser.c') to find paths to the sink\n"
    # Also extract from spec JSON keys
    for key in ["cwe", "cwe_id", "vulnerability_type", "description", "pattern"]:
        val = spec.get(key, "")
        if val and str(val) not in vuln_context:
            vuln_context += f"    - {key}: {val}\n"
    
    # --- STRUCT GROOM TEMPLATE ---
    struct_groom_hint = ""
    groom = frozen.get("struct_groom", {})
    if groom.get("init_template"):
        struct_groom_hint = f"\n    STRUCT INITIALIZATION TEMPLATE (auto-generated from spine analysis):\n"
        struct_groom_hint += groom["init_template"] + "\n"
        
        # Add important constants
        if groom.get("constants"):
            struct_groom_hint += "\n    IMPORTANT CONSTANTS (from source):\n"
            for k, v in sorted(groom["constants"].items()):
                struct_groom_hint += f"      {k} = {v}\n"
            struct_groom_hint += "      → Your symbolic buffer MUST be larger than the biggest constant above\n"
        
        # Add sub-struct summary
        if groom.get("sub_structs"):
            struct_groom_hint += "\n    SUB-STRUCTS THAT MUST BE ALLOCATED:\n"
            for var, subs in groom["sub_structs"].items():
                for sub, fields in subs.items():
                    struct_groom_hint += f"      {var}->{sub}: fields accessed: {', '.join(fields[:8])}\n"
    
    # --- SE CONFIG: Build analyst injection for agent context ---
    se_config_hint = ""
    se_cfg = frozen.get("se_config", {})
    if se_cfg and se_cfg.get("loaded_files"):
        se_parts = []
        
        # Verify mode: change the task framing
        if se_cfg.get("mode") == "verify":
            se_parts.append(
                "*** VERIFY MODE ***\n"
                "    An analyst has IDENTIFIED a specific bug and wants you to REPRODUCE it.\n"
                "    Your goal is to write a harness that triggers this EXACT vulnerability,\n"
                "    not discover new bugs. Focus on reproducing the analyst's scenario.")
        
        # Analyst notes (freeform — this is the most powerful injection)
        if se_cfg.get("analyst_notes"):
            notes = se_cfg["analyst_notes"].strip()
            # Truncate if extremely long but keep it generous
            if len(notes) > 4000:
                notes = notes[:4000] + "\n    ... (analyst notes truncated)"
            se_parts.append(f"*** ANALYST NOTES ***\n{notes}")
        
        # Crash output summary for context
        if se_cfg.get("crash_output"):
            crash = se_cfg["crash_output"]
            # Extract just the stack trace lines for compactness
            stack_lines = [l.strip() for l in crash.splitlines()
                           if l.strip().startswith("#") or "ERROR:" in l or "SUMMARY:" in l]
            if stack_lines:
                stack_str = "\n    ".join(stack_lines[:20])
                se_parts.append(f"*** CRASH STACK TRACE (from analyst) ***\n    {stack_str}")
        
        # Struct field values the analyst wants set
        if se_cfg.get("struct_field_values"):
            fields_str = "\n    ".join(f"{k} = {v}" for k, v in se_cfg["struct_field_values"].items())
            se_parts.append(
                f"*** REQUIRED STRUCT FIELD VALUES (from analyst) ***\n"
                f"    Set these concrete values in driver.c:\n    {fields_str}")
        
        # klee_assume constraints
        if se_cfg.get("klee_assumes"):
            assumes_str = "\n    ".join(f"klee_assume({a});" for a in se_cfg["klee_assumes"])
            se_parts.append(
                f"*** REQUIRED KLEE CONSTRAINTS (from analyst) ***\n"
                f"    Add these assumes to driver.c:\n    {assumes_str}")
        
        # Stub return policy overrides
        if se_cfg.get("stub_returns"):
            sr_str = "\n    ".join(f"{func}() → return {val}" for func, val in se_cfg["stub_returns"].items())
            se_parts.append(
                f"*** STUB RETURN OVERRIDES (from analyst) ***\n"
                f"    Use these return values in stubs:\n    {sr_str}")
        
        # PoC input available
        if se_cfg.get("poc_input_path"):
            se_parts.append(
                "*** PoC INPUT AVAILABLE ***\n"
                "    A proof-of-concept input binary is at harness/poc_input.bin.\n"
                "    You can read it in driver.c to use as concrete phase-1 input.")
        
        if se_parts:
            se_config_hint = "\n    ANALYST CONFIGURATION (se_config/):\n    " + "\n\n    ".join(se_parts) + "\n"
    
    # --- Build seed file note for the agent ---
    seed_file_note = ""
    if se_cfg.get("seed_driver"):
        seed_file_note += "\n    NOTE: An analyst-provided driver.c is pre-loaded in harness/. "
        seed_file_note += "Review it before making changes — it contains domain-specific knowledge.\n"
    if se_cfg.get("seed_stubs"):
        seed_file_note += "    NOTE: Analyst-provided stubs.c is pre-loaded. It may contain critical stub implementations.\n"
    if se_cfg.get("seed_harness"):
        seed_file_note += "    NOTE: Analyst-provided parser.c is pre-loaded (replaces ExtractFunction output).\n"
    
    msg = f"""
    CONTEXT:
    - Target: {ctx['vul_file']}:{ctx['vul_line']}
    - Vulnerable Function: {frozen['vul_func']}
    - Entry Point: {frozen['entry']}
    - Spine: {' -> '.join(frozen['spine'])}
    {sig_hint}{stub_hint}{entry_preconditions}{struct_groom_hint}{vuln_context}{se_config_hint}
    COMPILATION MODEL:
    - ExtractFunction creates harness/parser.c with the FULL preamble from the original source
      (all #includes, #defines, structs, typedefs). It compiles standalone — do NOT include it.
    - IMPORTANT: Line numbers in harness/parser.c differ from the original file due to preamble
      insertion and probe sanitization. ExtractFunction reports the mapping. Use GrepSource to
      find specific code patterns instead of relying on original line numbers.
    - driver.c compiles separately. Include the project header for real types (e.g., #include <project/header.h>).
      If compilation fails due to missing macros, add the project guard macro before the include (check spine preamble).
    - All .bc files are linked via llvm-link. Undefined symbols are auto-stubbed.
    
    TASK: Write a KLEE driver (driver.c) that calls {frozen['entry']} to reach {frozen['vul_func']}.
    
    SA CONTEXT: The vulnerability summary (shown automatically on ReadSAContext()) contains:
    - Source code around the vulnerability site (±20 lines)
    - The goto labels that reach the vulnerability and WHERE each goto is triggered from
    - Which switch case encloses the vulnerability (set ctxt->instate to this value!)
    - Key function calls on the path that need stubbing
    - Struct definitions for driver allocation (project-specific context structs from vulnerability_summary)
    - driver_hint: exactly what to set in driver.c
    
    READ THIS FIRST. It has everything you need to write driver.c and stubs.c on Turn 1.
    Do NOT spend turns on ReadSource/GrepSource/FindDefinition to understand the vulnerability —
    the summary already contains that information.
    {seed_file_note}"""
    history.append({"role": "user", "content": msg})
    
    # --- AUTO-GENERATE BASELINE DRIVER ---
    # The LLM consistently fails at driver writing (uses symbolic malloc sizes).
    # Generate a correct baseline driver from frozen plan data BEFORE the agent starts.
    # The agent can then modify it if needed.
    # Skip if analyst already provided a seed driver
    driver_path = tools.harness_dir / "driver.c"
    if not driver_path.exists():
        try:
            auto_driver = _generate_baseline_driver(frozen, func_sigs, tools.src_root)
            if auto_driver:
                driver_path.write_text(auto_driver, encoding="utf-8")
                print(f"  [i] Auto-generated baseline driver.c ({len(auto_driver)} chars)")
                history[0]["content"] += (
                    "\n\nNOTE: A baseline driver.c has been auto-generated for you. "
                    "It uses CONCRETE allocations and satisfies known guards. "
                    "You may need to adjust field values, but DO NOT replace it with symbolic malloc sizes. "
                    "All malloc/calloc sizes MUST be concrete numbers."
                )
        except Exception as e:
            print(f"  [!] Auto-driver generation failed: {e}")
    
    persistent_notes = []  # Track key discoveries so agent doesn't re-discover after trimming
    
    def _add_note(note):
        """Add a persistent note if not already recorded."""
        # Keep notes compact — max 30 notes, 150 chars each
        short = note[:150]
        for existing in persistent_notes:
            if short[:60] in existing or existing[:60] in short:
                return  # Similar note already exists
        if len(persistent_notes) >= 30:
            persistent_notes.pop(0)  # Drop oldest
        persistent_notes.append(short)
    
    def _auto_capture_notes(tool_name, tool_args, result_str):
        """Automatically extract key facts from tool results into persistent notes."""
        res = str(result_str)
        
        # Capture vulnerability site location from ExtractFunction / resolve_vul_line
        if "VULNERABILITY SITE" in res or "SAILOR_PROBE_SINK" in res:
            for line in res.split('\n'):
                if "VULNERABILITY SITE" in line or "SAILOR_PROBE_SINK" in line:
                    _add_note(f"VULN SITE: {line.strip()}")
                    break
        
        # Capture struct definitions from FindDefinition
        if tool_name == "FindDefinition" and "Found '" in res:
            sym = tool_args.get("symbol", "")
            # Extract first 2 meaningful lines
            lines = [l for l in res.split('\n') if l.strip() and not l.startswith("Found")][:3]
            _add_note(f"STRUCT DEF {sym}: {'; '.join(l.strip() for l in lines)}")
        
        # Capture function locations from GrepSource
        if tool_name == "GrepSource":
            pattern = tool_args.get("pattern", "")
            matches = [l for l in res.split('\n') if ':' in l and l[0].isdigit()]
            if matches and len(matches) <= 5:
                locs = ", ".join(m.split(':')[0] for m in matches[:3])
                _add_note(f"GREP '{pattern}': lines {locs}")
        
        # Capture KLEE results
        if "KLEE Finished" in res:
            for line in res.split('\n'):
                if "KLEE Finished" in line or "SINK" in line or "LOW COVERAGE" in line:
                    _add_note(f"KLEE: {line.strip()}")
        
        # Capture successful compilation
        if tool_name == "CompileSlice" and "KLEE Finished" in res:
            _add_note("COMPILATION SUCCEEDED with current driver.c/stubs.c/parser.c")
    
    history_keep = int(os.environ.get("LLM_HISTORY_KEEP", "16"))
    harness_dir = tools.harness_dir

    for turn in range(max_turns):
        if time.time() - start_time > timeout: break

        # Trim old history to prevent context window overflow
        # Keep: init message + persistent notes + last history_keep messages
        if len(history) > history_keep + 4:
            notes_msg = ""
            if persistent_notes:
                notes_msg = "\n[PERSISTENT NOTES from earlier turns — DO NOT re-discover these]:\n" + "\n".join(f"  {i+1}. {n}" for i, n in enumerate(persistent_notes))
            trimmed = history[:1]
            if notes_msg:
                trimmed.append({"role": "user", "content": notes_msg})
            trimmed.append({"role": "user", "content": f"[... {(len(history)-history_keep-1)//2} earlier turns trimmed ...]"})
            trimmed.extend(history[-history_keep:])
        else:
            trimmed = history
        
        resp = call_llm(SYSTEM_PROMPT, trimmed, out_dir, f"turn_{turn}")
        if "error" in resp and "tool" not in resp:
            print(f"  [!] LLM Error: {resp['error']}")
            history.append({"role": "user", "content": "SYSTEM: Output MUST be valid JSON."})
            continue
            
        tool, args = resp.get("tool", ""), resp.get("args", {})
        thought = resp.get("thought", "")
        if thought:
             print(f"  [Turn {turn+1}] Thought: {thought}")
        print(f"  [Turn {turn+1}] Tool: {tool}")
        
        # --- HARD ENFORCEMENT: Tool usage limits ---
        if not hasattr(tools, '_tool_counts'):
            tools._tool_counts = {}
        tools._tool_counts[tool] = tools._tool_counts.get(tool, 0) + 1
        
        TOOL_LIMITS = {
            "GrepSource": 5,
            "GatherCode": 2,
            "FindDefinition": 3,
            "ReadSAContext": 2,
            "ReadSource": 4,
            "SmartRecon": 2,
            "ExploreKleeOutput": 8,
        }
        
        # --- Consecutive same-tool loop detector ---
        if not hasattr(tools, '_last_tools'):
            tools._last_tools = []
        tools._last_tools.append(tool)
        if len(tools._last_tools) > 5:
            tools._last_tools = tools._last_tools[-5:]
        consecutive_same = 0
        for t in reversed(tools._last_tools):
            if t == tool:
                consecutive_same += 1
            else:
                break
        if consecutive_same >= 3 and tool not in ("CompileSlice", "WriteHarness", "WriteDriver", "WriteStubs", "ReplaceCode"):
            print(f"  [System] LOOP DETECTED: {tool} called {consecutive_same}x consecutively")
            history.append({"role": "user", "content": 
                f"SYSTEM: You have called {tool} {consecutive_same} times in a row — this is a loop. "
                f"STOP calling {tool}. Fix with WriteHarness/WriteDriver/WriteStubs/ReplaceCode, "
                f'then CompileSlice. For struct definitions, use #include "harness_types.h".'})
            continue
        
        if tool in TOOL_LIMITS and tools._tool_counts[tool] > TOOL_LIMITS[tool]:
            limit = TOOL_LIMITS[tool]
            print(f"  [System] BLOCKED: {tool} called {tools._tool_counts[tool]} times (limit: {limit})")
            history.append({"role": "user", "content": 
                f"SYSTEM: {tool} limit reached ({limit} calls). STOP RESEARCHING. "
                f"You have enough information. Write your harness NOW with WriteHarness, "
                f"then WriteDriver, then CompileSlice. If a macro/struct is unknown, "
                f"define it locally. Do NOT call {tool} again."})
            continue
        
        # --- HARD ENFORCEMENT: Turn-based nudges ---
        has_compiled = tools.iteration > 0
        has_harness = (tools.harness_dir / os.path.basename(tools.frozen.get("vul_file", "harness.c"))).exists()
        research_tools = {"GrepSource", "GatherCode", "FindDefinition", "ReadSAContext", "ReadSource", "SmartRecon"}
        
        if turn >= 5 and not has_harness and tool in research_tools:
            print(f"  [System] NUDGE: Turn {turn+1}, no harness yet — write code now")
            history.append({"role": "user", "content": 
                f"SYSTEM WARNING: Turn {turn+1}. No harness written! "
                f"You have enough information from ReadSAContext and GatherCode. "
                f"Call WriteHarness NOW. Define unknown structs/macros locally: "
                f"struct _xmlDict {{ int seed; int size; void *table; void *subdict; int limit; }}; "
                f"#define XML_HIDDEN  /* empty */. "
                f"Compile errors are FASTER to fix than researching."})
        
        if turn >= 8 and not has_harness and tool in research_tools:
            print(f"  [System] FORCE: Turn {turn+1}, no harness — blocking research")
            history.append({"role": "user", "content": 
                f"SYSTEM: Turn {turn+1}. Research BLOCKED. "
                f"Call WriteHarness NOW with what you know. "
                f"For any missing struct: use typedef struct {{ int field1; void *field2; }} TypeName; "
                f"For any missing macro: #define MACRO_NAME /* empty */. "
                f"Do NOT call {tool} again."})
            continue
        
        if turn >= 12 and not has_compiled and tool in research_tools:
            print(f"  [System] FORCE: Turn {turn+1}, no compile yet — blocking research")
            history.append({"role": "user", "content": 
                f"SYSTEM: Turn {turn+1}. You MUST compile now. "
                f"Call WriteHarness (if not done) then WriteDriver then CompileSlice. "
                f"Research time is OVER. Do NOT call {tool}."})
            continue

        # Enforce Logic Checks
        if tool == "Done" and tools.iteration == 0:
            print("  [System] Blocking early Done().")
            history.append({"role": "user", "content": "SYSTEM: You cannot call Done() before running KLEE (CompileSlice)."})
            continue

        try:
            if tool == "SmartRecon": res = tools.smart_recon(args.get("target_func"))
            elif tool == "FindDefinition": res = tools.find_definition(args.get("symbol"))
            elif tool == "GrepSource": res = tools.grep_source(args.get("pattern", ""), args.get("file", ""))
            elif tool == "ReadSAContext": res = tools.read_sa_context(args.get("file", ""))
            elif tool == "ReadSource":
                sl = args.get("start_line") or args.get("start", 1)
                el = args.get("end_line") or args.get("end", 50)
                res = tools.read_source(args.get("file", ""), int(sl), int(el))
            elif tool == "WriteDriver": res = tools.write_driver(args.get("code"))
            elif tool == "WriteTypes": res = tools.write_types(args.get("code"))
            elif tool == "WriteStubs": res = tools.write_stubs(args.get("code"))
            elif tool == "ExtractFunction": res = tools.extract_function(args.get("file"), args.get("func"))
            elif tool == "GatherCode": res = tools.gather_code(args.get("functions", ""), args.get("types", ""))
            elif tool == "WriteHarness": res = tools.write_harness(args.get("code"))
            elif tool == "CompileSlice":
                r = tools.compile_slice()
                if r["success"]:
                    # Record that compilation succeeded
                    driver_path = tools.harness_dir / "driver.c"
                    if driver_path.exists():
                        driver_code = driver_path.read_text(errors="replace")
                        includes = [l.strip() for l in driver_code.split('\n')[:15] if l.strip().startswith(('#include', '#define'))]
                        if includes:
                            note = f"- Compilation SUCCEEDED with driver.c includes: {'; '.join(includes)}"
                            _add_note(note)
                    
                    stats = r["klee_stats"]
                    out_dir = Path(stats.get("out_dir", ""))
                    
                    # --- AUTO-TERMINATE: bug_triggered → immediate Done(TP) ---
                    # bug_triggered = KLEE crash (.ptr.err/.div.err) at the vulnerability site
                    # This means the actual vulnerable statement crashed — send to concrete validation.
                    # site_reached alone (klee_assert fired) does NOT auto-terminate — it just
                    # means the site is reachable, not that the bug was triggered.
                    # HOWEVER: if sink_reached=True, the vulnerable code path IS feasible.
                    # Auto-terminate as LIKELY_TP to avoid wasting turns.
                    if stats.get("bug_triggered"):
                        print(f"  [BUG] {stats.get('bug_triggered_details', '')}")
                        
                        # Always rebuild line map before validation
                        try:
                            tools.build_line_map()
                        except Exception:
                            pass
                        
                        # Show line mapping immediately (before ASan which may fail)
                        crash_file = os.path.basename(stats.get('error_file', ''))
                        crash_line = int(stats.get('error_line', 0))
                        orig = tools.lookup_original_line(crash_file, crash_line)
                        if orig:
                            print(f"  [MAP] harness {crash_file}:{crash_line} → {orig['orig_file']}:{orig['orig_line']}")
                            print(f"  [MAP] Code: {orig['code'][:120]}")
                        else:
                            print(f"  [MAP] No mapping for {crash_file}:{crash_line}")
                        
                        # --- SLICING ARTIFACT CHECK (pre-concrete) ---
                        # Scan sliced code for synthetic UAF patterns BEFORE
                        # spending time on concrete validation. Runs for ALL specs
                        # since the patterns (volatile injection, synthetic comments,
                        # reproducer malloc→free→call) are UAF-specific and won't
                        # false-positive on OOB/NULL-deref specs.
                        _artifact_detected = False
                        _artifact_evidence = []
                        if True:  # check all specs — patterns are UAF-specific
                            _all_src = ""
                            _repro_src = ""
                            for _hf in harness_dir.glob("*.c"):
                                _txt = _hf.read_text(errors='replace')
                                _all_src += _txt + "\n"
                                if _hf.name == "driver.c":
                                    _repro_src = _txt
                            # Check 1: volatile injection after free
                            _vlines = _all_src.split('\n')
                            _saw_free = False; _free_ln = -1
                            for _vi, _vl in enumerate(_vlines):
                                _vs = _vl.strip()
                                if re.search(r'\bfree\s*\(', _vs) and not _vs.startswith('//'):
                                    _saw_free = True; _free_ln = _vi
                                if _saw_free and _vi - _free_ln <= 5:
                                    if re.search(r'\bvolatile\b.*=.*(\*.*\(|->)', _vs) or \
                                       re.search(r'\bvolatile\s+(unsigned\s+)?char\s+\w+\s*=\s*\*', _vs):
                                        _artifact_evidence.append(f"VOLATILE_INJECTION: line {_vi+1}: {_vs[:80]}")
                                if _saw_free and _vi - _free_ln > 10:
                                    _saw_free = False
                            # Check 2: synthetic comments
                            for _pat, _desc in [
                                (r'Phase\s*2.*stale|stale.*dereference', "Phase 2/stale deref"),
                                (r'materialize.*UAF|UAF.*materialize', "materialize UAF"),
                                (r'surface\s+UAF|UAF.*surface', "surface UAF"),
                                (r'UAF\s*read\s*if\s*freed', "UAF read if freed"),
                                (r'Simulate\s+UAF', "Simulate UAF"),
                                (r'immediate\s+stale\s+dereference', "stale deref"),
                            ]:
                                if re.search(_pat, _all_src, re.IGNORECASE):
                                    _artifact_evidence.append(f"SYNTHETIC_COMMENT: {_desc}")
                            # Check 3: reproducer synthetic malloc→free→call
                            if _repro_src:
                                _rlines = _repro_src.split('\n')
                                _aliases = {}
                                for _rl in _rlines:
                                    _rm = re.search(r'(\w+)\s*=\s*\(?(\w+)\)?;', _rl.strip())
                                    if _rm:
                                        _lhs, _rhs = _rm.group(1), _rm.group(2)
                                        if _rhs not in ('malloc', 'calloc', 'realloc', 'NULL', '0', 'sizeof'):
                                            _aliases.setdefault(_rhs, set()).add(_lhs)
                                            _aliases.setdefault(_lhs, set()).add(_rhs)
                                for _ri, _rl in enumerate(_rlines):
                                    _rs = _rl.strip()
                                    if re.search(r'(stale|dangling|UAF setup|alias retained)', _rs, re.IGNORECASE):
                                        _artifact_evidence.append(f"REPRODUCER_SYNTHETIC: UAF setup comment: {_rs[:60]}")
                                    if not re.search(r'\bfree\s*\(', _rs) or _rs.startswith('//'):
                                        continue
                                    _fm = re.search(r'\bfree\s*\(\s*(?:\(void\s*\*\)\s*)?(\w+)\s*\)', _rs)
                                    if not _fm:
                                        continue
                                    _fvar = _fm.group(1)
                                    _fnames = {_fvar}
                                    if _fvar in _aliases:
                                        _fnames.update(_aliases[_fvar])
                                    for _fa in list(_fnames):
                                        if _fa in _aliases:
                                            _fnames.update(_aliases[_fa])
                                    for _rj in range(_ri + 1, min(_ri + 30, len(_rlines))):
                                        if _rlines[_rj].strip().startswith('//'):
                                            continue
                                        for _fn in _fnames:
                                            if re.search(rf'\b{re.escape(_fn)}\b', _rlines[_rj]) and 'free' not in _rlines[_rj]:
                                                _artifact_evidence.append(f"REPRODUCER_SYNTHETIC: free({_fvar}), alias '{_fn}' used at line {_rj+1}")
                                                break
                                        else:
                                            continue
                                        break
                            _artifact_detected = len(_artifact_evidence) > 0
                            if _artifact_detected:
                                print(f"  [ARTIFACT] *** SLICING ARTIFACT DETECTED — skipping concrete validation ***")
                                for _ev in _artifact_evidence[:5]:
                                    print(f"  [ARTIFACT]   {_ev}")

                        if _artifact_detected:
                            # Skip concrete validation entirely — mark as artifact
                            verdict = "SLICING_ARTIFACT"
                            details = f"BUG TRIGGERED — {stats.get('bug_triggered_details', '')}\n"
                            details += f"Crash: {stats.get('diagnosis', 'none')}\n"
                            if orig:
                                details += f"Original: {orig['orig_file']}:{orig['orig_line']} → {orig['code'][:100]}\n"
                            details += f"SLICING ARTIFACT: {'; '.join(_artifact_evidence[:3])}\n"
                            details += "Concrete validation SKIPPED (synthetic UAF in sliced code).\n"
                            findings.append((verdict, details))
                            print(f"  [AUTO-DONE] verdict=SLICING_ARTIFACT")
                            break

                        # --- CONCRETE VALIDATION ---
                        cv_result = {}
                        try:
                            cv_result = tools.concrete_validate(stats.get("out_dir", ""))
                        except Exception as e:
                            print(f"  [!] Concrete validation error: {e}")
                            import traceback
                            traceback.print_exc()
                            cv_result = {"validated": False, "error": str(e)}

                        asan_confirmed = False
                        if isinstance(cv_result, dict):
                            asan_confirmed = cv_result.get("asan_result", {}).get("triggered", False) if "asan_result" in cv_result else cv_result.get("summary", {}).get("asan_confirmed", False)

                        verdict = "TP" if asan_confirmed else "LIKELY_TP"

                        details = f"BUG TRIGGERED — {stats.get('bug_triggered_details', '')}\n"
                        details += f"Crash: {stats.get('diagnosis', 'none')}\n"

                        # Line mapping info
                        if orig:
                            details += f"Original: {orig['orig_file']}:{orig['orig_line']} → {orig['code'][:100]}\n"

                        # ASan status
                        if asan_confirmed:
                            ar = cv_result.get("asan_result", {})
                            details += f"ASan CONFIRMED: {ar.get('error_type', '')} in {ar.get('crash_function', '')} at {ar.get('crash_file', '')}:{ar.get('crash_line', '')}\n"
                        else:
                            details += f"ASan: not confirmed"
                            if isinstance(cv_result, dict) and cv_result.get("error"):
                                details += f" ({cv_result['error'][:100]})"
                            details += "\n"

                        # All crashes from bug report
                        if isinstance(cv_result, dict):
                            all_crashes = cv_result.get("all_crashes", [])
                            if all_crashes:
                                details += f"\nAll crashes ({len(all_crashes)}):\n"
                                for cr in all_crashes:
                                    orig_info = f" → {cr['original_file']}:{cr['original_line']}" if cr.get('original_line') else ""
                                    details += f"  {cr['error_type']} at {cr['harness_file']}:{cr['harness_line']}{orig_info}\n"

                        # Surprise findings
                        surprise = getattr(tools, '_surprise_findings', [])
                        if surprise:
                            details += f"\n[SURPRISE FINDINGS] {len(surprise)} additional bugs:\n"
                            for i, sf in enumerate(surprise):
                                details += f"  #{i+1}: {sf['type']} at {sf['file']}:{sf['line']}\n"

                        findings.append((verdict, details))
                        print(f"  [AUTO-DONE] verdict={verdict}, asan={asan_confirmed}")
                        break
                    
                    elif stats.get("site_reached"):
                        # Sink reached = vulnerable code path IS feasible.
                        # Give the agent a FEW more turns to adjust driver/stubs to trigger
                        # the actual crash. If it can't within the budget, auto-terminate as LIKELY_TP.
                        if not hasattr(tools, '_sink_reached_turn'):
                            tools._sink_reached_turn = turn
                            tools._sink_reached_klee_dir = stats.get("out_dir", "")
                            print(f"  [SINK REACHED] Vulnerability reachable but no crash — giving agent {min(15, max_turns - turn)} more turns to trigger OOB")
                            # Fall through to let agent see the CWE-specific guidance below
                        else:
                            # Agent already had extra turns since first sink_reached
                            turns_since_sink = turn - tools._sink_reached_turn
                            if turns_since_sink >= 15:
                                # Budget exhausted — auto-terminate as LIKELY_TP
                                print(f"  [SINK REACHED] {turns_since_sink} turns since sink reached — auto-terminating")
                                
                                try:
                                    tools.build_line_map()
                                except Exception:
                                    pass
                                
                                # Validate with the BEST ktest we have (from first sink_reached run)
                                best_klee_dir = tools._sink_reached_klee_dir or stats.get("out_dir", "")
                                cv_result = {}
                                try:
                                    cv_result = tools.concrete_validate(best_klee_dir)
                                except Exception as e:
                                    print(f"  [!] Concrete validation error: {e}")
                                    cv_result = {"validated": False, "error": str(e)}
                                
                                asan_confirmed = False
                                if isinstance(cv_result, dict):
                                    asan_confirmed = cv_result.get("asan_result", {}).get("triggered", False) if "asan_result" in cv_result else cv_result.get("summary", {}).get("asan_confirmed", False)
                                
                                verdict = "TP" if asan_confirmed else "LIKELY_TP"
                                details = f"SINK REACHED — vulnerable code path confirmed feasible\n"
                                details += f"Agent had {turns_since_sink} extra turns but could not trigger actual crash.\n"
                                if asan_confirmed:
                                    ar = cv_result.get("asan_result", {})
                                    details += f"ASan CONFIRMED: {ar.get('error_type', '')} at {ar.get('crash_file', '')}:{ar.get('crash_line', '')}\n"
                                
                                findings.append((verdict, details))
                                print(f"  [AUTO-DONE] verdict={verdict}, asan={asan_confirmed}")
                                break
                    
                    res_parts = [f"KLEE Finished. Paths: {stats.get('completed_paths', 0)}, Tests: {stats.get('generated_tests', 0)}, Errors: {stats.get('total_errors', 0)}, Time: {stats.get('elapsed', 0):.1f}s"]
                    
                    # --- SAILOR PROBE RESULTS ---
                    probe_hits = stats.get("probe_hits", {})
                    if stats.get("bug_triggered"):
                        res_parts.append(f"*** BUG TRIGGERED! {stats.get('bug_triggered_details', '')} ***")
                        res_parts.append("The vulnerable statement CRASHED. Send to concrete validation.")
                    elif stats.get("site_reached"):
                        res_parts.append("SITE REACHED (klee_assert fired) but the vulnerable statement did NOT crash.")
                        
                        # CWE-specific guidance for triggering the actual bug
                        spec_name = os.path.basename(ctx.get("spec_path", ""))
                        cwe_m = re.search(r'cwe-(\d+)', spec_name, re.IGNORECASE)
                        cwe_id = cwe_m.group(1) if cwe_m else ""
                        
                        if cwe_id in ("125", "787", "119", "122", "121"):
                            # OOB read/write
                            res_parts.append(
                                "CWE-125/787 TRIGGER: The buffer access was in-bounds. To trigger OOB:\n"
                                "  - Allocate the TARGET buffer SMALL (e.g., 4-8 bytes)\n"
                                "  - Make the LENGTH/INDEX parameter symbolic and LARGER than the buffer\n"
                                "  - Example: char buf[4]; klee_assume(len > 4 && len < 256);\n"
                                "  - The key is: buffer_size < access_length")
                        elif cwe_id == "416":
                            res_parts.append(
                                "CWE-416 TRIGGER: Use-after-free. The driver must create a TWO-PHASE lifecycle:\n"
                                "  1. Allocate the target object concretely (calloc, not symbolic)\n"
                                "  2. Set up struct fields so the FREE path is reachable\n"
                                "  3. The free() stub MUST actually call free() — not return symbolic\n"
                                "  4. After free, the vul_func dereferences the freed pointer → .free.err\n"
                                "  CRITICAL: Do NOT remove the free() call during neutralization.\n"
                                "  The harness must keep BOTH the free AND the subsequent dereference.\n"
                                "  KLEE detects UAF natively as .free.err when it dereferences freed memory.\n"
                                "  If the free and use are in DIFFERENT functions, keep both in the harness.\n"
                                "  WMI pattern: If this is a stale-reference bug (WMI-1), ensure the\n"
                                "  back-pointer (e.g., trigger->owner) is NOT nullified after free.\n"
                                "  SLICING FIDELITY: Both the free() and the dereference MUST come from\n"
                                "  the REAL source code. Do NOT inject synthetic volatile reads, stub\n"
                                "  dereferences, or fake free() calls. Do NOT replace sub-field frees\n"
                                "  (e.g., free(obj->buf)) with whole-struct frees (free(obj)). If the\n"
                                "  real code nullifies the pointer after free, preserve that nullification.\n"
                                "  If no genuine free→use path exists, the spec is a false positive.")
                        elif cwe_id == "415":
                            res_parts.append(
                                "CWE-415 TRIGGER: Double free. The driver must call free() twice on same ptr:\n"
                                "  1. Allocate object, call function that frees it\n"
                                "  2. Call another function that frees the same pointer again\n"
                                "  The harness must keep BOTH free paths. KLEE detects double-free natively.")
                        elif cwe_id == "476":
                            res_parts.append(
                                "CWE-476 TRIGGER: NULL deref. Ensure the pointer CAN be NULL.\n"
                                "  - Make the pointer symbolic or returned from a stub that can return NULL")
                        else:
                            res_parts.append(
                                "The code is reachable but no bug was triggered. Adjust symbolic inputs:\n"
                                "  - Make buffers SMALLER than the length parameters\n"
                                "  - Ensure guard conditions allow the vulnerable path")
                    else:
                        res_parts.append("VULNERABILITY SITE NOT REACHED.")
                    
                    # --- KLEE crash details with stack trace + constraints ---
                    if stats.get("bug_found"):
                        crash_line = stats.get('error_line', '')
                        crash_file = stats.get('error_file', '')
                        crash_file_base = os.path.basename(crash_file) if crash_file else ""
                        
                        # --- DRIVER CRASH DETECTION ---
                        # If crash is in driver.c/stubs.c, diagnose the KLEE error and give fix
                        if crash_file_base in ("driver.c", "stubs.c", "smart_stubs.c"):
                            res_parts.append(f"⚠ DRIVER BUG: Crash in {crash_file_base}:{crash_line} — NOT a real vulnerability!")
                            res_parts.append("The entry function was NEVER reached. Fix driver.c first.")
                            
                            # Parse KLEE errors for specific diagnosis
                            klee_log = stats.get("full_log", "") + "\n" + stats.get("warnings_text", "")
                            driver_fixes = []
                            
                            if "concretized symbolic size" in klee_log or "huge malloc" in klee_log:
                                driver_fixes.append(
                                    "SYMBOLIC SIZE ERROR: You used a symbolic value as malloc/calloc size. "
                                    "KLEE needs CONCRETE sizes. FIX: Use concrete size, e.g.:\n"
                                    "  char *buf = (char*)malloc(1024);  // concrete size\n"
                                    "  klee_make_symbolic(buf, 1024, \"buf\");  // symbolic CONTENT")
                            
                            if "calling external" in klee_log:
                                # Extract which functions are called externally
                                ext_funcs = set(re.findall(r'calling external: (\w+)\(', klee_log))
                                entry = frozen.get("entry", "")
                                spine = frozen.get("spine", [])
                                ext_spine = ext_funcs & set(spine)
                                if ext_spine:
                                    driver_fixes.append(
                                        f"UNLINKED SPINE FUNCTIONS: {', '.join(ext_spine)} "
                                        f"are treated as EXTERNAL by KLEE — likely declared 'static' in the harness. "
                                        f"The system should auto-generate a public trampoline on next CompileSlice. "
                                        f"If it persists, ensure the function is defined (not just declared) in the harness .c file.")
                                elif ext_funcs:
                                    driver_fixes.append(
                                        f"EXTERNAL CALLS: {', '.join(list(ext_funcs)[:5])} are not defined. "
                                        f"Add stubs in WriteStubs or ensure the harness defines them.")
                            
                            if "invalid klee_assume" in klee_log or "provably false" in klee_log:
                                driver_fixes.append(
                                    "FALSE ASSUME: klee_assume condition is always false (e.g., NULL != NULL after failed malloc). "
                                    "FIX: Remove the klee_assume or fix the allocation it depends on.")
                            
                            if "Wrong size given to klee_make_symbolic" in klee_log:
                                driver_fixes.append(
                                    "WRONG SYMBOLIC SIZE: klee_make_symbolic size doesn't match the allocation. "
                                    "FIX: Ensure sizeof matches: klee_make_symbolic(&var, sizeof(var), \"name\")")
                            
                            if "memory error: out of bound" in klee_log:
                                driver_fixes.append(
                                    "OOB IN DRIVER: Accessing memory out of bounds in driver.c. "
                                    "FIX: Allocate enough space and check pointer arithmetic.")
                            
                            if "ASSERTION FAIL" in klee_log and crash_file_base == "driver.c":
                                driver_fixes.append(
                                    "ASSERT IN DRIVER: An assertion failed in driver.c. "
                                    "FIX: Remove defensive assertions from driver — let KLEE explore all paths.")
                            
                            if not driver_fixes:
                                driver_fixes.append(
                                    f"Driver crashed at {crash_file_base}:{crash_line}. "
                                    "Read the error details below and fix driver.c.")
                            
                            for fix in driver_fixes:
                                res_parts.append(f"  → {fix}")
                            
                            res_parts.append(
                                "\nDRIVER TEMPLATE (symbolic-first pattern):\n"
                                "  // 1. Concrete allocation\n"
                                "  struct MyType *obj = (struct MyType*)calloc(1, sizeof(struct MyType));\n"
                                "  // 2. Symbolic sub-buffers with concrete sizes\n"
                                "  char *name = (char*)malloc(64);\n"
                                "  klee_make_symbolic(name, 64, \"name\");\n"
                                "  obj->name = name;\n"
                                "  // 3. Concrete scalars that satisfy guards\n"
                                "  obj->size = 8;\n"
                                "  // 4. Call entry\n"
                                "  entry_func(obj, name, 64);")
                        else:
                            res_parts.append(f"KLEE CRASH: {stats['diagnosis']}")
                            
                            # Show original source line mapping
                            if crash_file and crash_line:
                                try:
                                    orig = tools.lookup_original_line(crash_file_base, int(crash_line))
                                    if orig:
                                        res_parts.append(
                                            f"ORIGINAL SOURCE: {orig['orig_file']}:{orig['orig_line']} → {orig['code']}")
                                except Exception:
                                    pass
                        
                        err_files = sorted(out_dir.glob("*.err")) if out_dir.exists() else []
                        for ef in err_files[:2]:
                            err_content = ef.read_text(errors="replace")
                            res_parts.append(f"  --- {ef.name} ---\n{err_content[:500]}")
                            
                            # Include path constraints (.kquery) for this crash
                            test_id = ef.stem.split(".")[0]  # test000001
                            for ext in [".kquery", ".smt2"]:
                                cf = out_dir / (test_id + ext)
                                if cf.exists():
                                    ctext = cf.read_text(errors="replace")
                                    if len(ctext) > 1500:
                                        ctext = ctext[:750] + "\n...(truncated)...\n" + ctext[-750:]
                                    res_parts.append(f"  --- {test_id}{ext} (path constraints) ---\n{ctext}")
                                    break
                        
                        # Tell agent whether crash is at vulnerability site or elsewhere
                        vul_loc = tools.resolve_vul_line()
                        if vul_loc and crash_line:
                            vul_line = int(vul_loc.get('harness_line', 0))
                            try:
                                cl = int(crash_line)
                                if abs(cl - vul_line) <= 10:
                                    res_parts.append(f"NOTE: Crash at line {cl} is NEAR the vulnerability site (line {vul_line}). This may be the vulnerability!")
                                else:
                                    res_parts.append(f"NOTE: Crash at line {cl} is NOT at the vulnerability site (line {vul_line}). This is a different bug — fix the crash cause (likely NULL pointer or unstubbed function) and retry.")
                            except (ValueError, TypeError):
                                pass
                    
                    # --- External calls ---
                    warns = stats.get("warnings_text", "")
                    if warns.strip():
                        external = set(re.findall(r'calling external: (\w+)', warns))
                        if external:
                            res_parts.append(f"EXTERNAL CALLS (un-stubbed): {', '.join(sorted(external)[:15])}")
                    
                    # --- Diagnostics (spine coverage + guidance) ---
                    if stats.get("diagnostics_summary"):
                        res_parts.append(f"Diagnostics: {stats['diagnostics_summary']}")
                    
                    # --- DIRECT ACTION INSTRUCTION ---
                    action = None
                    diag = stats.get("diagnostics_summary", "")
                    
                    # Track crash patterns
                    if not hasattr(tools, '_crash_history'):
                        tools._crash_history = []
                    crash_sig = f"{stats.get('error_file', '')}:{stats.get('error_line', '')}:{stats.get('crash_type', '')}"
                    if stats.get("bug_found"):
                        tools._crash_history.append(crash_sig)
                    
                    vul_func = frozen.get("vul_func", "")
                    spine_cov = stats.get("spine_coverage", {})
                    
                    # --- CRASH CLASSIFICATION ---
                    # Category A: HARNESS BUG — crash in driver.c, stubs.c, smart_stubs.c
                    #   → Fix immediately (bad struct setup, wrong stub return value)
                    # Category B: REAL CODE BUG, NOT at vuln site — crash in spine source
                    #   → Bypass it (stub/neutralize crashing line) and keep going toward target
                    # Category C: REAL CODE BUG AT vuln site — the target vulnerability
                    #   → Save for concrete validation, call Done(TP)
                    
                    crash_category = None
                    crash_line = stats.get('error_line', '')
                    crash_file = stats.get('error_file', '')
                    
                    if stats.get("bug_found") and crash_file:
                        crash_basename = os.path.basename(crash_file)
                        vul_basename = os.path.basename(frozen.get("vul_file", ""))
                        
                        # Category A: crash in harness/infrastructure files
                        if crash_basename in ("driver.c", "stubs.c", "smart_stubs.c", "auto_stubs.c"):
                            crash_category = "HARNESS_BUG"
                        else:
                            # Crash is in real code — check if at vulnerability site
                            vul_loc = tools.resolve_vul_line()
                            vul_line = int(vul_loc.get('harness_line', 0)) if vul_loc else 0
                            try:
                                cl = int(crash_line)
                                if vul_line > 0 and abs(cl - vul_line) <= 15:
                                    crash_category = "TARGET_BUG"
                                else:
                                    crash_category = "NONTARGET_REAL_BUG"
                            except (ValueError, TypeError):
                                crash_category = "NONTARGET_REAL_BUG"
                    
                    if stats.get("sink_reached"):
                        action = "ACTION: Call Done(verdict='TP') now. Sink reached!"
                    
                    elif crash_category == "TARGET_BUG":
                        # Category C: crash at vulnerability site → save for validation
                        # Reset driver crash counter (we got past the driver!)
                        if hasattr(tools, '_driver_crash_count'):
                            tools._driver_crash_count = 0
                        action = (
                            f"ACTION: KLEE crash at {crash_file}:{crash_line} is AT the vulnerability site. "
                            f"Call Done(verdict='TP'). Save KLEE test case for concrete validation."
                        )
                    
                    elif crash_category == "HARNESS_BUG":
                        # Category A: crash in harness code → fix immediately
                        # Track consecutive driver crashes
                        if not hasattr(tools, '_driver_crash_count'):
                            tools._driver_crash_count = 0
                        tools._driver_crash_count += 1
                        
                        if tools._driver_crash_count >= 2:
                            # AUTO-FIX: Generate a correct driver after repeated failures
                            print(f"  [System] {tools._driver_crash_count} consecutive driver crashes — auto-generating driver")
                            try:
                                auto_driver = tools._auto_generate_driver()
                                if auto_driver:
                                    driver_path = tools.harness_dir / "driver.c"
                                    driver_path.write_text(auto_driver, encoding="utf-8")
                                    print(f"  [System] Auto-wrote driver.c ({len(auto_driver)} chars)")
                                    action = (
                                        f"SYSTEM AUTO-FIX: Driver crashed {tools._driver_crash_count} times. "
                                        f"Auto-generated a new driver.c with concrete allocations. "
                                        f"Call CompileSlice to retry."
                                    )
                                else:
                                    action = (
                                        f"HARNESS ERROR (x{tools._driver_crash_count}): Auto-fix could not generate driver. "
                                        f"Rewrite driver.c manually. RULE: All malloc sizes MUST be concrete numbers."
                                    )
                            except Exception as e:
                                print(f"  [!] Auto-driver failed: {e}")
                                action = (
                                    f"HARNESS ERROR: KLEE crash at {crash_basename}:{crash_line}. "
                                    f"This is YOUR driver bug. All malloc/calloc sizes MUST be concrete numbers, not symbolic."
                                )
                        else:
                            action = (
                                f"HARNESS ERROR: KLEE crash at {crash_basename}:{crash_line}. "
                                f"This is a bug in YOUR harness/driver/stubs, not the target vulnerability. "
                                f"CRITICAL RULES:\n"
                                f"  - All malloc/calloc sizes MUST be concrete (e.g., malloc(1024), NOT malloc(sym_size))\n"
                                f"  - klee_make_symbolic on CONTENT, not on size/pointer\n"
                                f"  - Use calloc(1, sizeof(struct)) for structs, then set fields\n"
                                f"  Fix driver.c and CompileSlice to retry."
                            )
                    
                    elif crash_category == "NONTARGET_REAL_BUG":
                        # Category B: crash in real code but NOT at vulnerability site
                        # Reset driver crash counter (we got past the driver!)
                        if hasattr(tools, '_driver_crash_count'):
                            tools._driver_crash_count = 0
                        # → SAVE this as a surprise finding for concrete validation
                        # → ALSO bypass it so KLEE can continue toward the target
                        vul_loc = tools.resolve_vul_line()
                        vul_line_str = vul_loc.get('harness_line', '?') if vul_loc else '?'
                        
                        # Record surprise finding
                        if not hasattr(tools, '_surprise_findings'):
                            tools._surprise_findings = []
                        finding = {
                            "file": crash_file, "line": crash_line,
                            "type": stats.get("crash_type", ""),
                            "diagnosis": stats.get("diagnosis", ""),
                            "ktest": stats.get("ktest_file", ""),
                        }
                        tools._surprise_findings.append(finding)
                        n_surprise = len(tools._surprise_findings)
                        
                        action = (
                            f"SURPRISE FINDING #{n_surprise}: KLEE crash at {crash_basename}:{crash_line} "
                            f"is a REAL BUG in the source code (not a harness error). "
                            f"Saved for concrete validation. "
                            f"But it is NOT the target vulnerability (line {vul_line_str}). "
                            f"BYPASS this crash to keep going toward the target:\n"
                            f"  1. ExploreKleeOutput() — read .err to understand the crash\n"
                            f"  2. Add a guard or stub to skip past line {crash_line}\n"
                            f"     (e.g., stub the function call, or add if(!ptr) return)\n"
                            f"  3. CompileSlice to retry — KLEE should now get past this point"
                        )
                    
                    elif "WRONG CASE" in diag:
                        case_m = re.search(r'requires (\w+)\.', diag)
                        if case_m:
                            action = (f"ACTION NOW: WriteDriver with symbolic instate: "
                                      f"int sym_instate; klee_make_symbolic(&sym_instate, sizeof(sym_instate), \"instate\"); "
                                      f"klee_assume(sym_instate == {case_m.group(1)}); ctxt->instate = sym_instate; "
                                      f"Then CompileSlice. Do NOT read source.")
                    elif "BLOCKED" in diag and "NOT REACHED" in diag:
                        action = ("ACTION NOW: The entry function's guards are failing. "
                                  "WriteDriver with proper struct allocation (input, input->buf, buffer). "
                                  "Then CompileSlice. Do NOT read source.")
                    elif "CASE_" in diag and "NOT" in diag and "label" in diag.lower():
                        label_m = re.search(r"NOT '(\w+)'", diag)
                        missing_label = label_m.group(1) if label_m else "vulnerability label"
                        action = (f"ACTION NOW: Right case reached but '{missing_label}' not triggered. "
                                  f"WriteStubs for path functions. Then CompileSlice.")
                    elif stats.get("completed_paths", 0) == 0:
                        elapsed = stats.get("elapsed", 0)
                        tests = stats.get("generated_tests", 0)
                        if elapsed > 60 and tests > 0:
                            # KLEE ran for a while and generated tests but completed 0 paths
                            # → stuck in an inner loop with symbolic input
                            action = ("ACTION NOW: 0 completed paths but KLEE ran for "
                                      f"{elapsed:.0f}s with {tests} tests = STUCK IN LOOP. "
                                      "KLEE is exploding on symbolic inner loops. Fix: "
                                      "1. Use a SMALL symbolic buffer (8-16 bytes, not 512). "
                                      "2. Pre-fill most of the buffer with concrete bytes, "
                                      "only make the last few bytes symbolic. "
                                      "3. Stub functions called inside the loop to return "
                                      "concrete values. WriteDriver with these changes.")
                        else:
                            action = ("ACTION NOW: 0 paths = driver exits immediately. "
                                      "WriteDriver: allocate context manually with calloc, set all sub-structs. "
                                      "Then CompileSlice. Do NOT read source.")
                    elif external:
                        action = (f"ACTION NOW: WriteStubs for: {', '.join(sorted(external)[:5])}. "
                                  f"Then CompileSlice. Do NOT read source.")
                    
                    if action:
                        res_parts.append(f"\n>>> {action}")
                    
                    res_parts.append("TIP: Use ExploreKleeOutput() for full details. .kquery/.smt2 files contain path constraints showing exactly what input conditions triggered each test case.")
                    
                    # Show current vulnerability site location in harness (dynamically resolved)
                    vul_loc = tools.resolve_vul_line()
                    if vul_loc:
                        res_parts.append(f"VULNERABILITY SITE: harness/{vul_loc['harness_file']}:{vul_loc['harness_line']} (found via {vul_loc['marker']})")
                    
                    res = "\n".join(res_parts)
                else:
                    res = f"COMPILE ERROR: {r['error']}"
            elif tool == "ReplaceCode": res = tools.replace_code(args.get("file"), args.get("search"), args.get("replace"))
            elif tool == "ExploreKleeOutput": res = tools.explore_klee_output(args.get("file"))
            elif tool == "Done":
                verdict = args.get("verdict", "unknown")
                details = args.get("details", "")
                # Add sink_reached from last KLEE run
                if tools.last_klee_stats:
                    sink = tools.last_klee_stats.get("sink_reached", False)
                    probe_hits = tools.last_klee_stats.get("probe_hits", {})
                    details += f"\n[SAILOR] sink_reached={sink}, probes={probe_hits}"
                # Include surprise findings (non-target real bugs found along the way)
                surprise = getattr(tools, '_surprise_findings', [])
                if surprise:
                    details += f"\n[SURPRISE FINDINGS] {len(surprise)} additional real bugs found:"
                    for i, sf in enumerate(surprise):
                        details += f"\n  #{i+1}: {sf['type']} at {sf['file']}:{sf['line']} — {sf['diagnosis']}"
                        if sf.get('ktest'):
                            details += f" (ktest: {sf['ktest']})"
                findings.append((verdict, details))
                print(f"  [Done] verdict={verdict}, sink_reached={tools.last_klee_stats.get('sink_reached') if tools.last_klee_stats else 'N/A'}")
                if surprise:
                    print(f"  [Done] {len(surprise)} surprise findings saved for concrete validation")
                break
            else: res = "Unknown tool"
        except Exception as e:
            import traceback
            print(f"  [!] Tool exception in {tool}: {e}")
            traceback.print_exc()
            res = f"Tool Error: {e}"

        history.append({"role": "assistant", "content": json.dumps(resp)})
        
        # Auto-capture key discoveries into persistent notes
        _auto_capture_notes(tool, args, res)
        
        # Prioritize important info within observation limit
        obs = res
        if len(obs) > 4000:
            # Keep first 2000 chars (usually probe hits + crash info) and last 1000 (diagnostics + tips)
            obs = obs[:2500] + "\n... (truncated) ...\n" + obs[-1500:]
        history.append({"role": "user", "content": f"Observation:\n{obs}"})
        
    return findings, turn + 1  # return (findings_list, total_turns_used)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-id", default="test")
    parser.add_argument("--src-root", required=True)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--vul-file", required=True)
    parser.add_argument("--vul-line", required=True)
    parser.add_argument("--sa-out-dir", required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang-14"), help="Path to clang binary")
    parser.add_argument("--clang-flags", default=os.environ.get("CLANG_FLAGS", ""), help="Extra clang flags (or use CLANG_FLAGS env var)")
    parser.add_argument("--build-cmd", default=os.environ.get("BUILD_PROJECT_BC_CMD", ""), help="Build command template for the project. Use {SRC_ROOT} and {OUT_BC} placeholders.")
    parser.add_argument("--se-config", default=os.environ.get("SE_CONFIG_DIR", ""), help="Path to se_config/ folder with analyst knowledge (notes, seeds, constraints)")
    args, _ = parser.parse_known_args()
    
    # Validate LLM configuration
    missing = []
    if not os.environ.get("LLM_API_KEY") and not os.environ.get("OPENAI_API_KEY"):
        missing.append("LLM_API_KEY")
    if not os.environ.get("LLM_API_BASE"):
        missing.append("LLM_API_BASE")
    if not os.environ.get("LLM_MODEL"):
        missing.append("LLM_MODEL")
    if missing:
        print(f"[ERROR] Missing required environment variables: {', '.join(missing)}")
        print("  Set them before running:")
        print("    export LLM_API_KEY=your-api-key")
        print("    export LLM_API_BASE=https://api.openai.com/v1  # or any OpenAI-compatible endpoint")
        print("    export LLM_MODEL=gpt-4o  # or deepseek-chat, claude-3-sonnet, etc.")
        sys.exit(1)

    # Log effective LLM configuration for debugging
    _llm_cfg = {
        "model": os.environ.get("LLM_MODEL", ""),
        "api_base": os.environ.get("LLM_API_BASE", ""),
        "max_tokens": int(os.environ.get("LLM_MAX_TOKENS", "4096")),
        "temperature": float(os.environ.get("LLM_TEMPERATURE", "0.2")),
        "history_keep": int(os.environ.get("LLM_HISTORY_KEEP", "16")),
        "max_retries": int(os.environ.get("LLM_MAX_RETRIES", "3")),
    }
    print(f"[LLM Config] {json.dumps(_llm_cfg)}")

    # 1. Setup Logging (RESTORED)
    run_dir = ensure_dir(Path(args.run_dir))
    log_file = run_dir / "execution.log"
    class Tee:
        def __init__(self, *files): self.files = files
        def write(self, data):
            for f in self.files: f.write(data); f.flush()
        def flush(self):
            for f in self.files: f.flush()
    log_fh = open(log_file, "w")
    sys.stdout = Tee(sys.__stdout__, log_fh)
    sys.stderr = Tee(sys.__stderr__, log_fh)

    src_root = Path(args.src_root)
    
    # --- WORKING COPY: copy source tree to run_dir so we never modify the original ---
    src_copy = run_dir / "src_copy"
    if not src_copy.exists():
        print(f"  [i] Copying source tree to {src_copy}...")
        shutil.copytree(str(src_root), str(src_copy), symlinks=True,
                       ignore=shutil.ignore_patterns(
                           '*.o', '*.bc', '*.bca', '*.pyc', '__pycache__',
                           'asan_build', 'asan_replay', '.git'))
        print(f"  [i] Source copy ready ({sum(1 for _ in src_copy.rglob('*'))} files)")
        # Generate missing configure-produced headers (e.g. xmlversion.h)
        _generate_build_headers(src_copy)
    # Generate build headers on the ORIGINAL source tree too — needed because
    # include_paths from compile_commands.json point to original paths, and the
    # ASan replay compilers follow those paths (e.g. xmlversion.h must exist there)
    _generate_build_headers(src_root)
    src_root_original = src_root  # keep reference to original for ASan real-library build
    src_root = src_copy  # use copy everywhere from now on
    
    # Load SA Data
    sa_data = {}
    for f in ["compile_commands.json", "fact_pack.json", "findings.json"]:
        p = Path(args.sa_out_dir) / f
        if p.exists():
            sa_data[f.replace(".json","")] = read_json(p)
            print(f"  [i] Loaded: {f}")
    
    # Load spec JSON (SA-computed vulnerability details)
    spec = load_spec(args.spec)
    
    # --- LOAD SE CONFIG (analyst knowledge injection) ---
    se_config = load_se_config(args.se_config)
    
    # Inject crash output into spec for deep-bug analysis (if provided by analyst)
    if se_config.get("crash_output") and "crash_output" not in spec:
        spec["crash_output"] = se_config["crash_output"]
    
    ctx = {"vul_file": args.vul_file, "vul_line": args.vul_line, "strategy_name": "oob", "sa_data": sa_data, "spec_path": args.spec, "build_cmd": args.build_cmd, "src_root_original": str(src_root_original)}
    frozen = run_frozen_analysis(ctx, src_root, spec=spec)
    
    # --- APPLY SE CONFIG OVERRIDES TO FROZEN PLAN ---
    if se_config.get("entry_override"):
        old_entry = frozen.get("entry", "")
        frozen["entry"] = se_config["entry_override"]
        if se_config["entry_override"] not in frozen.get("spine", []):
            frozen["spine"] = [se_config["entry_override"]] + frozen.get("spine", [])
        print(f"  [SE-Config] Entry override: {old_entry} → {frozen['entry']}")
    if se_config.get("spine_override"):
        frozen["spine"] = se_config["spine_override"]
        frozen["entry"] = se_config["spine_override"][0]
        print(f"  [SE-Config] Spine override: {' → '.join(frozen['spine'])}")
    
    # Store se_config in frozen for downstream access
    frozen["se_config"] = se_config
    
    # --- COPY SA ARTIFACTS TO RUN DIR FOR AGENT ACCESS ---
    sa_dir = ensure_dir(run_dir / "sa_context")
    # Copy spec JSON
    if args.spec and Path(args.spec).exists():
        shutil.copy2(args.spec, sa_dir / "spec.json")
    # Copy SA outputs
    for fname in ["findings.json", "fact_pack.json", "compile_commands.json"]:
        src_p = Path(args.sa_out_dir) / fname
        if src_p.exists():
            shutil.copy2(src_p, sa_dir / fname)
    
    # Extract the compile_commands entry for the vulnerable file for quick agent access
    cc = sa_data.get("compile_commands", [])
    if cc:
        vul_base = os.path.basename(args.vul_file)
        # Use exact basename match (not substring) to avoid HTMLparser.c matching parser.c
        relevant_cc = [e for e in cc if os.path.basename(e.get("file") or "") == vul_base]
        if relevant_cc:
            write_json(sa_dir / "compile_entry.json", relevant_cc[0])
    
    # Generate a vulnerability summary for the agent
    vuln_summary = {
        "target_file": args.vul_file,
        "target_line": args.vul_line,
        "vulnerable_function": frozen["vul_func"],
        "entry_function": frozen["entry"],
        "spine": frozen["spine"],
        "spec_filename": os.path.basename(args.spec) if args.spec else "",
        "build_dir": frozen.get("build_dir", ""),
        "compile_flags": frozen.get("compile_flags", []),
        "include_paths": frozen.get("include_paths", []),
    }
    # Extract CWE and pattern from spec filename
    if args.spec:
        cwe_m = re.search(r'cwe-(\d+)', os.path.basename(args.spec), re.IGNORECASE)
        if cwe_m:
            vuln_summary["cwe_id"] = cwe_m.group(1)
        pat_m = re.search(r'cwe-\d+-(.+)\.json$', os.path.basename(args.spec), re.IGNORECASE)
        if pat_m:
            vuln_summary["vulnerability_pattern"] = pat_m.group(1).replace('-', ' ')
    # Add any spec keys
    if spec:
        for key in ["cwe", "description", "vulnerability_type", "message", "query_id",
                     "sink_label", "source_label", "code_pattern", "fix_description"]:
            if key in spec:
                vuln_summary[key] = spec[key]
    # Extract relevant findings that match our target line
    relevant_findings = []
    facts_list = []
    fp = sa_data.get("fact_pack", {})
    raw_facts = fp.get("facts", {}) if isinstance(fp, dict) else {}
    if isinstance(raw_facts, list):
        facts_list = raw_facts
    findings_data = sa_data.get("findings", [])
    if isinstance(findings_data, list):
        facts_list.extend(findings_data)
    vul_line_int = int(args.vul_line)
    for finding in facts_list:
        if not isinstance(finding, dict):
            continue
        fline = int(finding.get("line") or finding.get("startLine") or 0)
        if abs(fline - vul_line_int) < 10:
            relevant_findings.append(finding)
    if relevant_findings:
        vuln_summary["relevant_findings"] = relevant_findings[:5]  # limit to 5
    
    # --- ENRICHMENT: Source context around vulnerability site ---
    # This eliminates 20-30 turns of ReadSource/GrepSource/FindDefinition
    vul_source = find_source_file(src_root, args.vul_file)
    if vul_source:
        src_text = vul_source.read_text(errors="replace")
        src_lines = src_text.splitlines()
        
        # 1. Code around the vulnerability line (±20 lines)
        vl = vul_line_int - 1  # 0-indexed
        ctx_start = max(0, vl - 20)
        ctx_end = min(len(src_lines), vl + 20)
        vuln_summary["source_context"] = {
            "lines": {str(i+1): src_lines[i] for i in range(ctx_start, ctx_end)},
            "note": f"Lines {ctx_start+1}-{ctx_end} of {args.vul_file} around line {args.vul_line}"
        }
        
        # 2. Find the sink label (goto target) if vulnerability is reached via goto
        goto_labels = []
        goto_sources = []
        
        # Find the label that leads to the vulnerability site.
        # Strategy: search FORWARD from vul_line for the label that immediately
        # precedes the SAILOR instrumentation block. This is the vulnerability's
        # own label (e.g., encoding_error:), not generic labels like done:.
        # We also search BACKWARD from vul_line in case the label is before it.
        
        # First: find the SAILOR_INST block near vul_line
        sailor_begin = None
        for i in range(vl, min(len(src_lines), vl + 60)):
            if 'SAILOR_INST_BEGIN' in src_lines[i] or 'klee_assert' in src_lines[i] or 'klee_check_memory_access' in src_lines[i]:
                sailor_begin = i
                break
        
        if sailor_begin:
            # Search backward from SAILOR block for the nearest label
            for i in range(sailor_begin, max(-1, sailor_begin - 20), -1):
                m = re.match(r'^(\w+)\s*:', src_lines[i])
                if m and m.group(1) not in ('default', 'case', 'public', 'private', 'protected'):
                    goto_labels.append(m.group(1))
                    break  # only the NEAREST label
        
        # Fallback: search ±10 lines from vul_line for any label
        if not goto_labels:
            for i in range(max(0, vl - 10), min(len(src_lines), vl + 10)):
                m = re.match(r'^(\w+)\s*:', src_lines[i])
                if m and m.group(1) not in ('default', 'case', 'public', 'private', 'protected', 'done'):
                    if m.group(1) not in goto_labels:
                        goto_labels.append(m.group(1))
        if goto_labels:
            # Find all goto <label> in the same function
            goto_sources = []
            func_span = find_function_span(src_text, frozen["vul_func"])
            if func_span:
                func_text = src_text[func_span[0]:func_span[2]]
                func_lines = func_text.splitlines()
                func_start_line = src_text[:func_span[0]].count('\n') + 1
                for label in goto_labels:
                    for i, fl in enumerate(func_lines):
                        if f'goto {label}' in fl:
                            actual_line = func_start_line + i
                            # Include surrounding context
                            ctx_s = max(0, i - 3)
                            ctx_e = min(len(func_lines), i + 3)
                            goto_sources.append({
                                "label": label,
                                "goto_line": actual_line,
                                "context": [func_lines[j] for j in range(ctx_s, ctx_e)]
                            })
            if goto_sources:
                vuln_summary["goto_sources"] = goto_sources
        
        # 3. Which switch case contains the goto that reaches the vulnerability?
        # IMPORTANT: If the vulnerability is at a goto label (like encoding_error:),
        # the label is OUTSIDE the switch. We must find which case contains the
        # "goto <label>" statement, NOT which case is textually before the label.
        func_span = find_function_span(src_text, frozen["vul_func"])
        if func_span:
            func_text = src_text[func_span[0]:func_span[2]]
            func_lines = func_text.splitlines()
            func_start_line = src_text[:func_span[0]].count('\n') + 1
            
            # Strategy 1: If we have goto_sources, find the case enclosing the goto
            target_case = None
            if goto_sources:
                for gs in goto_sources:
                    gs_rel = gs["goto_line"] - func_start_line
                    # Scan backwards from the goto line to find its enclosing case
                    for i in range(min(gs_rel, len(func_lines) - 1), -1, -1):
                        m = re.match(r'\s*case\s+(\w+)\s*:', func_lines[i])
                        if m:
                            target_case = m.group(1)
                            break
                    if target_case:
                        break
            
            # Strategy 2: Fallback — scan backwards from vulnerability line
            if not target_case:
                target_rel = vul_line_int - func_start_line
                for i in range(min(target_rel, len(func_lines) - 1), -1, -1):
                    m = re.match(r'\s*case\s+(\w+)\s*:', func_lines[i])
                    if m:
                        target_case = m.group(1)
                        break
            
            if target_case:
                vuln_summary["enclosing_switch_case"] = target_case
                hint_parts = [
                    f"Make ctxt->instate SYMBOLIC and constrain it: "
                    f"int sym_instate; klee_make_symbolic(&sym_instate, sizeof(sym_instate), \"instate\"); "
                    f"klee_assume(sym_instate == {target_case}); ctxt->instate = sym_instate;  "
                    f"This lets KLEE verify the correct case ({target_case}) while remaining robust."
                ]
                if goto_sources:
                    labels = set(gs["label"] for gs in goto_sources)
                    hint_parts.append(
                        f"The vulnerability is at label '{', '.join(labels)}' which is "
                        f"reached via goto from inside the {target_case} case.")
                hint_parts.append("Do NOT start from a default/initial state — KLEE cannot transition through states.")
                vuln_summary["driver_hint"] = " ".join(hint_parts)
        
        # 4. Key function calls on the path (what needs stubbing)
        if goto_sources:
            # Read the code between goto source and goto target
            path_calls = set()
            for gs in goto_sources:
                gs_rel = gs["goto_line"] - func_start_line
                for i in range(max(0, gs_rel - 10), min(len(func_lines), gs_rel + 2)):
                    for m in re.finditer(r'\b([a-zA-Z_]\w+)\s*\(', func_lines[i]):
                        fn = m.group(1)
                        if fn not in ('if', 'while', 'for', 'switch', 'return', 'sizeof',
                                      'goto', 'case', 'break', 'continue'):
                            path_calls.add(fn)
            if path_calls:
                vuln_summary["path_calls_needing_stubs"] = sorted(path_calls)
    
    # --- ENRICHMENT: Struct definitions needed for driver ---
    # Auto-detect struct types from the vulnerability source context
    struct_defs = {}
    source_context = vuln_summary.get("source_context", "")
    # source_context may be a dict {lines: {...}, note: ...} or a string
    if isinstance(source_context, dict):
        source_context = "\n".join(source_context.get("lines", {}).values())
    # Find struct-like type names: FooCtxt, FooContext, FooInput, FooBuffer, FooState, etc.
    struct_candidates = set()
    for m in re.finditer(r'\b(\w+(?:Ctxt|Context|State|Input|Buffer|Buf|Conn|Session|Parser|Handle)\w*)\b', source_context):
        struct_candidates.add(m.group(1))
    # Also check the entry function signature for parameter types
    entry_func = frozen.get("entry_func", "")
    if entry_func:
        func_span = find_function_span(src_text, entry_func)
        if func_span:
            sig = src_text[func_span[0]:func_span[1]]
            for m in re.finditer(r'\b(\w+(?:Ptr|_t|Ctxt|Context|State))\b', sig):
                # Try to find the underlying struct from typedef
                struct_candidates.add(m.group(1).replace("Ptr", ""))
    
    for struct_name in sorted(struct_candidates):
        if len(struct_name) < 4:
            continue  # skip short names like "int", "buf"
        defn = find_definition(src_root, struct_name)
        if defn:
            defn_lines = defn.splitlines()[:30]
            struct_defs[struct_name] = '\n'.join(defn_lines)
    if struct_defs:
        vuln_summary["struct_definitions"] = struct_defs
    
    write_json(sa_dir / "vulnerability_summary.json", vuln_summary)
    
    # Write struct groom data
    groom = frozen.get("struct_groom", {})
    if groom:
        write_json(sa_dir / "struct_groom.json", groom)
        # Also write the init template as a standalone .c file for easy copy
        if groom.get("init_template"):
            (sa_dir / "context_init_template.c").write_text(groom["init_template"], encoding="utf-8")
    
    print(f"  [i] SA context written to {sa_dir}")
    
    extra_cflags = shlex.split(args.clang_flags)
    
    # Read tool paths and limits from environment (set by run_worker.sh)
    clang_bin = args.clang
    llvm_link_bin = os.environ.get("LLVM_LINK", "llvm-link-14")
    klee_bin = os.environ.get("KLEE", "klee")
    max_turns = int(os.environ.get("MAX_TURNS", 40))
    run_timeout = int(os.environ.get("TIMEOUT", 600))
    
    # --- SE CONFIG: Apply KLEE + timeout overrides ---
    klee_flags = []
    if se_config.get("klee_flags"):
        klee_flags.extend(se_config["klee_flags"])
        print(f"  [SE-Config] KLEE flags: {' '.join(se_config['klee_flags'])}")
    if se_config.get("search_strategy"):
        klee_flags.append(f"--search={se_config['search_strategy']}")
        print(f"  [SE-Config] Search strategy: {se_config['search_strategy']}")
    if se_config.get("klee_timeout") and se_config["klee_timeout"] > 0:
        run_timeout = se_config["klee_timeout"]
        print(f"  [SE-Config] KLEE timeout override: {run_timeout}s")
    if se_config.get("max_turns") and se_config["max_turns"] > 0:
        max_turns = se_config["max_turns"]
        print(f"  [SE-Config] Max turns override: {max_turns}")
    
    tools = SliceTools(ctx, frozen, src_root, run_dir/"harness", run_dir/"logs",
                       clang_bin, llvm_link_bin, klee_bin, klee_flags, run_timeout, time.time(),
                       extra_cflags=extra_cflags, se_config=se_config)
    
    # --- SE CONFIG: Pre-populate harness with seed files ---
    harness_dir = tools.harness_dir
    if se_config.get("seed_driver"):
        (harness_dir / "driver.c").write_text(se_config["seed_driver"], encoding="utf-8")
        print(f"  [SE-Config] Seeded harness/driver.c ({se_config['seed_driver'].count(chr(10))+1} lines)")
    if se_config.get("seed_stubs"):
        (harness_dir / "stubs.c").write_text(se_config["seed_stubs"], encoding="utf-8")
        print(f"  [SE-Config] Seeded harness/stubs.c")
    if se_config.get("seed_harness"):
        (harness_dir / "parser.c").write_text(se_config["seed_harness"], encoding="utf-8")
        print(f"  [SE-Config] Seeded harness/parser.c")
    if se_config.get("extra_stubs"):
        extra_stubs_path = harness_dir / "analyst_stubs.c"
        extra_stubs_path.write_text(se_config["extra_stubs"], encoding="utf-8")
        print(f"  [SE-Config] Wrote harness/analyst_stubs.c (will be compiled + linked)")
    if se_config.get("poc_input_path"):
        poc_src = Path(se_config["poc_input_path"])
        if poc_src.exists():
            poc_dst = harness_dir / "poc_input.bin"
            shutil.copy2(str(poc_src), str(poc_dst))
            print(f"  [SE-Config] Copied PoC input to harness/ ({poc_src.stat().st_size} bytes)")
    
    # --- SE CONFIG: Write se_config summary to sa_context for agent reference ---
    if se_config.get("loaded_files"):
        se_summary = {k: v for k, v in se_config.items()
                      if k not in ("seed_driver", "seed_stubs", "seed_harness",
                                   "extra_stubs", "analyst_notes", "crash_output")
                      and v}
        write_json(sa_dir / "se_config_summary.json", se_summary)
    
    findings, agent_turns = run_agent(ctx, frozen, tools, run_dir, max_turns, run_timeout, time.time(), spec=spec)
    
    # Determine search status from findings / bug report
    search_status = "NO_BUG"
    verdict = "FP"
    bug_report = None
    
    bug_report_path = run_dir / "harness" / ".." / "bug_report.json"
    actual_bug_report = run_dir / "bug_report.json"
    for brp in [actual_bug_report, bug_report_path]:
        if brp.exists():
            try:
                bug_report = read_json(brp)
                verdict = bug_report.get("summary", {}).get("verdict", "LIKELY_TP")
            except Exception:
                pass
            break
    
    if verdict in ("TP",):
        search_status = "FOUND_TP"
    elif verdict in ("LIKELY_TP",):
        search_status = "FOUND_LIKELY_TP"
    elif verdict in ("SLICING_ARTIFACT",):
        search_status = "SLICING_ARTIFACT"
    elif verdict in ("LIKELY_TP_DIFFERENT_CRASH",):
        search_status = "FOUND_DIFFERENT_CRASH"
    elif verdict in ("LIKELY_FP_NULL_DEREF",):
        search_status = "FOUND_LIKELY_FP_NULL_DEREF"
    elif verdict in ("INCONCLUSIVE_LOW_COVERAGE",):
        search_status = "INCONCLUSIVE"
    elif findings:
        search_status = "FOUND_UNTARGETED"
    
    # --- Granular NO_BUG sub-status ---
    # When no bug found, determine WHY for actionable diagnostics.
    failure_reason = ""
    if search_status == "NO_BUG":
        klee_ran = tools.iteration > 0
        # Check KLEE logs for last run stats
        last_klee_log = None
        logs_dir = run_dir / "logs"
        if logs_dir.exists():
            klee_logs = sorted(logs_dir.glob("klee_*.log"), reverse=True)
            if klee_logs:
                try:
                    last_klee_log = klee_logs[0].read_text(errors="replace")
                except Exception:
                    pass
        
        if not klee_ran:
            # Agent never compiled successfully
            search_status = "BUILD_ERROR"
            failure_reason = "Agent never reached successful KLEE execution"
        elif last_klee_log:
            # Parse last KLEE log for clues
            if "KLEE EXIT ERROR" in (last_klee_log or "") or "Exit code: 1" in (last_klee_log or ""):
                search_status = "KLEE_ERROR"
                failure_reason = "KLEE crashed or failed to run"
            elif "SPINE_PROBE:" in (last_klee_log or ""):
                # Check which spine functions were reached
                vf = frozen.get("vul_func", "")
                if vf and f"SPINE_PROBE:{vf}" in (last_klee_log or ""):
                    search_status = "REACHED_NO_BUG"
                    failure_reason = f"Reached {vf} but no bug triggered"
                else:
                    search_status = "UNREACHABLE"
                    failure_reason = f"Could not reach {vf} via spine"
            else:
                search_status = "UNREACHABLE"
                failure_reason = "KLEE ran but no spine functions reached"
        else:
            search_status = "TIMEOUT"
            failure_reason = "Agent timed out or exhausted turns"

    # --- INCONCLUSIVE verdict for low-coverage NO_BUG ---
    # When agent exhausted turns without finding a bug AND KLEE explored very few paths,
    # mark as INCONCLUSIVE_LOW_COVERAGE so these specs get flagged for manual review
    # instead of being dismissed as FP.
    if verdict == "FP" and search_status in ("TIMEOUT", "UNREACHABLE", "REACHED_NO_BUG"):
        last_completed_paths = (tools.last_klee_stats or {}).get("completed_paths", 0)
        if last_completed_paths < 20:
            verdict = "INCONCLUSIVE_LOW_COVERAGE"
            search_status = "INCONCLUSIVE"
            failure_reason += f" (only {last_completed_paths} completed paths — insufficient coverage)"
    
    # Assemble report.json (internal detailed report)
    final_report = {
        "findings": findings,
        "line_map": tools.harness_line_map,
    }
    if bug_report:
        final_report["bug_report"] = bug_report
    write_json(run_dir / "report.json", final_report)
    
    # --- Extract bug location details for TSV ---
    bug_type = ""
    bug_file = ""
    bug_line = 0
    bug_func = ""
    asan_confirmed = False
    if bug_report:
        summary = bug_report.get("summary", {})
        klee_crash = bug_report.get("klee_crash", {})
        asan_data = bug_report.get("asan_result", {})
        bug_type = klee_crash.get("error_type", "")
        bug_file = klee_crash.get("original_file", "") or klee_crash.get("harness_file", "")
        bug_line = klee_crash.get("original_line", 0) or klee_crash.get("harness_line", 0)
        bug_func = bug_report.get("vulnerability", {}).get("function", "")
        asan_confirmed = asan_data.get("triggered", False)
        if asan_confirmed and asan_data.get("error_type"):
            bug_type = asan_data["error_type"]
            if asan_data.get("original_file"):
                bug_file = asan_data["original_file"]
                bug_line = asan_data.get("original_line", 0)
    
    # Assemble run_report.json (expected by run_worker.sh)
    secondary_count = 0
    crash_relevance = ""
    cwe_id = ""
    if bug_report:
        summary = bug_report.get("summary", {})
        secondary_count = summary.get("secondary_bugs", 0)
        crash_relevance = summary.get("crash_relevance", "")
        cwe_id = summary.get("cwe", "")
    
    run_report = {
        "search_status": search_status,
        "verdict": verdict,
        "crash_relevance": crash_relevance,
        "secondary_bugs": secondary_count,
        "failure_reason": failure_reason,
        "metrics": {
            "tokens_total": _TOKEN_TOTAL,
            "tokens_prompt": _TOKEN_PROMPT,
            "tokens_completion": _TOKEN_COMPLETION,
            "turns": agent_turns,
            "klee_runs": tools.iteration,
        },
        "bug": {
            "type": bug_type,
            "file": bug_file,
            "line": bug_line,
            "function": bug_func,
            "asan_confirmed": asan_confirmed,
            "cwe": cwe_id,
        },
        "spec": str(args.spec),
        "vul_file": args.vul_file,
        "vul_line": args.vul_line,
    }
    if bug_report:
        run_report["bug_report"] = bug_report
        # Log secondary bugs
        for sb in bug_report.get("secondary_bugs", [])[:10]:
            print(f"  [Secondary] {sb['error_type']} at {sb['original_file']}:{sb['original_line']} "
                  f"({sb.get('crash_function', '?')}) [{sb['relevance']}]")
    write_json(run_dir / "run_report.json", run_report)
    
    print("Done.")
    # Restore original streams BEFORE closing log file to avoid
    # "Exception ignored in sys.unraisablehook" during interpreter shutdown
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    log_fh.close()

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise  # Let sys.exit() through
    except Exception as e:
        # Emergency: write a minimal run_report.json so run_worker.sh always has data
        import traceback
        traceback.print_exc()
        try:
            import argparse as _ap
            # Try to find run_dir from sys.argv
            _parser = _ap.ArgumentParser()
            _parser.add_argument("--run-dir", default="")
            _parser.add_argument("--spec", default="")
            _parser.add_argument("--vul-file", default="")
            _parser.add_argument("--vul-line", default="0")
            _known, _ = _parser.parse_known_args()
            if _known.run_dir:
                _rd = Path(_known.run_dir)
                _rd.mkdir(parents=True, exist_ok=True)
                _rr = {
                    "search_status": "CRASHED",
                    "verdict": "FP",
                    "failure_reason": f"Unhandled exception: {type(e).__name__}: {str(e)[:200]}",
                    "crash_relevance": "",
                    "secondary_bugs": 0,
                    "metrics": {"tokens_total": _TOKEN_TOTAL, "tokens_prompt": _TOKEN_PROMPT,
                                "tokens_completion": _TOKEN_COMPLETION, "turns": 0, "klee_runs": 0},
                    "bug": {"type": "", "file": "", "line": 0, "function": "",
                            "asan_confirmed": False, "cwe": ""},
                    "spec": _known.spec, "vul_file": _known.vul_file, "vul_line": _known.vul_line,
                }
                write_json(_rd / "run_report.json", _rr)
                print(f"[EMERGENCY] Wrote crash run_report.json to {_rd}")
        except Exception:
            pass
        sys.exit(1)