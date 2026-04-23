#!/usr/bin/env python3
"""Standalone ASan concrete validation for SAILOR KLEE results.

Re-runs the ASan replay step on existing harness + KLEE outputs without
requiring the full LLM agent loop. Reads bug_report.json to find crashes,
decodes ktest files, generates a concrete replay driver, and compiles with
AddressSanitizer.

Usage:
    python3 asan_replay.py /path/to/run_dir [--run-dir2 ...]
    python3 asan_replay.py --results-dir /path/to/se_runs/project/

Examples:
    # Replay a single spec:
    python3 asan_replay.py se_runs/sailor_engine/libxml2_e334a9d_vul/727_xmlschemastypes.c_1809_...

    # Replay all TPs in a project:
    python3 asan_replay.py --results-dir se_runs/sailor_engine/libxml2_e334a9d_vul/
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
def run_cmd(cmd, cwd=None, timeout=120, env=None) -> Tuple[int, str, str, float]:
    """Run a subprocess and return (rc, stdout, stderr, elapsed)."""
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, env=env)
        return r.returncode, r.stdout, r.stderr, time.time() - t0
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT", time.time() - t0
    except Exception as e:
        return -1, "", str(e), time.time() - t0


def read_json(path: Path) -> Optional[Dict]:
    try:
        return json.loads(path.read_text(errors="replace"))
    except Exception:
        return None


def write_json(path: Path, data):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# ktest decoding
# ---------------------------------------------------------------------------
def decode_ktest(ktest_path: str) -> List[Dict]:
    """Decode a .ktest file using ktest-tool and return list of objects."""
    rc, out, err, _ = run_cmd(["ktest-tool", ktest_path], timeout=10)
    if rc != 0:
        print(f"  [!] ktest-tool failed: {err[:200]}")
        return []

    objects = []
    current = {}
    for line in out.split("\n"):
        line = line.strip()
        m = re.match(r"object\s+(\d+):\s+(\w+):\s+(.*)", line)
        if not m:
            continue
        idx, field, value = int(m.group(1)), m.group(2), m.group(3).strip()
        if field == "name":
            if current:
                objects.append(current)
            current = {"name": value.strip("b'\""), "size": 0, "data": ""}
        elif field == "size":
            current["size"] = int(value)
        elif field == "data":
            current["data"] = value
    if current:
        objects.append(current)
    return objects


def parse_ktest_data(data_str: str, expected_size: int) -> List[int]:
    """Parse ktest-tool output data into a list of byte values."""
    byte_values = []
    if not data_str:
        return [0] * expected_size

    # Format 1: Python bytes literal b'...'
    if data_str.startswith("b'") or data_str.startswith('b"'):
        inner = data_str[2:-1]
        i = 0
        while i < len(inner):
            if inner[i] == '\\' and i + 1 < len(inner):
                nxt = inner[i + 1]
                if nxt == 'x' and i + 3 < len(inner):
                    byte_values.append(int(inner[i+2:i+4], 16))
                    i += 4
                elif nxt == '0':
                    byte_values.append(0)
                    i += 2
                elif nxt == 'n':
                    byte_values.append(ord('\n'))
                    i += 2
                elif nxt == 't':
                    byte_values.append(ord('\t'))
                    i += 2
                elif nxt == '\\':
                    byte_values.append(ord('\\'))
                    i += 2
                else:
                    byte_values.append(ord(inner[i]))
                    i += 1
            else:
                byte_values.append(ord(inner[i]))
                i += 1
    # Format 2: Hex integer
    elif data_str.startswith("0x"):
        val = int(data_str, 16)
        while val > 0:
            byte_values.insert(0, val & 0xFF)
            val >>= 8

    # Pad or truncate
    if len(byte_values) < expected_size:
        byte_values.extend([0] * (expected_size - len(byte_values)))
    elif len(byte_values) > expected_size:
        byte_values = byte_values[:expected_size]
    return byte_values


# ---------------------------------------------------------------------------
# Replay driver generation
# ---------------------------------------------------------------------------
def generate_replay_driver(driver_src: str, ktest_objects: List[Dict]) -> str:
    """Transform a symbolic driver into a concrete replay driver."""
    obj_map = {o["name"]: o for o in ktest_objects}

    def replace_symbolic(m):
        args_str = m.group(1)
        parts = [p.strip() for p in args_str.split(",")]
        if len(parts) < 3:
            return "memset({}, 0, {})".format(parts[0], parts[1] if len(parts) > 1 else "0")
        ptr, size_expr, name_raw = parts[0], parts[1], parts[2]
        name = name_raw.strip('"\'')
        obj = obj_map.get(name)
        if obj:
            byte_values = parse_ktest_data(obj["data"], obj["size"])
            hex_arr = ", ".join(f"0x{b:02x}" for b in byte_values)
            return (f'{{ /* replay: concrete values for "{name}" ({len(byte_values)} bytes) */\n'
                    f'    static const unsigned char {name}_data[] = {{{hex_arr}}};\n'
                    f'    memcpy({ptr}, {name}_data, '
                    f'({size_expr}) < {len(byte_values)} ? ({size_expr}) : {len(byte_values)});\n'
                    f'  }}')
        else:
            return f"memset({ptr}, 0, {size_expr})"

    replay = driver_src
    # Remove KLEE includes and decls
    replay = re.sub(r'#include\s*[<"]klee/klee\.h[>"]', '// klee removed for replay', replay)
    replay = re.sub(r'extern\s+\w+\s+klee_\w+\s*\([^)]*\)\s*;', '/* klee decl removed */', replay)
    # Replace klee_make_symbolic with concrete values
    replay = re.sub(r'\bklee_make_symbolic\s*\(((?:[^()]|\([^()]*\))+)\)',
                    replace_symbolic, replay)
    # Remove other KLEE calls
    replay = re.sub(r'\bklee_warning\([^)]*\)\s*;', '/* probe removed */', replay)
    replay = re.sub(r'\bklee_assert\([^)]*\)\s*;', '/* assert removed */', replay)
    replay = re.sub(r'\bklee_check_memory_access\([^)]*\)\s*;', '/* check removed */', replay)
    replay = re.sub(r'\bklee_report_error\([^)]*\)\s*;', '/* report removed */', replay)
    replay = re.sub(r'\bklee_get_obj_size\([^)]*\)', '0 /* klee removed */', replay)
    replay = re.sub(r'\bklee_assume\([^)]*\)\s*;', '/* assume removed */', replay)
    # Remove spine probes (klee_warning_once used for SPINE_PROBE coverage)
    replay = re.sub(r'\bklee_warning_once\([^)]*\)\s*;', '/* spine probe removed */', replay)
    replay = re.sub(r'\bklee_warning\([^)]*\)\s*;', '/* klee warning removed */', replay)
    # Remove SAILOR-specific bounds checks
    replay = re.sub(r'/\*\s*SAILOR:.*?bounds check\s*\*/', '/* bounds check removed */', replay)
    replay = re.sub(r'\bif\s*\(\s*klee_get_obj_size\b[^;]*klee_report_error\b[^;]*;',
                    '/* SAILOR bounds check removed */', replay, flags=re.DOTALL)
    replay = re.sub(r'\bif\s*\(\s*\(size_t\)[^;]*klee_get_obj_size\b[^;]*klee_report_error\b[^;]*;',
                    '/* SAILOR bounds check removed */', replay, flags=re.DOTALL)

    # Add headers
    header = """/* AUTO-GENERATED REPLAY DRIVER for ASan concrete validation.
 * Generated by asan_replay.py from KLEE test case.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
"""
    return header + replay


def clean_harness_file(src: str) -> str:
    """Clean KLEE-specific code from a harness .c file."""
    clean = src
    clean = re.sub(r'#include\s*[<"]klee/klee\.h[>"]', '// klee removed', clean)
    clean = re.sub(r'extern\s+\w+\s+klee_\w+\s*\([^)]*\)\s*;', '/* klee decl removed */', clean)
    clean = re.sub(r'\bklee_warning_once\([^)]*\)\s*;', '/* spine probe removed */', clean)
    clean = re.sub(r'\bklee_warning\([^)]*\)\s*;', '/* probe removed */', clean)
    clean = re.sub(r'\bklee_assert\([^)]*\)\s*;', '/* assert removed */', clean)
    clean = re.sub(r'\bklee_check_memory_access\([^)]*\)\s*;', '/* check removed */', clean)
    clean = re.sub(r'\bklee_report_error\([^)]*\)\s*;', '/* report removed */', clean)
    clean = re.sub(r'\bklee_get_obj_size\([^)]*\)', '0 /* klee removed */', clean)
    clean = re.sub(r'\bklee_make_symbolic\s*\(((?:[^()]|\([^()]*\))+)\)',
                   lambda m: f'memset({m.group(1).split(",")[0].strip()}, 0, '
                             f'{m.group(1).split(",")[1].strip() if len(m.group(1).split(",")) > 1 else "0"})',
                   clean)
    clean = re.sub(r'\bklee_assume\([^)]*\)\s*;', '/* assume removed */', clean)
    clean = re.sub(r'/\*\s*SAILOR:.*?bounds check\s*\*/', '/* removed */', clean)
    clean = re.sub(r'\bif\s*\(\s*klee_get_obj_size\b[^;]*klee_report_error\b[^;]*;',
                   '/* removed */', clean, flags=re.DOTALL)
    return clean


# ---------------------------------------------------------------------------
# ASan output parsing
# ---------------------------------------------------------------------------
def parse_asan_output(stderr: str) -> Dict:
    """Parse ASan error output for error type, function, file, line."""
    result = {"triggered": False, "error_type": "", "crash_function": "",
              "crash_file": "", "crash_line": 0, "output": stderr[:2000]}

    # Look for "ERROR: AddressSanitizer: <type>"
    m = re.search(r'ERROR:\s*AddressSanitizer:\s*(\S+)', stderr)
    if m:
        result["triggered"] = True
        result["error_type"] = m.group(1)

    # Look for SEGV
    if not result["triggered"]:
        m = re.search(r'AddressSanitizer:DEADLYSIGNAL.*?SEGV', stderr, re.DOTALL)
        if m:
            result["triggered"] = True
            result["error_type"] = "SEGV"

    # Extract crash location from stack trace
    if result["triggered"]:
        # Pattern: #0 0xADDR in func_name file:line
        for line in stderr.split('\n'):
            m = re.search(r'#0\s+\S+\s+in\s+(\w+)\s+(\S+):(\d+)', line)
            if m:
                result["crash_function"] = m.group(1)
                result["crash_file"] = m.group(2)
                result["crash_line"] = int(m.group(3))
                break

    return result


# ---------------------------------------------------------------------------
# Main replay logic
# ---------------------------------------------------------------------------
def replay_spec(run_dir: Path, force: bool = False) -> Dict:
    """Run ASan replay for a single spec run directory.

    Args:
        run_dir: Path to spec run directory (e.g., se_runs/.../727_xmlschemastypes...)
        force: If True, re-run even if asan_result already exists in bug_report

    Returns:
        dict with asan replay result
    """
    harness_dir = run_dir / "harness"
    src_copy = run_dir / "src_copy"

    # Read bug report
    br_path = run_dir / "bug_report.json"
    if not br_path.exists():
        return {"success": False, "error": "No bug_report.json found"}

    br = read_json(br_path)
    if not br:
        return {"success": False, "error": "Failed to parse bug_report.json"}

    # Check if already has ASan result
    existing_asan = br.get("asan_result", {})
    if existing_asan.get("triggered") and not force:
        print(f"  [i] ASan already confirmed (use --force to re-run)")
        return {"success": True, "skipped": True, **existing_asan}

    # Get crashes
    crashes = br.get("all_crashes", [])
    if not crashes:
        return {"success": False, "error": "No crashes in bug report"}

    # Find KLEE output dir
    klee_dir = None
    for d in sorted((run_dir / "logs").glob("klee_run_*")):
        if d.is_dir():
            klee_dir = d
            break
    if not klee_dir:
        return {"success": False, "error": "No KLEE output directory found"}

    # Find ktest files
    ktests = sorted(klee_dir.glob("*.ktest"))
    if not ktests:
        return {"success": False, "error": "No .ktest files found"}

    print(f"  [i] Found {len(ktests)} ktest file(s), {len(crashes)} crash(es)")

    # Use the first crash's ktest (usually the most relevant)
    crash = crashes[0]
    ktest_path = crash.get("ktest", str(ktests[0]))

    # Decode ktest
    objects = decode_ktest(ktest_path)
    if not objects:
        # Fallback: try the first ktest file directly
        objects = decode_ktest(str(ktests[0]))
    print(f"  [i] Decoded ktest: {len(objects)} symbolic objects")
    for obj in objects:
        print(f"      {obj['name']}: {obj['size']} bytes")

    # Read driver source
    driver_path = harness_dir / "driver.c"
    if not driver_path.exists():
        return {"success": False, "error": "No driver.c in harness"}
    driver_src = driver_path.read_text(errors="replace")

    # Generate replay driver
    replay_driver = generate_replay_driver(driver_src, objects)

    # Create replay directory
    replay_dir = run_dir / "asan_replay"
    if replay_dir.exists():
        shutil.rmtree(replay_dir)
    replay_dir.mkdir(parents=True)

    # Write replay driver
    replay_driver_path = replay_dir / "replay_driver.c"
    replay_driver_path.write_text(replay_driver, encoding="utf-8")
    print(f"  [+] Wrote replay driver: {replay_driver_path.name}")

    # Only compile the replay driver (no companion harness .c files —
    # those are self-confirming sliced code with no validation signal)
    harness_c_files = [str(replay_driver_path)]

    # Build include flags
    # -isystem /usr/include FIRST so <string.h> resolves to real libc
    inc_flags = ["-isystem", "/usr/include",
                 "-I", str(harness_dir), "-I", str(src_copy)]

    # Add source subdirs with -idirafter (lower priority than system headers)
    if src_copy.exists():
        for root, dirs, files in os.walk(str(src_copy)):
            if any(f.endswith('.h') for f in files):
                inc_flags.extend(["-idirafter", root])

    # Auto-detect project macros (e.g., IN_LIBXML)
    extra_defs = []
    for hfile in (src_copy.rglob("lib*.h") if src_copy.exists() else []):
        stem = hfile.stem.upper()
        extra_defs.append(f"-D{f'IN_{stem}'}")
        break

    # Compile with ASan
    cflags = ["-fsanitize=address", "-fno-omit-frame-pointer", "-g", "-O0", "-w"]
    cflags.extend(extra_defs)
    cflags.extend(inc_flags)

    out_bin = replay_dir / "replay_bin"
    cmd = ["gcc"] + cflags + harness_c_files + ["-o", str(out_bin), "-lm"]

    print(f"  [ASan] Compiling {len(harness_c_files)} files with ASan...")
    rc, stdout, stderr, elapsed = run_cmd(cmd, timeout=60)

    if rc != 0:
        print(f"  [ASan] gcc failed: {stderr[:300]}")
        cmd[0] = "clang"
        print(f"  [ASan] Trying clang...")
        rc, stdout, stderr, elapsed = run_cmd(cmd, timeout=60)

    if rc != 0:
        print(f"  [ASan] clang also failed: {stderr[:300]}")
        return {"success": False, "error": f"Compilation failed: {stderr[:500]}",
                "compile_stderr": stderr[:2000]}

    print(f"  [ASan] Compiled successfully")

    # Run with ASan
    env = {**os.environ, "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1:print_stacktrace=1"}
    print(f"  [ASan] Running replay binary...")
    rc, stdout, stderr, elapsed = run_cmd([str(out_bin)], timeout=10, env=env)

    asan_result = parse_asan_output(stderr)
    asan_result["exit_code"] = rc
    asan_result["elapsed"] = elapsed
    asan_result["success"] = True

    if asan_result["triggered"]:
        print(f"  [ASan] TRIGGERED: {asan_result['error_type']}")
        print(f"  [ASan] Function: {asan_result['crash_function']}")
        print(f"  [ASan] Location: {asan_result['crash_file']}:{asan_result['crash_line']}")
    elif rc != 0:
        print(f"  [ASan] Crashed (exit={rc}) but no ASan report")
    else:
        print(f"  [ASan] No crash detected")

    # Update bug report
    br["asan_result"] = {
        "triggered": asan_result["triggered"],
        "error_type": asan_result.get("error_type", ""),
        "crash_function": asan_result.get("crash_function", ""),
        "crash_file": asan_result.get("crash_file", ""),
        "crash_line": asan_result.get("crash_line", 0),
        "original_file": "",
        "original_line": 0,
        "original_code": "",
        "original_context": "",
        "output": asan_result.get("output", ""),
    }
    if asan_result["triggered"]:
        br["summary"]["asan_confirmed"] = True
        # Update verdict if currently LIKELY_TP
        if br["summary"].get("verdict", "").startswith("LIKELY_TP"):
            br["summary"]["verdict"] = "SE_DETECTED"
            print(f"  [Report] Verdict upgraded to SE_DETECTED")
        br["summary"]["total_asan_crashes"] = 1
        br["summary"]["target_asan_crashes"] = 1

    write_json(br_path, br)
    print(f"  [Report] Updated: {br_path}")

    return asan_result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Standalone ASan replay for SAILOR KLEE results")
    parser.add_argument("run_dirs", nargs="*", help="Spec run directories to replay")
    parser.add_argument("--results-dir", help="Project results dir (replays all specs with bug_report.json)")
    parser.add_argument("--force", action="store_true", help="Re-run even if ASan already confirmed")
    args = parser.parse_args()

    run_dirs = []
    if args.results_dir:
        base = Path(args.results_dir)
        for d in sorted(base.iterdir()):
            if d.is_dir() and (d / "bug_report.json").exists():
                run_dirs.append(d)
    for rd in (args.run_dirs or []):
        run_dirs.append(Path(rd))

    if not run_dirs:
        parser.error("Provide run directories or --results-dir")

    print(f"=== ASan Replay for {len(run_dirs)} spec(s) ===\n")

    results = {}
    for rd in run_dirs:
        spec_name = rd.name
        print(f"\n--- {spec_name} ---")
        result = replay_spec(rd, force=args.force)
        results[spec_name] = result

    # Summary
    print(f"\n{'='*60}")
    print(f"ASan Replay Summary:")
    triggered = sum(1 for r in results.values() if r.get("triggered"))
    failed = sum(1 for r in results.values() if not r.get("success"))
    skipped = sum(1 for r in results.values() if r.get("skipped"))
    print(f"  Total:     {len(results)}")
    print(f"  Triggered: {triggered}")
    print(f"  Failed:    {failed}")
    print(f"  Skipped:   {skipped}")
    print(f"{'='*60}")

    return 0 if triggered > 0 or skipped > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
