#!/usr/bin/env python3
"""Concrete validation for all SAILOR baselines.

Validates baseline-reported bugs against the project source compiled with
AddressSanitizer. Provides uniform validation across all baselines.

For KLEE-based baselines (B1, B2):
  - Decodes KLEE .ktest files to extract concrete input values
  - Generates replay_driver.c with concrete values injected
  - Compiles replay_driver.c + stubs.c with ASan
  - Runs and checks for ASan crashes

For LLM-based baselines (B3, B4, B5):
  - Takes the LLM-generated crashing inputs and builds a replay driver
  - Compiles replay driver with ASan against project .a
  - Runs and checks for ASan crashes

For A1 (SAILOR - SA):
  - Same KLEE replay approach as B1/B2
  - A1 uses SAILOR engine directory layout

Usage:
    python3 baselines/concrete_validate_baseline.py \
        --baseline-type b2 \
        --baseline-dir se_runs/b2/libtiff_f324415_vul \
        --dataset-root dataset/f324415/libtiff_f324415_vul
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent / "common"))
from baseline_utils import (
    compile_with_asan,
    run_with_asan,
    dedup_bugs,
    write_summary_tsv,
)

# ── ktest decoding ──────────────────────────────────────────────────

def decode_ktest(ktest_path: str) -> Optional[Dict]:
    """Decode a KLEE .ktest file using ktest-tool.

    Returns dict with {"objects": [{"name", "size", "data"}, ...]}
    or None on failure.
    """
    if not os.path.exists(ktest_path):
        return None

    try:
        proc = subprocess.run(
            ["ktest-tool", ktest_path],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    # Parse ktest-tool output:
    #   object 0: name: b'sym_name'
    #   object 0: size: 4
    #   object 0: data: b'\x00\x01\x02\x03'
    obj_fields: Dict[int, Dict[str, str]] = {}
    for line in proc.stdout.splitlines():
        m = re.match(r"\s*object\s+(\d+):\s*(\w+):\s*(.*)", line)
        if m:
            idx = int(m.group(1))
            field = m.group(2).strip()
            value = m.group(3).strip()
            if idx not in obj_fields:
                obj_fields[idx] = {}
            obj_fields[idx][field] = value

    objects = []
    for idx in sorted(obj_fields.keys()):
        fields = obj_fields[idx]
        name_raw = fields.get("name", "")
        nm = re.match(r"b'([^']*)'", name_raw)
        name = nm.group(1) if nm else name_raw.strip("'\"")

        try:
            size = int(fields.get("size", "0"))
        except ValueError:
            size = 0

        data = fields.get("data", "")
        if name:
            objects.append({"name": name, "size": size, "data": data})

    return {"objects": objects}


def _parse_ktest_data(data_str: str, expected_size: int) -> List[int]:
    """Parse ktest-tool data string into byte values.

    Handles:
      b'\\x00\\x01\\x02'  (Python bytes literal)
      0x00000001           (hex integer)
    """
    byte_values: List[int] = []

    if not data_str:
        return [0] * expected_size

    # Format 1: Python bytes literal
    if data_str.startswith("b'") or data_str.startswith('b"'):
        inner = data_str[2:-1]
        i = 0
        while i < len(inner):
            if inner[i] == '\\' and i + 1 < len(inner):
                nxt = inner[i + 1]
                if nxt == 'x' and i + 3 < len(inner):
                    try:
                        byte_values.append(int(inner[i + 2:i + 4], 16))
                        i += 4
                        continue
                    except ValueError:
                        pass
                elif nxt == '0':
                    byte_values.append(0); i += 2; continue
                elif nxt == 'n':
                    byte_values.append(10); i += 2; continue
                elif nxt == 't':
                    byte_values.append(9); i += 2; continue
                elif nxt == '\\':
                    byte_values.append(ord('\\')); i += 2; continue
            byte_values.append(ord(inner[i]) if i < len(inner) else 0)
            i += 1

    # Format 2: hex integer
    elif data_str.startswith("0x"):
        try:
            val = int(data_str, 16)
            for i in range(expected_size):
                byte_values.append(
                    (val >> (8 * (expected_size - 1 - i))) & 0xFF
                )
        except ValueError:
            byte_values = [0] * expected_size

    # Pad or truncate
    if len(byte_values) < expected_size:
        byte_values.extend([0] * (expected_size - len(byte_values)))
    elif len(byte_values) > expected_size:
        byte_values = byte_values[:expected_size]

    return byte_values


# ── Replay driver generation ────────────────────────────────────────

def generate_replay_driver(driver_source: str, ktest_info: Dict) -> str:
    """Transform a KLEE symbolic driver into a concrete replay driver.

    Replaces klee_make_symbolic() with concrete byte injection from ktest,
    removes klee_assume/klee_assert, strips klee includes.
    """
    if not driver_source:
        return ""

    replay = driver_source
    objects = ktest_info.get("objects", [])
    obj_map = {obj["name"]: obj for obj in objects}

    # Remove klee includes
    replay = re.sub(
        r'#include\s*[<"]klee/klee\.h[>"]',
        '// klee removed for replay', replay
    )

    def replace_symbolic(m):
        args_str = m.group(1)
        parts = [p.strip() for p in args_str.split(',')]
        if len(parts) < 3:
            return (f'memset({parts[0]}, 0, '
                    f'{parts[1] if len(parts) > 1 else "1"}); '
                    f'/* replay: parse error */')

        ptr = parts[0]
        size = parts[1]
        name = parts[2].strip('"').strip("'")

        if name in obj_map:
            obj = obj_map[name]
            byte_values = _parse_ktest_data(
                obj.get("data", ""), obj.get("size", 0)
            )
            if byte_values:
                hex_vals = ', '.join(f'0x{b:02x}' for b in byte_values[:512])
                safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
                return (
                    f'{{ /* replay: concrete values for "{name}" '
                    f'({len(byte_values)} bytes) */\n'
                    f'  static const unsigned char {safe_name}_data[] = '
                    f'{{{hex_vals}}};\n'
                    f'  memcpy({ptr}, {safe_name}_data, '
                    f'({size}) < {len(byte_values)} ? '
                    f'({size}) : {len(byte_values)});\n'
                    f'}}'
                )
        return (f'memset({ptr}, 0xAA, {size}); '
                f'/* replay: "{name}" not in ktest */')

    # Replace klee_make_symbolic (handles one level of nested parens)
    replay = re.sub(
        r'klee_make_symbolic\s*\(((?:[^()]|\([^()]*\))+)\)\s*;',
        replace_symbolic, replay
    )

    # Remove klee_assume / klee_assert
    replay = re.sub(
        r'klee_assume\s*\((?:[^()]|\([^()]*\))+\)\s*;',
        '/* klee_assume removed */', replay
    )
    replay = re.sub(
        r'klee_assert\s*\((?:[^()]|\([^()]*\))+\)\s*;',
        '/* klee_assert removed */', replay
    )

    # Remove SAILOR markers
    replay = re.sub(r'/\*.*?SAILOR_SINK_REACHED.*?\*/', '', replay)
    replay = re.sub(r'/\*.*?SAILOR_PROBE.*?\*/', '', replay)

    # Add header
    header = (
        '/* AUTO-GENERATED REPLAY DRIVER for concrete validation\n'
        ' * Compile: clang -fsanitize=address -g -O0 replay_driver.c '
        'stubs.c -o replay\n */\n'
        '#include <string.h>\n'
        '#include <stdlib.h>\n'
        '#include <stdio.h>\n\n'
    )
    replay = header + replay

    return replay


# ── A1 (SAILOR) multi-file harness support ──────────────────────────

def _match_balanced_parens(text: str, start: int) -> int:
    """Return index after the closing ')' matching the '(' at text[start]."""
    assert text[start] == '('
    depth = 1
    i = start + 1
    while i < len(text) and depth > 0:
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
        i += 1
    return i if depth == 0 else -1


def _remove_klee_call(source: str, func_name: str,
                      replacement: str = '') -> str:
    """Remove all occurrences of func_name(...) with balanced parens."""
    pattern = re.compile(r'\b' + re.escape(func_name) + r'\s*\(')
    out_parts: List[str] = []
    last = 0
    for m in pattern.finditer(source):
        paren_start = m.end() - 1
        paren_end = _match_balanced_parens(source, paren_start)
        if paren_end == -1:
            continue
        end = paren_end
        rest = source[end:]
        semi = re.match(r'\s*;', rest)
        if semi:
            end += semi.end()
        out_parts.append(source[last:m.start()])
        out_parts.append(replacement)
        last = end
    out_parts.append(source[last:])
    return ''.join(out_parts)


def _split_top_level(text: str, sep: str) -> List[str]:
    """Split text on sep only at the top nesting level."""
    parts: List[str] = []
    depth = 0
    current: List[str] = []
    for ch in text:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(''.join(current))
            current = []
        else:
            current.append(ch)
    parts.append(''.join(current))
    return parts


def _replace_make_symbolic(source: str) -> str:
    """klee_make_symbolic(ptr, size, name) -> memset(ptr, 0xAA, size)."""
    pattern = re.compile(r'\bklee_make_symbolic\s*\(')
    out_parts: List[str] = []
    last = 0
    for m in pattern.finditer(source):
        paren_start = m.end() - 1
        paren_end = _match_balanced_parens(source, paren_start)
        if paren_end == -1:
            continue
        inner = source[paren_start + 1:paren_end - 1]
        args = _split_top_level(inner, ',')
        if len(args) >= 2:
            ptr = args[0].strip()
            size = args[1].strip()
            repl = f'memset({ptr}, 0xAA, {size})'
        else:
            repl = '/* klee_make_symbolic removed */'
        end = paren_end
        rest = source[end:]
        semi = re.match(r'\s*;', rest)
        if semi:
            end += semi.end()
            repl += ';'
        out_parts.append(source[last:m.start()])
        out_parts.append(repl)
        last = end
    out_parts.append(source[last:])
    return ''.join(out_parts)


def _convert_klee_to_concrete(source: str) -> str:
    """Convert KLEE-instrumented C source to concrete replay.

    Strips klee/klee.h, replaces klee_make_symbolic with memset(0xAA),
    removes klee_assume/assert/warning and SAILOR markers.
    """
    out = source
    out = re.sub(r'#include\s*[<"]klee/klee\.h[>"]\s*\n?', '', out)
    out = _replace_make_symbolic(out)
    out = _remove_klee_call(out, 'klee_assume', '/* klee_assume removed */')
    out = _remove_klee_call(out, 'klee_assert', '/* klee_assert removed */')
    out = _remove_klee_call(out, 'klee_warning')
    out = _remove_klee_call(out, 'klee_warning_once')
    out = re.sub(r'/\*.*?SAILOR_SINK_REACHED.*?\*/', '', out)
    out = re.sub(r'/\*.*?SAILOR_PROBE.*?\*/', '', out)
    return out


def _generate_asan_replay(harness_dir: Path, replay_dir: Path) -> bool:
    """Generate asan_replay/ from harness/ for A1 multi-file harnesses.

    Converts all files: driver.c -> replay_driver.c, stubs, sliced .c,
    and .h files.  All KLEE API calls are replaced with concrete values.
    """
    driver_c = harness_dir / "driver.c"
    if not driver_c.exists():
        return False

    replay_dir.mkdir(parents=True, exist_ok=True)

    # Convert driver.c -> replay_driver.c
    driver_src = driver_c.read_text(errors="replace")
    replay_src = _convert_klee_to_concrete(driver_src)
    (replay_dir / "replay_driver.c").write_text(replay_src, encoding="utf-8")

    # Copy and convert stubs
    for stub_name in ["stubs.c", "smart_stubs.c", "auto_stubs.c"]:
        stub_path = harness_dir / stub_name
        if stub_path.exists():
            stub_src = stub_path.read_text(errors="replace")
            clean = _convert_klee_to_concrete(stub_src)
            (replay_dir / stub_name).write_text(clean, encoding="utf-8")

    # Copy and convert header files
    for h_file in harness_dir.glob("*.h"):
        content = h_file.read_text(errors="replace")
        clean = _convert_klee_to_concrete(content)
        (replay_dir / h_file.name).write_text(clean, encoding="utf-8")

    # Copy and convert sliced .c files (not driver/stubs)
    for c_file in harness_dir.glob("*.c"):
        if c_file.name in ("driver.c", "stubs.c", "smart_stubs.c",
                           "auto_stubs.c"):
            continue
        content = c_file.read_text(errors="replace")
        clean = _convert_klee_to_concrete(content)
        (replay_dir / c_file.name).write_text(clean, encoding="utf-8")

    return True


def _validate_a1_finding(
    spec: str,
    crash_info: Dict,
    artifacts: Dict,
    dataset_root: Path,
    val_dir: Path,
) -> Dict:
    """Validate A1 finding using full multi-file harness conversion.

    Unlike B1/B2 which only compile replay_driver.c + stubs.c, A1 uses
    SAILOR's full engine with multi-file harnesses that include sliced
    library source files and harness_types.h.
    """
    harness_dir = artifacts["harness_dir"]
    replay_dir = val_dir / "asan_replay"

    if not _generate_asan_replay(harness_dir, replay_dir):
        return _validation_result(
            spec, "REPLAY_GEN_FAIL", crash_info,
            "Failed to generate asan_replay/"
        )

    # Compile ALL .c files from asan_replay/
    sources = [str(f) for f in sorted(replay_dir.glob("*.c"))]
    if not sources:
        return _validation_result(
            spec, "REPLAY_GEN_FAIL", crash_info,
            "No .c files in asan_replay/"
        )

    binary = str(val_dir / "replay")
    include_dirs = _build_include_dirs(dataset_root)
    include_dirs.append(str(replay_dir))  # For harness_types.h etc.

    ok, err = compile_with_asan(
        sources, binary,
        include_dirs=include_dirs,
        extra_flags=["-w"],
    )

    if not ok:
        (val_dir / "compile_error.txt").write_text(err, encoding="utf-8")
        return _validation_result(
            spec, "REPLAY_BUILD_FAIL", crash_info, err[:200]
        )

    # Run with ASan
    asan = run_with_asan(binary, timeout=30)
    if "output" in asan:
        (val_dir / "asan_output.txt").write_text(
            asan["output"], encoding="utf-8"
        )

    return _classify_asan_result(spec, crash_info, asan)


# ── Artifact discovery per baseline type ────────────────────────────

def find_klee_artifacts_b1(
    spec: str, baseline_dir: Path
) -> Optional[Dict]:
    """Find KLEE artifacts for a B1 spec.

    B1 layout: <baseline_dir>/<harness_name>/klee_out/
               <baseline_dir>/<harness_name>/harness/klee_driver.c
    """
    # Spec format: <harness_name>_<bugfile>_<bugline>_<bugtype>
    # We need to find the harness name (prefix before the crash info)
    # Search for harness dirs that are prefixes of the spec
    for d in baseline_dir.iterdir():
        if not d.is_dir() or d.name == "findings":
            continue
        if spec.startswith(d.name):
            klee_out = d / "klee_out"
            harness_dir = d / "harness"
            if klee_out.exists() and harness_dir.exists():
                driver = harness_dir / "klee_driver.c"
                stubs = None
                # B1 may not have stubs.c
                for sf in harness_dir.glob("stubs*.c"):
                    stubs = sf
                    break
                return {
                    "klee_out": klee_out,
                    "driver": driver if driver.exists() else None,
                    "harness_dir": harness_dir,
                    "stubs": stubs,
                }
    return None


def find_klee_artifacts_b2(
    spec: str, baseline_dir: Path
) -> Optional[Dict]:
    """Find KLEE artifacts for a B2 spec.

    B2 layout: findings/<name>/harness/{harness.c, driver.c, stubs.c}
               findings/<name>/klee_out/
    """
    findings_dir = baseline_dir / "findings"
    if not findings_dir.exists():
        return None

    # Spec might be harness name or harness_name_crash<N>
    harness_name = re.sub(r'_crash\d+$', '', spec)
    harness_dir = findings_dir / harness_name / "harness"
    klee_out = findings_dir / harness_name / "klee_out"

    if not harness_dir.exists() or not klee_out.exists():
        return None

    driver = harness_dir / "driver.c"
    stubs = harness_dir / "stubs.c"

    return {
        "klee_out": klee_out,
        "driver": driver if driver.exists() else None,
        "harness_dir": harness_dir,
        "stubs": stubs if stubs.exists() else None,
    }


def find_reproducer_b3(
    spec: str, baseline_dir: Path
) -> Optional[Path]:
    """Find replay driver for a B3 spec.

    B3 layout: findings/<vuln_id>/reproducer.c
    """
    repro = baseline_dir / "findings" / spec / "reproducer.c"
    if repro.exists():
        return repro
    return None


def find_reproducer_b4(
    spec: str, baseline_dir: Path
) -> Optional[Path]:
    """Find replay driver for a B4 spec.

    B4 layout: findings/<basename>/repro_<idx>_<line>/reproducer.c
    """
    findings_dir = baseline_dir / "findings"
    if not findings_dir.exists():
        return None

    # Search all repro dirs for matching spec
    for file_dir in findings_dir.iterdir():
        if not file_dir.is_dir():
            continue
        for repro_dir in file_dir.iterdir():
            if not repro_dir.is_dir():
                continue
            repro = repro_dir / "reproducer.c"
            if repro.exists():
                # Check if this repro_dir relates to the spec
                # Spec format: <idx>_<basename>_<line>_<rule>
                # repro_dir name: repro_<finding_idx>_<line>
                parts = spec.split("_")
                if len(parts) >= 3:
                    spec_line = parts[-2]  # line number
                    if spec_line in repro_dir.name:
                        return repro

    # Fallback: search by spec index
    parts = spec.split("_")
    if parts:
        idx_str = parts[0]
        for file_dir in findings_dir.iterdir():
            if not file_dir.is_dir():
                continue
            for repro_dir in file_dir.iterdir():
                if not repro_dir.is_dir():
                    continue
                if idx_str in repro_dir.name:
                    repro = repro_dir / "reproducer.c"
                    if repro.exists():
                        return repro
    return None


def find_klee_artifacts_a1(
    spec: str, baseline_dir: Path
) -> Optional[Dict]:
    """Find KLEE artifacts for an A1 spec.

    A1 uses SAILOR engine layout:
    se_runs/sailor_engine/<project>/<spec_name>/harness/{driver.c,harness.c,stubs.c}
    se_runs/sailor_engine/<project>/<spec_name>/logs/klee_run_*/
    """
    # A1 output is nested: baseline_dir/se_runs/sailor_engine/<project>/<spec>/
    se_dir = baseline_dir / "se_runs" / "sailor_engine"
    if not se_dir.exists():
        return None

    # Find the project subdir
    for proj_dir in se_dir.iterdir():
        if not proj_dir.is_dir():
            continue
        spec_dir = proj_dir / spec
        if not spec_dir.exists():
            continue

        harness_dir = spec_dir / "harness"
        if not harness_dir.exists():
            continue

        # Find KLEE output (may be in logs/klee_run_N/)
        klee_out = None
        logs_dir = spec_dir / "logs"
        if logs_dir.exists():
            klee_dirs = sorted(logs_dir.glob("klee_run_*"), reverse=True)
            for kd in klee_dirs:
                if list(kd.glob("*.err")):
                    klee_out = kd
                    break

        driver = harness_dir / "driver.c"
        stubs = harness_dir / "stubs.c"
        if not stubs.exists():
            stubs = harness_dir / "smart_stubs.c"

        return {
            "klee_out": klee_out,
            "driver": driver if driver.exists() else None,
            "harness_dir": harness_dir,
            "stubs": stubs if stubs.exists() else None,
        }
    return None


# ── Validation functions ────────────────────────────────────────────

def _build_include_dirs(dataset_root: Path) -> List[str]:
    """Build include directories for ASan compilation."""
    dirs = [str(dataset_root)]
    for sub in ["include", "libtiff", ".", "src", "lib"]:
        inc = dataset_root / sub
        if inc.is_dir():
            dirs.append(str(inc))
    return dirs


def validate_klee_finding(
    spec: str,
    crash_info: Dict,
    artifacts: Dict,
    dataset_root: Path,
    val_dir: Path,
    baseline_type: str = "",
) -> Dict:
    """Validate a KLEE-reported crash via ASan replay.

    1. Find the .ktest file for the crash
    2. Decode it
    3. Generate replay_driver.c
    4. Compile with ASan
    5. Run and classify

    For A1 (baseline_type="a1"), uses multi-file harness conversion
    instead of ktest decoding.
    """
    val_dir.mkdir(parents=True, exist_ok=True)

    # A1 uses multi-file harnesses — delegate to dedicated handler
    if baseline_type == "a1":
        return _validate_a1_finding(
            spec, crash_info, artifacts, dataset_root, val_dir
        )
    klee_out = artifacts["klee_out"]
    driver_path = artifacts.get("driver")
    harness_dir = artifacts["harness_dir"]
    stubs_path = artifacts.get("stubs")

    # Find .ktest file for this crash
    ktest_path = crash_info.get("ktest_file", "")
    if not ktest_path or not os.path.exists(ktest_path):
        # Try to find any .ktest with matching .err
        err_file = crash_info.get("err_file", "")
        if err_file:
            ktest_path = err_file.replace(".err", ".ktest")

    if not ktest_path or not os.path.exists(ktest_path):
        # Fallback: find first .ktest in klee_out
        ktests = sorted(klee_out.glob("*.ktest")) if klee_out else []
        if ktests:
            ktest_path = str(ktests[0])
        else:
            return _validation_result(
                spec, "NO_KTEST", crash_info, "No .ktest file found"
            )

    # Decode ktest
    ktest_info = decode_ktest(ktest_path)
    if not ktest_info or not ktest_info.get("objects"):
        return _validation_result(
            spec, "KTEST_DECODE_FAIL", crash_info, "Failed to decode .ktest"
        )

    # Read driver source
    driver_source = ""
    if driver_path and driver_path.exists():
        driver_source = driver_path.read_text(errors="replace")
    else:
        return _validation_result(
            spec, "NO_DRIVER", crash_info, "No driver.c found"
        )

    # Generate replay driver
    replay_source = generate_replay_driver(driver_source, ktest_info)
    if not replay_source:
        return _validation_result(
            spec, "REPLAY_GEN_FAIL", crash_info, "Failed to generate replay"
        )

    replay_path = val_dir / "replay_driver.c"
    replay_path.write_text(replay_source, encoding="utf-8")

    # Copy harness.c if present (driver.c typically #includes it)
    for hf in ["harness.c", "harness.h"]:
        src = harness_dir / hf
        if src.exists():
            dst = val_dir / hf
            if not dst.exists():
                dst.write_text(src.read_text(errors="replace"), encoding="utf-8")

    # Build source list
    sources = [str(replay_path)]
    if stubs_path and stubs_path.exists():
        stubs_copy = val_dir / stubs_path.name
        stubs_copy.write_text(
            stubs_path.read_text(errors="replace"), encoding="utf-8"
        )
        sources.append(str(stubs_copy))

    binary = str(val_dir / "replay")
    include_dirs = _build_include_dirs(dataset_root)
    # Also include harness dir for local includes
    include_dirs.append(str(val_dir))

    ok, err = compile_with_asan(
        sources, binary,
        include_dirs=include_dirs,
        extra_flags=["-w"],
    )

    if not ok:
        (val_dir / "compile_error.txt").write_text(err, encoding="utf-8")
        return _validation_result(
            spec, "REPLAY_BUILD_FAIL", crash_info, err[:200]
        )

    # Run with ASan
    asan = run_with_asan(binary, timeout=30)
    if "output" in asan:
        (val_dir / "asan_output.txt").write_text(
            asan["output"], encoding="utf-8"
        )

    return _classify_asan_result(spec, crash_info, asan)


def validate_reproducer(
    spec: str,
    reproducer_path: Path,
    dataset_root: Path,
    val_dir: Path,
    crash_info: Dict,
) -> Dict:
    """Validate LLM-generated crashing inputs via ASan replay.

    1. Compile replay driver with ASan + project .a
    2. Run and classify
    """
    val_dir.mkdir(parents=True, exist_ok=True)

    # Copy reproducer to validation dir
    repro_copy = val_dir / "reproducer.c"
    repro_copy.write_text(
        reproducer_path.read_text(errors="replace"), encoding="utf-8"
    )

    binary = str(val_dir / "reproducer")
    include_dirs = _build_include_dirs(dataset_root)

    ok, err = compile_with_asan(
        [str(repro_copy)], binary,
        include_dirs=include_dirs,
        extra_flags=["-w"],
    )

    if not ok:
        (val_dir / "compile_error.txt").write_text(err, encoding="utf-8")
        return _validation_result(
            spec, "REPRODUCER_BUILD_FAIL", crash_info, err[:200]
        )

    # Run with ASan
    asan = run_with_asan(binary, timeout=30)
    if "output" in asan:
        (val_dir / "asan_output.txt").write_text(
            asan["output"], encoding="utf-8"
        )

    return _classify_asan_result(spec, crash_info, asan)


def _classify_asan_result(
    spec: str, crash_info: Dict, asan: Dict
) -> Dict:
    """Classify ASan replay result."""
    if asan.get("asan_triggered"):
        if asan.get("is_harness_artifact"):
            status = "HARNESS_ARTIFACT"
        else:
            status = "CONCRETE_CONFIRMED"
    elif asan.get("timeout"):
        status = "TIMEOUT"
    else:
        status = "NOT_REPRODUCIBLE"

    return {
        "Spec": spec,
        "ConcreteStatus": status,
        "BugType": asan.get("error_type", crash_info.get("BugType", "")),
        "BugFile": os.path.basename(
            asan.get("crash_file", crash_info.get("BugFile", ""))
        ),
        "BugLine": asan.get("crash_line", crash_info.get("BugLine", 0)),
        "BugFunc": asan.get("crash_function", crash_info.get("BugFunc", "")),
        "CWE": crash_info.get("CWE", ""),
        "OriginalStatus": crash_info.get("FinalStatus", ""),
    }


def _validation_result(
    spec: str, status: str, crash_info: Dict, message: str = ""
) -> Dict:
    """Create a validation result for non-ASan outcomes."""
    return {
        "Spec": spec,
        "ConcreteStatus": status,
        "BugType": crash_info.get("BugType", ""),
        "BugFile": crash_info.get("BugFile", ""),
        "BugLine": crash_info.get("BugLine", 0),
        "BugFunc": crash_info.get("BugFunc", ""),
        "CWE": crash_info.get("CWE", ""),
        "OriginalStatus": crash_info.get("FinalStatus", ""),
        "Message": message,
    }


# ── Summary reading ────────────────────────────────────────────────

def read_summary(baseline_dir: Path, baseline_type: str) -> List[Dict]:
    """Read summary.tsv from a baseline output directory."""
    # A1 has nested layout
    if baseline_type == "a1":
        se_dir = baseline_dir / "se_runs" / "sailor_engine"
        if se_dir.exists():
            for proj_dir in se_dir.iterdir():
                if proj_dir.is_dir():
                    summary = proj_dir / "summary.tsv"
                    if summary.exists():
                        return _read_tsv(summary)
    summary = baseline_dir / "summary.tsv"
    if summary.exists():
        return _read_tsv(summary)
    return []


def _read_tsv(path: Path) -> List[Dict]:
    """Read a TSV file into list of dicts."""
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            # Normalize numeric fields
            for k in ("BugLine", "Time", "Tokens"):
                if k in row:
                    try:
                        row[k] = int(row[k])
                    except (ValueError, TypeError):
                        row[k] = 0
            rows.append(row)
    return rows


# ── Crash info extraction from summary row ──────────────────────────

def _extract_crash_info(row: Dict, baseline_type: str) -> Dict:
    """Extract crash metadata from a summary.tsv row for ktest lookup."""
    info = {
        "Spec": row.get("Spec", ""),
        "FinalStatus": row.get("FinalStatus", ""),
        "BugType": row.get("BugType", ""),
        "BugFile": row.get("BugFile", ""),
        "BugLine": row.get("BugLine", 0),
        "BugFunc": row.get("BugFunc", ""),
        "CWE": row.get("CWE", ""),
    }

    # For B1/B2: reconstruct the ktest_file path from KLEE output
    # The .err → .ktest mapping is done in the validate function
    return info


def _find_ktest_for_crash(
    crash_info: Dict, klee_out: Path
) -> Optional[str]:
    """Find the .ktest file for a specific crash in klee_out/.

    Matches by error type and file/line from .err contents.
    """
    if not klee_out or not klee_out.exists():
        return None

    bug_type = crash_info.get("BugType", "")
    bug_file = crash_info.get("BugFile", "")
    bug_line = crash_info.get("BugLine", 0)

    for err_file in sorted(klee_out.glob("*.err")):
        content = err_file.read_text(errors="replace")
        m_file = re.search(r"File:\s*(\S+)", content)
        m_line = re.search(r"Line:\s*(\d+)", content)

        err_basename = ""
        err_line = 0
        if m_file:
            err_basename = os.path.basename(m_file.group(1).strip())
        if m_line:
            err_line = int(m_line.group(1))

        # Match on file+line or just type
        stem_parts = err_file.stem.split(".")
        err_type = stem_parts[-1] if len(stem_parts) > 1 else ""

        if ((err_basename == bug_file and err_line == bug_line) or
                (err_type == bug_type and err_basename == bug_file)):
            ktest = str(err_file).replace(".err", ".ktest")
            if os.path.exists(ktest):
                return ktest

    # Fallback: return first .ktest
    ktests = sorted(klee_out.glob("*.ktest"))
    return str(ktests[0]) if ktests else None


# ── Main pipeline ───────────────────────────────────────────────────

def run_validation(args):
    baseline_type = args.baseline_type
    baseline_dir = Path(args.baseline_dir).resolve()
    dataset_root = Path(args.dataset_root).resolve()
    val_root = baseline_dir / "concrete_validation"
    val_root.mkdir(parents=True, exist_ok=True)

    print(f"[CV] Baseline type:  {baseline_type}")
    print(f"[CV] Baseline dir:   {baseline_dir}")
    print(f"[CV] Dataset root:   {dataset_root}")
    print(f"[CV] Validation dir: {val_root}")

    is_klee_based = baseline_type in ("b1", "b2", "a1")
    is_reproducer_based = baseline_type in ("b3", "b4")

    # Read summary
    summary_rows = read_summary(baseline_dir, baseline_type)
    print(f"[CV] Total entries in summary: {len(summary_rows)}")

    # Filter to entries that claim bugs
    positive_statuses = {"SE_DETECTED", "CONCRETE_CONFIRMED"}
    candidates = [
        r for r in summary_rows
        if r.get("FinalStatus") in positive_statuses
    ]
    print(f"[CV] Entries to validate: {len(candidates)}")

    if not candidates:
        print("[CV] No entries to validate. Done.")
        _write_validation_summary(val_root, [])
        return

    # Validate each candidate
    results = []
    for idx, row in enumerate(candidates):
        spec = row.get("Spec", f"unknown_{idx}")
        crash_info = _extract_crash_info(row, baseline_type)
        val_dir = val_root / spec.replace("/", "_")

        print(f"\n[CV] [{idx+1}/{len(candidates)}] {spec}")

        if is_klee_based:
            # Find KLEE artifacts
            if baseline_type == "b1":
                artifacts = find_klee_artifacts_b1(spec, baseline_dir)
            elif baseline_type == "b2":
                artifacts = find_klee_artifacts_b2(spec, baseline_dir)
            elif baseline_type == "a1":
                artifacts = find_klee_artifacts_a1(spec, baseline_dir)
            else:
                artifacts = None

            if not artifacts:
                result = _validation_result(
                    spec, "NO_ARTIFACTS", crash_info, "KLEE artifacts not found"
                )
                results.append(result)
                print(f"  [NO_ARTIFACTS] Could not find KLEE output")
                continue

            # Find the specific .ktest for this crash
            ktest_path = _find_ktest_for_crash(
                crash_info, artifacts.get("klee_out")
            )
            if ktest_path:
                crash_info["ktest_file"] = ktest_path

            result = validate_klee_finding(
                spec, crash_info, artifacts, dataset_root, val_dir,
                baseline_type=baseline_type,
            )

        elif is_reproducer_based:
            # Find reproducer
            if baseline_type == "b3":
                repro_path = find_reproducer_b3(spec, baseline_dir)
            elif baseline_type == "b4":
                repro_path = find_reproducer_b4(spec, baseline_dir)
            else:
                repro_path = None

            if not repro_path:
                result = _validation_result(
                    spec, "NO_REPRODUCER", crash_info, "reproducer.c not found"
                )
                results.append(result)
                print(f"  [NO_REPRODUCER] Could not find reproducer.c")
                continue

            result = validate_reproducer(
                spec, repro_path, dataset_root, val_dir, crash_info
            )

        else:
            result = _validation_result(
                spec, "UNSUPPORTED", crash_info,
                f"Unsupported baseline type: {baseline_type}"
            )

        results.append(result)
        status = result.get("ConcreteStatus", "UNKNOWN")
        bug_info = (f"{result.get('BugType', '')} at "
                    f"{result.get('BugFile', '')}:{result.get('BugLine', 0)}")
        print(f"  [{status}] {bug_info}")

    # Write validation summary
    _write_validation_summary(val_root, results)

    # Print report
    n_confirmed = sum(1 for r in results
                      if r["ConcreteStatus"] == "CONCRETE_CONFIRMED")
    n_not_repro = sum(1 for r in results
                      if r["ConcreteStatus"] == "NOT_REPRODUCIBLE")
    n_harness = sum(1 for r in results
                    if r["ConcreteStatus"] == "HARNESS_ARTIFACT")
    n_build_fail = sum(1 for r in results
                       if r["ConcreteStatus"] in (
                           "REPLAY_BUILD_FAIL", "REPRODUCER_BUILD_FAIL"))
    n_other = len(results) - n_confirmed - n_not_repro - n_harness - n_build_fail

    # Dedup confirmed bugs
    if n_confirmed > 0:
        confirmed = [r for r in results
                     if r["ConcreteStatus"] == "CONCRETE_CONFIRMED"]
        bugs_for_dedup = [
            {"bug_file": r["BugFile"], "bug_line": r["BugLine"],
             "bug_type": r["BugType"], **r}
            for r in confirmed
        ]
        unique_bugs, n_dups = dedup_bugs(bugs_for_dedup)
    else:
        unique_bugs, n_dups = [], 0

    print(f"\n[CV] ═══ Concrete Validation Summary ═══")
    print(f"  Candidates validated: {len(results)}")
    print(f"  CONCRETE_CONFIRMED:   {n_confirmed}")
    print(f"  Unique confirmed:     {len(unique_bugs)}")
    print(f"  NOT_REPRODUCIBLE:     {n_not_repro}")
    print(f"  HARNESS_ARTIFACT:     {n_harness}")
    print(f"  Build failures:       {n_build_fail}")
    print(f"  Other:                {n_other}")
    print(f"  Results:              {val_root / 'validation_summary.tsv'}")


def _write_validation_summary(val_root: Path, results: List[Dict]):
    """Write validation results to TSV."""
    summary_path = val_root / "validation_summary.tsv"
    fields = [
        "Spec", "ConcreteStatus", "OriginalStatus",
        "BugType", "BugFile", "BugLine", "BugFunc", "CWE",
    ]
    with open(summary_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=fields, delimiter="\t",
            extrasaction="ignore",
        )
        writer.writeheader()
        for r in results:
            writer.writerow(r)


def main():
    parser = argparse.ArgumentParser(
        description="Concrete validation for SAILOR baselines"
    )
    parser.add_argument("--baseline-type", required=True,
                        choices=["b1", "b2", "b3", "b4", "a1"],
                        help="Baseline type")
    parser.add_argument("--baseline-dir", required=True,
                        help="Path to baseline output directory")
    parser.add_argument("--dataset-root", required=True,
                        help="Path to project source (same commit as SAILOR)")
    args = parser.parse_args()

    run_validation(args)


if __name__ == "__main__":
    main()