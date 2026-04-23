#!/usr/bin/env python3
"""Revalidate all baseline/SAILOR findings against unmodified upstream .a libraries.

For each finding that has a reproducer calling entry_func (or similar wrapper),
this script:
  1. Finds the sliced .c file in the finding directory
  2. Extracts what real library function entry_func calls
  3. Creates a minimal wrapper.c that bridges entry_func → real function
  4. Compiles reproducer + stubs + wrapper against the .a (NO sliced source)
  5. Runs with ASan and classifies the result

This is the authoritative validation: crashes must occur in the real library code.

Usage:
    python3 scripts/revalidate_against_lib.py \
        --findings-dir artifacts/baseline_concrete/a1/libtiff_f324415_vul/findings \
        --asan-lib /tmp/libtiff_upstream/build_asan/libtiff/libtiff.a \
        --include-dirs /tmp/libtiff_upstream/libtiff,/tmp/libtiff_upstream/build_asan \
        --src-root /tmp/libtiff_upstream \
        --extra-libs "-lm -lpthread -lz"
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

HARNESS_FILES = {"reproducer.c", "replay_driver.c", "smart_stubs.c",
                 "stubs.c", "auto_stubs.c", "driver.c", "harness_types.h",
                 "harness_types_upstream.h", "harness_types_agent.h",
                 "build.sh", "REPORT.md", "result.json", "reproducer_bin",
                 "upstream_asan_output.txt", "compile_error.txt"}


def run_cmd(cmd, timeout=60, cwd=None, env=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd, env=env)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def find_sliced_source(finding_dir: Path) -> list:
    """Find sliced .c files (everything that's not a known harness/meta file)."""
    sliced = []
    for f in sorted(finding_dir.glob("*.c")):
        if f.name not in HARNESS_FILES:
            sliced.append(f)
    return sliced


def find_entry_wrapper(finding_dir: Path) -> tuple:
    """Find what entry_func (or similar) calls in the sliced source.

    Returns (entry_name, real_func_name, wrapper_params) or (None, None, None).
    """
    # First check the reproducer to find what function it calls
    reproducer = finding_dir / "reproducer.c"
    if not reproducer.exists():
        reproducer = finding_dir / "replay_driver.c"
    if not reproducer.exists():
        return None, None, None

    repro_src = reproducer.read_text(errors="replace")

    # Find the declared entry function (before main)
    # Patterns: int entry_func(...); void entry_func(...);
    # Also: int harness_entry(...); int sail_entry(...); int tif_entry(...);
    entry_decl = re.search(
        r'(?:int|void)\s+(\w+)\s*\(([^)]*)\)\s*;',
        repro_src
    )
    if entry_decl:
        entry_name = entry_decl.group(1)
        entry_params = entry_decl.group(2)
    else:
        # Fallback: look for undeclared calls to entry_func/harness_entry/etc.
        call_match = re.search(r'\b(entry_func|harness_entry|sail_entry)\s*\(', repro_src)
        if not call_match:
            return None, None, None
        entry_name = call_match.group(1)
        entry_params = ""  # will be inferred from sliced source

    # Skip if the entry function is a real library function (not a wrapper)
    # Real library functions wouldn't cause undefined reference errors
    if entry_name.startswith("xml") or entry_name.startswith("html") or \
       entry_name.startswith("TIFF") or entry_name.startswith("png_"):
        return None, None, None

    # Now find what this wrapper calls in the sliced source
    sliced_files = find_sliced_source(finding_dir)
    for sliced in sliced_files:
        src = sliced.read_text(errors="replace")

        # Find entry function definition and extract the real function call
        # Also extract params if we didn't get them from the reproducer
        defn_match = re.search(
            r'(?:int|void)\s+' + re.escape(entry_name) +
            r'\s*\(([^)]*)\)\s*\{', src)
        if defn_match and not entry_params:
            entry_params = defn_match.group(1)

        # Match both simple and complex entry function bodies
        patterns = [
            # Pattern 1: int entry_func(...) { ... real_func(...); ... }
            re.compile(
                r'(?:int|void)\s+' + re.escape(entry_name) +
                r'\s*\([^)]*\)\s*\{([^}]*)\}', re.DOTALL),
            # Pattern 2: longer bodies with multiple statements
            re.compile(
                r'(?:int|void)\s+' + re.escape(entry_name) +
                r'\s*\([^)]*\)\s*\{((?:[^{}]|\{[^{}]*\})*)\}', re.DOTALL),
        ]

        for pat in patterns:
            m = pat.search(src)
            if not m:
                continue
            body = m.group(1)

            # Find function calls (excluding common helpers)
            skip = {'memset', 'memcpy', 'memmove', 'malloc', 'calloc',
                    'free', 'realloc', 'return', 'sizeof', 'printf',
                    'fprintf', 'abort', 'exit', 'klee_assert', 'klee_assume',
                    'klee_make_symbolic', 'klee_warning', 'if', 'while',
                    'for', 'switch', 'assert', 'strlen', 'strcpy', 'strdup',
                    'strncpy', 'strcmp', 'strncmp'}
            calls = []
            for cm in re.finditer(r'\b([a-zA-Z_]\w+)\s*\(', body):
                fname = cm.group(1)
                if fname not in skip:
                    calls.append(fname)

            # The real function is typically the first non-helper call
            if calls:
                real_func = calls[0]
                return entry_name, real_func, entry_params

    return entry_name, None, entry_params


def create_wrapper(finding_dir: Path, entry_name: str, real_func: str,
                   entry_params: str, include_dirs: list, src_root: str) -> Path:
    """Create a minimal wrapper.c that bridges entry_func → real library function.

    Uses harness_types.h from the finding dir (same types the reproducer uses)
    to avoid header conflicts with upstream project headers.
    """
    wrapper_path = finding_dir / "_wrapper.c"

    # Use the same harness_types.h as the reproducer for type consistency
    includes = ['#include <stdint.h>', '#include <stddef.h>']
    if (finding_dir / "harness_types.h").exists():
        includes.append('#include "harness_types.h"')

    # Parse entry_params to build the wrapper call
    param_names = []
    if entry_params.strip() and entry_params.strip() != "void":
        for param in entry_params.split(","):
            param = param.strip()
            parts = param.split()
            if parts:
                name = parts[-1].lstrip("*")
                param_names.append(name)

    call_args = ", ".join(param_names)

    wrapper_src = "\n".join(includes) + f"""

/* Forward declaration of real library function */
int {real_func}({entry_params});

/* Wrapper: bridges entry_func → real library function */
int {entry_name}({entry_params}) {{
    return {real_func}({call_args});
}}
"""
    wrapper_path.write_text(wrapper_src, encoding="utf-8")
    return wrapper_path


def validate_finding(finding_dir: Path, asan_lib: str, include_dirs: list,
                     src_root: str, extra_libs: list) -> dict:
    """Validate a single finding against the real .a library."""
    spec = finding_dir.name

    # Find the reproducer
    reproducer = finding_dir / "reproducer.c"
    if not reproducer.exists():
        reproducer = finding_dir / "replay_driver.c"
    if not reproducer.exists():
        return {"spec": spec, "status": "MISSING_REPRODUCER"}

    # Find stubs
    stubs = finding_dir / "smart_stubs.c"
    if not stubs.exists():
        stubs = finding_dir / "stubs.c"

    # Check if we need a wrapper (entry_func not in .a)
    entry_name, real_func, entry_params = find_entry_wrapper(finding_dir)

    c_files = [str(reproducer)]

    # For stubs, create a cleaned version that removes functions also in the .a
    # to avoid multiple-definition errors
    cleaned_stubs = None
    if stubs and stubs.exists():
        stubs_src = stubs.read_text(errors="replace")
        # Get exported symbols from .a
        try:
            nm_result = subprocess.run(["nm", asan_lib], capture_output=True,
                                       text=True, timeout=10)
            lib_symbols = set()
            for line in nm_result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] == 'T':
                    lib_symbols.add(parts[2])
            # Remove stub function definitions that conflict with .a exports
            for sym in lib_symbols:
                # Remove one-line stubs: "int TIFFErrorExt() { return 0; }"
                stubs_src = re.sub(
                    r'(?:int|void|unsigned|long|short|char|size_t|tmsize_t|[a-zA-Z_]\w+\s*\*?)\s+'
                    + re.escape(sym) + r'\s*\([^)]*\)\s*\{[^}]*\}\s*',
                    f'/* removed {sym}: exists in .a */\n', stubs_src)
        except Exception:
            pass
        cleaned_stubs = finding_dir / "_clean_stubs.c"
        cleaned_stubs.write_text(stubs_src, encoding="utf-8")
        c_files.append(str(cleaned_stubs))

    wrapper_path = None
    if entry_name and real_func:
        wrapper_path = create_wrapper(finding_dir, entry_name, real_func,
                                      entry_params, include_dirs, src_root)
        c_files.append(str(wrapper_path))

    # Build include flags
    inc_flags = ["-I", str(finding_dir)]
    for d in include_dirs:
        if os.path.isdir(d):
            inc_flags.extend(["-I", d])
    if src_root and os.path.isdir(src_root):
        inc_flags.extend(["-I", src_root])

    # Compile
    out_bin = finding_dir / "_revalidate_bin"
    cmd = (["gcc", "-fsanitize=address", "-fno-omit-frame-pointer", "-g", "-O0",
            "-w"] + inc_flags + c_files + [asan_lib] +
           ["-o", str(out_bin)] + extra_libs)

    rc, _, stderr = run_cmd(cmd, timeout=60)

    if rc != 0:
        # Try with --allow-multiple-definition as last resort? No — user said unmodified only
        # Clean up
        if wrapper_path and wrapper_path.exists():
            wrapper_path.unlink()
        return {"spec": spec, "status": "BUILD_FAIL",
                "error": stderr[:300] if stderr else ""}

    # Run with ASan
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:print_stacktrace=1"
    rc, stdout, stderr = run_cmd([str(out_bin)], timeout=30, env=env)
    asan_output = stderr or stdout

    # Clean up temp files
    if out_bin.exists():
        out_bin.unlink()
    if wrapper_path and wrapper_path.exists():
        wrapper_path.unlink()
    if cleaned_stubs and cleaned_stubs.exists():
        cleaned_stubs.unlink()

    # Parse ASan output
    asan_types = [
        "heap-buffer-overflow", "heap-use-after-free", "stack-buffer-overflow",
        "global-buffer-overflow", "SEGV", "double-free", "null-dereference",
        "attempting free", "alloc-dealloc-mismatch",
    ]

    crash_type = ""
    for at in asan_types:
        if at in asan_output:
            crash_type = at
            break

    # Check for FPE (not always reported as AddressSanitizer)
    if not crash_type and ("FPE" in asan_output or "floating point" in asan_output.lower()):
        crash_type = "FPE"

    if not crash_type and "ERROR: AddressSanitizer" not in asan_output and "SEGV" not in asan_output:
        if "ERROR: LeakSanitizer" in asan_output:
            return {"spec": spec, "status": "LEAK_ONLY"}
        return {"spec": spec, "status": "NO_CRASH"}

    if not crash_type:
        crash_type = "unknown"

    # Extract crash location — must be in real library code (src_root path)
    frame_re = re.compile(r'#(\d+)\s+0x[0-9a-f]+\s+in\s+(\w+)\s+(\S+):(\d+)')
    crash_func = ""
    crash_file = ""
    crash_line = 0
    in_library = False

    for m in frame_re.finditer(asan_output):
        func, fpath, fline = m.group(2), m.group(3), int(m.group(4))
        basename = os.path.basename(fpath)

        # Skip harness/stub frames
        if basename in ("reproducer.c", "replay_driver.c", "stubs.c",
                        "smart_stubs.c", "auto_stubs.c", "_wrapper.c"):
            continue
        # Skip ASan runtime frames
        if func.startswith("__") or "interceptor" in func:
            continue
        # Skip ASan/sanitizer internal files
        if "libsanitizer" in fpath or "sanitizer" in basename:
            continue

        crash_func = func
        crash_file = fpath
        crash_line = fline

        # Check if crash is in the library source (src_root path)
        if src_root and src_root in fpath:
            in_library = True
        break

    if not crash_func:
        return {"spec": spec, "status": "HARNESS_CRASH", "type": crash_type}

    return {
        "spec": spec,
        "status": "REAL_CRASH" if in_library else "CRASH_UNKNOWN_LOC",
        "type": crash_type,
        "function": crash_func,
        "file": crash_file,
        "line": crash_line,
        "in_library": in_library,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Revalidate findings against unmodified upstream .a library")
    parser.add_argument("--findings-dir", required=True,
                        help="Directory containing finding subdirectories")
    parser.add_argument("--asan-lib", required=True,
                        help="Path to ASan-built .a library")
    parser.add_argument("--include-dirs", default="",
                        help="Comma-separated include directories")
    parser.add_argument("--src-root", default="",
                        help="Source root (for classifying crash locations)")
    parser.add_argument("--extra-libs", default="-lm -lpthread -lz",
                        help="Extra linker flags")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel workers")
    parser.add_argument("--filter-status", default="",
                        help="Only revalidate findings with this status in verification_summary.tsv")
    args = parser.parse_args()

    findings_dir = Path(args.findings_dir)
    if not findings_dir.exists():
        print(f"ERROR: {findings_dir} does not exist")
        sys.exit(1)

    include_dirs = [d.strip() for d in args.include_dirs.split(",") if d.strip()]
    extra_libs = args.extra_libs.split()

    # Find finding directories
    finding_dirs = sorted([d for d in findings_dir.iterdir() if d.is_dir()])
    print(f"Found {len(finding_dirs)} findings")

    # Filter by status if requested
    if args.filter_status:
        summary_tsv = findings_dir.parent / "verification_summary.tsv"
        if summary_tsv.exists():
            matching = set()
            for line in summary_tsv.read_text().splitlines()[1:]:
                parts = line.split("\t")
                if len(parts) >= 3 and parts[2] == args.filter_status:
                    matching.add(parts[0])
            finding_dirs = [d for d in finding_dirs if d.name in matching]
            print(f"Filtered to {len(finding_dirs)} with status={args.filter_status}")

    # Validate
    results = {"REAL_CRASH": [], "BUILD_FAIL": 0, "NO_CRASH": 0,
               "HARNESS_CRASH": 0, "LEAK_ONLY": 0, "MISSING_REPRODUCER": 0,
               "CRASH_UNKNOWN_LOC": []}

    if args.jobs > 1:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            futures = {
                pool.submit(validate_finding, d, args.asan_lib, include_dirs,
                            args.src_root, extra_libs): d
                for d in finding_dirs
            }
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                _tally(results, result, i, len(finding_dirs))
    else:
        for i, d in enumerate(finding_dirs):
            result = validate_finding(d, args.asan_lib, include_dirs,
                                      args.src_root, extra_libs)
            _tally(results, result, i, len(finding_dirs))

    # Summary
    print(f"\n{'='*60}")
    print(f"Revalidation Summary:")
    print(f"  REAL_CRASH (in library):  {len(results['REAL_CRASH'])}")
    print(f"  CRASH_UNKNOWN_LOC:       {len(results['CRASH_UNKNOWN_LOC'])}")
    print(f"  BUILD_FAIL:              {results['BUILD_FAIL']}")
    print(f"  NO_CRASH:                {results['NO_CRASH']}")
    print(f"  HARNESS_CRASH:           {results['HARNESS_CRASH']}")
    print(f"  LEAK_ONLY:               {results['LEAK_ONLY']}")
    print(f"  MISSING_REPRODUCER:      {results['MISSING_REPRODUCER']}")

    # Dedup by crash location
    if results["REAL_CRASH"]:
        locations = {}
        for r in results["REAL_CRASH"]:
            key = f"{r['file']}:{r['line']}"
            if key not in locations:
                locations[key] = r
        print(f"\n  Unique crash locations: {len(locations)}")
        print(f"\n  Confirmed bugs:")
        for loc, r in sorted(locations.items()):
            print(f"    {r['spec']}: {r['type']} in {r['function']} {loc}")

    if results["CRASH_UNKNOWN_LOC"]:
        print(f"\n  Crashes at unknown locations (may be real):")
        for r in results["CRASH_UNKNOWN_LOC"]:
            print(f"    {r['spec']}: {r['type']} in {r.get('function', '?')} {r.get('file', '?')}:{r.get('line', '?')}")


def _tally(results, result, i, total):
    status = result["status"]
    if status == "REAL_CRASH":
        results["REAL_CRASH"].append(result)
        print(f"  [{i+1}/{total}] REAL_CRASH: {result['spec']} — "
              f"{result['type']} in {result['function']} {result['file']}:{result['line']}")
    elif status == "CRASH_UNKNOWN_LOC":
        results["CRASH_UNKNOWN_LOC"].append(result)
        print(f"  [{i+1}/{total}] CRASH_UNKNOWN: {result['spec']} — "
              f"{result['type']} in {result.get('function', '?')}")
    elif status == "BUILD_FAIL":
        results["BUILD_FAIL"] += 1
        if results["BUILD_FAIL"] <= 5:
            print(f"  [{i+1}/{total}] BUILD_FAIL: {result['spec']} — {result.get('error', '')[:80]}")
    else:
        results[status] = results.get(status, 0) + 1


if __name__ == "__main__":
    main()
