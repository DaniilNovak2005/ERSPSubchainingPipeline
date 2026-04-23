#!/usr/bin/env python3
"""Re-validate B3/B4 reproducers by removing static function copies
and linking against real .a library.

For each reproducer:
1. Remove static/local function definitions that shadow .a symbols
2. Keep main(), struct definitions, and input setup
3. Compile against real .a
4. Run with ASan
5. Check if crash is in .a library code

Usage:
    python3 scripts/revalidate_baselines.py \
        --baseline b3 \
        --findings-dir se_runs/b3_v2/libtiff_f324415_vul/findings \
        --upstream-libs dataset/f324415/libtiff_f324415_vul/build_simple/libtiff.a \
        --include-dirs dataset/f324415/libtiff_f324415_vul/libtiff \
        --src-root dataset/f324415/libtiff_f324415_vul \
        --output-dir /tmp/b3_revalidated/libtiff \
        --jobs 16
"""

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path


def run_cmd(cmd, timeout=60, env=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def strip_static_functions(src: str) -> str:
    """Remove static function definitions that shadow .a symbols.
    Keep: main(), struct/typedef definitions, #include, variable declarations.
    Remove: static function bodies, non-static function implementations."""

    # Remove #include <klee/klee.h>
    src = re.sub(r'#include\s*[<"]klee/klee\.h[>"]', '', src)

    # Remove klee_make_symbolic calls
    src = re.sub(r'klee_make_symbolic\([^)]+\)\s*;', '', src)
    src = re.sub(r'klee_assume\([^)]+\)\s*;', '', src)

    lines = src.split('\n')
    result = []
    in_function = False
    brace_depth = 0
    skip_function = False
    func_start_line = -1

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Detect function definition start (not main, not struct/enum)
        if not in_function:
            # Match: [static] type func_name(...) {
            func_match = re.match(
                r'^(?:static\s+)?(?:(?:unsigned|signed|const|volatile|struct|enum|union)\s+)*'
                r'(?:void|int|char|long|short|float|double|size_t|ssize_t|uint\w+|int\w+|'
                r'tmsize_t|tsize_t|toff_t|png_\w+|bfd_\w+|sepol_\w+|fz_\w+|TIFF|BIO|EVP_\w+|RSA|'
                r'sqlite3_\w+|av_\w+)\s*\*?\s*'
                r'(\w+)\s*\([^)]*\)\s*\{?\s*$',
                stripped
            )

            if func_match:
                func_name = func_match.group(1)
                # Keep main() and test_ functions
                if func_name in ('main', 'LLVMFuzzerTestOneInput') or func_name.startswith('test_'):
                    result.append(line)
                    if '{' in stripped:
                        in_function = True
                        brace_depth = stripped.count('{') - stripped.count('}')
                        skip_function = False
                    continue
                else:
                    # Skip this function — it shadows .a symbol
                    skip_function = True
                    if '{' in stripped:
                        in_function = True
                        brace_depth = stripped.count('{') - stripped.count('}')
                    continue

            result.append(line)
        else:
            brace_depth += stripped.count('{') - stripped.count('}')
            if not skip_function:
                result.append(line)
            if brace_depth <= 0:
                in_function = False
                skip_function = False
                brace_depth = 0

    return '\n'.join(result)


def validate_one(finding_dir, upstream_libs, include_dirs, extra_link_flags,
                 src_root, output_dir):
    """Validate a single B3/B4 finding."""
    spec_name = finding_dir.name

    # Find reproducer
    reproducer = finding_dir / "reproducer.c"
    if not reproducer.exists():
        # B4 structure: findings/file_c/repro_NNN_line/reproducer.c
        repro_dirs = list(finding_dir.glob("repro_*/reproducer.c"))
        if repro_dirs:
            reproducer = repro_dirs[0]
        else:
            return {"spec": spec_name, "status": "NO_REPRODUCER"}

    src = reproducer.read_text(errors="replace")

    # Strip static function copies
    stripped = strip_static_functions(src)

    # Save stripped version
    spec_out = Path(output_dir) / spec_name
    spec_out.mkdir(parents=True, exist_ok=True)
    stripped_c = spec_out / "reproducer_stripped.c"
    stripped_c.write_text(stripped)

    # Also copy original for comparison
    shutil.copy2(str(reproducer), str(spec_out / "reproducer_original.c"))

    # Compile against .a
    binary = str(spec_out / "reproducer_bin")
    inc_flags = []
    for d in include_dirs:
        inc_flags.extend(["-I", d])

    cmd = (["gcc", "-fsanitize=address", "-fno-omit-frame-pointer", "-g", "-O0", "-w"] +
           inc_flags + [str(stripped_c)] +
           ["-o", binary] +
           upstream_libs + extra_link_flags)

    rc, stdout, stderr = run_cmd(cmd, timeout=60)
    if rc != 0:
        # Try with clang
        cmd[0] = "clang"
        rc, stdout, stderr = run_cmd(cmd, timeout=60)

    if rc != 0:
        (spec_out / "compile_error.txt").write_text(stderr[:4000])
        return {"spec": spec_name, "status": "BUILD_FAIL", "error": stderr[:200]}

    # Run with ASan
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:print_stacktrace=1"
    rc, stdout, stderr = run_cmd([binary], timeout=30, env=env)
    combined = stdout + "\n" + stderr
    (spec_out / "asan_output.txt").write_text(combined[:16000])

    if "ERROR: AddressSanitizer:" not in combined and "SEGV" not in combined:
        return {"spec": spec_name, "status": "NO_CRASH"}

    # Parse crash location
    error_type = ""
    for p in ["heap-buffer-overflow", "stack-buffer-overflow", "heap-use-after-free",
              "double-free", "SEGV", "global-buffer-overflow"]:
        if p in combined:
            error_type = p
            break

    crash_file, crash_line, crash_func = "", "", ""
    for line in combined.split('\n'):
        m = re.search(r'#\d+\s+\S+\s+in\s+(\S+)\s+(\S+):(\d+)', line)
        if m:
            func, fpath, fline = m.group(1), m.group(2), m.group(3)
            if any(s in func or s in fpath for s in
                   ['__asan', '__interceptor', 'libsanitizer', '_start',
                    'libc_start', 'libc.so', 'string_fortified', '/usr/include']):
                continue
            # Skip if crash is in the stripped reproducer's main()
            if 'reproducer_stripped' in fpath and func == 'main':
                continue
            crash_func = func
            crash_file = os.path.basename(fpath)
            crash_line = fline
            break

    # Check if crash is in library code (not in reproducer)
    is_library = False
    if crash_file and 'reproducer' not in crash_file:
        # Check ASan output for src_root path
        if src_root and src_root in combined:
            is_library = True
        else:
            # Check if file exists in source tree
            for root, dirs, files in os.walk(src_root):
                if crash_file in files:
                    is_library = True
                    break

    status = "CONFIRMED" if is_library else "CRASH_NOT_IN_LIBRARY"

    return {
        "spec": spec_name, "status": status,
        "crash_file": crash_file, "crash_line": crash_line,
        "crash_func": crash_func, "error_type": error_type,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, choices=["b3", "b4"])
    parser.add_argument("--findings-dir", required=True, type=Path)
    parser.add_argument("--upstream-libs", required=True,
                        help="Comma-separated .a paths")
    parser.add_argument("--include-dirs", default="",
                        help="Comma-separated include dirs")
    parser.add_argument("--extra-link-flags", default="-lm,-lpthread,-ldl",
                        help="Comma-separated link flags")
    parser.add_argument("--src-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--jobs", type=int, default=16)
    args = parser.parse_args()

    upstream_libs = [x for x in args.upstream_libs.split(",") if x]
    include_dirs = [x for x in args.include_dirs.split(",") if x]
    extra_link_flags = [x for x in args.extra_link_flags.split(",") if x]

    # Find all findings
    findings = []
    for d in sorted(args.findings_dir.iterdir()):
        if d.is_dir():
            # B3: each dir has reproducer.c directly
            # B4: each dir has repro_NNN_line/reproducer.c subdirs
            if (d / "reproducer.c").exists():
                findings.append(d)
            else:
                for sub in sorted(d.iterdir()):
                    if sub.is_dir() and (sub / "reproducer.c").exists():
                        findings.append(sub)

    print(f"[{args.baseline.upper()}] Found {len(findings)} findings to validate")
    print(f"[{args.baseline.upper()}] Libs: {upstream_libs}")

    results = []
    with ProcessPoolExecutor(max_workers=args.jobs) as executor:
        futures = {}
        for f in findings:
            fut = executor.submit(
                validate_one, f, upstream_libs, include_dirs,
                extra_link_flags, args.src_root, args.output_dir
            )
            futures[fut] = f.name

        for fut in as_completed(futures):
            spec = futures[fut]
            try:
                r = fut.result()
                results.append(r)
                if r["status"] == "CONFIRMED":
                    print(f"  ✓ {spec}: {r.get('error_type','')} in {r.get('crash_func','')} at {r.get('crash_file','')}:{r.get('crash_line','')}")
            except Exception as e:
                results.append({"spec": spec, "status": "ERROR"})

    # Summary
    from collections import Counter
    counts = Counter(r["status"] for r in results)
    print(f"\n{'='*50}")
    print(f"Validation Summary ({args.baseline.upper()}):")
    for s, c in counts.most_common():
        print(f"  {s}: {c}")
    print(f"  Total: {len(results)}")

    confirmed = [r for r in results if r["status"] == "CONFIRMED"]
    if confirmed:
        print(f"\nConfirmed ({len(confirmed)}):")
        for r in confirmed:
            print(f"  {r['crash_func']} at {r['crash_file']}:{r['crash_line']} ({r['error_type']})")

    # Save CSV
    out_csv = Path(args.output_dir) / "validation_results.csv"
    with open(out_csv, 'w', newline='') as f:
        fields = ["spec", "status", "crash_file", "crash_line", "crash_func", "error_type"]
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(results)
    print(f"\nSaved to {out_csv}")


if __name__ == "__main__":
    main()
