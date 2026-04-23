#!/usr/bin/env python3
"""Batch ASan replay for SAILOR specs.

Runs ASan concrete validation OUTSIDE Docker for all specs that have
bug_report.json with asan_confirmed=false. Builds the project with ASan
ONCE, then links each spec's replay driver against the shared library.

Usage:
    python3 asan_replay_batch.py \
        --se-runs-dir /path/to/se_runs/sailor_engine/<project>/ \
        --src-root /path/to/dataset/<id>/<project>/ \
        --jobs 32
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path


def run_cmd(cmd, timeout=120, cwd=None, env=None):
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, timeout=timeout, cwd=cwd, env=env,
            capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def build_asan_project(src_root: Path, cache_dir: Path) -> Path:
    """Build the project with ASan. Returns path to .a library or None."""
    # Check cache first
    if cache_dir.exists():
        for lib in sorted(cache_dir.glob("*.a")):
            print(f"  [cache] Using cached ASan library: {lib}")
            return lib

    cache_dir.mkdir(parents=True, exist_ok=True)

    # Copy source tree
    asan_src = cache_dir / "src"
    if asan_src.exists():
        shutil.rmtree(str(asan_src))
    print(f"  Copying source tree to {asan_src}...")
    shutil.copytree(str(src_root), str(asan_src), symlinks=True,
                    ignore=shutil.ignore_patterns('*.o', '*.bc', '*.bca', '.git'))

    asan_env = dict(os.environ)
    asan_cflags = "-fsanitize=address -fno-omit-frame-pointer -g -O0 -w"
    asan_env["CC"] = "gcc"
    asan_env["CXX"] = "g++"
    asan_env["CFLAGS"] = asan_cflags
    asan_env["CXXFLAGS"] = asan_cflags
    asan_env["LDFLAGS"] = "-fsanitize=address"

    build_sh = asan_src / "build.sh"
    configure_script = asan_src / "configure"
    cmake_file = asan_src / "CMakeLists.txt"

    built_ok = False

    if build_sh.exists():
        print(f"  Running build.sh with ASan env...")
        rc, out, err = run_cmd(["bash", str(build_sh)], timeout=600, cwd=str(asan_src), env=asan_env)
        built_ok = True  # partial builds may still produce libraries
        if rc != 0:
            print(f"  build.sh returned {rc}: {err[:300]}")

    elif cmake_file.exists():
        build_dir = asan_src / "build"
        build_dir.mkdir(exist_ok=True)
        print(f"  CMake configure...")
        clean_env = dict(os.environ)
        clean_env["CC"] = "gcc"
        clean_env["CXX"] = "g++"
        rc, _, err = run_cmd([
            "cmake", "..", "-DCMAKE_C_COMPILER=gcc", "-DCMAKE_CXX_COMPILER=g++",
            "-DBUILD_SHARED_LIBS=OFF",
        ], timeout=120, cwd=str(build_dir), env=clean_env)
        if rc == 0:
            print(f"  CMake build with ASan...")
            rc, _, err = run_cmd(
                ["make", "-j32", f"CFLAGS={asan_cflags}", f"LDFLAGS=-fsanitize=address"],
                timeout=600, cwd=str(build_dir), env=asan_env)
            built_ok = True
        else:
            print(f"  CMake failed: {err[:300]}")

    elif configure_script.exists():
        # Detect autotools vs custom
        rc, help_out, _ = run_cmd([str(configure_script), "--help"], timeout=10, cwd=str(asan_src))
        is_autotools = "disable-nls" in (help_out or "")

        run_cmd(["make", "distclean"], timeout=60, cwd=str(asan_src))

        if is_autotools:
            args = [str(configure_script), "--disable-shared", "--enable-static",
                    "--disable-nls", "--disable-werror"]
        else:
            args = [str(configure_script), "--disable-shared", "--enable-static"]

        print(f"  Configure ({'autotools' if is_autotools else 'custom'})...")
        rc, _, err = run_cmd(args, timeout=120, cwd=str(asan_src), env=asan_env)
        if rc == 0:
            print(f"  Make with ASan...")
            rc, _, err = run_cmd(["make", "-j32"], timeout=600, cwd=str(asan_src), env=asan_env)
            built_ok = True
            if rc != 0:
                print(f"  Make errors (partial build): {err[:300]}")
        else:
            print(f"  Configure failed: {err[:300]}")

    if not built_ok:
        print(f"  ERROR: Could not build project with ASan")
        return None

    # Find libraries
    search_dirs = [asan_src]
    if (asan_src / "build").exists():
        search_dirs.insert(0, asan_src / "build")

    all_libs = []
    for sd in search_dirs:
        all_libs.extend(sd.rglob("*.a"))
    all_libs = [f for f in all_libs if "CMakeFiles" not in str(f)]

    if all_libs:
        # Prefer library matching project name
        project_name = src_root.name.split("_")[0]
        matched = [f for f in all_libs if project_name.lower() in f.name.lower()]
        chosen = matched[0] if matched else all_libs[0]

        # Cache the library
        cached = cache_dir / chosen.name
        shutil.copy2(str(chosen), str(cached))
        print(f"  ASan library built: {cached}")
        # Also cache all other .a files
        for lib in all_libs:
            if lib != chosen:
                shutil.copy2(str(lib), str(cache_dir / lib.name))
        return cached
    else:
        print(f"  No .a/.so files found after build")
        return None


def parse_ktest_data(data_str: str, expected_size: int) -> list:
    """Parse ktest data string to byte values."""
    if not data_str:
        return [0] * expected_size

    # Format: b'\x00\x01\x02...'
    m = re.match(r"b'(.*)'", data_str, re.DOTALL)
    if m:
        raw = m.group(1)
        result = []
        i = 0
        while i < len(raw):
            if raw[i] == '\\' and i + 1 < len(raw):
                if raw[i + 1] == 'x' and i + 3 < len(raw):
                    result.append(int(raw[i + 2:i + 4], 16))
                    i += 4
                elif raw[i + 1] == '\\':
                    result.append(ord('\\'))
                    i += 2
                elif raw[i + 1] == 'n':
                    result.append(ord('\n'))
                    i += 2
                elif raw[i + 1] == 't':
                    result.append(ord('\t'))
                    i += 2
                elif raw[i + 1] == '0':
                    result.append(0)
                    i += 2
                else:
                    result.append(ord(raw[i + 1]))
                    i += 2
            else:
                result.append(ord(raw[i]))
                i += 1
        return result

    return [0] * expected_size


def generate_replay_driver(driver_src: str, concrete_inputs: list) -> str:
    """Generate concrete replay driver from symbolic driver + ktest data."""
    if not driver_src:
        return ""

    replay = driver_src
    # Remove klee includes
    replay = re.sub(r'#include\s*[<"]klee/klee\.h[>"]', '// klee removed for replay', replay)

    # Build name→data map
    obj_map = {inp["name"]: inp for inp in concrete_inputs}

    def replace_symbolic(m):
        args_str = m.group(1)
        parts = [p.strip() for p in args_str.split(',')]
        if len(parts) < 3:
            return f'memset({parts[0]}, 0, {parts[1] if len(parts) > 1 else "1"}); /* replay */'

        ptr = parts[0]
        size = parts[1]
        name = parts[2].strip('"').strip("'")

        if name in obj_map:
            obj = obj_map[name]
            byte_values = parse_ktest_data(obj.get("data", ""), obj.get("size", 0))
            if byte_values:
                hex_vals = ', '.join(f'0x{b:02x}' for b in byte_values[:512])
                safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
                return (f'{{ static const unsigned char {safe_name}_data[] = {{{hex_vals}}}; '
                        f'memcpy({ptr}, {safe_name}_data, '
                        f'({size} < sizeof({safe_name}_data)) ? {size} : sizeof({safe_name}_data)); }}')
        return f'memset({ptr}, 0, {size}); /* replay: no ktest data for "{name}" */'

    replay = re.sub(r'\bklee_make_symbolic\s*\(((?:[^()]|\([^()]*\))+)\)', replace_symbolic, replay)
    replay = re.sub(r'\bklee_assume\([^)]*\)\s*;', '/* klee_assume removed */', replay)
    replay = re.sub(r'\bklee_assert\([^)]*\)\s*;', '/* klee_assert removed */', replay)
    replay = re.sub(r'\bklee_warning_once\([^)]*\)\s*;', '', replay)
    replay = re.sub(r'\bklee_warning\([^)]*\)\s*;', '', replay)
    replay = re.sub(r'\bklee_report_error\([^)]*\)\s*;', 'abort();', replay)

    # Add string.h for memcpy/memset if not present
    if '#include <string.h>' not in replay and '#include<string.h>' not in replay:
        replay = '#include <string.h>\n' + replay

    return replay


def find_ktest_tool() -> str:
    """Find ktest-tool binary."""
    # Check PATH first
    if shutil.which("ktest-tool"):
        return "ktest-tool"
    # Common locations
    for path in [
        "/home/$USER/tools/klee/build/bin/ktest-tool",
        "/opt/klee/bin/ktest-tool",
        os.path.expanduser("~/tools/klee/build/bin/ktest-tool"),
    ]:
        if os.path.isfile(path):
            return path
    return "ktest-tool"  # fallback, may fail


KTEST_TOOL = find_ktest_tool()


def decode_ktest_file(ktest_path: str) -> list:
    """Decode a .ktest file using ktest-tool, return list of {name, size, data}."""
    try:
        result = subprocess.run([KTEST_TOOL, ktest_path], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return []
    except Exception:
        return []

    objects = []
    obj_fields = {}
    for line in result.stdout.splitlines():
        m = re.match(r'\s*object\s+(\d+):\s*(\w+):\s*(.*)', line)
        if m:
            idx, field, value = int(m.group(1)), m.group(2).strip(), m.group(3).strip()
            if idx not in obj_fields:
                obj_fields[idx] = {}
            obj_fields[idx][field] = value

    for idx in sorted(obj_fields.keys()):
        f = obj_fields[idx]
        nm = re.match(r"b'([^']*)'", f.get("name", ""))
        name = nm.group(1) if nm else f.get("name", "").strip("'\"")
        try:
            size = int(f.get("size", "0"))
        except ValueError:
            size = 0
        objects.append({"name": name, "size": size, "data": f.get("data", "")})
    return objects


def find_klee_crashes(spec_dir: Path) -> list:
    """Find KLEE .err + .ktest pairs from a spec's logs directory."""
    logs_dir = spec_dir / "logs"
    if not logs_dir.exists():
        return []

    crashes = []
    for klee_dir in sorted(logs_dir.glob("klee_run_*"), reverse=True):
        for ef in sorted(klee_dir.glob("*.err")):
            err_type = ef.stem.split(".")[-1] if "." in ef.stem else "unknown"
            # Skip non-memory errors (assert, user, external)
            if err_type not in ("ptr", "free", "div"):
                continue
            ktest_name = ef.name.split(".")[0] + ".ktest"
            ktest = ef.parent / ktest_name
            if ktest.exists():
                crashes.append({"err_file": str(ef), "ktest": str(ktest), "err_type": err_type})
        if crashes:
            break  # use the latest klee_run
    return crashes


def find_real_function(spec_dir: Path) -> tuple:
    """Parse the sliced source to find the real project function name.

    The harness has an entry wrapper (entry_func, sail_entry, etc.) that calls
    the real project function. We need the real name so we can link against the
    project .a instead of the harness's gutted copy.

    Returns: (entry_name, real_func_name, real_func_signature) or (None, None, None)
    """
    harness_dir = spec_dir / "harness"

    # Find the sliced source file (not driver.c, stubs, etc.)
    sliced_files = []
    for f in sorted(harness_dir.glob("*.c")):
        if f.name not in ("driver.c", "stubs.c", "smart_stubs.c", "auto_stubs.c"):
            sliced_files.append(f)

    if not sliced_files:
        return None, None, None

    for sliced in sliced_files:
        src = sliced.read_text(errors="replace")

        # Pattern: entry function body calls a single real function
        # e.g., "int entry_func(...) { av_adts_header_parse(...); return 0; }"
        # or "int sail_entry(...) { ff_ivi_inverse_slant_8x8(...); return 0; }"
        #
        # Find function definitions that contain a single function call + return
        # Look for the entry function: it's typically the LAST function defined,
        # has "entry" in the name or is a simple pass-through.

        # Strategy: find all function calls inside entry-like functions
        entry_pattern = re.compile(
            r'(?:int|void)\s+(\w*(?:entry|Entry)\w*)\s*\(([^)]*)\)\s*\{([^}]*)\}',
            re.DOTALL
        )

        for m in entry_pattern.finditer(src):
            entry_name = m.group(1)
            entry_params = m.group(2)
            entry_body = m.group(3)

            # Find function calls in the body (not memset/memcpy/etc.)
            call_pattern = re.compile(r'\b([a-zA-Z_]\w+)\s*\(')
            calls = [c.group(1) for c in call_pattern.finditer(entry_body)
                     if c.group(1) not in ('memset', 'memcpy', 'memmove', 'malloc',
                                           'calloc', 'free', 'return', 'sizeof',
                                           'klee_assert', 'klee_assume', 'abort',
                                           'printf', 'fprintf', 'if', 'while', 'for')]

            if len(calls) == 1:
                real_func = calls[0]
                return entry_name, real_func, entry_params

    return None, None, None


def rewrite_driver_for_real_func(driver_src: str, entry_name: str, real_func: str) -> str:
    """Rewrite replay driver to call the real function instead of the entry wrapper.

    Replaces:
      - Declaration of entry_name with declaration of real_func
      - Calls to entry_name with calls to real_func
    """
    if not entry_name or not real_func:
        return driver_src

    # Replace prototype declaration
    result = re.sub(
        r'(?:int|void)\s+' + re.escape(entry_name) + r'\s*\(',
        f'int {real_func}(',
        driver_src
    )
    # Replace calls
    result = re.sub(
        r'\b' + re.escape(entry_name) + r'\s*\(',
        f'{real_func}(',
        result
    )
    return result


def replay_spec(spec_dir: Path, asan_lib: Path, src_root: Path, include_paths: list,
                output_root: Path = None) -> dict:
    """Run ASan replay for a single spec against the REAL project library.

    Compiles only the replay driver + stubs, linked against the ASan-built
    project .a library. Does NOT include the harness's sliced source files.
    The driver is rewritten to call the real project function directly.
    """
    spec_name = spec_dir.name
    bug_report_path = spec_dir / "bug_report.json"

    # Try to get concrete inputs from bug_report.json first
    report = None
    concrete_inputs = []

    if bug_report_path.exists():
        try:
            report = json.loads(bug_report_path.read_text())
        except Exception:
            report = None

    if report:
        if report.get("summary", {}).get("asan_confirmed"):
            return {"spec": spec_name, "status": "skip", "reason": "already confirmed"}
        concrete_inputs = report.get("concrete_inputs", [])

    # If no concrete inputs from bug_report, decode ktest files directly
    if not concrete_inputs:
        crashes = find_klee_crashes(spec_dir)
        if crashes:
            objects = decode_ktest_file(crashes[0]["ktest"])
            concrete_inputs = objects
        if not concrete_inputs:
            return {"spec": spec_name, "status": "skip", "reason": "no concrete inputs"}

    # Read driver.c
    driver_path = spec_dir / "harness" / "driver.c"
    if not driver_path.exists():
        return {"spec": spec_name, "status": "skip", "reason": "no driver.c"}

    driver_src = driver_path.read_text(errors="replace")

    # Find the real function name and rewrite driver to call it directly
    entry_name, real_func, _ = find_real_function(spec_dir)
    if entry_name and real_func:
        driver_src = rewrite_driver_for_real_func(driver_src, entry_name, real_func)

    replay_driver = generate_replay_driver(driver_src, concrete_inputs)
    if not replay_driver:
        return {"spec": spec_name, "status": "error", "reason": "could not generate replay driver"}

    # Prepare replay directory (use output_root if spec_dir is not writable)
    if output_root:
        replay_dir = output_root / spec_name / "asan_real"
    else:
        replay_dir = spec_dir / "asan_real"
    replay_dir.mkdir(parents=True, exist_ok=True)

    replay_driver_path = replay_dir / "replay_driver.c"
    replay_driver_path.write_text(replay_driver, encoding="utf-8")

    # Only compile replay_driver + stubs. The real project functions come from the .a library.
    # Do NOT include harness sliced source (they are gutted copies, not real code).
    c_files = [str(replay_driver_path)]
    harness_dir = spec_dir / "harness"
    for stub_name in ["stubs.c", "smart_stubs.c", "auto_stubs.c"]:
        stub_path = harness_dir / stub_name
        if stub_path.exists():
            src = stub_path.read_text(errors="replace")
            # Clean KLEE references
            clean = re.sub(r'#include\s*[<"]klee/klee\.h[>"]', '// klee removed', src)
            clean = re.sub(r'\bklee_warning_once\([^)]*\)\s*;', '', clean)
            clean = re.sub(r'\bklee_warning\([^)]*\)\s*;', '', clean)
            clean = re.sub(r'\bklee_assert\([^)]*\)\s*;', '', clean)
            clean = re.sub(r'\bklee_make_symbolic\s*\(((?:[^()]|\([^()]*\))+)\)',
                           r'memset(\1) /* stub */;', clean)
            clean = re.sub(r'\bklee_assume\([^)]*\)\s*;', '', clean)
            clean = re.sub(r'\bklee_report_error\([^)]*\)\s*;', 'abort();', clean)
            clean_path = replay_dir / stub_name
            clean_path.write_text(clean, encoding="utf-8")
            c_files.append(str(clean_path))

    # Copy header files from harness
    for h_file in harness_dir.glob("*.h"):
        shutil.copy2(str(h_file), str(replay_dir / h_file.name))

    # Include flags — project headers needed for struct definitions etc.
    inc_flags = ["-isystem", "/usr/include"]
    for ip in include_paths:
        if os.path.isdir(ip):
            inc_flags.extend(["-idirafter", ip])
    inc_flags.extend(["-I", str(src_root), "-I", str(spec_dir / "harness"), "-I", str(replay_dir)])

    # Find config.h
    for root in [src_root]:
        for rel in ["config.h", "include/config.h"]:
            candidate = root / rel
            if candidate.exists():
                inc_flags.extend(["-include", str(candidate)])
                inc_flags.extend(["-I", str(candidate.parent)])
                break

    # Compile: driver + stubs linked against real project .a
    asan_flags = ["-fsanitize=address", "-fno-omit-frame-pointer", "-g", "-O0", "-w"]
    out_bin = replay_dir / "replay_bin"

    all_libs = [str(asan_lib)]
    cache_dir = asan_lib.parent
    for extra in cache_dir.glob("*.a"):
        if extra != asan_lib:
            all_libs.append(str(extra))

    cmd = (["gcc"] + asan_flags + inc_flags + c_files + all_libs +
           ["-o", str(out_bin), "-lm", "-lz", "-llzma", "-lpthread", "-ldl", "-lstdc++"])
    rc, stdout, stderr = run_cmd(cmd, timeout=60)

    if rc != 0:
        cmd[0] = "clang"
        rc, stdout, stderr = run_cmd(cmd, timeout=60)

    if rc != 0:
        return {"spec": spec_name, "status": "build_error",
                "reason": stderr[:500] if stderr else "compile failed"}

    # Run with ASan
    run_env = dict(os.environ)
    run_env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:print_stacktrace=1"
    rc, stdout, stderr = run_cmd([str(out_bin)], timeout=30, env=run_env)

    asan_output = stderr or stdout
    asan_triggered = False
    asan_error_type = ""
    crash_function = ""
    crash_file = ""
    crash_line = 0

    # Check for ASan errors
    asan_patterns = [
        (r'AddressSanitizer:\s*(heap-buffer-overflow)', "heap-buffer-overflow"),
        (r'AddressSanitizer:\s*(stack-buffer-overflow)', "stack-buffer-overflow"),
        (r'AddressSanitizer:\s*(heap-use-after-free)', "heap-use-after-free"),
        (r'AddressSanitizer:\s*(double-free)', "double-free"),
        (r'AddressSanitizer:\s*(global-buffer-overflow)', "global-buffer-overflow"),
        (r'AddressSanitizer:\s*(SEGV)', "SEGV"),
        (r'AddressSanitizer:\s*(null-dereference)', "null-dereference"),
    ]

    for pattern, etype in asan_patterns:
        if re.search(pattern, asan_output):
            asan_triggered = True
            asan_error_type = etype
            break

    if asan_triggered:
        # Extract crash location
        frame_re = re.compile(r'#\d+\s+0x[0-9a-f]+\s+in\s+(\w+)\s+(\S+):(\d+)')
        for m in frame_re.finditer(asan_output):
            func, fpath, fline = m.group(1), m.group(2), int(m.group(3))
            basename = os.path.basename(fpath)
            if basename not in ("replay_driver.c", "stubs.c", "smart_stubs.c",
                                "auto_stubs.c", "driver.c"):
                crash_function = func
                crash_file = fpath
                crash_line = fline
                break

    # Update or create bug report
    if not report:
        report = {
            "summary": {"verdict": "LIKELY_TP", "asan_confirmed": False,
                        "crash_relevance": "no_asan", "cwe": "", "total_asan_crashes": 0},
            "vulnerability": {"original_file": spec_name.split("_")[1] if "_" in spec_name else "",
                              "original_line": 0},
            "all_crashes": [], "all_asan_crashes": [],
        }
    report["asan_result"] = {
        "triggered": asan_triggered,
        "harness_artifact": False,
        "error_type": asan_error_type,
        "crash_function": crash_function,
        "crash_file": crash_file,
        "crash_line": crash_line,
        "original_file": "",
        "original_line": 0,
        "original_code": "",
        "original_context": "",
        "output": asan_output[:2000] if asan_triggered else "",
    }

    if asan_triggered:
        report["summary"]["asan_confirmed"] = True
        report["summary"]["crash_relevance"] = "asan_confirmed"
        report["summary"]["cwe"] = asan_error_type
        report["summary"]["total_asan_crashes"] = 1
        report["summary"]["verdict"] = "SE_DETECTED"
        report["all_asan_crashes"] = [{
            "error_type": asan_error_type,
            "crash_function": crash_function,
            "crash_file": crash_file,
            "crash_line": crash_line,
        }]

    # Save updated bug report (to output dir if spec dir is not writable)
    if output_root:
        out_report = output_root / spec_name / "bug_report.json"
        out_report.parent.mkdir(parents=True, exist_ok=True)
        out_report.write_text(json.dumps(report, indent=4))
    else:
        try:
            bug_report_path.write_text(json.dumps(report, indent=4))
        except PermissionError:
            out_report = Path("/tmp/asan_replay_results") / spec_name / "bug_report.json"
            out_report.parent.mkdir(parents=True, exist_ok=True)
            out_report.write_text(json.dumps(report, indent=4))

    status = "confirmed" if asan_triggered else "no_crash"
    return {
        "spec": spec_name,
        "status": status,
        "asan_type": asan_error_type if asan_triggered else "",
        "crash_location": f"{crash_function} at {crash_file}:{crash_line}" if asan_triggered else "",
    }


def main():
    parser = argparse.ArgumentParser(description="Batch ASan replay for SAILOR specs")
    parser.add_argument("--se-runs-dir", required=True, help="Path to se_runs/sailor_engine/<project>/")
    parser.add_argument("--src-root", required=True, help="Path to project source root")
    parser.add_argument("--cache-dir", default=None, help="ASan build cache directory (default: <se-runs-dir>/.asan_cache)")
    parser.add_argument("--output-dir", default=None, help="Output directory for results (if spec dirs are not writable)")
    parser.add_argument("--jobs", type=int, default=16, help="Parallel workers")
    parser.add_argument("--only-with-bugs", action="store_true", help="Only replay specs that have KLEE crashes")
    args = parser.parse_args()

    se_runs_dir = Path(args.se_runs_dir)
    src_root = Path(args.src_root)
    cache_dir = Path(args.cache_dir) if args.cache_dir else se_runs_dir / ".asan_cache"
    output_root = Path(args.output_dir) if args.output_dir else None
    if output_root:
        output_root.mkdir(parents=True, exist_ok=True)

    if not se_runs_dir.exists():
        print(f"ERROR: {se_runs_dir} does not exist")
        sys.exit(1)
    if not src_root.exists():
        print(f"ERROR: {src_root} does not exist")
        sys.exit(1)

    # Step 1: Build project with ASan
    print(f"[1/3] Building project with ASan...")
    asan_lib = build_asan_project(src_root, cache_dir)
    if not asan_lib:
        print("FATAL: Could not build ASan library")
        sys.exit(1)

    # Discover include paths from source tree
    include_paths = []
    for d in src_root.iterdir():
        if d.is_dir() and not d.name.startswith('.'):
            include_paths.append(str(d))
    include_paths.append(str(src_root))

    # Step 2: Find specs to replay
    print(f"[2/3] Finding specs to replay...")
    specs = []
    for spec_dir in sorted(se_runs_dir.iterdir()):
        if not spec_dir.is_dir() or spec_dir.name.startswith('.'):
            continue

        # Include if has bug_report.json (with KLEE crashes)
        bug_report = spec_dir / "bug_report.json"
        if bug_report.exists():
            if args.only_with_bugs:
                try:
                    r = json.loads(bug_report.read_text())
                    if not r.get("all_crashes"):
                        continue
                except Exception:
                    continue
            specs.append(spec_dir)
            continue

        # Also include specs WITHOUT bug_report but WITH KLEE .err files
        # (these had the harness_dir NameError that prevented concrete_validate)
        if find_klee_crashes(spec_dir):
            specs.append(spec_dir)

    print(f"  Found {len(specs)} specs with bug reports")

    # Step 3: Replay in parallel
    print(f"[3/3] Running ASan replay ({args.jobs} workers)...")
    results = {"confirmed": 0, "no_crash": 0, "build_error": 0, "error": 0, "skip": 0}
    confirmed_specs = []

    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        futures = {
            pool.submit(replay_spec, spec, asan_lib, src_root, include_paths, output_root): spec
            for spec in specs
        }

        for i, future in enumerate(as_completed(futures)):
            try:
                result = future.result()
            except Exception as e:
                spec = futures[future]
                result = {"spec": spec.name, "status": "error", "reason": str(e)}
            status = result.get("status", "error")
            results[status] = results.get(status, 0) + 1

            if status == "confirmed":
                confirmed_specs.append(result)
                print(f"  [{i+1}/{len(specs)}] ✓ CONFIRMED: {result['spec']} — "
                      f"{result['asan_type']} at {result['crash_location']}")
            elif status == "build_error" and (i + 1) <= 10:
                print(f"  [{i+1}/{len(specs)}] BUILD ERROR: {result['spec']} — "
                      f"{result.get('reason', '')[:100]}")

            if (i + 1) % 50 == 0:
                print(f"  Progress: {i+1}/{len(specs)} — "
                      f"confirmed={results['confirmed']}, no_crash={results['no_crash']}, "
                      f"build_err={results['build_error']}")

    # Summary
    print(f"\n{'='*60}")
    print(f"ASan Replay Summary:")
    print(f"  Total specs:    {len(specs)}")
    print(f"  Confirmed:      {results['confirmed']}")
    print(f"  No crash:       {results['no_crash']}")
    print(f"  Build errors:   {results['build_error']}")
    print(f"  Other errors:   {results['error']}")
    print(f"  Skipped:        {results['skip']}")
    print(f"{'='*60}")

    if confirmed_specs:
        print(f"\nConfirmed bugs:")
        for r in confirmed_specs:
            print(f"  {r['spec']}: {r['asan_type']} at {r['crash_location']}")


if __name__ == "__main__":
    main()
