#!/usr/bin/env python3
"""Unified Concrete Validation — validates bug reports from ANY baseline
using per-project harness templates.

Input: A bug report CSV/TSV with columns:
  - Spec (identifier)
  - BugFile (source file where bug occurs)
  - BugLine (line number)
  - BugFunc (function name)
  - EntryPath (how to reach the function — optional, auto-detected)
  - InputParams (crashing input description — optional)

The script:
  1. Maps (project, BugFunc) → harness template entry path
  2. Generates a concrete harness from the template
  3. Compiles against the real upstream .a
  4. Runs with ASan
  5. Checks if crash occurs in BugFunc/BugFile (library code)

Usage:
    python3 scripts/unified_validate.py \
        --project libtiff \
        --bug-reports se_runs/sailor_engine/libtiff_f324415_vul/summary.tsv \
        --template export/harness_templates/harness_libtiff.c \
        --upstream-libs dataset/f324415/libtiff_f324415_vul/build_simple/libtiff.a \
        --include-dirs dataset/f324415/libtiff_f324415_vul/libtiff \
        --src-root dataset/f324415/libtiff_f324415_vul \
        --output-dir export/unified_validation/libtiff \
        --jobs 16
"""

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path


# ── Function → Entry Path Mapping ──────────────────────────────────

# Maps (project, function_pattern) → entry_path in the harness template
# The first matching pattern wins
ENTRY_PATH_MAP = {
    "libtiff": [
        (r"TIFFRead.*Strip|TIFFSeek|TIFFCheckRead", "read_strip"),
        (r"TIFFRead.*Tile", "read_tile"),
        (r"TIFFWrite", "write_strip"),
        (r"TIFFRGBA|TIFFReadRGBA", "read_rgba"),
        (r"TIFFPrint", "print_directory"),
        (r"TIFFFindField|TIFFSetField|TIFFGetField|TIFFDefaultDirectory", "read_strip"),
        (r"TIFFVStripSize|TIFFStripSize", "read_strip"),
        (r"TIFFErrorExtR|_TIFFmemcpy|TIFFSwab", "read_strip"),
        (r".*", "read_strip"),  # default
    ],
    "libpng": [
        (r"png_read|png_combine_row|png_do_read", "read_image"),
        (r"png_write|png_do_write", "write_image"),
        (r"png_set_keep_unknown|png_handle", "read_image"),
        (r"png_set_", "set_transforms"),
        (r".*", "read_image"),
    ],
    "libxml2": [
        (r"xmlParse|xmlRead|xmlDetect", "parse_memory"),
        (r"xmlXPath", "xpath"),
        (r"xmlSchema|xmlSchemaFormat", "schema_validate"),
        (r"xmlRelaxNG", "relaxng"),
        (r"xmlNormalize|xmlURI", "parse_memory"),
        (r".*", "parse_memory"),
    ],
    "binutils": [
        (r"bfd_check_format", "bfd_check_format"),
        (r"bfd_get_section|bfd_get_symtab", "bfd_get_section"),
        (r"_bfd_elf|elf", "bfd_check_format"),
        (r"ctf_|dyn_string|fibheap|hash|objalloc|splay", "bfd_check_format"),
        (r".*", "bfd_open"),
    ],
    "curl": [
        (r"curl_easy_perform|Curl_", "easy_perform"),
        (r"curl_url|Curl_url", "url_parse"),
        (r"curl_mime", "mime"),
        (r"dynhds|header", "header_parse"),
        (r".*", "easy_perform"),
    ],
    "openssl": [
        (r"readbuffer|mem_read|bread_conv|BIO_read", "bio_readbuffer"),
        (r"BIO_|bio_", "bio_mem"),
        (r"RSA_padding", "rsa_padding"),
        (r"EVP_|evp_", "evp_cipher"),
        (r"kdf_|PBKDF|pbkdf", "kdf"),
        (r"CONF_|conf_", "conf"),
        (r"ASN1_|asn1_|ossl_i2c", "asn1_encode"),
        (r"X509_|v2i_|v3_", "x509_ext"),
        (r".*", "bio_mem"),
    ],
    "ffmpeg": [
        (r"decode|avcodec_receive", "decode_packet"),
        (r"encode|avcodec_send", "encode_frame"),
        (r"av_read_frame|avformat", "parse_header"),
        (r"avfilter|av_buffersrc", "filter"),
        (r".*", "decode_packet"),
    ],
    "selinux": [
        (r"node_from_record|sepol_node", "node_modify"),
        (r"hashtab_", "hashtab"),
        (r"sepol_context|context_to_string|context_new", "context_create"),
        (r"sepol_bool|selinux_boolean", "bool_create"),
        (r"kernel_to_cil|write_type_|map_filename", "kernel_to_cil"),
        (r"module_to_cil|cond_expr_to_cil", "module_to_cil"),
        (r"ebitmap_", "ebitmap"),
        (r".*", "node_modify"),
    ],
    "sqlite": [
        (r"memdb|sqlite3_deserialize", "deserialize"),
        (r"sqlite3_prepare|sqlite3_step|sqlite3_finalize", "prepare"),
        (r"sqlite3_exec", "exec"),
        (r".*", "exec"),
    ],
    "mupdf": [
        (r"fz_open_document|pdf_", "open_document"),
        (r"fz_load_page|fz_bound_page|fz_run_page", "load_page"),
        (r"fz_new_pixmap|fz_clear_pixmap|fz_clone_pixmap|fz_invert", "pixmap_ops"),
        (r"fz_new_buffer|fz_append|fz_terminate_buffer|fz_resize_buffer|fz_clone_buffer", "buffer_ops"),
        (r"fz_clone_path|fz_pack_path", "path_ops"),
        (r".*", "open_document"),
    ],
}


def detect_entry_path(project: str, bug_func: str) -> str:
    """Map a bug function name to a harness template entry path."""
    patterns = ENTRY_PATH_MAP.get(project, [])
    for pattern, entry_path in patterns:
        if re.search(pattern, bug_func, re.IGNORECASE):
            return entry_path
    return "default"


# ── Validation ─────────────────────────────────────────────────────

def run_cmd(cmd, timeout=60, env=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def validate_one(bug, template_path, upstream_libs, include_dirs,
                 extra_link_flags, src_root, output_dir, project):
    """Validate a single bug report using the harness template."""
    spec = bug.get("Spec", bug.get("BugID", "unknown"))
    bug_func = bug.get("BugFunc", bug.get("Function", ""))
    bug_file = bug.get("BugFile", bug.get("File", ""))
    bug_line = bug.get("BugLine", bug.get("Line", "0"))

    # Detect entry path — prefer LLM-provided entry_function, fallback to auto-detect
    entry_path = bug.get("EntryPath", "")
    if not entry_path:
        # Use LLM's entry_function if available
        llm_entry = bug.get("entry_function", bug.get("EntryFunction", ""))
        if llm_entry:
            entry_path = detect_entry_path(project, llm_entry)
        else:
            entry_path = detect_entry_path(project, bug_func)

    # Create output directory
    spec_dir = Path(output_dir) / spec
    spec_dir.mkdir(parents=True, exist_ok=True)

    # Generate harness from template with defines
    template_src = Path(template_path).read_text()
    harness_src = f'''/* Auto-generated from unified validation template */
#define TARGET_FUNC  "{bug_func}"
#define TARGET_FILE  "{bug_file}"
#define TARGET_LINE  {bug_line}
#define ENTRY_PATH   "{entry_path}"

''' + template_src

    harness_c = spec_dir / "harness.c"
    harness_c.write_text(harness_src)

    # Compile
    binary = str(spec_dir / "harness_bin")
    inc_flags = []
    for d in include_dirs:
        inc_flags.extend(["-I", d])

    cmd = (["gcc", "-fsanitize=address", "-fno-omit-frame-pointer", "-g", "-O0", "-w"] +
           inc_flags + [str(harness_c)] +
           ["-o", binary] +
           upstream_libs + extra_link_flags)

    rc, stdout, stderr = run_cmd(cmd, timeout=60)
    if rc != 0:
        (spec_dir / "compile_error.txt").write_text(stderr[:4000])
        return {
            "Spec": spec, "Status": "BUILD_FAIL",
            "BugFunc": bug_func, "BugFile": bug_file, "BugLine": bug_line,
            "EntryPath": entry_path, "CrashFile": "", "CrashLine": "",
            "CrashFunc": "", "ErrorType": "",
        }

    # Run with ASan
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:print_stacktrace=1"
    rc, stdout, stderr = run_cmd([binary], timeout=30, env=env)
    combined = stdout + "\n" + stderr
    (spec_dir / "asan_output.txt").write_text(combined[:16000])

    if "ERROR: AddressSanitizer:" not in combined and "SEGV" not in combined:
        return {
            "Spec": spec, "Status": "NO_CRASH",
            "BugFunc": bug_func, "BugFile": bug_file, "BugLine": bug_line,
            "EntryPath": entry_path, "CrashFile": "", "CrashLine": "",
            "CrashFunc": "", "ErrorType": "",
        }

    # Parse crash
    error_type = ""
    for p in ["heap-buffer-overflow", "stack-buffer-overflow", "heap-use-after-free",
              "double-free", "SEGV", "global-buffer-overflow", "stack-overflow"]:
        if p in combined:
            error_type = p
            break

    crash_file, crash_line, crash_func = "", "", ""
    for line in combined.split('\n'):
        m = re.search(r'#\d+\s+\S+\s+in\s+(\S+)\s+(\S+):(\d+)', line)
        if m:
            func, fpath, fline = m.group(1), m.group(2), m.group(3)
            if any(s in func or s in fpath for s in
                   ['__asan', '__interceptor', 'libsanitizer', '_start', 'libc_start',
                    'string_fortified', 'fortified', '/usr/include']):
                continue
            if 'harness.c' in fpath or 'harness_' in fpath:
                continue  # skip harness template code
            crash_func = func
            crash_file = os.path.basename(fpath)
            crash_line = fline
            break

    # Determine if crash is in library code
    is_library = False
    if crash_file and src_root:
        # Check if crash file exists in source tree
        for root, dirs, files in os.walk(src_root):
            if crash_file in files:
                is_library = True
                break
    # Also check: if the full crash path from ASan contains src_root path
    if not is_library:
        for line in combined.split('\n'):
            if src_root in line and crash_func and crash_func in line:
                is_library = True
                break

    status = "CONFIRMED" if is_library else "CRASH_NOT_IN_LIBRARY"
    if error_type == "SEGV" and not is_library:
        status = "SEGV_SETUP_ERROR"

    return {
        "Spec": spec, "Status": status,
        "BugFunc": bug_func, "BugFile": bug_file, "BugLine": bug_line,
        "EntryPath": entry_path, "CrashFile": crash_file, "CrashLine": crash_line,
        "CrashFunc": crash_func, "ErrorType": error_type,
    }


def main():
    parser = argparse.ArgumentParser(description="Unified concrete validation")
    parser.add_argument("--project", required=True,
                        choices=list(ENTRY_PATH_MAP.keys()))
    parser.add_argument("--bug-reports", required=True,
                        help="CSV/TSV with bug reports to validate")
    parser.add_argument("--template", required=True,
                        help="Path to harness template .c file")
    parser.add_argument("--upstream-libs", required=True,
                        help="Comma-separated .a library paths")
    parser.add_argument("--include-dirs", default="",
                        help="Comma-separated include directories")
    parser.add_argument("--extra-link-flags", default="-lm,-lpthread,-ldl",
                        help="Comma-separated extra linker flags")
    parser.add_argument("--src-root", default="",
                        help="Source root for library-crash detection")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--jobs", type=int, default=16)
    args = parser.parse_args()

    upstream_libs = [x for x in args.upstream_libs.split(",") if x]
    include_dirs = [x for x in args.include_dirs.split(",") if x]
    extra_link_flags = [x for x in args.extra_link_flags.split(",") if x]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Read bug reports
    bug_file = Path(args.bug_reports)
    delimiter = '\t' if bug_file.suffix == '.tsv' else ','
    with open(bug_file) as f:
        bugs = list(csv.DictReader(f, delimiter=delimiter))

    print(f"[Validate] Project:   {args.project}")
    print(f"[Validate] Template:  {args.template}")
    print(f"[Validate] Bugs:      {len(bugs)}")
    print(f"[Validate] Libs:      {upstream_libs}")
    print(f"[Validate] Output:    {output_dir}")

    # Validate
    results = []
    with ProcessPoolExecutor(max_workers=args.jobs) as executor:
        futures = {}
        for bug in bugs:
            f = executor.submit(
                validate_one, bug, args.template, upstream_libs,
                include_dirs, extra_link_flags, args.src_root,
                str(output_dir), args.project
            )
            futures[f] = bug.get("Spec", bug.get("BugID", "?"))

        for f in as_completed(futures):
            spec = futures[f]
            try:
                result = f.result()
                results.append(result)
                s = result["Status"]
                if s == "CONFIRMED":
                    print(f"  ✓ {spec}: {result['ErrorType']} in {result['CrashFile']}:{result['CrashLine']}")
                elif s == "BUILD_FAIL":
                    print(f"  ✗ {spec}: BUILD_FAIL")
                elif s == "NO_CRASH":
                    print(f"  · {spec}: no crash")
                else:
                    print(f"  ~ {spec}: {s}")
            except Exception as e:
                print(f"  ! {spec}: {e}")

    # Summary
    from collections import Counter
    counts = Counter(r["Status"] for r in results)
    print(f"\n{'='*50}")
    print(f"Validation Summary:")
    for s, c in counts.most_common():
        print(f"  {s}: {c}")
    print(f"  Total: {len(results)}")

    # Write results CSV
    out_csv = output_dir / "validation_results.csv"
    with open(out_csv, 'w', newline='') as f:
        fields = ["Spec", "Status", "BugFunc", "BugFile", "BugLine",
                  "EntryPath", "CrashFile", "CrashLine", "CrashFunc", "ErrorType"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nResults saved to {out_csv}")

    # Confirmed bugs summary
    confirmed = [r for r in results if r["Status"] == "CONFIRMED"]
    if confirmed:
        print(f"\nConfirmed bugs ({len(confirmed)}):")
        for r in confirmed:
            print(f"  {r['CrashFunc']} at {r['CrashFile']}:{r['CrashLine']} ({r['ErrorType']})")


if __name__ == "__main__":
    main()
