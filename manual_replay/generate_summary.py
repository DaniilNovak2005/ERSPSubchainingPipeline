#!/usr/bin/env python3
"""Generate manual_replay_summary.tsv matching the pipeline's summary.tsv format."""
import os, json, re, csv

SPECS_DIR = "/home/danii/Documents/SAILOR_Replication_Package/manual_replay/specs"
SE_BASE = "/home/danii/Documents/SAILOR_Replication_Package/se_runs/sailor_engine/libxml2_8effcb57_vul"
OUTPUT = "/home/danii/Documents/SAILOR_Replication_Package/manual_replay/manual_replay_summary.tsv"

# Known driver artifacts (not real libxml2 bugs)
DRIVER_ARTIFACTS = {
    "573_parser.c_13146_local_cpp_cwe-125-cursor-lookahead-missing-bytes-check": "memcpy_oversize",
    "576_parser.c_13158_local_cpp_cwe-125-cursor-lookahead-missing-bytes-check": "memcpy_oversize",
    "2204_xmlschemas.c_13056_sailor_kernel-lifecycle-mismatch": "memcpy_oversize",
    "057_nanohttp.c_551_local_cpp_cwe-120-overflow": "odr_violation",
}

rows = []

for spec_dir in sorted(os.listdir(SPECS_DIR)):
    spec_path = os.path.join(SPECS_DIR, spec_dir)
    if not os.path.isdir(spec_path):
        continue

    asan_file = os.path.join(spec_path, "asan_output.txt")
    bug_file = os.path.join(spec_path, "bug_report.json")

    if not os.path.exists(asan_file):
        continue

    asan_txt = open(asan_file).read() if os.path.exists(asan_file) else ""
    has_asan = "AddressSanitizer" in asan_txt
    is_artifact = spec_dir in DRIVER_ARTIFACTS
    asan_confirmed = has_asan and not is_artifact

    # Parse crash location from ASan output
    crash_type = ""
    crash_file = ""
    crash_line = ""
    crash_func = ""

    if has_asan:
        summary_m = re.search(r"SUMMARY: AddressSanitizer: (\S+) (.+?) in (\S+)", asan_txt)
        if summary_m:
            crash_type = summary_m.group(1)
            loc = summary_m.group(2)
            crash_func = summary_m.group(3)
            loc_m = re.search(r'(\w+\.c):(\d+)', loc)
            if loc_m:
                crash_file = loc_m.group(1)
                crash_line = loc_m.group(2)
        # Get the first frame in libxml2 code
        frame_m = re.search(r'#0 .+ in (\S+) .+/asan_build/(\w+\.c):(\d+)', asan_txt)
        if frame_m:
            crash_func = frame_m.group(1)
            crash_file = frame_m.group(2)
            crash_line = frame_m.group(3)

    # Get original pipeline info from run_report.json
    orig_dir = os.path.join(SE_BASE, spec_dir)
    rr_file = os.path.join(orig_dir, "run_report.json")
    orig_verdict = "LIKELY_TP"
    orig_vul_file = ""
    orig_vul_line = ""
    orig_func = ""
    orig_cwe = ""

    if os.path.exists(rr_file):
        try:
            rr = json.load(open(rr_file))
            orig_verdict = rr.get("verdict", "LIKELY_TP")
            vul = rr.get("vulnerability", {})
            orig_vul_file = vul.get("original_file", "")
            orig_vul_line = str(vul.get("original_line", ""))
            orig_func = vul.get("function", "")
            orig_cwe = str(vul.get("cwe", ""))
        except:
            pass

    artifact_note = DRIVER_ARTIFACTS.get(spec_dir, "")
    rows.append({
        "Spec": spec_dir,
        "ManualASan": "CONFIRMED" if asan_confirmed else ("ARTIFACT" if is_artifact else "NO_CRASH"),
        "CrashType": crash_type,
        "CrashFile": crash_file,
        "CrashLine": crash_line,
        "CrashFunc": crash_func,
        "OriginalVulFile": orig_vul_file,
        "OriginalVulLine": orig_vul_line,
        "OriginalFunc": orig_func,
        "CWE": orig_cwe,
        "ArtifactNote": artifact_note,
    })

# Write TSV
with open(OUTPUT, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys(), delimiter='\t')
    w.writeheader()
    w.writerows(rows)

confirmed = sum(1 for r in rows if r["ManualASan"] == "CONFIRMED")
artifact = sum(1 for r in rows if r["ManualASan"] == "ARTIFACT")
no_crash = sum(1 for r in rows if r["ManualASan"] == "NO_CRASH")

print(f"Total specs: {len(rows)}")
print(f"  ASan CONFIRMED: {confirmed}")
print(f"  Driver ARTIFACT: {artifact}")
print(f"  NO_CRASH: {no_crash}")
print(f"\nOutput: {OUTPUT}")
print("\n=== CONFIRMED crashes ===")
for r in rows:
    if r["ManualASan"] == "CONFIRMED":
        print(f"  {r['Spec'][:60]:<60} | {r['CrashType']:<25} | {r['CrashFunc']} @ {r['CrashFile']}:{r['CrashLine']}")
