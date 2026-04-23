#!/usr/bin/env python3
"""
collect_results.py

Consolidated artifact collector for SAILOR.
Now includes Performance & Cost metrics in summary_report.csv.
"""

import argparse
import json
import shutil
import csv
from pathlib import Path
from typing import Optional, Dict, Any

def safe_read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def collect_run(spec_dir: Path, out_root: Path, src_root: Path):
    meta_path = spec_dir / "run_meta.json"
    if not meta_path.exists(): return None

    meta = safe_read_json(meta_path) or {}
    
    # --- Extract Metrics ---
    status = meta.get("class", "E")
    stats = meta.get("klee", {})
    reason = stats.get("failure_reason", "Unknown")
    
    # Performance Metrics
    duration = meta.get("total_analysis_time", stats.get("elapsed", 0))
    # Tries to find total attempts (compile attempts or refinement loops)
    # Adjust "cycles" or "iterations" based on your exact run_agent_for_spec.py structure
    attempts = meta.get("cycles", 0) 
    
    # LLM Token Usage
    llm_stats = meta.get("tokens", {})
    prompt_tok = llm_stats.get("prompt_tokens", 0)
    compl_tok = llm_stats.get("completion_tokens", 0)
    total_tok = llm_stats.get("total_tokens", 0)
    
    # -----------------------

    # Categorize Output Directory
    if status == "H2_BUG":
        dest_base = out_root / "verified_bugs"
    elif status == "H2_REACH":
        dest_base = out_root / "validation_failed_fp"
    else:
        dest_base = out_root / "failures" / status

    dest_dir = dest_base / spec_dir.name
    dest_dir.mkdir(parents=True, exist_ok=True)

    # --- Artifact Collection (Same as before) ---
    shutil.copy2(meta_path, dest_dir / "run_meta.json")
    if (spec_dir / "execution.log").exists():
        shutil.copy2(spec_dir / "execution.log", dest_dir / "execution.log")
    if (spec_dir / "replay_validation.log").exists():
        shutil.copy2(spec_dir / "replay_validation.log", dest_dir / "replay_validation.log")
    
    (dest_dir / "result_info.txt").write_text(f"Status: {status}\nReason: {reason}\nTime: {duration}s\nTokens: {total_tok}")

    ctx_dir = spec_dir / "ctx"
    if ctx_dir.exists():
        shutil.copytree(ctx_dir, dest_dir / "ctx", dirs_exist_ok=True)
        ctx_data = safe_read_json(ctx_dir / "context.json")
        if ctx_data and "vul_file" in ctx_data:
            src_file = src_root / ctx_data["vul_file"]
            if src_file.exists():
                shutil.copy2(src_file, dest_dir / f"original_{src_file.name}")

    harness_dir = spec_dir / "refinement" / "harness"
    if harness_dir.exists() and (harness_dir / "harness.c").exists():
        shutil.copy2(harness_dir / "harness.c", dest_dir / "harness.c")
    
    logs_dir = spec_dir / "refinement" / "logs"
    if logs_dir.exists():
        for err_file in logs_dir.glob("**/*.err"):
            should_copy = False
            if status == "H2_BUG":
                if "assert.err" in err_file.name or "ptr.err" in err_file.name:
                    should_copy = True
            else:
                should_copy = True

            if should_copy:
                shutil.copy2(err_file, dest_dir / err_file.name)
                stem = err_file.name.split('.')[0] 
                ktest = err_file.parent / f"{stem}.ktest"
                if ktest.exists():
                    shutil.copy2(ktest, dest_dir / ktest.name)
    
    # Return metrics row for CSV
    return [
        spec_dir.name, 
        status, 
        reason, 
        f"{duration:.2f}", 
        attempts, 
        prompt_tok, 
        compl_tok, 
        total_tok
    ]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode-root", required=True, help="Path to SAILOR results directory")
    parser.add_argument("--src-root", required=True, help="Path to source code root")
    parser.add_argument("--out-dir", default="sailor_report_pack", help="Output directory")
    args = parser.parse_args()

    mode_root = Path(args.mode_root)
    src_root = Path(args.src_root)
    out_dir = Path(args.out_dir)

    if out_dir.exists(): shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    summary_rows = []

    for spec_dir in mode_root.iterdir():
        if spec_dir.is_dir() and (spec_dir / "run_meta.json").exists():
            row = collect_run(spec_dir, out_dir, src_root)
            if row:
                summary_rows.append(row)

    # Write aggregate CSV with NEW COLUMNS
    with open(out_dir / "summary_report.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Spec", "Status", "Reason", 
            "Time(s)", "Attempts", 
            "Prompt_Tokens", "Compl_Tokens", "Total_Tokens"
        ])
        writer.writerows(summary_rows)

    print(f"\n[✓] SAILOR Collection Complete.")
    print(f"    Report: {out_dir}/summary_report.csv")

if __name__ == "__main__":
    main()