#!/usr/bin/env python3
"""Collect LLM token usage across all baselines and update llm_token_usage.csv.

Reads from:
  - se_runs/sailor_engine/*/summary.tsv (SAILOR-GPT5: Tokens column)
  - se_runs/sailor_deepseek/*/summary.tsv (SAILOR-DeepSeek: Tokens column)
  - se_runs/b3/*/summary.tsv (B3: Tokens column)
  - se_runs/b4/*/summary.tsv (B4: Tokens column)
  - se_runs/b5/*/targets/*/agent_stdout.txt (B5: JSON usage field)

Usage:
    python3 scripts/collect_token_usage.py
"""

import argparse
import csv
import glob
import json
import os
import re
from pathlib import Path


def sum_tsv_tokens(tsv_path):
    """Sum the Tokens column from a SAILOR/baseline summary.tsv."""
    total = 0
    time_total = 0
    try:
        with open(tsv_path) as f:
            reader = csv.DictReader(f, delimiter='\t')
            for row in reader:
                try:
                    total += int(row.get('Tokens', 0))
                except (ValueError, TypeError):
                    pass
                try:
                    time_total += float(row.get('Time', 0))
                except (ValueError, TypeError):
                    pass
    except Exception:
        pass
    return total, time_total


def collect_b5_tokens(b5_dir):
    """Collect token usage from B5 agent_stdout.txt JSON files."""
    total_input = 0
    total_output = 0
    total_cost = 0.0
    total_time = 0.0
    count = 0

    for stdout_file in sorted(Path(b5_dir).rglob("agent_stdout.txt")):
        try:
            data = json.loads(stdout_file.read_text())
            usage = data.get("modelUsage", {})
            for model, u in usage.items():
                total_input += u.get("inputTokens", 0) + u.get("cacheReadInputTokens", 0) + u.get("cacheCreationInputTokens", 0)
                total_output += u.get("outputTokens", 0)
                total_cost += u.get("costUSD", 0)
            total_time += data.get("duration_ms", 0) / 1000.0
            count += 1
        except (json.JSONDecodeError, Exception):
            pass

    return {
        "input_tokens": total_input,
        "output_tokens": total_output,
        "total_tokens": total_input + total_output,
        "cost_usd": total_cost,
        "time_s": total_time,
        "targets_completed": count,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--se-runs", default="se_runs", help="Path to se_runs directory")
    parser.add_argument("--output", default="export/baseline_confirmed/llm_token_usage.csv")
    args = parser.parse_args()

    se = Path(args.se_runs)
    rows = []

    # --- SAILOR-GPT5 ---
    for tsv in sorted(se.glob("sailor_engine/*/summary.tsv")):
        proj = tsv.parent.name
        tokens, time_s = sum_tsv_tokens(tsv)
        if tokens > 0:
            rows.append({
                "Baseline": "SAILOR-GPT5",
                "Project": proj,
                "Model": "GPT-5",
                "Input_tokens_M": "",
                "Output_tokens_M": "",
                "Total_tokens_M": f"{tokens / 1e6:.1f}",
                "Cost_USD": "",
                "Wall_clock_h": f"{time_s / 3600:.1f}",
                "Status": "complete",
            })

    # --- SAILOR-DeepSeek ---
    for tsv in sorted(se.glob("sailor_deepseek/*/summary.tsv")):
        proj = tsv.parent.name
        tokens, time_s = sum_tsv_tokens(tsv)
        rows.append({
            "Baseline": "SAILOR-DeepSeek",
            "Project": proj,
            "Model": "DeepSeek-V3",
            "Input_tokens_M": "",
            "Output_tokens_M": "",
            "Total_tokens_M": f"{tokens / 1e6:.1f}" if tokens > 0 else "",
            "Cost_USD": "",
            "Wall_clock_h": f"{time_s / 3600:.1f}" if time_s > 0 else "",
            "Status": "complete" if tokens > 0 else "running",
        })

    # --- B3 ---
    for tsv in sorted(se.glob("b3/*/summary.tsv")):
        proj = tsv.parent.name
        tokens, time_s = sum_tsv_tokens(tsv)
        if tokens > 0:
            rows.append({
                "Baseline": "B3",
                "Project": proj,
                "Model": "GPT-5",
                "Input_tokens_M": "",
                "Output_tokens_M": "",
                "Total_tokens_M": f"{tokens / 1e6:.2f}",
                "Cost_USD": "",
                "Wall_clock_h": f"{time_s / 3600:.1f}",
                "Status": "complete",
            })

    # --- B4 ---
    for tsv in sorted(se.glob("b4/*/summary.tsv")):
        proj = tsv.parent.name
        tokens, time_s = sum_tsv_tokens(tsv)
        if tokens > 0:
            rows.append({
                "Baseline": "B4",
                "Project": proj,
                "Model": "GPT-5",
                "Input_tokens_M": "",
                "Output_tokens_M": "",
                "Total_tokens_M": f"{tokens / 1e6:.2f}",
                "Cost_USD": "",
                "Wall_clock_h": f"{time_s / 3600:.1f}",
                "Status": "complete",
            })

    # --- B5 ---
    for proj_dir in sorted(se.glob("b5/*")):
        if not proj_dir.is_dir():
            continue
        proj = proj_dir.name
        usage = collect_b5_tokens(proj_dir)
        if usage["targets_completed"] > 0:
            rows.append({
                "Baseline": "B5",
                "Project": proj,
                "Model": "Claude Opus 4.6",
                "Input_tokens_M": f"{usage['input_tokens'] / 1e6:.1f}",
                "Output_tokens_M": f"{usage['output_tokens'] / 1e6:.1f}",
                "Total_tokens_M": f"{usage['total_tokens'] / 1e6:.1f}",
                "Cost_USD": f"{usage['cost_usd']:.2f}",
                "Wall_clock_h": f"{usage['time_s'] / 3600:.1f}",
                "Status": "complete" if usage["targets_completed"] > 5 else "running",
            })


    # Write CSV
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "Baseline", "Project", "Model",
            "Input_tokens_M", "Output_tokens_M", "Total_tokens_M",
            "Cost_USD", "Wall_clock_h", "Status",
        ])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Written {len(rows)} rows to {args.output}")

    # Print summary
    from collections import Counter
    baselines = Counter(r["Baseline"] for r in rows)
    for bl, cnt in sorted(baselines.items()):
        print(f"  {bl}: {cnt} projects")


if __name__ == "__main__":
    main()
