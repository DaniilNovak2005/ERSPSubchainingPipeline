#!/usr/bin/env python3
"""Compare SAILOR against all baselines and ablations.

Reads summary.tsv from each baseline/ablation and SAILOR, generates a
unified comparison table with metrics.

Usage:
    python3 baselines/compare_baselines.py \
        --sailor se_runs/sailor_engine/libtiff_f324415_vul \
        --b1 se_runs/b1/libtiff_f324415_vul \
        --b2 se_runs/b2/libtiff_f324415_vul \
        --b3 se_runs/b3/libtiff_f324415_vul \
        --b4 se_runs/b4/libtiff_f324415_vul \
        --a1 se_runs/a1/libtiff_f324415_vul \
        --output reports/comparison/libtiff_f324415_vul
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

# ── Loading ──────────────────────────────────────────────────────────

def load_summary(results_dir: Path) -> list[dict]:
    """Load summary.tsv from a results directory."""
    tsv = results_dir / "summary.tsv"
    if not tsv.exists():
        return []
    with open(tsv) as f:
        return list(csv.DictReader(f, delimiter="\t"))


def extract_bugs(rows: list[dict]) -> list[dict]:
    """Extract SE_DETECTED bugs from summary rows."""
    return [
        r for r in rows
        if r.get("FinalStatus") == "SE_DETECTED"
    ]


def extract_unique_bugs(rows: list[dict]) -> set[tuple]:
    """Extract unique bug signatures as (BugFile, BugLine, BugType) tuples."""
    bugs = set()
    for r in extract_bugs(rows):
        sig = (
            os.path.basename(r.get("BugFile", "")),
            r.get("BugLine", ""),
            r.get("BugType", ""),
        )
        if sig[0]:  # skip empty
            bugs.add(sig)
    return bugs


def sum_field(rows: list[dict], field: str, default: int = 0) -> int:
    """Sum a numeric field across all rows."""
    total = 0
    for r in rows:
        try:
            total += int(r.get(field, default))
        except (ValueError, TypeError):
            pass
    return total


def load_token_stats(results_dir: Path) -> int:
    """Load total token count from token_stats.json or summary.tsv."""
    token_file = results_dir / "token_stats.json"
    if token_file.exists():
        try:
            data = json.loads(token_file.read_text())
            return data.get("total", 0)
        except Exception:
            pass
    # Fallback: sum Tokens column
    rows = load_summary(results_dir)
    return sum_field(rows, "Tokens")


# ── Metrics ──────────────────────────────────────────────────────────

def compute_metrics(name: str, rows: list[dict], results_dir: Path) -> dict:
    """Compute comparison metrics for one approach."""
    total = len(rows)
    se_detected = extract_bugs(rows)
    unique_bugs = extract_unique_bugs(rows)

    build_errors = sum(1 for r in rows if r.get("FinalStatus") in (
        "BUILD_ERROR", "REPRODUCER_BUILD_FAIL"))
    harness_artifacts = sum(1 for r in rows if r.get("FinalStatus") == "HARNESS_ARTIFACT")
    no_bug = sum(1 for r in rows if r.get("FinalStatus") in (
        "NO_BUG", "FP", "LLM_FP", "NOT_REPRODUCIBLE"))

    total_time = sum_field(rows, "Time")
    total_tokens = load_token_stats(results_dir)
    if total_tokens == 0:
        total_tokens = sum_field(rows, "Tokens")

    return {
        "name": name,
        "total_specs": total,
        "se_detected": len(se_detected),
        "unique_bugs": len(unique_bugs),
        "bug_signatures": unique_bugs,
        "build_errors": build_errors,
        "harness_artifacts": harness_artifacts,
        "no_bug_fp": no_bug,
        "total_time_s": total_time,
        "total_tokens": total_tokens,
        "precision": len(se_detected) / max(total, 1),
    }


# ── Overlap Analysis ─────────────────────────────────────────────────

def compute_overlap(metrics: list[dict]) -> dict:
    """Compute pairwise and multi-way bug overlap."""
    overlap = {}
    names = [m["name"] for m in metrics]
    bug_sets = {m["name"]: m["bug_signatures"] for m in metrics}

    # Pairwise overlap
    for i, n1 in enumerate(names):
        for n2 in names[i + 1 :]:
            common = bug_sets[n1] & bug_sets[n2]
            only_1 = bug_sets[n1] - bug_sets[n2]
            only_2 = bug_sets[n2] - bug_sets[n1]
            overlap[f"{n1} ∩ {n2}"] = len(common)
            overlap[f"{n1} only (vs {n2})"] = len(only_1)
            overlap[f"{n2} only (vs {n1})"] = len(only_2)

    # Union of all
    all_bugs = set()
    for s in bug_sets.values():
        all_bugs |= s
    overlap["union_all"] = len(all_bugs)

    # Bugs found by SAILOR only
    if "SAILOR" in bug_sets:
        sailor_only = bug_sets["SAILOR"]
        for name, bugs in bug_sets.items():
            if name != "SAILOR":
                sailor_only = sailor_only - bugs
        overlap["SAILOR_exclusive"] = len(sailor_only)

    return overlap


# ── Output ───────────────────────────────────────────────────────────

def format_table(metrics: list[dict]) -> str:
    """Format comparison table as markdown."""
    lines = []
    lines.append("# Baseline Comparison Results\n")

    # Main table
    headers = [
        "Approach", "Specs", "Detected", "Unique Bugs",
        "Build Err", "Harness Art.", "FP/No Bug",
        "Precision", "Tokens", "Time (s)",
    ]
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

    for m in metrics:
        row = [
            m["name"],
            str(m["total_specs"]),
            str(m["se_detected"]),
            str(m["unique_bugs"]),
            str(m["build_errors"]),
            str(m["harness_artifacts"]),
            str(m["no_bug_fp"]),
            f"{m['precision']:.1%}",
            f"{m['total_tokens']:,}" if m["total_tokens"] else "N/A",
            f"{m['total_time_s']:,}" if m["total_time_s"] else "N/A",
        ]
        lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines)


def format_overlap(overlap: dict) -> str:
    """Format overlap analysis as markdown."""
    lines = ["\n## Bug Overlap Analysis\n"]
    for key, val in sorted(overlap.items()):
        lines.append(f"- **{key}**: {val}")
    return "\n".join(lines)


def format_unique_to_sailor(metrics: list[dict]) -> str:
    """List bugs found only by SAILOR."""
    bug_sets = {m["name"]: m["bug_signatures"] for m in metrics}
    if "SAILOR" not in bug_sets:
        return ""

    sailor_bugs = bug_sets["SAILOR"]
    other_bugs = set()
    for name, bugs in bug_sets.items():
        if name != "SAILOR":
            other_bugs |= bugs

    exclusive = sailor_bugs - other_bugs
    if not exclusive:
        return "\n## SAILOR-Exclusive Bugs\n\nNone — all SAILOR bugs were also found by at least one baseline.\n"

    lines = [f"\n## SAILOR-Exclusive Bugs ({len(exclusive)})\n"]
    lines.append("| BugFile | BugLine | BugType |")
    lines.append("| --- | --- | --- |")
    for bug_file, bug_line, bug_type in sorted(exclusive):
        lines.append(f"| {bug_file} | {bug_line} | {bug_type} |")

    return "\n".join(lines)


# ── Main ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Compare SAILOR baselines and ablations")
    parser.add_argument("--sailor", required=True, help="SAILOR results dir")
    parser.add_argument("--b1", default="", help="B1 results dir")
    parser.add_argument("--b2", default="", help="B2 results dir")
    parser.add_argument("--b3", default="", help="B3 results dir")
    parser.add_argument("--b4", default="", help="B4 results dir")
    parser.add_argument("--a1", default="", help="A1 (SAILOR-SA) results dir")
    parser.add_argument("--output", default="", help="Output directory for report")
    parser.add_argument("--format", choices=["markdown", "json", "both"], default="both")
    args = parser.parse_args()

    approaches = []

    # Load each approach
    for name, path in [
        ("B1: OSS-Fuzz+SE", args.b1),
        ("B2: LLM Harness+SE", args.b2),
        ("B3: LLM Detect", args.b3),
        ("B4: Raw SA+LLM", args.b4),
        ("A1: SAILOR-SA", args.a1),
        ("SAILOR", args.sailor),
    ]:
        if not path:
            continue
        results_dir = Path(path)
        rows = load_summary(results_dir)
        if not rows:
            print(f"  [!] No data for {name} at {results_dir}")
            continue
        m = compute_metrics(name, rows, results_dir)
        approaches.append(m)
        print(f"  [{name}] {m['unique_bugs']} unique bugs, "
              f"{m['se_detected']} detected, {m['total_specs']} specs")

    if not approaches:
        print("[!] No data loaded. Check paths.")
        return

    # Compute overlap
    overlap = compute_overlap(approaches)

    # Format output
    table_md = format_table(approaches)
    overlap_md = format_overlap(overlap)
    exclusive_md = format_unique_to_sailor(approaches)

    report = table_md + "\n" + overlap_md + "\n" + exclusive_md

    # Output
    print("\n" + report)

    if args.output:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)

        if args.format in ("markdown", "both"):
            (out_dir / "comparison.md").write_text(report, encoding="utf-8")
            print(f"\n[+] Markdown report: {out_dir / 'comparison.md'}")

        if args.format in ("json", "both"):
            json_data = {
                "approaches": [
                    {k: v for k, v in m.items() if k != "bug_signatures"}
                    for m in approaches
                ],
                "overlap": overlap,
                "bug_details": {
                    m["name"]: [
                        {"file": b[0], "line": b[1], "type": b[2]}
                        for b in sorted(m["bug_signatures"])
                    ]
                    for m in approaches
                },
            }
            (out_dir / "comparison.json").write_text(
                json.dumps(json_data, indent=2, default=str), encoding="utf-8"
            )
            print(f"[+] JSON report:    {out_dir / 'comparison.json'}")


if __name__ == "__main__":
    main()
