#!/usr/bin/env python3
"""A1: SAILOR − SA (Full Agent Loop, No Static Analysis).

Ablation study: runs the full SAILOR agent loop (iterative WriteDriver →
CompileSlice → RunKLEE → feedback) but with NO static analysis:
- No CodeQL-derived target locations (LLM scans files to discover targets)
- No SA rule details, CWE hints, or SA message
- No fact_pack, findings.json, call chains
- The LLM sees only raw source code and its own scan results

This isolates the contribution of static analysis to SAILOR (both the
target location selection AND the SA-enriched context).

Pipeline:
  1. Scan source files with LLM to discover potential vulnerability locations
  2. Generate spec JSON files from LLM-discovered targets (SAILOR format)
  3. Generate blank SA outputs (empty findings, minimal fact_pack)
  4. Run SAILOR agent via run_batch.sh with LLM-discovered specs + blank SA
  5. Collect results in SAILOR-compatible format

Usage:
    python3 baselines/a1_sailor_no_sa/run_a1.py \
        --project libtiff_f324415_vul \
        --dataset-root dataset/f324415/libtiff_f324415_vul \
        --output-dir se_runs/a1/libtiff_f324415_vul \
        --max-files 50 \
        --jobs 128
"""

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from baseline_utils import run_cmd
from run_single_shot_klee import scan_source_for_targets

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def generate_specs_from_targets(targets: list, output_dir: Path, project: str) -> int:
    """Convert LLM-discovered targets into SAILOR-compatible spec JSON files.

    Each target from scan_source_for_targets() becomes a spec file that
    the SAILOR agent loop can process.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    count = 0

    for target in targets:
        stem = target["_stem"]

        # Build a SAILOR-compatible spec (minimal, no SA context)
        spec = {
            "schema": "llmse.vul_spec.v1",
            "id": target.get("id", stem),
            "project": project,
            "rule_id": target.get("rule_id", "llm-scan/generic"),
            "family": "GENERIC",
            "file": target.get("file", ""),
            "line": target.get("line", 0),
            "column": target.get("column", 0),
            "end_line": target.get("end_line", 0),
            "end_column": target.get("end_column", 0),
            "message": target.get("message", "LLM-identified vulnerability"),
            "context": target.get("context", {}),
            "target_statement": target.get("target_statement", {}),
            # Empty SA facts
            "facts": {
                "suspect_calls": [],
                "pointer_vars": [],
                "length_vars": [],
                "bounds_hints": [],
            },
            # Minimal LLM hints (no SA-informed entry/spine)
            "llm_hints": {
                "entrypoint": {"strategy": "LLM_INFER", "candidates": []},
                "assertions": {
                    "presence_assertion_hint": "",
                    "reachability_assertion": "klee_assert(0);",
                },
                "notes": [],
            },
        }

        out_path = output_dir / f"{stem}.json"
        out_path.write_text(json.dumps(spec, indent=2), encoding="utf-8")
        count += 1

    return count


def generate_blank_sa_outputs(sa_dir: Path):
    """Create empty SA output directory (no findings, no fact_pack)."""
    sa_dir.mkdir(parents=True, exist_ok=True)

    # Empty findings
    (sa_dir / "findings.json").write_text("[]", encoding="utf-8")

    # Minimal fact_pack
    (sa_dir / "fact_pack.json").write_text(
        json.dumps({"facts": {}, "build_context": {}}), encoding="utf-8"
    )

    # Empty compile_commands (agent will use include discovery fallback)
    (sa_dir / "compile_commands.json").write_text("[]", encoding="utf-8")


def run_a1(args):
    dataset_root = Path(args.dataset_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    project = args.project
    project_id = str(dataset_root.relative_to(dataset_root.parent.parent))

    print(f"[A1] Project:     {project}")
    print(f"[A1] Dataset:     {dataset_root}")
    print(f"[A1] Max files:   {args.max_files}")
    print(f"[A1] Output:      {output_dir}")

    # 1. Scan source files with LLM to discover target locations (no SA)
    print(f"\n[A1] Phase 1: Scanning source files with LLM...")
    targets = scan_source_for_targets(
        dataset_root, max_files=args.max_files, tag="A1"
    )

    if not targets:
        print("[A1] No targets discovered. Exiting.")
        return

    print(f"[A1] Discovered {len(targets)} target locations")

    # 2. Generate spec JSON files from LLM-discovered targets
    llm_specs_dir = output_dir / "llm_specs" / project
    n_specs = generate_specs_from_targets(targets, llm_specs_dir, project)
    print(f"[A1] Generated {n_specs} spec files in {llm_specs_dir}")

    # 3. Create blank SA outputs
    blank_sa_dir = output_dir / "blank_sa" / project
    generate_blank_sa_outputs(blank_sa_dir)
    print(f"[A1] Created blank SA outputs in {blank_sa_dir}")

    # 4. Run SAILOR batch with LLM-discovered specs and blank SA
    batch_script = REPO_ROOT / "sailor_engine" / "run_batch.sh"

    env = os.environ.copy()
    env["SA_OUT_DIR"] = str(output_dir / "blank_sa")
    env["SE_RUNS_ROOT"] = str(output_dir / "se_runs")
    env["DATASET_ROOT"] = str(dataset_root.parent.parent)
    env["SAILOR_ROOT"] = str(REPO_ROOT)
    # Ensure no SE_CONFIG_DIR leaks in
    env.pop("SE_CONFIG_DIR", None)

    cmd = [
        "bash", str(batch_script),
        project_id,
        "ablation/a1-no-sa",
        str(output_dir / "llm_specs"),
        str(args.jobs),
    ]

    print(f"\n[A1] Phase 2: Running SAILOR agent batch ({n_specs} specs, {args.jobs} jobs)...")
    print(f"[A1] Command: {' '.join(cmd)}")

    rc, stdout, stderr, elapsed = run_cmd(cmd, timeout=args.timeout, env=env)

    print(f"[A1] Batch complete: rc={rc}, elapsed={elapsed:.1f}s")

    # 5. Copy results to canonical location
    se_results = output_dir / "se_runs" / "sailor_engine" / project
    summary_tsv = se_results / "summary.tsv"

    if summary_tsv.exists():
        shutil.copy2(summary_tsv, output_dir / "summary.tsv")
        print(f"[A1] Results: {output_dir / 'summary.tsv'}")

        # Count results
        import csv
        with open(summary_tsv) as f:
            rows = list(csv.DictReader(f, delimiter="\t"))
        se_detected = sum(1 for r in rows if r.get("FinalStatus") == "SE_DETECTED")
        total = len(rows)
        print(f"[A1] ═══ Summary ═══")
        print(f"  Total specs:    {total}")
        print(f"  SE_DETECTED:    {se_detected}")
        print(f"  Wall-clock:     {elapsed:.1f}s")
    else:
        print(f"[A1] WARNING: No summary.tsv found at {summary_tsv}")


def main():
    parser = argparse.ArgumentParser(description="A1: SAILOR − SA (Full Agent, No SA)")
    parser.add_argument("--project", required=True)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-files", type=int, default=50,
                        help="Max source files to scan with LLM (default: 50)")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=86400,
                        help="Total batch timeout (seconds)")
    args = parser.parse_args()

    run_a1(args)


if __name__ == "__main__":
    main()
