#!/usr/bin/env python3
"""triage_specs_llm.py — LLM-based bug chain triage with pre-filtering and ranking.

Strips boilerplate keys from each spec, assigns a short ID to save tokens,
runs a zero-cost pre-filter pass to eliminate obvious non-candidates, then asks
an LLM (in segments) to score each remaining spec for chain likelihood.

Ranking thresholds:
    score >= 75  → EXTREMELY LIKELY  (strong chain candidate)
    50 <= score < 75 → MEDIUM        (possible chain candidate)
    score < 50   → UNLIKELY          (filtered out)

A bug chain is a situation where triggering one vulnerability creates the
conditions for another — e.g. a stale pointer enabling a use-after-free, or
an OOB read corrupting metadata that causes a downstream buffer overflow.

Usage:
    python3 triage_specs_llm.py --specs-dir specs/proj_vul --segments 8
    python3 triage_specs_llm.py --specs-dir specs/proj_vul --segments 4 --src-root dataset/hash/proj
    python3 triage_specs_llm.py --specs-dir specs/proj_vul --segments 4 --score-threshold 50

Environment variables (required):
    LLM_API_KEY   — API key for the LLM provider
    LLM_API_BASE  — Base URL (e.g. https://api.openai.com/v1)
    LLM_MODEL     — Model name (e.g. gpt-4o, claude-sonnet-4-6)

Output:
    specs_dir/llm_chain_keep.json         — Specs kept as chain candidates (full spec restored)
    specs_dir/llm_chain_removed.json      — Specs removed by LLM scoring
    specs_dir/llm_prefilter_removed.json  — Specs removed before LLM (pre-filter)
    specs_dir/llm_chain_log.json          — Segment-level reasoning log
"""

import argparse
import json
import math
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import openai
except ImportError:
    print("[!] openai package not found. Install with: pip install openai")
    sys.exit(1)

# ── Boilerplate keys to strip before sending to LLM ─────────────────────────

STRIP_ROOT_KEYS  = {"llm_hints", "target_statement", "column", "end_line", "end_column"}
STRIP_FACTS_KEYS = {"bounds_hints"}

# ── Ranking thresholds ────────────────────────────────────────────────────────

RANK_EXTREMELY_LIKELY = 75   # score >= 75
RANK_MEDIUM           = 50   # 50 <= score < 75
# score < 50 → UNLIKELY → removed

RANK_LABELS = {
    "extremely_likely": f"score >= {RANK_EXTREMELY_LIKELY}",
    "medium":           f"{RANK_MEDIUM} <= score < {RANK_EXTREMELY_LIKELY}",
    "unlikely":         f"score < {RANK_MEDIUM}  (removed)",
}

# ── Pre-filter: CWE blocklist ─────────────────────────────────────────────────
# CWEs that are almost always self-contained and cannot plausibly trigger or
# receive a downstream vulnerability.

ISOLATED_CWES = {
    "369",   # divide-by-zero — no memory side-effects
    "400",   # uncontrolled resource consumption — usually terminal
    "404",   # improper resource shutdown — terminal, not a trigger
    "476",   # null deref — usually a sink, rarely a useful trigger
    "835",   # infinite loop — no downstream memory corruption
    "401",   # memory leak — DoS only, no chain potential
    "772",   # missing release — resource leak, no chain
    "252",   # unchecked return — logic error, rarely chainable
}

# CWEs that can plausibly appear in a chain (as trigger or sink)
TRIGGER_CWES = {"119", "120", "122", "125", "190", "191", "194", "787", "126", "127", "823"}
SINK_CWES    = {"122", "125", "416", "787", "823", "824", "908", "415", "121"}
CHAINABLE_CWES = TRIGGER_CWES | SINK_CWES

# File patterns that are unlikely to have chainable bugs
SKIP_FILE_PATTERNS = [
    r'test[_/]', r'tests[_/]', r'_test\.c$',
    r'example[_/]', r'sample[_/]', r'demo[_/]',
    r'doc[_/]', r'docs[_/]',
    r'conftest\.c$', r'\.gen\.c$', r'\.pb\.c$',
]

# ── Source context ────────────────────────────────────────────────────────────

CONTEXT_LINES = 10

_text_cache:    Dict[str, Optional[str]]  = {}
_resolve_cache: Dict[Tuple, Optional[Path]] = {}


def _read_file(path: Path) -> Optional[str]:
    key = str(path)
    if key not in _text_cache:
        try:
            _text_cache[key] = path.read_text(errors="replace")
        except Exception:
            _text_cache[key] = None
    return _text_cache[key]


def _resolve_file(src_root: Optional[Path], vul_file: str) -> Optional[Path]:
    if not src_root or not vul_file:
        return None
    key = (str(src_root), vul_file)          # tuple key — no pipe-collision risk
    if key in _resolve_cache:
        return _resolve_cache[key]
    p = src_root / vul_file
    if p.is_file():
        _resolve_cache[key] = p
        return p
    basename = os.path.basename(vul_file)
    for match in src_root.rglob(basename):
        if match.is_file():
            _resolve_cache[key] = match
            return match
    _resolve_cache[key] = None
    return None


def _get_source_context(src_root: Optional[Path], vul_file: str,
                         target_line: int) -> str:
    if not src_root or not target_line:
        return ""
    src_path = _resolve_file(src_root, vul_file)
    if not src_path:
        return ""
    src = _read_file(src_path)
    if not src:
        return ""
    lines = src.splitlines()
    start = max(0, target_line - CONTEXT_LINES // 2 - 1)
    end   = min(len(lines), target_line + CONTEXT_LINES // 2)
    numbered = []
    for i, line in enumerate(lines[start:end], start + 1):
        marker = ">>>" if i == target_line else "   "
        numbered.append(f"{marker} {i:4d}: {line}")
    return "\n".join(numbered)


def _extract_cwe(spec: dict, stem: str) -> str:
    cwe = str(spec.get("cwe_id", spec.get("cwe", "")))
    if not cwe:
        m = re.search(r'cwe-(\d+)', stem, re.IGNORECASE)
        if m:
            cwe = m.group(1)
    return re.sub(r'^CWE-', '', cwe, flags=re.IGNORECASE)


# ── Pre-filter helpers ────────────────────────────────────────────────────────

def _cwe_filter(spec: dict, stem: str) -> Tuple[bool, str]:
    """Return (keep, reason). Drops specs with known-isolated CWEs."""
    cwe = _extract_cwe(spec, stem)
    if cwe in ISOLATED_CWES:
        return False, f"isolated_cwe:{cwe}"
    return True, ""


def _has_chain_signals(spec: dict, stem: str) -> Tuple[bool, str]:
    """Return (keep, reason). Drops specs with zero chain-relevant facts."""
    facts   = spec.get("facts", {})
    signals = (
        len(facts.get("pointer_vars",  [])) +
        len(facts.get("length_vars",   [])) +
        len(facts.get("suspect_calls", []))
    )
    if signals == 0:
        return False, "no_chain_signals"
    return True, ""


def _cwe_chainable(spec: dict, stem: str) -> Tuple[bool, str]:
    """Return (keep, reason). Drops specs with CWEs that can't compose."""
    cwe = _extract_cwe(spec, stem)
    if cwe and cwe not in CHAINABLE_CWES:
        return False, f"unchainable_cwe:{cwe}"
    return True, ""


def _file_pattern_filter(spec: dict, stem: str) -> Tuple[bool, str]:
    """Return (keep, reason). Drops specs in test/example/generated files."""
    vul_file = spec.get("file", spec.get("vul_file", "")).lower()
    for pattern in SKIP_FILE_PATTERNS:
        if re.search(pattern, vul_file):
            return False, f"skip_file_pattern:{pattern}"
    return True, ""


def _build_overlap_index(registry: dict) -> Dict[str, int]:
    """
    For each spec, count how many *other* specs share at least one signal:
    pointer var, length var, suspect call, or source file.
    A spec with overlap_count == 0 shares nothing with anyone → safe to drop.
    """
    index: Dict[tuple, set] = defaultdict(set)

    for sid, entry in registry.items():
        facts = entry["stripped"].get("facts", {})
        for var in facts.get("pointer_vars",  []):
            index[("ptr",  var)].add(sid)
        for var in facts.get("length_vars",   []):
            index[("len",  var)].add(sid)
        for call in facts.get("suspect_calls", []):
            index[("call", call)].add(sid)
        f = entry["stripped"].get("file", "")
        if f:
            index[("file", f)].add(sid)

    overlap: Dict[str, int] = {sid: 0 for sid in registry}
    for sids in index.values():
        if len(sids) < 2:
            continue
        for sid in sids:
            overlap[sid] += len(sids) - 1

    return overlap


def _prefilter(registry: dict) -> Tuple[dict, list]:
    """
    Zero-cost pre-filter pass applied before any LLM call.

    Filters applied (all combined):
      1. CWE blocklist       — known self-contained CWE classes
      2. No chain signals    — specs with no pointer/length/call facts
      3. CWE composition     — CWEs that can't appear in known chain patterns
      4. Zero cross-overlap  — specs that share nothing with any other spec

    Returns:
        filtered_registry  — specs that survived all filters
        prefilter_removed  — list of {id, stem, reasons} for dropped specs
    """
    overlap = _build_overlap_index(registry)
    kept    = {}
    removed = []

    for sid, entry in registry.items():
        spec    = entry["stripped"]
        stem    = entry["stem"]
        reasons = []

        for check_fn in (_cwe_filter, _has_chain_signals, _cwe_chainable, _file_pattern_filter):
            keep, reason = check_fn(spec, stem)
            if not keep:
                reasons.append(reason)

        # Overlap check (independent — needs full registry index)
        if overlap.get(sid, 0) == 0:
            reasons.append("zero_cross_overlap")

        if reasons:
            removed.append({
                "id":      sid,
                "stem":    stem,
                "reasons": reasons,
                "spec":    entry["original"],
            })
        else:
            kept[sid] = entry

    print(f"[pre-filter] {len(registry)} specs → {len(kept)} kept, "
          f"{len(removed)} removed  "
          f"({100 * len(removed) // max(len(registry), 1)}% reduction)")

    return kept, removed


# ── Strip / restore boilerplate ───────────────────────────────────────────────

def _strip_spec(spec: dict) -> Tuple[dict, dict]:
    """Return (stripped_spec, stripped_keys)."""
    stripped = json.loads(json.dumps(spec))
    removed  = {}

    for key in STRIP_ROOT_KEYS:
        if key in stripped:
            removed[key] = stripped.pop(key)

    if "facts" in stripped:
        removed_facts = {}
        for key in STRIP_FACTS_KEYS:
            if key in stripped["facts"]:
                removed_facts[key] = stripped["facts"].pop(key)
        if removed_facts:
            removed["_facts"] = removed_facts

    return stripped, removed


def _restore_spec(stripped: dict, removed: dict) -> dict:
    """Re-attach stripped keys to a surviving spec. Non-destructive."""
    removed  = json.loads(json.dumps(removed))   # defensive copy — never mutate caller's dict
    full     = json.loads(json.dumps(stripped))

    removed_facts = removed.pop("_facts", {})
    full.update(removed)

    if removed_facts:
        full.setdefault("facts", {}).update(removed_facts)

    return full


# ── Compact prompt representation ─────────────────────────────────────────────

def _format_for_prompt(short_id: str, stripped: dict, stem: str,
                        src_root: Optional[Path]) -> str:
    vul_file = stripped.get("file", stripped.get("vul_file", ""))
    vul_line = int(stripped.get("line", stripped.get("vul_line", 0)))
    cwe      = _extract_cwe(stripped, stem)
    basename = os.path.basename(vul_file) if vul_file else "?"

    facts         = stripped.get("facts", {})
    suspect_calls = facts.get("suspect_calls", [])
    pointer_vars  = facts.get("pointer_vars",  [])
    length_vars   = facts.get("length_vars",   [])

    lines = [
        f"[{short_id}]",
        f"  file: {basename}:{vul_line}  cwe: {cwe or 'unknown'}",
    ]
    if suspect_calls:
        lines.append(f"  calls: {', '.join(suspect_calls)}")
    if pointer_vars:
        lines.append(f"  ptrs:  {', '.join(pointer_vars)}")
    if length_vars:
        lines.append(f"  lens:  {', '.join(length_vars)}")

    ctx = _get_source_context(src_root, vul_file, vul_line)
    if ctx:
        lines.append("  ctx:")
        for cl in ctx.splitlines():
            lines.append(f"    {cl}")

    return "\n".join(lines)


# ── Ranking helper ────────────────────────────────────────────────────────────

def _rank_label(score: int) -> str:
    if score >= RANK_EXTREMELY_LIKELY:
        return "extremely_likely"
    if score >= RANK_MEDIUM:
        return "medium"
    return "unlikely"


# ── Prompts ───────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a vulnerability research assistant specialising in C/C++ bug chain analysis.

A bug chain is a sequence of two or more vulnerabilities where triggering one
creates the conditions for another. Examples:
  • OOB read corrupts image dimension metadata → downstream ScaleImage() null-deref
  • Integer truncation creates undersized allocation → subsequent memcpy overflows it
  • Stale pointer left by one function → use-after-free when caller dereferences it
  • Missing palette bounds check → OOB read feeds attacker bytes into a pixel-write path
  • realloc() invalidates a stored pointer → use-after-realloc in the same call chain

Your job is to score each spec from 0–100 on how likely it is to participate in
a bug chain with at least one other spec in the batch.

Scoring guidance:
  75–100  Extremely likely: shared memory structures, known composable CWE pairs
          (CWE-190→CWE-122, CWE-125→CWE-787), free/alloc pairs, aliased pointers.
  50–74   Medium: some shared signals (same file, related calls) but less direct evidence.
  0–49    Unlikely: no shared state, self-contained bug, terminal sink with no trigger path.\
"""

USER_PROMPT_TEMPLATE = """\
Below are {n} vulnerability specs from project {project}.
Each spec has a short ID like S0001.

Score each spec from 0–100 on how likely it is to participate in a bug chain
with at least one other spec in this batch.

  >= 75  → extremely likely chain candidate
  50–74  → medium likelihood
  <  50  → unlikely (will be filtered out)

Respond ONLY with valid JSON — no prose, no markdown fences:
{{
  "scores": {{
    "S0001": 82,
    "S0042": 31,
    ...
  }},
  "reason": "one sentence summary of your scoring logic"
}}

Every ID in the batch must appear in "scores".

--- SPECS ---
{specs_block}
"""


def _build_prompt(specs_block: str, project: str, n: int) -> str:
    return USER_PROMPT_TEMPLATE.format(
        n=n,
        project=project,
        specs_block=specs_block,
    )


# ── LLM client ────────────────────────────────────────────────────────────────

def _make_client() -> Tuple["openai.OpenAI", str]:
    api_key  = os.environ.get("LLM_API_KEY",  "")
    api_base = os.environ.get("LLM_API_BASE", "")
    model    = os.environ.get("LLM_MODEL",    "gpt-4o")

    if not api_key:
        print("[!] LLM_API_KEY not set.", file=sys.stderr)
        sys.exit(1)

    kwargs: dict = {"api_key": api_key}
    if api_base:
        kwargs["base_url"] = api_base

    return openai.OpenAI(**kwargs), model


def _call_llm(client: "openai.OpenAI", model: str, user_prompt: str,
              retries: int = 3) -> dict:
    for attempt in range(retries):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_prompt},
                ],
                temperature=0.2,
            )
            raw = response.choices[0].message.content.strip()
            raw = re.sub(r'^```(?:json)?\s*', '', raw)
            raw = re.sub(r'\s*```$',          '', raw)
            return json.loads(raw)

        except (json.JSONDecodeError, Exception) as e:
            if attempt == retries - 1:
                print(f"\n[!] LLM call failed after {retries} attempts: {e}",
                      file=sys.stderr)
                return {"scores": {}, "reason": f"ERROR:{e}"}
            wait = 2 ** attempt
            print(f"\n[!] Attempt {attempt + 1} failed ({e}), retrying in {wait}s …",
                  file=sys.stderr)
            time.sleep(wait)

    return {"scores": {}, "reason": "ERROR: exhausted retries"}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="LLM-based bug chain triage with pre-filtering and ranking"
    )
    parser.add_argument("--specs-dir", required=True,
                        help="Directory containing spec JSON files")
    parser.add_argument("--segments", type=int, default=4,
                        help="Number of LLM batches (default: 4)")
    parser.add_argument("--src-root", default=None,
                        help="Project source root for source context (optional)")
    parser.add_argument("--score-threshold", type=int, default=RANK_MEDIUM,
                        help=f"Minimum score to keep a spec (default: {RANK_MEDIUM})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Run pre-filter only, don't call LLM")
    parser.add_argument("--estimate-cost", action="store_true",
                        help="Estimate token cost before running")
    args = parser.parse_args()

    specs_dir       = Path(args.specs_dir)
    src_root        = Path(args.src_root) if args.src_root else None
    score_threshold = args.score_threshold

    spec_files = sorted(f for f in specs_dir.glob("*.json")
                        if f.name not in {
                            "triage_stats.json",
                            "llm_chain_keep.json",
                            "llm_chain_removed.json",
                            "llm_chain_log.json",
                            "llm_prefilter_removed.json",
                        })
    if not spec_files:
        print(f"[!] No spec JSON files found in {specs_dir}")
        sys.exit(0)

    project = specs_dir.name
    print(f"[*] Project:         {project}")
    print(f"[*] Specs found:     {len(spec_files)}")
    print(f"[*] Score threshold: {score_threshold}  "
          f"(keep >= {score_threshold}, remove < {score_threshold})")
    print(f"[*] Rank bands:")
    for label, desc in RANK_LABELS.items():
        print(f"      {label:<20} {desc}")
    print()

    # ── Load all specs ────────────────────────────────────────────────────────
    registry: Dict[str, dict] = {}
    for i, sp in enumerate(spec_files):
        short_id = f"S{i:04d}"
        try:
            with open(sp) as f:
                original = json.load(f)
        except Exception:
            original = {}
        stripped, removed = _strip_spec(original)
        registry[short_id] = {
            "stem":     sp.stem,
            "path":     sp,
            "stripped": stripped,
            "removed":  removed,
            "original": original,
        }

    # ── Pre-filter pass ───────────────────────────────────────────────────────
    registry, prefilter_removed = _prefilter(registry)

    if not registry:
        print("[!] Pre-filter removed all specs. Nothing to send to LLM.")
        _write_json(specs_dir / "llm_prefilter_removed.json", {
            "project": project,
            "total_removed": len(prefilter_removed),
            "specs": prefilter_removed,
        })
        sys.exit(0)

    # ── Dry run: just show pre-filter results ──────────────────────────────
    if args.dry_run:
        print("\n[dry-run] Pre-filter complete. Would send to LLM:")
        print(f"  Specs remaining: {len(registry)}")
        print(f"  Pre-filtered:    {len(prefilter_removed)}")
        
        # Show breakdown of pre-filter reasons
        reason_counts = defaultdict(int)
        for item in prefilter_removed:
            for r in item.get("reasons", []):
                reason_counts[r.split(":")[0]] += 1
        print("\n  Pre-filter breakdown:")
        for reason, count in sorted(reason_counts.items(), key=lambda x: -x[1]):
            print(f"    {reason}: {count}")
        
        _write_json(specs_dir / "llm_prefilter_removed.json", {
            "project": project,
            "total_removed": len(prefilter_removed),
            "specs": prefilter_removed,
        })
        sys.exit(0)

    # ── Cost estimation ────────────────────────────────────────────────────
    if args.estimate_cost:
        # Estimate tokens: ~200 tokens per spec (prompt) + ~50 tokens response
        estimated_input_tokens = len(registry) * 200
        estimated_output_tokens = len(registry) * 50
        
        # Rough cost estimates (GPT-4o pricing as baseline)
        input_cost = estimated_input_tokens * 0.005 / 1000   # $5/1M input
        output_cost = estimated_output_tokens * 0.015 / 1000  # $15/1M output
        total_cost = input_cost + output_cost
        
        print(f"\n[cost estimate]")
        print(f"  Specs to score: {len(registry)}")
        print(f"  Est. input tokens: ~{estimated_input_tokens:,}")
        print(f"  Est. output tokens: ~{estimated_output_tokens:,}")
        print(f"  Est. cost (GPT-4o): ~${total_cost:.2f}")
        print("\nRun without --estimate-cost to proceed.")

    # ── Clamp segments ────────────────────────────────────────────────────────
    total    = len(registry)
    segments = max(1, args.segments)
    if segments > total:
        print(f"[!] segments ({segments}) > surviving specs ({total}), "
              f"clamping to {total}")
        segments = total

    batch_size = math.ceil(total / segments)
    client, model = _make_client()

    print(f"\n[*] LLM model:       {model}")
    print(f"[*] Specs to score:  {total}  ({segments} segment(s) of ~{batch_size})")
    print(f"[*] Stripping keys:  {STRIP_ROOT_KEYS | STRIP_FACTS_KEYS}")
    print()

    # ── LLM scoring segments ──────────────────────────────────────────────────
    all_short_ids  = list(registry.keys())
    scores: Dict[str, int] = {}     # sid → 0-100 score
    segment_log    = []

    for seg_idx in range(segments):
        batch_ids = all_short_ids[seg_idx * batch_size: (seg_idx + 1) * batch_size]
        if not batch_ids:
            break

        print(f"[Segment {seg_idx + 1}/{segments}] {len(batch_ids)} specs …",
              end=" ", flush=True)

        blocks = []
        for sid in batch_ids:
            entry = registry[sid]
            block = _format_for_prompt(sid, entry["stripped"], entry["stem"], src_root)
            blocks.append(block)

        specs_block = "\n\n".join(blocks)
        user_prompt = _build_prompt(specs_block, project, len(batch_ids))
        result      = _call_llm(client, model, user_prompt)

        seg_scores  = result.get("scores", {})
        reason      = result.get("reason", "")

        # Only accept scores for IDs in this batch
        batch_set = set(batch_ids)
        for sid in batch_ids:
            raw_score = seg_scores.get(sid)
            if isinstance(raw_score, (int, float)):
                scores[sid] = max(0, min(100, int(raw_score)))
            else:
                # LLM omitted this ID — default to 0 (will be removed)
                scores[sid] = 0
                print(f"\n  [!] No score returned for {sid}, defaulting to 0",
                      file=sys.stderr)

        # Tally by rank band for this segment
        band_counts = defaultdict(int)
        for sid in batch_ids:
            band_counts[_rank_label(scores[sid])] += 1

        print(f"done  |  "
              f"extremely_likely={band_counts['extremely_likely']}  "
              f"medium={band_counts['medium']}  "
              f"unlikely={band_counts['unlikely']}")
        if reason:
            print(f"  reason: {reason}")

        segment_log.append({
            "segment":  seg_idx + 1,
            "batch_ids": batch_ids,
            "scores":   {sid: scores[sid] for sid in batch_ids},
            "reason":   reason,
        })

    # ── Partition by score ────────────────────────────────────────────────────
    kept_specs    = []
    removed_specs = []

    for short_id, entry in registry.items():
        full   = _restore_spec(entry["stripped"], entry["removed"])
        score  = scores.get(short_id, 0)
        label  = _rank_label(score)
        record = {
            "id":    short_id,
            "stem":  entry["stem"],
            "score": score,
            "rank":  label,
            "spec":  full,
        }
        if score >= score_threshold:
            kept_specs.append(record)
        else:
            removed_specs.append(record)

    # Sort kept specs by score descending so highest-confidence are first
    kept_specs.sort(key=lambda r: r["score"], reverse=True)
    removed_specs.sort(key=lambda r: r["score"], reverse=True)

    # ── Summary stats ─────────────────────────────────────────────────────────
    total_in = len(spec_files)
    prefiltered_count  = len(prefilter_removed)
    llm_removed_count  = len(removed_specs)
    final_kept         = len(kept_specs)

    band_summary = defaultdict(int)
    for r in kept_specs:
        band_summary[r["rank"]] += 1

    # ── Write outputs ─────────────────────────────────────────────────────────
    _write_json(specs_dir / "llm_chain_keep.json", {
        "project":          project,
        "model":            model,
        "score_threshold":  score_threshold,
        "total_kept":       final_kept,
        "band_counts":      dict(band_summary),
        "specs":            kept_specs,
    })

    _write_json(specs_dir / "llm_chain_removed.json", {
        "project":          project,
        "model":            model,
        "score_threshold":  score_threshold,
        "total_removed":    llm_removed_count,
        "specs":            removed_specs,
    })

    _write_json(specs_dir / "llm_prefilter_removed.json", {
        "project":          project,
        "total_removed":    prefiltered_count,
        "specs":            prefilter_removed,
    })

    _write_json(specs_dir / "llm_chain_log.json", {
        "segments": segment_log,
    })

    # ── Final summary ─────────────────────────────────────────────────────────
    print()
    print("=" * 55)
    print(f"  INPUT SPECS        {total_in:>5}")
    print(f"  Pre-filter removed {prefiltered_count:>5}  (zero-cost)")
    print(f"  Sent to LLM        {total:>5}")
    print(f"  LLM removed        {llm_removed_count:>5}  (score < {score_threshold})")
    print(f"  ─────────────────────────")
    print(f"  FINAL KEPT         {final_kept:>5}")
    print()
    print(f"  Rank breakdown (kept specs):")
    print(f"    extremely_likely  {band_summary.get('extremely_likely', 0):>5}  (score >= {RANK_EXTREMELY_LIKELY})")
    print(f"    medium            {band_summary.get('medium', 0):>5}  (score >= {RANK_MEDIUM})")
    print("=" * 55)

    keep_path     = specs_dir / "llm_chain_keep.json"
    removed_path  = specs_dir / "llm_chain_removed.json"
    pre_path      = specs_dir / "llm_prefilter_removed.json"
    log_path      = specs_dir / "llm_chain_log.json"

    print(f"\n  Kept     → {keep_path}")
    print(f"  Removed  → {removed_path}")
    print(f"  Pre-filt → {pre_path}")
    print(f"  Log      → {log_path}")


# ── Utility ───────────────────────────────────────────────────────────────────

def _write_json(path: Path, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    main()