#!/usr/bin/env python3
"""triage_specs.py — Pre-LLM spec triage.

Removes specs that are provably not actionable library vulnerabilities:
test/benchmark/fuzzer code, generated files, unresolvable sources, and
test-harness functions.  Everything else is kept.

Optional --dedup flag collapses redundant specs sharing the same
function+CWE (budget optimisation, not lossless).

Usage:
    python3 triage_specs.py --specs-dir specs/proj_vul --src-root dataset/hash/proj_vul
    python3 triage_specs.py ... --fact-pack sa_outputs/proj_vul/fact_pack.json --dedup
    python3 triage_specs.py ... --evaluate se_runs/.../summary.tsv

Output:
    specs_dir/triage.tsv        — Per-spec diagnostic scores
    specs_dir/triage_order.txt  — Active spec filenames
    specs_dir/triage_stats.json — Summary statistics
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── CWE risk tiers ──────────────────────────────────────────────────────────

CWE_HIGH = {
    "122", "121", "120",   # Stack/heap buffer overflow
    "787", "125",           # OOB write/read
    "416",                  # Use after free
    "415",                  # Double free
    "476",                  # NULL pointer dereference
    "190", "191",           # Integer overflow/underflow
    "369",                  # Divide by zero
    "123",                  # Write-what-where
    "562",                  # Return stack-allocated memory
}

CWE_MEDIUM = {
    "119",  # Improper restriction of operations within bounds
    "674",  # Uncontrolled recursion
    "400",  # Uncontrolled resource consumption
    "401",  # Memory leak
    "772",  # Missing release of resource
    "134",  # Uncontrolled format string
    "761",  # Free pointer not at start
    "823",  # Use of out-of-range pointer offset
}

CWE_LOW = {
    "457",  # Use of uninitialized variable
    "252",  # Unchecked return value
    "704",  # Incorrect type conversion
}

# ── Skip patterns ───────────────────────────────────────────────────────────

SKIP_FILE_PATTERNS = [
    r'conftest\.c$',
    r'test[_/]', r'tests[_/]', r'_test\.c$',
    r'^test[A-Za-z]',
    r'^runtest\.c$',
    r'bench[_/]', r'benchmark',
    r'example[_/]', r'examples[_/]',
    r'tools[_/]', r'doc[_/]', r'docs[_/]',
    r'fuzz[_/]', r'fuzzer',
    r'\.pb\.c$', r'\.gen\.c$',
]

SKIP_FUNCTION_PATTERNS = [
    r'^main$',
    r'^test_', r'_test$', r'^Test',
    r'^bench_', r'_bench$',
    r'^example_',
    r'^__',
]

# ── Dangerous-call patterns ─────────────────────────────────────────────────

FREE_RE = re.compile(
    r'(?i)\b\w*(free|destroy|close|release|cleanup|finalize|unref|dealloc)\b'
)
ALLOC_RE = re.compile(
    r'(?i)\b\w*(alloc|malloc|calloc|realloc|strdup|strndup|new|create|init)\b'
)
MEM_RE = re.compile(
    r'\b(memcpy|memmove|memset|memcmp|bcopy|bzero|strcpy|strncpy'
    r'|strcat|strncat|sprintf|snprintf)\b'
)

# ── Function detection ──────────────────────────────────────────────────────

FUNC_DEF_RE = re.compile(
    r'^(?:static\s+|inline\s+|extern\s+|__inline\s+)*'
    r'(?:const\s+|volatile\s+|unsigned\s+|signed\s+|long\s+|short\s+)*'
    r'[\w][\w\s\*]*?'
    r'\b(\w+)\s*\('
    r'[^;]*$'
)

_C_KEYWORDS = frozenset({
    "if", "while", "for", "switch", "return", "sizeof", "typeof",
    "else", "do", "case", "goto", "break", "continue",
})

LINE_BUCKET = 30

FEATURE_NAMES = ["cwe_risk", "reachability", "dangerous_calls"]

# ── Simple caches ────────────────────────────────────────────────────────────

_text_cache: Dict[str, Optional[str]] = {}
_resolve_cache: Dict[str, Optional[Path]] = {}


def _read_file(path: Path) -> Optional[str]:
    key = str(path)
    if key not in _text_cache:
        try:
            _text_cache[key] = path.read_text(errors="replace")
        except Exception:
            _text_cache[key] = None
    return _text_cache[key]


def _resolve_file(src_root: Path, vul_file: str) -> Optional[Path]:
    if vul_file in _resolve_cache:
        return _resolve_cache[vul_file]
    p = src_root / vul_file
    if p.is_file():
        _resolve_cache[vul_file] = p
        return p
    basename = os.path.basename(vul_file)
    for match in src_root.rglob(basename):
        if match.is_file():
            _resolve_cache[vul_file] = match
            return match
    _resolve_cache[vul_file] = None
    return None


# ── Function boundary detection ──────────────────────────────────────────────

_bounds_cache: Dict[str, Optional[Dict[str, Tuple[int, int]]]] = {}


def _func_boundaries(src_path: Path) -> Optional[Dict[str, Tuple[int, int]]]:
    """Regex-based function boundary detection. Returns {name: (start, end)}."""
    key = str(src_path)
    if key in _bounds_cache:
        return _bounds_cache[key]

    src = _read_file(src_path)
    if not src:
        _bounds_cache[key] = None
        return None

    lines = src.splitlines()
    func_starts: List[Tuple[str, int]] = []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        m = FUNC_DEF_RE.match(stripped)
        if m:
            name = m.group(1)
            if name not in _C_KEYWORDS:
                func_starts.append((name, i))

    if not func_starts:
        _bounds_cache[key] = None
        return None

    bounds = {}
    for idx, (name, start) in enumerate(func_starts):
        end = func_starts[idx + 1][1] - 1 if idx + 1 < len(func_starts) else len(lines)
        bounds[name] = (start, end)

    _bounds_cache[key] = bounds
    return bounds


def _find_function(src_path: Path, target_line: int) -> Tuple[str, bool, List[str]]:
    """Return (func_name, is_static, callers) for the function containing target_line."""
    bounds = _func_boundaries(src_path)
    if not bounds:
        return ("", False, [])

    best_name, best_start, best_end = "", 0, 0
    for name, (start, end) in bounds.items():
        if start <= target_line <= end:
            best_name, best_start, best_end = name, start, end
            break
        if start <= target_line and start > best_start:
            best_name, best_start, best_end = name, start, end

    if not best_name:
        return ("", False, [])

    src = _read_file(src_path)
    if not src:
        return (best_name, False, [])

    is_static = bool(
        re.search(rf'\bstatic\b[^;]*\b{re.escape(best_name)}\s*\(', src)
    )

    callers = []
    call_pat = re.compile(rf'\b{re.escape(best_name)}\s*\(')
    lines = src.splitlines()
    for name, (start, end) in bounds.items():
        if name == best_name:
            continue
        for li in range(start - 1, min(end, len(lines))):
            if call_pat.search(lines[li]):
                callers.append(name)
                break

    return (best_name, is_static, callers)


# ── Fact pack loader ─────────────────────────────────────────────────────────

def _load_fact_pack(path: Optional[str]) -> Dict[Tuple[str, int], dict]:
    """Load fact_pack.json → {(basename, line): fact}."""
    if not path:
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return {}
    index = {}
    for fact in data.get("facts", []):
        base = os.path.basename(fact.get("file", ""))
        line = int(fact.get("line", 0))
        index[(base, line)] = fact
    return index


# ── CWE extraction ──────────────────────────────────────────────────────────

def _extract_cwe(spec: dict, stem: str) -> str:
    cwe = str(spec.get("cwe_id", spec.get("cwe", "")))
    if not cwe:
        m = re.search(r'cwe-(\d+)', stem, re.IGNORECASE)
        if m:
            cwe = m.group(1)
    return re.sub(r'^CWE-', '', cwe, flags=re.IGNORECASE)


# ── Stage 1: Filter ─────────────────────────────────────────────────────────

def _should_filter(vul_file: str, vul_basename: str,
                   tool_files: set = frozenset()) -> Optional[str]:
    """Return filter reason if spec should be skipped, else None."""
    if not vul_file:
        return "NO_VUL_FILE"
    if vul_basename in tool_files:
        return f"TOOL_FILE:{vul_basename}"
    for pat in SKIP_FILE_PATTERNS:
        if re.search(pat, vul_file, re.IGNORECASE):
            return f"SKIP_FILE:{pat}"
    return None


# ── Scoring (diagnostic — used as dedup tiebreaker only) ─────────────────────

def _score_cwe_risk(cwe: str) -> int:
    if cwe in CWE_HIGH:
        return 25
    if cwe in CWE_MEDIUM:
        return 15
    if cwe in CWE_LOW:
        return 5
    if cwe:
        return 10  # unknown but present
    return 0


def _score_reachability(
    func_name: str, is_static: bool, callers: List[str],
    src_path: Optional[Path],
) -> int:
    if not func_name:
        return 8  # unresolved — don't over-penalize
    if not is_static:
        return 20  # public
    if callers and src_path:
        src = _read_file(src_path)
        if src:
            for c in callers:
                if not re.search(rf'\bstatic\b[^;]*\b{re.escape(c)}\s*\(', src):
                    return 15  # has public caller
        return 10  # callers, all static
    if callers:
        return 10
    return 3  # static, no callers


def _score_dangerous_calls(suspect_calls: List[str]) -> int:
    if not suspect_calls:
        return 0
    joined = " ".join(suspect_calls)
    has_free = bool(FREE_RE.search(joined))
    has_alloc = bool(ALLOC_RE.search(joined))
    has_mem = bool(MEM_RE.search(joined))

    if has_alloc and has_free:
        return 15
    if has_free:
        return 8
    if has_mem:
        return 4
    return 0


# ── Stage 2: Dedup ──────────────────────────────────────────────────────────

def _dedup_key(r: dict) -> str:
    basename = os.path.basename(r.get("file", ""))
    func = r.get("func", "")
    cwe = r.get("cwe", "")
    line = r.get("line", 0)
    cwe_part = cwe if cwe else "ANY"

    if func:
        return f"{basename}|{func}|{cwe_part}"
    if line > 0:
        return f"{basename}|L{line // LINE_BUCKET}|{cwe_part}"
    return f"{basename}|UNKNOWN|{cwe_part}"


def _dedup_specs(results: List[dict]) -> Tuple[List[dict], List[dict]]:
    groups: Dict[str, List[dict]] = defaultdict(list)
    for r in results:
        key = _dedup_key(r)
        r["dedup_key"] = key
        groups[key].append(r)

    kept, removed = [], []
    for group in groups.values():
        group.sort(key=lambda r: -r["score"])
        kept.append(group[0])
        removed.extend(group[1:])
    return kept, removed


# ── Process one spec ─────────────────────────────────────────────────────────

def _process_spec(
    spec_path: Path, src_root: Path,
    facts: Dict[Tuple[str, int], dict],
    tool_files: set = frozenset(),
) -> dict:
    spec = {}
    try:
        with open(spec_path) as f:
            spec = json.load(f)
    except Exception:
        pass

    stem = spec_path.stem
    reasons: List[str] = []

    vul_file = spec.get("file", spec.get("vul_file", ""))
    vul_line = int(spec.get("line", spec.get("vul_line", 0)))
    cwe = _extract_cwe(spec, stem)
    vul_basename = os.path.basename(vul_file) if vul_file else ""

    def _dropped(reason: str) -> dict:
        reasons.append(reason)
        return {
            "score": 0, "reasons": reasons, "stem": stem,
            "cwe": cwe, "func": "", "file": vul_file, "line": vul_line,
            "features": {fn: 0 for fn in FEATURE_NAMES},
            "dedup_key": "", "filtered": True,
        }

    # ── Pattern filters ──
    filter_reason = _should_filter(vul_file, vul_basename, tool_files)
    if filter_reason:
        return _dropped(filter_reason)

    src_path = _resolve_file(src_root, vul_file)
    if not src_path:
        return _dropped("FILE_NOT_FOUND")

    func_name, is_static, callers = "", False, []
    if vul_line > 0:
        func_name, is_static, callers = _find_function(src_path, vul_line)

    if func_name:
        for pat in SKIP_FUNCTION_PATTERNS:
            if re.search(pat, func_name):
                return _dropped(f"SKIP_FUNC:{func_name}")

    # ── Diagnostic score (dedup tiebreaker only, never used to drop) ──
    fact = facts.get((vul_basename, vul_line))
    suspect_calls = fact.get("suspect_calls", []) if fact else []

    f_cwe = _score_cwe_risk(cwe)
    f_reach = _score_reachability(func_name, is_static, callers, src_path)
    f_calls = _score_dangerous_calls(suspect_calls)

    score = f_cwe + f_reach + f_calls
    features = {
        "cwe_risk": f_cwe,
        "reachability": f_reach,
        "dangerous_calls": f_calls,
    }

    # Build reasons
    if f_cwe == 25:
        reasons.append(f"CWE_{cwe}_HIGH")
    elif f_cwe == 15:
        reasons.append(f"CWE_{cwe}_MED")
    elif f_cwe == 5:
        reasons.append(f"CWE_{cwe}_LOW")
    elif f_cwe == 0 and not cwe:
        reasons.append("NO_CWE")

    if func_name:
        reasons.append(f"FUNC:{func_name}")
    else:
        reasons.append("FUNC_NOT_FOUND")

    if f_reach == 20:
        reasons.append("PUBLIC")
    elif f_reach >= 15:
        reasons.append("STATIC+PUB_CALLER")
    elif f_reach >= 10:
        reasons.append("HAS_CALLERS")
    elif f_reach == 3:
        reasons.append("STATIC_NO_CALLER")

    if f_calls > 0:
        reasons.append(f"CALLS:{f_calls}pts")

    return {
        "score": score, "reasons": reasons, "stem": stem,
        "cwe": cwe, "func": func_name, "file": vul_file, "line": vul_line,
        "features": features, "dedup_key": "", "filtered": False,
    }


# ── Evaluation ───────────────────────────────────────────────────────────────

def _evaluate(results: List[dict], summary_path: str) -> None:
    truth = {}
    try:
        with open(summary_path) as f:
            for row in csv.DictReader(f, delimiter='\t'):
                spec = row.get("Spec", "").strip()
                verdict = row.get("Verdict", row.get("FinalStatus", "")).strip()
                if spec:
                    truth[spec] = verdict
    except Exception as e:
        print(f"[!] Failed to load ground truth: {e}", file=sys.stderr)
        return

    if not truth:
        print("[!] No ground truth loaded.")
        return

    tp_verdicts = {"TP", "SE_DETECTED", "LIKELY_TP"}

    matched = []
    for r in results:
        verdict = truth.get(r["stem"], "")
        matched.append({**r, "verdict": verdict, "is_tp": verdict in tp_verdicts})

    total_tp = sum(1 for m in matched if m["is_tp"])
    active = [m for m in matched if not m.get("filtered", False)]
    active_tp = sum(1 for m in active if m["is_tp"])

    # Dedup safety
    dedup_kept, dedup_removed = _dedup_specs(list(active))
    dedup_tp = sum(1 for m in dedup_kept if m["is_tp"])
    dedup_lost = [m for m in dedup_removed if m["is_tp"]]

    print(f"\n{'='*60}")
    print(f"  TRIAGE EVALUATION")
    print(f"{'='*60}")
    print(f"  Ground truth:  {len(truth)} specs, {total_tp} TPs")
    print(f"  Filter safety: {active_tp}/{total_tp} TPs survive filtering"
          f" ({active_tp/max(total_tp,1)*100:.0f}%)")
    print(f"  Dedup safety:  {dedup_tp}/{active_tp} TPs survive dedup"
          f" ({dedup_tp/max(active_tp,1)*100:.0f}%)")
    if dedup_lost:
        print(f"  WARNING: {len(dedup_lost)} TPs lost in dedup:")
        for m in dedup_lost:
            print(f"    - {m['stem']}  (key={m.get('dedup_key','?')}, score={m['score']})")

    # Counts
    total = len(results)
    filtered = sum(1 for r in results if r.get("filtered"))
    deduped = len(dedup_removed)
    final = len(dedup_kept)
    print(f"\n  Reduction: {total} → {total - filtered} (filter)"
          f" → {final} (dedup) = {(1 - final/max(total,1))*100:.0f}% removed")
    print(f"  TP recall: {dedup_tp}/{total_tp}"
          f" ({dedup_tp/max(total_tp,1)*100:.0f}%)")
    print(f"{'='*60}\n")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Pre-LLM spec triage — filter and dedup"
    )
    parser.add_argument("--specs-dir", required=True)
    parser.add_argument("--src-root", required=True)
    parser.add_argument("--fact-pack", default=None)
    parser.add_argument("--findings", default=None, help="(unused, reserved)")
    parser.add_argument("--skip-p3", action="store_true",
                        help="(ignored, kept for backward compat)")
    parser.add_argument("--dedup", action="store_true")
    parser.add_argument("--dedup-func", action="store_true",
                        help="Alias for --dedup")
    parser.add_argument("--max-specs", type=int, default=0)
    parser.add_argument("--tool-files", default=None,
                        help="Comma-separated tool/test file basenames to skip (e.g., 'tiffcrop.c,xmllint.c')")
    parser.add_argument("--evaluate", default=None)
    args = parser.parse_args()

    if args.dedup_func:
        args.dedup = True

    tool_file_set: set[str] = set()
    if args.tool_files:
        tool_file_set = {f.strip() for f in args.tool_files.split(",")} - {""}

    specs_dir = Path(args.specs_dir)
    src_root = Path(args.src_root)
    spec_files = sorted(specs_dir.glob("*.json"))

    if not spec_files:
        print(f"[!] No spec files in {specs_dir}")
        sys.exit(0)

    facts = _load_fact_pack(args.fact_pack)

    # ── Stage 1: Filter ──
    results = [_process_spec(sp, src_root, facts, tool_file_set) for sp in spec_files]

    filtered = [r for r in results if r.get("filtered")]
    active = [r for r in results if not r.get("filtered")]

    # Move filtered specs to skipped/
    skipped_count = 0
    skip_dir = specs_dir / "skipped"
    skip_dir.mkdir(exist_ok=True)
    for r in filtered:
        src = specs_dir / f"{r['stem']}.json"
        if src.exists():
            src.rename(skip_dir / f"{r['stem']}.json")
            skipped_count += 1

    # ── Stage 2: Dedup ──
    deduped_count = 0
    if args.dedup:
        kept, removed = _dedup_specs(active)
        dedup_dir = specs_dir / "deduped"
        dedup_dir.mkdir(exist_ok=True)
        for r in removed:
            src = specs_dir / f"{r['stem']}.json"
            if src.exists():
                src.rename(dedup_dir / f"{r['stem']}.json")
                deduped_count += 1
        active = kept
    else:
        for r in active:
            r["dedup_key"] = _dedup_key(r)

    # Sort by score descending (for --max-specs budget only)
    active.sort(key=lambda r: -r["score"])

    limited_count = 0
    if args.max_specs > 0 and len(active) > args.max_specs:
        deferred_dir = specs_dir / "deferred"
        deferred_dir.mkdir(exist_ok=True)
        for r in active[args.max_specs:]:
            src = specs_dir / f"{r['stem']}.json"
            if src.exists():
                src.rename(deferred_dir / f"{r['stem']}.json")
                limited_count += 1
        active = active[:args.max_specs]

    # ── Output ──

    # triage.tsv (all results)
    all_sorted = sorted(results, key=lambda r: (-int(not r.get("filtered")), -r["score"]))
    tsv_path = specs_dir / "triage.tsv"
    with open(tsv_path, "w") as f:
        header = ["Score", "Spec", "CWE", "Func", "File", "Line"] \
                 + FEATURE_NAMES + ["DedupKey", "Reasons"]
        f.write("\t".join(header) + "\n")
        for r in all_sorted:
            feats = r.get("features", {})
            row = [
                str(r["score"]), r["stem"], r["cwe"],
                r["func"], r["file"], str(r["line"]),
            ] + [str(feats.get(fn, 0)) for fn in FEATURE_NAMES] + [
                r.get("dedup_key", ""),
                "; ".join(r["reasons"]),
            ]
            f.write("\t".join(row) + "\n")
    print(f"[✓] Wrote {tsv_path}")

    # triage_order.txt (active specs)
    order_path = specs_dir / "triage_order.txt"
    with open(order_path, "w") as f:
        for r in active:
            f.write(f"{r['stem']}.json\n")
    print(f"[✓] Wrote {order_path}")

    # triage_stats.json
    n_active = max(len(active), 1)
    feature_means = {}
    for fn in FEATURE_NAMES:
        feature_means[fn] = round(
            sum(r.get("features", {}).get(fn, 0) for r in active) / n_active, 2
        )

    stats = {
        "total_specs": len(results),
        "filtered": len(filtered),
        "deduped": deduped_count,
        "active": len(active),
        "deferred": limited_count,
        "score_range": {
            "min": min((r["score"] for r in active), default=0),
            "max": max((r["score"] for r in active), default=0),
        },
        "feature_means": feature_means,
    }
    stats_path = specs_dir / "triage_stats.json"
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"[✓] Wrote {stats_path}")

    # Summary
    print(f"\n[TRIAGE] {len(results)} specs → {len(active)} active"
          f" ({len(filtered)} filtered, {deduped_count} deduped)")
    if limited_count:
        print(f"  Deferred {limited_count} specs (max-specs={args.max_specs})")

    active_on_disk = len(list(specs_dir.glob("*.json")))
    print(f"  Specs on disk for agent run: {active_on_disk}")

    # Evaluation
    if args.evaluate:
        _evaluate(results, args.evaluate)


if __name__ == "__main__":
    main()
