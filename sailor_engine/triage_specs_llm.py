#!/usr/bin/env python3
"""triage_specs_llm.py — LLM-based bug chain triage.

Strips boilerplate keys from each spec, assigns a short ID to save tokens,
then asks an LLM (in segments) to decide which specs are unlikely to participate
in a bug chain and should be removed. Specs that survive have the stripped keys
appended back. Two output files are written: kept specs and removed specs.

A bug chain is a situation where triggering one vulnerability creates the
conditions for another — e.g. a stale pointer enabling a use-after-free, or
an OOB read corrupting metadata that causes a downstream buffer overflow.

Usage:
    python3 triage_specs_llm.py --specs-dir specs/proj_vul --segments 8
    python3 triage_specs_llm.py --specs-dir specs/proj_vul --segments 4 --src-root dataset/hash/proj

Environment variables (required):
    LLM_API_KEY   — API key for the LLM provider
    LLM_API_BASE  — Base URL (e.g. https://api.openai.com/v1)
    LLM_MODEL     — Model name (e.g. gpt-4o, claude-sonnet-4-6)

Output:
    specs_dir/llm_chain_keep.json    — Specs kept as chain candidates (full spec restored)
    specs_dir/llm_chain_removed.json — Specs the LLM decided are not chain-relevant
"""

import argparse
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import openai
except ImportError:
    print("[!] openai package not found. Install with: pip install openai")
    sys.exit(1)

# ── Boilerplate keys to strip before sending to LLM ─────────────────────────
# These are either redundant or near-identical across all specs (confirmed by analysis).

STRIP_ROOT_KEYS = {"llm_hints", "target_statement", "column", "end_line", "end_column"}
STRIP_FACTS_KEYS = {"bounds_hints"}

# ── Source context ────────────────────────────────────────────────────────────

CONTEXT_LINES = 10

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


def _resolve_file(src_root: Optional[Path], vul_file: str) -> Optional[Path]:
    if not src_root or not vul_file:
        return None
    key = f"{src_root}|{vul_file}"
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


def _get_source_context(src_root: Optional[Path], vul_file: str, target_line: int) -> str:
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
    end = min(len(lines), target_line + CONTEXT_LINES // 2)
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


# ── Strip / restore boilerplate ───────────────────────────────────────────────

def _strip_spec(spec: dict) -> Tuple[dict, dict]:
    """Return (stripped_spec, stripped_keys). stripped_keys holds everything removed."""
    stripped = json.loads(json.dumps(spec))  # deep copy
    removed = {}

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
    """Re-attach the stripped keys to a surviving spec."""
    full = json.loads(json.dumps(stripped))

    removed_facts = removed.pop("_facts", {})
    full.update(removed)

    if removed_facts:
        if "facts" not in full:
            full["facts"] = {}
        full["facts"].update(removed_facts)

    return full


# ── Compact prompt representation ─────────────────────────────────────────────

def _format_for_prompt(short_id: str, stripped: dict, stem: str,
                        src_root: Optional[Path]) -> str:
    """Render a stripped spec as a compact text block using a short ID."""
    vul_file = stripped.get("file", stripped.get("vul_file", ""))
    vul_line = int(stripped.get("line", stripped.get("vul_line", 0)))
    cwe = _extract_cwe(stripped, stem)
    basename = os.path.basename(vul_file) if vul_file else "?"

    facts = stripped.get("facts", {})
    suspect_calls = facts.get("suspect_calls", [])
    pointer_vars = facts.get("pointer_vars", [])
    length_vars = facts.get("length_vars", [])

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


# ── Prompt ────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a vulnerability research assistant specialising in C/C++ bug chain analysis.

A bug chain is a sequence of two or more vulnerabilities where triggering one
creates the conditions for another. Examples:
  • OOB read corrupts image dimension metadata → downstream ScaleImage() null-deref
  • Integer truncation creates undersized allocation → subsequent memcpy overflows it
  • Stale pointer left by one function → use-after-free when caller dereferences it
  • Missing palette bounds check → OOB read feeds attacker bytes into a pixel-write path
  • realloc() invalidates a stored pointer → use-after-realloc in the same call chain

Your job is to filter OUT specs that are clearly isolated — they cannot plausibly
serve as an upstream trigger or downstream sink for another spec in the batch.
Keep specs that share data structures, CWE classes that commonly compose
(CWE-125→CWE-787, CWE-190→CWE-122, CWE-416 as sink), or suspect calls
suggesting shared state (free/alloc pairs, pointer aliasing, shared buffers).\
"""

USER_PROMPT_TEMPLATE = """\
Below are {n} vulnerability specs from project {project}.
Each spec has a short ID like S0001.

Your task: return the IDs of specs to REMOVE — those that are clearly isolated
and cannot plausibly be part of a bug chain with any other spec in this batch.
Specs NOT in your remove list will be kept as chain candidates.

Respond ONLY with valid JSON — no prose, no markdown fences:
{{
  "remove": ["S0001", "S0042", ...],
  "reason": "one sentence summary of your filtering logic"
}}

If all specs should be removed: {{"remove": [{all_ids}], "reason": "..."}}
If none should be removed: {{"remove": [], "reason": "..."}}

--- SPECS ---
{specs_block}
"""


def _build_prompt(specs_block: str, project: str, n: int,
                  all_short_ids: List[str]) -> str:
    quoted = ", ".join(f'"{s}"' for s in all_short_ids)
    return USER_PROMPT_TEMPLATE.format(
        n=n,
        project=project,
        specs_block=specs_block,
        all_ids=quoted,
    )


# ── LLM client ────────────────────────────────────────────────────────────────

def _make_client() -> Tuple["openai.OpenAI", str]:
    api_key = os.environ.get("LLM_API_KEY", "")
    api_base = os.environ.get("LLM_API_BASE", "")
    model = os.environ.get("LLM_MODEL", "gpt-5.4")

    if not api_key:
        print("[!] LLM_API_KEY not set.", file=sys.stderr)
        sys.exit(1)

    kwargs: dict = {"api_key": api_key}
    if api_base:
        kwargs["base_url"] = api_base

    return openai.OpenAI(**kwargs), model


def _call_llm(client: "openai.OpenAI", model: str, user_prompt: str) -> dict:
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
    raw = re.sub(r'\s*```$', '', raw)

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"\n[!] JSON parse error: {e}", file=sys.stderr)
        print(f"    Raw: {raw[:400]}", file=sys.stderr)
        return {"remove": [], "reason": f"PARSE_ERROR: {e}", "raw": raw}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="LLM-based bug chain triage — filters specs unlikely to chain"
    )
    parser.add_argument("--specs-dir", required=True,
                        help="Directory containing spec JSON files (e.g. specs/proj_vul)")
    parser.add_argument("--segments", type=int, default=4,
                        help="Number of batches to split specs into for LLM evaluation (default: 4)")
    parser.add_argument("--src-root", default=None,
                        help="Project source root for source context lines (optional but recommended)")
    args = parser.parse_args()

    specs_dir = Path(args.specs_dir)
    src_root = Path(args.src_root) if args.src_root else None

    spec_files = sorted(f for f in specs_dir.glob("*.json")
                        if f.name not in {"triage_stats.json"})
    if not spec_files:
        print(f"[!] No spec JSON files found in {specs_dir}")
        sys.exit(0)

    project = specs_dir.name
    total = len(spec_files)
    segments = max(1, args.segments)
    batch_size = math.ceil(total / segments)

    print(f"[*] {total} specs  |  {segments} segment(s) of ~{batch_size}")
    print(f"[*] Project: {project}")

    client, model = _make_client()
    print(f"[*] Model: {model}")
    print(f"[*] Stripping keys: {STRIP_ROOT_KEYS | STRIP_FACTS_KEYS}")
    print()

    # ── Load and strip all specs ──────────────────────────────────────────────
    # short_id → {stem, path, stripped, removed, spec_original}
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
            "stem": sp.stem,
            "path": sp,
            "stripped": stripped,
            "removed": removed,
            "original": original,
        }

    # ── Process segments ──────────────────────────────────────────────────────
    all_short_ids = list(registry.keys())
    removed_ids: set = set()
    segment_log = []

    for seg_idx in range(segments):
        batch_ids = all_short_ids[seg_idx * batch_size: (seg_idx + 1) * batch_size]
        if not batch_ids:
            break

        print(f"[Segment {seg_idx + 1}/{segments}] {len(batch_ids)} specs ...",
              end=" ", flush=True)

        blocks = []
        for sid in batch_ids:
            entry = registry[sid]
            block = _format_for_prompt(sid, entry["stripped"], entry["stem"], src_root)
            blocks.append(block)

        specs_block = "\n\n".join(blocks)
        user_prompt = _build_prompt(specs_block, project, len(batch_ids), batch_ids)

        result = _call_llm(client, model, user_prompt)
        to_remove = result.get("remove", [])
        reason = result.get("reason", "")

        # Only remove IDs that were actually in this batch
        valid_remove = [sid for sid in to_remove if sid in set(batch_ids)]
        removed_ids.update(valid_remove)

        kept = len(batch_ids) - len(valid_remove)
        print(f"kept {kept}, removed {len(valid_remove)}")
        if reason:
            print(f"  reason: {reason}")

        segment_log.append({
            "segment": seg_idx + 1,
            "batch_ids": batch_ids,
            "removed": valid_remove,
            "kept": [sid for sid in batch_ids if sid not in set(valid_remove)],
            "reason": reason,
        })

    # ── Restore stripped keys and write output ────────────────────────────────
    kept_specs = []
    removed_specs = []

    for short_id, entry in registry.items():
        full = _restore_spec(entry["stripped"], entry["removed"])
        record = {
            "id": short_id,
            "stem": entry["stem"],
            "spec": full,
        }
        if short_id in removed_ids:
            removed_specs.append(record)
        else:
            kept_specs.append(record)

    keep_path = specs_dir / "llm_chain_keep.json"
    with open(keep_path, "w") as f:
        json.dump({
            "project": project,
            "model": model,
            "total_kept": len(kept_specs),
            "specs": kept_specs,
        }, f, indent=2)
    print(f"\nKept    {len(kept_specs):>5} specs → {keep_path}")

    removed_path = specs_dir / "llm_chain_removed.json"
    with open(removed_path, "w") as f:
        json.dump({
            "project": project,
            "model": model,
            "total_removed": len(removed_specs),
            "specs": removed_specs,
        }, f, indent=2)
    print(f" Removed {len(removed_specs):>5} specs → {removed_path}")

    log_path = specs_dir / "llm_chain_log.json"
    with open(log_path, "w") as f:
        json.dump({"segments": segment_log}, f, indent=2)
    print(f"Log                    → {log_path}")

    print(f"\n[DONE] {total} specs → {len(kept_specs)} kept, {len(removed_specs)} removed")


if __name__ == "__main__":
    main()
