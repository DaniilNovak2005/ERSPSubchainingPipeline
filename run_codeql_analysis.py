#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
End-to-end CodeQL runner focused on extracting rich, LLM/symexec-ready
vulnerability artifacts from SARIF (locations, traces, code context, metadata).

Adds: fact_pack.json (heuristic, over-approximated)
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Any


# ---------- Logging & shell helpers ----------
def parse_ram_mb(spec: str | None) -> str | None:
    if not spec:
        return None
    s = str(spec).strip()
    if s.endswith("%"):
        try:
            pct = max(1, min(100, int(s[:-1])))
        except ValueError:
            return None
        # Read total RAM from /proc/meminfo (kB → MB)
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        mb_total = max(1, kb // 1024)
                        mb = max(256, (mb_total * pct) // 100)  # floor, min 256MB
                        return str(mb)
        except Exception:
            return None
        return None
    # plain integer megabytes
    try:
        mb = int(s)
        return str(max(256, mb))
    except ValueError:
        return None

def setup_logging(verbosity: str):
    level = getattr(logging, verbosity.upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

def run(cmd: List[str], cwd: Optional[Path] = None, check: bool = True) -> Tuple[int, str, str]:
    prefix = f" ({cwd})" if cwd else ""
    logging.debug("⋙ %s%s", " ".join(shlex.quote(c) for c in cmd), prefix)
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.stdout:
        for line in proc.stdout.splitlines():
            logging.debug("[stdout] %s", line)
    if proc.stderr:
        for line in proc.stderr.splitlines():
            logging.debug("[stderr] %s", line)
    if check and proc.returncode != 0:
        raise SystemExit(proc.returncode)
    return proc.returncode, proc.stdout, proc.stderr

def run_timed(cmd: List[str], cwd: Optional[Path] = None, check: bool = True) -> Tuple[int, str, str, float]:
    """Run a command and return (rc, stdout, stderr, wall_seconds)."""
    t0 = time.perf_counter()
    rc, out, err = run(cmd, cwd=cwd, check=check)
    dt = time.perf_counter() - t0
    return rc, out, err, dt

def extend_common_flags(cmd: list[str], args: argparse.Namespace) -> list[str]:
    if args.search_path:
        cmd += ["--search-path", args.search_path]
    if args.threads is not None:
        cmd += ["--threads", str(args.threads)]
    ram_mb = parse_ram_mb(getattr(args, "ram", None))
    if ram_mb:
        cmd += ["--ram", ram_mb]
    if getattr(args, "log_to_stderr", False):
        cmd += ["--log-to-stderr"]
    if getattr(args, "verbosity", 0):
        cmd += ["-" + "v" * int(args.verbosity)]
    return cmd


def resolve_queries(query_specifiers: List[str], args: argparse.Namespace, additional_packs: List[Path]) -> List[str]:
    """Expand suites/dirs/packs to a flat list of individual .ql files."""
    cmd = ["codeql", "resolve", "queries", "--format=json"]
    # resolve-queries has its own pack search options; threads/ram are not relevant here.
    if getattr(args, "search_path", None):
        cmd += ["--search-path", args.search_path]
    if additional_packs:
        cmd += ["--additional-packs", os.pathsep.join(str(p) for p in additional_packs)]
    # per CLI docs, query specifiers come after "--" to avoid ambiguity.
    cmd += ["--", *query_specifiers]

    rc, out, err = run(cmd, check=True)
    try:
        data = json.loads(out or "[]")
        if isinstance(data, list):
            return [str(x) for x in data if isinstance(x, str)]
    except Exception:
        pass
    # Fallback: treat line-oriented output as list.
    return [ln.strip() for ln in (out or "").splitlines() if ln.strip()]


def sarif_rule_ids(sarif_obj: Dict[str, Any]) -> List[str]:
    rids: List[str] = []
    for run_obj in sarif_obj.get("runs", []) or []:
        tool = run_obj.get("tool", {}) or {}
        driver = tool.get("driver", {}) or {}
        for r in driver.get("rules", []) or []:
            rid = r.get("id") or r.get("name")
            if rid:
                rids.append(str(rid))
    # de-dup while preserving order
    seen = set()
    out = []
    for x in rids:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ---------- Pack & suite helpers ----------

def ensure_pack_install(pack_dir: Path):
    if not pack_dir.exists():
        return
    if not (pack_dir / "qlpack.yml").exists():
        return
    logging.info("Ensuring CodeQL pack deps are installed: %s", pack_dir)
    run(["codeql", "pack", "install"], cwd=pack_dir, check=True)

def infer_local_pack_roots_from_suites(suite_paths: List[Path]) -> List[Path]:
    roots = set()
    for suite in suite_paths:
        p = suite.resolve()
        if p.is_file():
            p = p.parent
        while True:
            if (p / "qlpack.yml").exists():
                roots.add(p)
                break
            if p == p.parent:
                break
            p = p.parent
    return sorted(roots)

def normalize_additional_packs(paths: List[str]) -> List[Path]:
    out: List[Path] = []
    for p in paths:
        if not p:
            continue
        # split on OS pathsep to allow "a:b:c"
        for chunk in p.split(os.pathsep):
            if not chunk:
                continue
            out.append(Path(chunk).resolve())
    return out

# ---------- Source code helpers ----------

def read_file_lines(path: Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []

def grab_context(lines: List[str], zero_based_line: int, ctx: int) -> Dict[str, Any]:
    n = len(lines)
    start = max(0, zero_based_line - ctx)
    end = min(n, zero_based_line + ctx + 1)
    return {
        "start_line_1based": start + 1,
        "end_line_1based": end,
        "snippet": "\n".join(lines[start:end]),
    }

# ---------- SARIF parsing & enrichment ----------

def extract_rule_lookup(run_obj: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    tool = run_obj.get("tool", {}) or {}
    driver = tool.get("driver", {}) or {}
    for r in driver.get("rules", []) or []:
        rid = r.get("id") or r.get("name")
        if not rid:
            continue
        props = r.get("properties", {}) or {}
        tags = props.get("tags", []) or []
        out[rid] = {
            "id": rid,
            "name": r.get("name"),
            "shortDescription": (r.get("shortDescription", {}) or {}).get("text"),
            "fullDescription": (r.get("fullDescription", {}) or {}).get("text"),
            "helpUri": r.get("helpUri"),
            "properties": props,
            "tags": tags,
            "securitySeverityLevel": props.get("security-severity") or props.get("problem.severity") or r.get("defaultConfiguration", {}).get("level"),
            "precision": props.get("precision") or (r.get("defaultConfiguration") or {}).get("precision"),
        }
    return out

def format_region(region: Dict[str, Any]) -> Tuple[int, int, int, int]:
    sl = int(region.get("startLine", 1))
    sc = int(region.get("startColumn", 1))
    el = int(region.get("endLine", sl))
    ec = int(region.get("endColumn", sc))
    return sl, sc, el, ec

def primary_loc(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    locs = result.get("locations") or []
    return locs[0] if locs else None

def iter_threadflow_steps(result: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for cf in result.get("codeFlows") or []:
        for tf in cf.get("threadFlows") or []:
            for loc in tf.get("locations") or []:
                yield loc

def normalize_artifact_uri(uri: str, source_root: Path) -> Path:
    if uri.startswith("file://"):
        uri = uri[7:]
    p = Path(uri)
    return p if p.is_absolute() else (source_root / p)

def cwe_list(rule_meta: Dict[str, Any]) -> List[str]:
    texts = []
    texts.extend(rule_meta.get("tags") or [])
    if rule_meta.get("name"):
        texts.append(rule_meta["name"])
    if rule_meta.get("fullDescription"):
        texts.append(rule_meta["fullDescription"])
    if rule_meta.get("shortDescription"):
        texts.append(rule_meta["shortDescription"])

    cwes: set[str] = set()
    for t in texts:
        if not t:
            continue
        for m in re.finditer(r'(?i)\bcwe[-/:]?(\d+)\b', str(t)):
            cwes.add(f"CWE-{m.group(1)}")
    return sorted(cwes)

from collections import Counter

def write_cwe_counts(findings: List[Dict[str, Any]], out_path: Path) -> None:
    """
    Output format:
      CWE,count
      CWE-416,12
      CWE-787,3
    """
    counts = Counter()
    for f in findings:
        for cwe in (f.get("cwe") or []):
            counts[cwe] += 1

    lines = ["CWE,count"]
    if counts:
        for cwe, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"{cwe},{n}")
    else:
        lines.append("NONE,0")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

def enrich_results(sarif: Dict[str, Any], source_root: Path, context_lines: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    all_flat: List[Dict[str, Any]] = []
    all_llm: List[Dict[str, Any]] = []

    for run_idx, run_obj in enumerate(sarif.get("runs", []) or []):
        rulemeta = extract_rule_lookup(run_obj)
        artifacts = (run_obj.get("artifacts") or [])
        artifact_index_to_path: Dict[int, Path] = {}
        for idx, art in enumerate(artifacts):
            uri = art.get("location", {}).get("uri") or art.get("location", {}).get("uriBaseId")
            if not uri:
                continue
            artifact_index_to_path[idx] = normalize_artifact_uri(uri, source_root)

        for res in run_obj.get("results", []) or []:
            rid = res.get("ruleId") or (res.get("rule", {}) or {}).get("id")
            rmeta = rulemeta.get(rid, {})
            loc = primary_loc(res)

            file_path: Optional[Path] = None
            start_line = start_col = end_line = end_col = 0
            snippet = ""

            if loc:
                phys = (loc.get("physicalLocation") or {})
                artloc = (phys.get("artifactLocation") or {})
                if "index" in artloc and isinstance(artloc["index"], int) and artloc["index"] in artifact_index_to_path:
                    file_path = artifact_index_to_path[artloc["index"]]
                else:
                    uri = artloc.get("uri")
                    if uri:
                        file_path = normalize_artifact_uri(uri, source_root)

                region = (phys.get("region") or {})
                start_line, start_col, end_line, end_col = format_region(region)

            if file_path and file_path.exists():
                lines = read_file_lines(file_path)
                snippet_ctx = grab_context(lines, max(0, start_line - 1), context_lines)
                snippet = snippet_ctx["snippet"]
                ctx_from = snippet_ctx["start_line_1based"]
                ctx_to = snippet_ctx["end_line_1based"]
            else:
                lines = []
                ctx_from = ctx_to = 0

            hops: List[Dict[str, Any]] = []
            for step in iter_threadflow_steps(res):
                phys = (step.get("location", {}) or {}).get("physicalLocation", {}) or {}
                artloc = phys.get("artifactLocation", {}) or {}
                reg = phys.get("region", {}) or {}
                hop_uri = artloc.get("uri")
                hop_file = normalize_artifact_uri(hop_uri, source_root) if hop_uri else None
                sl, sc, el, ec = format_region(reg)
                hop_snip = ""
                if hop_file and hop_file.exists():
                    hop_lines = read_file_lines(hop_file)
                    hop_ctx = grab_context(hop_lines, max(0, sl - 1), context_lines)
                    hop_snip = hop_ctx["snippet"]
                    hop_from = hop_ctx["start_line_1based"]
                    hop_to = hop_ctx["end_line_1based"]
                else:
                    hop_from = hop_to = 0
                hops.append({
                    "file": str(hop_file) if hop_file else None,
                    "startLine": sl, "startColumn": sc, "endLine": el, "endColumn": ec,
                    "contextStart": hop_from, "contextEnd": hop_to,
                    "snippet": hop_snip,
                    "message": (step.get("location", {}) or {}).get("message", {}).get("text"),
                })

            flat = {
                "ruleId": rid,
                "ruleName": rmeta.get("name"),
                "severity": rmeta.get("securitySeverityLevel"),
                "precision": rmeta.get("precision"),
                "cwe": cwe_list(rmeta),
                "message": (res.get("message", {}) or {}).get("text"),
                "file": str(file_path) if file_path else None,
                "startLine": start_line, "startColumn": start_col,
                "endLine": end_line, "endColumn": end_col,
                "contextStart": ctx_from, "contextEnd": ctx_to,
                "snippet": snippet,
                "helpUri": rmeta.get("helpUri"),
                "properties": rmeta.get("properties") or {},
                "partialFingerprints": res.get("partialFingerprints"),
                "codeFlows": hops,
            }
            all_flat.append(flat)

            all_llm.append({
                "rule": {"id": rid, "name": rmeta.get("name"), "cwe": cwe_list(rmeta)},
                "severity": rmeta.get("securitySeverityLevel"),
                "precision": rmeta.get("precision"),
                "message": flat["message"],
                "location": {"file": flat["file"], "line": start_line, "col": start_col},
                "snippet": snippet,
                "trace": [
                    {
                        "file": h["file"], "line": h["startLine"], "col": h["startColumn"],
                        "message": h.get("message"),
                        "snippet": h["snippet"]
                    } for h in hops
                ],
                "helpUri": rmeta.get("helpUri"),
            })

    return all_flat, all_llm

# ---------- CSV writer ----------

def write_csv(findings: List[Dict[str, Any]], out_csv: Path):
    headers = [
        "ruleId","ruleName","severity","precision","cwe","file","startLine","startColumn",
        "endLine","endColumn","message","helpUri","contextStart","contextEnd","snippet"
    ]
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for fnd in findings:
            row = {k: fnd.get(k) for k in headers}
            row["cwe"] = ",".join(fnd.get("cwe") or [])
            w.writerow(row)


def write_rule_timing_csv(rows: List[Dict[str, Any]], out_csv: Path) -> None:
    """Write per-rule/per-query timing data.

    Expected row keys:
      ruleIds (list[str])
      query (str)
      suites (list[str])
      wall_seconds (float)
      sarif (str)
      returncode (int)
    """
    headers = ["ruleIds", "query", "suites", "wall_seconds", "sarif", "returncode"]
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow({
                "ruleIds": ",".join(r.get("ruleIds") or []),
                "query": r.get("query"),
                "suites": ",".join(r.get("suites") or []),
                "wall_seconds": f"{float(r.get('wall_seconds') or 0.0):.6f}",
                "sarif": r.get("sarif"),
                "returncode": int(r.get("returncode") or 0),
            })

# ---------- CodeQL version/pack info ----------

def codeql_version() -> str:
    try:
        _, out, _ = run(["codeql", "version"], check=False)
        return (out or "").strip()
    except Exception:
        return "unknown"

def resolve_pack_versions() -> Dict[str, str]:
    try:
        rc, out, _ = run(["codeql", "pack", "ls", "--format=json"], check=False)
        if rc == 0 and out:
            pkgs = json.loads(out)
            return {p["name"]: p.get("version", "") for p in pkgs}
    except Exception:
        pass
    return {}

# ---------- compile_commands.json helpers ----------

COMMON_CC_LOCATIONS = [
    ".", "build", "builddir", "out", "cmake-build", "_build", "obj", "objs"
]

def which(prog: str) -> Optional[str]:
    return shutil.which(prog)

def _read_cc(path: Path) -> List[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []

def _is_nonempty_cc(path: Path) -> bool:
    return path.exists() and path.is_file() and len(_read_cc(path)) > 0

def find_existing_compile_commands(src_root: Path) -> Optional[Path]:
    for d in COMMON_CC_LOCATIONS:
        cand = (src_root / d / "compile_commands.json").resolve()
        if _is_nonempty_cc(cand):
            return cand
    for d in COMMON_CC_LOCATIONS:
        cmake_out = (src_root / d / "CMakeFiles" / "CMakeOutput.log").resolve()
        if cmake_out.exists():
            cc = cmake_out.parent.parent / "compile_commands.json"
            if _is_nonempty_cc(cc):
                return cc
    for root in [src_root, src_root.parent, Path.cwd()]:
        try:
            for p in root.rglob("compile_commands.json"):
                rel = p.relative_to(root)
                if len(rel.parts) <= 4 and _is_nonempty_cc(p):
                    return p
        except Exception:
            pass
    return None

def normalize_cc_entries(cc: List[dict], make_abs: bool = True) -> List[dict]:
    out = []
    for e in cc:
        file = e.get("file") or e.get("source") or ""
        dir_ = e.get("directory") or ""
        cmd  = e.get("command") or e.get("arguments")
        if not file or not dir_ or not cmd:
            continue
        if make_abs:
            try:
                file = str((Path(dir_) / file).resolve())
                dir_  = str(Path(dir_).resolve())
            except Exception:
                pass
        e2 = {"file": file, "directory": dir_}
        if isinstance(cmd, list):
            e2["arguments"] = cmd
        else:
            e2["command"] = cmd
        out.append(e2)
    return out

def write_cc(out_path: Path, entries: List[dict]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")

def generate_cc_with_interceptor(src_root: Path, build_command: str, dest: Path) -> bool:
    intercept = which("intercept-build")
    bear = which("bear")
    compiledb = which("compiledb")

    env = os.environ.copy()
    env.setdefault("CC", "clang")
    env.setdefault("CXX", "clang++")

    def sh(cmd: str) -> Tuple[int, str]:
        logging.info("Generating compile_commands.json via: %s", cmd)
        try:
            cp = subprocess.run(cmd, cwd=str(src_root), shell=True, check=True,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
            return cp.returncode, cp.stdout
        except subprocess.CalledProcessError as e:
            return e.returncode, e.stdout

    if intercept:
        rc, _ = sh(f'{intercept} --cdb "{dest}" -- /bin/sh -lc \'{build_command}\'')
        if rc != 0:
            rc, _ = sh(f'{intercept} -o "{dest}" -- /bin/sh -lc \'{build_command}\'')
        if _is_nonempty_cc(dest):
            return True

    if bear:
        rc, _ = sh(f'{bear} --output "{dest}" -- /bin/sh -lc \'{build_command}\'')
        if _is_nonempty_cc(dest):
            return True

    if compiledb:
        rc, _ = sh(f'/bin/sh -lc \'{build_command} && {compiledb} -o "{dest}" make -n\'')
        if _is_nonempty_cc(dest):
            return True

    if (src_root / "CMakeLists.txt").exists():
        build_dir = src_root / "build"
        build_dir.mkdir(exist_ok=True)
        rc, _ = sh('cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON && cmake --build build -j')
        cand = build_dir / "compile_commands.json"
        if _is_nonempty_cc(cand):
            shutil.copyfile(cand, dest)
            return True

    return False

def ensure_compile_commands(src_root: Path, out_dest: Path, build_command: str) -> Path | None:
    existing = find_existing_compile_commands(src_root)
    if existing:
        logging.info("Found existing compile_commands.json at: %s", existing)
        entries = normalize_cc_entries(_read_cc(existing))
        if entries:
            write_cc(out_dest, entries)
            logging.info("Wrote normalized compile_commands.json → %s", out_dest)
            return out_dest

    ok = generate_cc_with_interceptor(src_root, build_command, out_dest)
    if ok:
        entries = normalize_cc_entries(_read_cc(out_dest))
        if entries:
            write_cc(out_dest, entries)
            logging.info("Generated compile_commands.json → %s", out_dest)
            return out_dest

    logging.warning("Unable to produce a non-empty compile_commands.json")
    return None

# ---------- Heuristic fact-pack synthesis ----------

_KEYWORDS = {
    "if","for","while","switch","return","sizeof","case","do","else","struct","union",
    "typedef","break","continue","goto","enum","static","inline","extern"
}

def _find_function_calls(text: str) -> List[str]:
    names = set()
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
        n = m.group(1)
        if n not in _KEYWORDS:
            names.add(n)
    return sorted(names)

def _find_pointer_like_vars(text: str) -> List[str]:
    out = set()
    for m in re.finditer(r"\b(?:const\s+)?[A-Za-z_]\w*\s*\*\s*([A-Za-z_]\w*)", text):
        out.add(m.group(1))
    for m in re.finditer(r"\bchar\s+([A-Za-z_]\w*)\s*\[", text):
        out.add(m.group(1))
    for m in re.finditer(r"\bxmlChar\s*\*\s*([A-Za-z_]\w*)", text):
        out.add(m.group(1))
    return sorted(out)

def _find_length_like_vars(text: str) -> List[str]:
    out = set()
    for m in re.finditer(r"\b([A-Za-z_]\w*(?:len|size|count|cap|n|num|length))\b", text, flags=re.I):
        out.add(m.group(1))
    return sorted(out)

def build_fact_pack(project: str, findings: List[Dict[str, Any]], ccdb_path: Optional[Path], outputs_root: Path) -> Dict[str, Any]:
    facts = []
    for f in findings:
        snippet = f.get("snippet") or ""
        calls = _find_function_calls(snippet)
        ptrs  = _find_pointer_like_vars(snippet)
        lens  = _find_length_like_vars(snippet)

        bounds_hints = []
        for v in lens:
            bounds_hints.append({"var": v, "relation": ">= 0", "source": "heuristic"})
        for p in ptrs:
            for v in lens:
                base = re.sub(r"(Len|Length|Size|Count|Capacity|Num|N)$", "", v, flags=re.I)
                if base and p.lower().startswith(base.lower()):
                    bounds_hints.append({"var": v, "relation": f"<= sizeof({p})", "source": "name-affinity"})

        facts.append({
            "file": f.get("file"),
            "line": f.get("startLine"),
            "ruleId": f.get("ruleId"),
            "cwe": f.get("cwe") or [],
            "message": f.get("message"),
            "suspect_calls": calls,
            "pointer_vars": ptrs,
            "length_vars": lens,
            "bounds_hints": bounds_hints,
            "extern_signatures": [],
            "pointer_dependencies": [],
        })

    build_ctx = {}
    try:
        if ccdb_path and ccdb_path.exists():
            cc = _read_cc(ccdb_path)
            incs = []
            defs = []
            for e in cc[:200]:
                cmd = e.get("command") or " ".join(e.get("arguments", []))
                incs += re.findall(r"(?:^|\s)-I\s*([^\s]+)", cmd)
                defs += re.findall(r"(?:^|\s)-D\s*([^\s]+)", cmd)
            build_ctx = {
                "sampled_include_paths": sorted(set(incs))[:64],
                "sampled_defines": sorted(set(defs))[:128],
            }
    except Exception:
        pass

    pack = {
        "schema": "llmse.factpack.v1",
        "project": project,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "facts": facts,
        "build_context": build_ctx,
        "notes": [
            "Heuristic, over-approximated. Safe to feed to LLM/stub planner.",
            "Bounds hints are suggestions; treat as refinements only if corroborated."
        ],
    }
    out_path = outputs_root / "fact_pack.json"
    out_path.write_text(json.dumps(pack, indent=2), encoding="utf-8")
    logging.info("Wrote fact pack → %s", out_path)
    return pack

# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="Run CodeQL and extract rich vulnerability artifacts for LLM/symexec.")
    ap.add_argument("--project-name", required=True)
    ap.add_argument("--source-path", required=True)
    ap.add_argument("--build-command", required=True)
    ap.add_argument("--query-suites", required=True, nargs="+",
                    help="One or more .qls suites (local file paths or pack-qualified like codeql/cpp-queries).")
    ap.add_argument("--also-run-cpp-queries", action="store_true",
                    help="Additionally run built-in codeql/cpp-queries suite for wider coverage.")
    ap.add_argument("--context-lines", type=int, default=6,
                    help="Number of context lines around each primary/threadflow location.")
    ap.add_argument("--overwrite", action="store_true", help="Overwrite CodeQL DB if it exists.")
    ap.add_argument("--additional-packs", nargs="*", default=[],
                    help=f"Extra pack roots to search (accepts multiple args and/or {os.pathsep}-separated lists).")
    ap.add_argument("--loglevel", default=os.environ.get("LOGLEVEL", "INFO"))
    ap.add_argument("--threads", default=None,
                help="Forwarded to CodeQL CLI (0 = all cores)")
    ap.add_argument("--ram", default=None,
                    help="Forwarded to CodeQL CLI (e.g., 80%)")
    ap.add_argument("--search-path", dest="search_path", default=None,
                    help="Pack search path like /path/to/cli:/path/to/packs[:more]")
    ap.add_argument("--log-to-stderr", dest="log_to_stderr", action="store_true",
                    help="Stream CodeQL logs to stderr")
    ap.add_argument("-v", dest="verbosity", action="count", default=0,
                    help="Increase CodeQL CLI verbosity (-v/-vv/-vvv)")

    ap.add_argument("--time-per-rule", action="store_true",
                    help="Run CodeQL queries one-by-one (after expanding suites) and emit per-rule timing logs. Produces codeql_rule_time.(jsonl|csv) and a merged codeql-results.sarif.")

    args = ap.parse_args()

    setup_logging(args.loglevel)

    project = args.project_name
    source_root = Path(args.source_path).resolve()
    # Respect SA_OUT_DIR env var (set by Docker/sailor_prepare.sh), fall back to cwd/sa_outputs
    sa_out_base = Path(os.environ.get("SA_OUT_DIR", str(Path.cwd() / "sa_outputs")))
    outputs_root = sa_out_base / project
    outputs_root.mkdir(parents=True, exist_ok=True)

    db_path = outputs_root / "codeql-db"
    sarif_path = outputs_root / "codeql-results.sarif"
    json_out = outputs_root / "findings.json"
    jsonl_out = outputs_root / "findings.jsonl"
    csv_out = outputs_root / "findings.csv"
    meta_out = outputs_root / "run_meta.json"

    # 0) Ensure local pack deps for the provided suites
    suite_paths = [Path(s) for s in args.query_suites if Path(s).exists()]
    for pack_root in infer_local_pack_roots_from_suites(suite_paths):
        ensure_pack_install(pack_root)

    # 0a) Normalize & ensure additional pack roots
    additional_packs = normalize_additional_packs(args.additional_packs)

    # Auto-add "rules" if suites look like "rules/..." and user didn't pass any packs
    if not additional_packs:
        if any(str(s).startswith("rules/") for s in args.query_suites):
            additional_packs = [Path("rules").resolve()]

    for pr in additional_packs:
        # best-effort install (ignores dirs that are plain parents)
        if (pr / "qlpack.yml").exists():
            ensure_pack_install(pr)

    # 1) Create DB
    build_cmd = args.build_command
    if build_cmd.strip().startswith("cmake"):
        toks = shlex.split(build_cmd)
        if not any(t.startswith("-DCMAKE_EXPORT_COMPILE_COMMANDS") for t in toks):
            toks.insert(1, "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON")
            build_cmd = " ".join(shlex.quote(t) for t in toks)
    # When the build command contains shell operators (&&, ||, ;, |), write it
    # to a temporary script so that CodeQL and bear can execute it as a single
    # command without shell-quoting issues.
    _build_script = None
    if any(op in build_cmd for op in ("&&", "||", ";", "|")):
        import tempfile
        _build_script = tempfile.NamedTemporaryFile(
            mode="w", suffix="_build.sh", dir=str(source_root),
            delete=False, prefix=".sailor_")
        _build_script.write("#!/bin/sh\nset -e\n" + build_cmd + "\n")
        _build_script.close()
        os.chmod(_build_script.name, 0o755)
        build_cmd = _build_script.name
    if which("bear") and "bear " not in build_cmd and not build_cmd.strip().startswith("bear "):
        build_cmd = f"bear -- {build_cmd}"

    create_cmd = [
        "codeql","database","create", str(db_path),
        "--language=cpp",
        f"--command={build_cmd}",
        f"--source-root={source_root}",
    ]
    if args.overwrite:
        create_cmd.append("--overwrite")
    create_cmd = extend_common_flags(create_cmd, args)

    logging.info("==> Creating CodeQL database...")
    try:
        run(create_cmd, check=True)
    finally:
        if _build_script is not None:
            try:
                os.unlink(_build_script.name)
            except OSError:
                pass
    logging.info("✓ Database created at %s", db_path)

    # 2) Analyze with requested suites (+ optional built-ins)
    suites_to_run: List[str] = [str(s) for s in args.query_suites]
    if args.also_run_cpp_queries:
        suites_to_run.append("codeql/cpp-queries")

    if args.time_per_rule:
        timing_dir = outputs_root / "timing"
        timing_dir.mkdir(parents=True, exist_ok=True)
        timing_jsonl = outputs_root / "codeql_rule_time.jsonl"
        timing_csv = outputs_root / "codeql_rule_time.csv"

        # Expand suites to an ordered list of individual queries.
        q_to_suites: Dict[str, List[str]] = {}
        ordered_queries: List[str] = []
        for suite in suites_to_run:
            for q in resolve_queries([suite], args=args, additional_packs=additional_packs):
                if q not in q_to_suites:
                    q_to_suites[q] = [suite]
                    ordered_queries.append(q)
                elif suite not in q_to_suites[q]:
                    q_to_suites[q].append(suite)

        if not ordered_queries:
            logging.warning("resolve-queries produced an empty query set; falling back to suite-level analysis")
            args.time_per_rule = False

        timing_rows: List[Dict[str, Any]] = []
        merged: Dict[str, Any] = {"version": "2.1.0", "runs": []}

        if args.time_per_rule:
            logging.info("==> Analyzing %d queries (expanded from %d suite specifier(s))...",
                         len(ordered_queries), len(suites_to_run))
            for idx, q in enumerate(ordered_queries, start=1):
                q_out = timing_dir / f"{idx:04d}_{Path(q).stem}.sarif"
                one_cmd = [
                    "codeql", "database", "analyze", str(db_path),
                    q,
                    "--format=sarifv2.1.0",
                    "--output", str(q_out),
                ]
                if additional_packs:
                    one_cmd += ["--additional-packs", os.pathsep.join(str(p) for p in additional_packs)]
                one_cmd = extend_common_flags(one_cmd, args)

                logging.info("==> [%d/%d] %s", idx, len(ordered_queries), q)
                rc, _, _, wall = run_timed(one_cmd, check=True)

                try:
                    sarif_q = json.loads(q_out.read_text(encoding="utf-8"))
                except Exception:
                    sarif_q = {"runs": []}

                merged["runs"].extend((sarif_q.get("runs") or []))
                timing_rows.append({
                    "ruleIds": sarif_rule_ids(sarif_q),
                    "query": q,
                    "suites": q_to_suites.get(q, []),
                    "wall_seconds": float(wall),
                    "sarif": str(q_out),
                    "returncode": int(rc),
                })

            sarif_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")

            with timing_jsonl.open("w", encoding="utf-8") as f:
                for r in timing_rows:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            write_rule_timing_csv(timing_rows, timing_csv)
            logging.info("✓ Analysis complete → %s", sarif_path)
            logging.info("Wrote per-rule timing logs → %s / %s", timing_jsonl, timing_csv)

    if not args.time_per_rule:
        analyze_cmd = [
            "codeql","database","analyze", str(db_path),
            *suites_to_run,
            "--format=sarifv2.1.0",
            "--output", str(sarif_path),
        ]
        if additional_packs:
            analyze_cmd += ["--additional-packs", os.pathsep.join(str(p) for p in additional_packs)]
        analyze_cmd = extend_common_flags(analyze_cmd, args)

        logging.info("==> Analyzing database with %d suite(s)...", len(suites_to_run))
        run(analyze_cmd, check=True)
        logging.info("✓ Analysis complete → %s", sarif_path)


    # 2b) Ensure compile_commands.json exists (for downstream tools like KLEE)
    cc_out = outputs_root / "compile_commands.json"
    ccdb_path = ensure_compile_commands(source_root, cc_out, build_cmd)

    # 3) Parse/enrich SARIF → JSON / JSONL / CSV
    try:
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    except Exception as e:
        logging.error("Failed to parse SARIF: %s", e)
        sarif = {}

    flat, llm = enrich_results(sarif, source_root=source_root, context_lines=args.context_lines)

    json_out.write_text(json.dumps({"results": flat}, indent=2), encoding="utf-8")
    logging.info("Wrote JSON findings → %s", json_out)

    with jsonl_out.open("w", encoding="utf-8") as f:
        for item in llm:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    logging.info("Wrote JSONL findings → %s", jsonl_out)

    write_csv(flat, csv_out)
    logging.info("Wrote CSV findings → %s", csv_out)

    # Per-CWE counts
    cwe_counts_out = outputs_root / "detected_cwes.txt"
    write_cwe_counts(flat, cwe_counts_out)
    logging.info("Wrote CWE counts → %s", cwe_counts_out)
    
    # 4) Metadata for reproducibility
    meta = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "project": project,
        "args": {
            "query_suites": args.query_suites,
            "also_run_cpp_queries": args.also_run_cpp_queries,
            "context_lines": args.context_lines,
            "overwrite": args.overwrite,
            "time_per_rule": bool(args.time_per_rule),
            "additional_packs": [str(p) for p in additional_packs],
        },
        "codeql_version": codeql_version(),
        "installed_packs": resolve_pack_versions(),
        "paths": {
            "outputs_root": str(outputs_root),
            "db_path": str(db_path),
            "sarif": str(sarif_path),
            "rule_timing_jsonl": str(outputs_root / "codeql_rule_time.jsonl") if args.time_per_rule else None,
            "rule_timing_csv": str(outputs_root / "codeql_rule_time.csv") if args.time_per_rule else None,
            "json": str(json_out),
            "jsonl": str(jsonl_out),
            "csv": str(csv_out),
            "ccdb": str(ccdb_path) if ccdb_path else None,
        }
    }
    meta_out.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    logging.info("Wrote run metadata → %s", meta_out)

    # 5) NEW: heuristic fact pack
    build_fact_pack(project, findings=flat, ccdb_path=ccdb_path, outputs_root=outputs_root)

    logging.info("Done. Findings: %d (see %s / %s). Fact pack at %s",
                 len(flat), json_out, jsonl_out, outputs_root / "fact_pack.json")

if __name__ == "__main__":
    main()
