#!/usr/bin/env python3
import argparse, json, os, pathlib, re, sys
from typing import Dict, Any, List, Tuple

def load_findings(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        first = f.read(2048)
        f.seek(0)
        if first.lstrip().startswith("{"):
            data = json.load(f)
            if isinstance(data, dict) and "results" in data and isinstance(data["results"], list):
                return data["results"]
            # SARIF minimal support
            if "runs" in data and data["runs"]:
                out = []
                for run in data["runs"]:
                    for r in run.get("results", []):
                        locs = r.get("locations", [])
                        if not locs:
                            continue
                        phys = locs[0].get("physicalLocation", {})
                        art = phys.get("artifactLocation", {})
                        reg = phys.get("region", {})
                        out.append({
                            "ruleId": r.get("ruleId"),
                            "message": (r.get("message") or {}).get("text", ""),
                            "file": art.get("uri") or art.get("uriBaseId"),
                            "startLine": reg.get("startLine"),
                            "startColumn": reg.get("startColumn"),
                            "endLine": reg.get("endLine", reg.get("startLine")),
                            "endColumn": reg.get("endColumn", reg.get("startColumn")),
                            "properties": r.get("properties", {}),
                        })
                return out
            raise SystemExit(f"[!] Unsupported JSON shape in {path}")
        else:
            # JSONL
            findings = []
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    obj = json.loads(ln)
                    findings.append(obj)
                except Exception:
                    continue
            return findings

def load_facts(path: str) -> Dict[Tuple[str,int,str], Dict[str,Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    facts = {}
    for it in data.get("facts", []):
        k = (os.path.abspath(it.get("file","")), int(it.get("line",0)), it.get("ruleId",""))
        facts[k] = it
    return facts

def sanitize(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_.-]+", "_", s or "")
    return s.strip("_")[:120] or "item"

def guess_family(rule_id: str) -> str:
    if not rule_id:
        return "GENERIC"
    r = rule_id.lower()
    if "memfunc" in r or "memcmp" in r or "oob" in r:
        return "OOB_MEMCMP"
    if "toctou" in r:
        return "TOCTOU"
    if "external-entity" in r or "xxe" in r:
        return "XXE"
    return "GENERIC"

def assertion_hint(family: str) -> Dict[str, Any]:
    if family == "OOB_MEMCMP":
        return {
            "vuln_kind": "OOB_READ",
            "assertion_template": "/* model: n <= min(len(lhs), len(rhs)) */ /* fill with program vars */"
        }
    if family == "TOCTOU":
        return {
            "vuln_kind": "TOCTOU",
            "assertion_template": "/* model: ensure use is not based on stale checked state; encode check/use linkage */"
        }
    if family == "XXE":
        return {
            "vuln_kind": "XXE",
            "assertion_template": "/* model: prohibit XML_PARSE_NOENT/DTDLOAD or assert flags sanitized before parse */"
        }
    return {
        "vuln_kind": "UNKNOWN",
        "assertion_template": "/* fill with program-specific property */"
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True)
    ap.add_argument("--facts", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    outdir = pathlib.Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    findings = load_findings(args.findings)
    facts = load_facts(args.facts)

    written = 0
    for idx, r in enumerate(findings):
        file = r.get("file")
        line = r.get("startLine")
        rule = r.get("ruleId")
        if not file or not line or not rule:
            continue

        key = (os.path.abspath(file), int(line), rule)
        fx = facts.get(key, {})
        fam = guess_family(rule)
        ah = assertion_hint(fam)

        # shape the minimal spec for Loop-A/Loop-B
        spec = {
            "schema": "llmse.vul_spec.v1",
            "id": f"{sanitize(rule)}@{sanitize(os.path.basename(file))}:{int(line)}",
            "project": None,
            "rule_id": rule,
            "family": fam,
            "file": file,
            "line": int(line),
            "column": r.get("startColumn"),
            "end_line": r.get("endLine", r.get("startLine")),
            "end_column": r.get("endColumn", r.get("startColumn")),
            "message": r.get("message", ""),
            "context": {
                "contextStart": r.get("contextStart"),
                "contextEnd": r.get("contextEnd"),
                "snippet": r.get("snippet", "")
            },
            "target_statement": {
                "text": None,  # Loop-B can refine exact AST stmt
                "line": int(line),
                "column_start": r.get("startColumn"),
                "column_end": r.get("endColumn")
            },
            # SA facts merged in
            "facts": {
                "suspect_calls": fx.get("suspect_calls", []),
                "pointer_vars": fx.get("pointer_vars", []),
                "length_vars": fx.get("length_vars", []),
                "bounds_hints": fx.get("bounds_hints", []),
            },
            # Hints to LLM loops
            "llm_hints": {
                "entrypoint": {
                    "strategy": "LLM_INFER",    # Loop-A will infer realistic entry; user can override
                    "candidates": []            # (optional) later from call-graph if available
                },
                "assertions": {
                    "presence_assertion_hint": ah["assertion_template"],
                    "reachability_assertion": "klee_assert(0);  /* must be placed immediately before the vulnerable instruction */"
                },
                "notes": [
                    "Non-in-path helpers should be stub candidates.",
                    "Groom all in-path data structures to avoid null derefs."
                ],
            }
        }

        name = f"{idx:03d}_{sanitize(os.path.basename(file))}_{int(line)}_{sanitize(rule)}.json"
        with open(outdir / name, "w", encoding="utf-8") as w:
            json.dump(spec, w, indent=2, sort_keys=False)
        written += 1

    print(f"[i] Wrote {written} spec(s) to {outdir}")

if __name__ == "__main__":
    main()
