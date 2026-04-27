#!/usr/bin/env python3
"""
count_sa_tokens.py — Count estimated tokens for all files directly inside
each project folder under sa_outputs/. Ignores subdirectories (e.g. codeql-db/).

Usage:
    python3 scripts/count_sa_tokens.py [sa_outputs_path]
"""

import os
import sys

SA_OUTPUTS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'sa_outputs')
SA_OUTPUTS = os.path.realpath(SA_OUTPUTS)

if not os.path.isdir(SA_OUTPUTS):
    print(f"[!] Directory not found: {SA_OUTPUTS}")
    sys.exit(1)

grand_total = 0

for project in sorted(os.listdir(SA_OUTPUTS)):
    project_path = os.path.join(SA_OUTPUTS, project)
    if not os.path.isdir(project_path):
        continue

    print(f"\n{project}")
    print("-" * 60)

    project_total = 0
    rows = []

    for fname in sorted(os.listdir(project_path)):
        fpath = os.path.join(project_path, fname)
        if not os.path.isfile(fpath):
            continue  # skip subdirectories
        try:
            with open(fpath, 'r', errors='replace') as f:
                chars = len(f.read())
            tokens = chars // 4
            rows.append((fname, tokens))
            project_total += tokens
        except Exception as e:
            rows.append((fname, f"ERROR: {e}"))

    for fname, tokens in rows:
        if isinstance(tokens, int):
            print(f"  {fname:<45} {tokens:>10,} tokens")
        else:
            print(f"  {fname:<45} {tokens}")

    print(f"  {'TOTAL':<45} {project_total:>10,} tokens")
    grand_total += project_total

print("\n" + "=" * 60)
print(f"  {'GRAND TOTAL':<45} {grand_total:>10,} tokens")
