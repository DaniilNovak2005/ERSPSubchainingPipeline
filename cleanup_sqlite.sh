#!/usr/bin/env bash
# cleanup_sqlite.sh — Remove all intermediary files from the SQLite SAILOR run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[Cleanup] Removing SQLite dataset..."
rm -rf dataset/0f08d958/

echo "[Cleanup] Removing CodeQL outputs..."
rm -rf sa_outputs/sqlite_0f08d958_vul/

echo "[Cleanup] Removing generated specs..."
rm -rf specs/sqlite_0f08d958_vul/

echo "[Cleanup] Removing SE run results..."
rm -rf se_runs/sailor_engine/sqlite_0f08d958_vul/

echo "[Cleanup] Removing results.tsv..."
rm -f results.tsv

echo "[Cleanup] Done."
