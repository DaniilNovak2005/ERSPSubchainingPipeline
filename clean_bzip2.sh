#!/usr/bin/env bash
# clean_bzip2.sh — Wipe all bzip2 pipeline artifacts for a fresh restart.
# Removes: dataset clone, sa_outputs, specs, se_runs, commit cache.
# Keeps:   configs/bzip2_*_config.sh (already tuned — run_sailor_bzip2.sh recreates it anyway)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMMIT_CACHE="dataset/.bzip2_commit"

# Resolve commit hash if we have it cached
if [ -f "$COMMIT_CACHE" ]; then
    COMMIT_FULL=$(cat "$COMMIT_CACHE")
    COMMIT="${COMMIT_FULL:0:8}"
    PROJECT="bzip2_${COMMIT}_vul"
    echo "[clean] Detected project: ${PROJECT}"
else
    # Fall back to glob so this works even without a cache file
    COMMIT=""
    PROJECT=""
fi

echo ""
echo "The following will be deleted:"

# Build list of targets
TARGETS=()

if [ -n "$COMMIT" ]; then
    [ -d "dataset/${COMMIT}" ]             && TARGETS+=("dataset/${COMMIT}")
    [ -d "sa_outputs/${PROJECT}" ]         && TARGETS+=("sa_outputs/${PROJECT}")
    [ -d "specs/${PROJECT}" ]              && TARGETS+=("specs/${PROJECT}")
    [ -d "se_runs/sailor_engine/${PROJECT}" ] && TARGETS+=("se_runs/sailor_engine/${PROJECT}")
fi

# Commit cache itself
[ -f "$COMMIT_CACHE" ] && TARGETS+=("$COMMIT_CACHE")

# Any leftover temp clone
[ -d "dataset/_bzip2_tmp" ] && TARGETS+=("dataset/_bzip2_tmp")

if [ ${#TARGETS[@]} -eq 0 ]; then
    echo "  Nothing found — already clean."
    exit 0
fi

for t in "${TARGETS[@]}"; do
    echo "  rm -rf $t"
done

echo ""
read -r -p "Proceed? [y/N] " confirm
if [[ "${confirm,,}" != "y" ]]; then
    echo "Aborted."
    exit 0
fi

echo ""
for t in "${TARGETS[@]}"; do
    echo "[clean] Removing $t ..."
    rm -rf "$t"
done

echo ""
echo "[clean] Done. Run ./run_sailor_bzip2.sh to start fresh."
