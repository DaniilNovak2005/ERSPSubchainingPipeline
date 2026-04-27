#!/usr/bin/env bash
# install_security_extended_queries.sh
# Downloads codeql/cpp-queries inside Docker, extracts the .ql files
# listed in cpp-security-extended.qls, and copies them to
# rules/sailor-queries/queries/.
# Existing custom .ql files are moved to queries/temp_original/ (if not already there).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "123" | sudo -S docker run --rm \
    -v "$(pwd)/rules:/app/rules" \
    sailor bash -c '
set -euo pipefail

QUERIES_OUT="/app/rules/sailor-queries/queries"
TEMP_DIR="/app/rules/sailor-queries/queries/temp_original"

# --- 1. Locate or install codeql/cpp-queries ---
echo "[1] Locating codeql/cpp-queries pack..."
PACK_ROOT=""
for search_path in /root/.codeql/packages /usr/local/codeql/qlpacks /opt/codeql/qlpacks; do
    found=$(find "$search_path" -maxdepth 3 -name "cpp-security-extended.qls" 2>/dev/null | head -1)
    if [ -n "$found" ]; then
        PACK_ROOT="$(dirname "$(dirname "$found")")"
        SUITE_FILE="$found"
        break
    fi
done

if [ -z "$PACK_ROOT" ]; then
    echo "    Not found locally — downloading..."
    codeql pack download codeql/cpp-queries 2>&1
    SUITE_FILE=$(find /root/.codeql/packages -name "cpp-security-extended.qls" 2>/dev/null | head -1)
    PACK_ROOT="$(dirname "$(dirname "$SUITE_FILE")")"
fi

echo "    Pack root : $PACK_ROOT"
echo "    Suite file: $SUITE_FILE"

# --- 2. Parse .qls to get the list of .ql file paths ---
echo "[2] Resolving query paths from suite..."
# The suite references queries by relative path inside the pack.
# Extract lines like: - query: Security/CWE/CWE-120/BufferAccessWithIncorrectLengthValue.ql
QL_FILES=()
while IFS= read -r line; do
    # Match "  - query: path/to/Something.ql"
    if [[ "$line" =~ query:[[:space:]]*(.+\.ql) ]]; then
        rel="${BASH_REMATCH[1]}"
        full="$PACK_ROOT/$rel"
        if [ -f "$full" ]; then
            QL_FILES+=("$full")
        else
            # Try searching the pack root
            found=$(find "$PACK_ROOT" -name "$(basename "$rel")" 2>/dev/null | head -1)
            [ -n "$found" ] && QL_FILES+=("$found")
        fi
    fi
done < "$SUITE_FILE"

echo "    Resolved ${#QL_FILES[@]} query files."

# --- 3. Move existing custom .ql files to temp_original ---
echo "[3] Backing up existing custom queries..."
mkdir -p "$TEMP_DIR"
for f in "$QUERIES_OUT"/*.ql; do
    [ -f "$f" ] && mv "$f" "$TEMP_DIR/"
done

# --- 4. Copy security-extended .ql files ---
echo "[4] Copying security-extended queries..."
for f in "${QL_FILES[@]}"; do
    dest="$QUERIES_OUT/$(basename "$f")"
    # Avoid name collision
    if [ -f "$dest" ]; then
        dest="$QUERIES_OUT/$(basename "${f%.ql}")_ext.ql"
    fi
    cp "$f" "$dest"
done

echo ""
echo "[done] Copied ${#QL_FILES[@]} queries to $QUERIES_OUT"
ls "$QUERIES_OUT"/*.ql | wc -l
'
