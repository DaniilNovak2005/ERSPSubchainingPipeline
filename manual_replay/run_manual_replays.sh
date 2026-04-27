#!/usr/bin/env bash
# Run manual ASan replay harnesses for LIKELY_TP specs.
# Creates manual_replay/ subdirectory inside each spec's se_run dir.
set -euo pipefail

SE_BASE="/home/danii/Documents/SAILOR_Replication_Package/se_runs/sailor_engine/libxml2_8effcb57_vul"
ASAN_LIB="/home/danii/Documents/SAILOR_Replication_Package/manual_replay/asan_build/.libs/libxml2.a"
INCLUDE_DIR="/home/danii/Documents/SAILOR_Replication_Package/manual_replay/asan_build/include"

ASAN_FLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer"
LINK_FLAGS="-lm -lz -lpthread -ldl -Wl,--allow-multiple-definition"

ok=0; fail=0; crash=0

MANUAL_BASE="/home/danii/Documents/SAILOR_Replication_Package/manual_replay/specs"
mkdir -p "$MANUAL_BASE"

run_replay() {
    local SPEC_DIR="$1"
    local DRIVER_SRC="$2"  # path to replay_driver.c
    local SPEC_ID="$3"
    local SPEC_NAME=$(basename "$SPEC_DIR")
    local OUT_DIR="$MANUAL_BASE/${SPEC_NAME}"

    mkdir -p "$OUT_DIR"
    cp "$DRIVER_SRC" "$OUT_DIR/replay_driver.c"

    local BIN="$OUT_DIR/replay_driver"
    local LOG="$OUT_DIR/asan_output.txt"
    local REPORT="$OUT_DIR/bug_report.json"

    echo -n "  [Compile] spec $SPEC_ID ... "
    if gcc $ASAN_FLAGS -I"$INCLUDE_DIR" \
        "$OUT_DIR/replay_driver.c" \
        "$ASAN_LIB" \
        -o "$BIN" \
        $LINK_FLAGS 2>"$OUT_DIR/compile.log"; then
        echo "OK"
    else
        echo "FAILED (see $OUT_DIR/compile.log)"
        ((fail++)) || true
        return
    fi

    echo -n "  [Run]     spec $SPEC_ID ... "
    local EXIT_CODE=0
    ASAN_OPTIONS="abort_on_error=0:detect_leaks=0" \
        "$BIN" >"$LOG" 2>&1 || EXIT_CODE=$?

    if grep -q "AddressSanitizer\|ASan" "$LOG" 2>/dev/null; then
        echo "CRASH! (ASan confirmed)"
        ((crash++)) || true
        ASAN_CONFIRMED=true
    else
        echo "no crash (exit=$EXIT_CODE)"
        ((ok++)) || true
        ASAN_CONFIRMED=false
    fi

    # Write bug_report.json
    local BUG_FILE=$(basename "$SPEC_DIR" | grep -oP '\d+(?=_)' | head -1)_vuln
    local ASAN_OUTPUT=$(head -20 "$LOG" 2>/dev/null | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo '""')
    cat > "$REPORT" << EOF
{
  "summary": {
    "verdict": "LIKELY_TP",
    "manual_replay": true,
    "asan_confirmed": $ASAN_CONFIRMED,
    "crash_relevance": "$([ "$ASAN_CONFIRMED" = true ] && echo target || echo no_asan)"
  },
  "manual_replay": {
    "driver": "$(basename $DRIVER_SRC)",
    "binary": "$(basename $BIN)",
    "asan_output_file": "asan_output.txt",
    "exit_code": $EXIT_CODE,
    "asan_confirmed": $ASAN_CONFIRMED
  }
}
EOF
}

echo "=== Manual ASan Replay for LIKELY_TP specs ==="
echo "Library: $ASAN_LIB"
echo ""

# ── Spec 529: parserInternals.c:620 xmlCurrentChar (2-byte lead, 1-byte buf) ──
echo "[Spec 529] parserInternals.c:620 xmlCurrentChar"
DIR529="$SE_BASE/529_parserInternals.c_620_local_cpp_cwe-125-cursor-lookahead-missing-bytes-check"
cat > /tmp/replay_529.c << 'ENDC'
/* Manual replay driver: spec 529 — parserInternals.c:620 xmlCurrentChar
 * Bug: 2-byte UTF-8 lead byte (0xC8) in 1-byte buffer → cur[1] OOB read
 * Expected: heap-buffer-overflow READ of size 1 at parserInternals.c:620
 */
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>

int main(void) {
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr)calloc(1, sizeof(xmlParserCtxt));
    xmlParserInputPtr input = (xmlParserInputPtr)calloc(1, sizeof(xmlParserInput));
    unsigned char *buf = (unsigned char *)malloc(1);
    int len = 0;

    if (!ctxt || !input || !buf) return 1;

    /* 0xC8 = 2-byte UTF-8 lead (0xC0-0xDF), forces read of cur[1] */
    buf[0] = 0xC8;

    ctxt->input = input;
    ctxt->instate = 0;           /* not EOF */
    ctxt->charset = 1;           /* XML_CHAR_ENCODING_UTF8 */

    input->base = buf;
    input->cur  = buf;
    input->end  = buf + 1;       /* only 1 byte allocated */
    input->buf  = NULL;

    /* xmlCurrentChar reads cur[1] → 1 past malloc(1) → ASan fires */
    xmlCurrentChar(ctxt, &len);
    return 0;
}
ENDC
run_replay "$DIR529" "/tmp/replay_529.c" "529"
echo ""

# ── Spec 541: parserInternals.c:654 xmlCurrentChar (3-byte lead, 2-byte buf) ──
echo "[Spec 541] parserInternals.c:654 xmlCurrentChar"
DIR541="$SE_BASE/541_parserInternals.c_654_local_cpp_cwe-125-cursor-lookahead-missing-bytes-check"
cat > /tmp/replay_541.c << 'ENDC'
/* Manual replay driver: spec 541 — parserInternals.c:654 xmlCurrentChar
 * Bug: 3-byte UTF-8 lead (0xE0) + continuation (0x80), 2-byte buffer
 *      → cur[2] OOB read at "if (cur[2] == 0)" check
 * Expected: heap-buffer-overflow READ of size 1 at parserInternals.c
 */
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>

int main(void) {
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr)calloc(1, sizeof(xmlParserCtxt));
    xmlParserInputPtr input = (xmlParserInputPtr)calloc(1, sizeof(xmlParserInput));
    unsigned char *buf = (unsigned char *)malloc(2);
    int len = 0;

    if (!ctxt || !input || !buf) return 1;

    /* 0xE0 = 3-byte UTF-8 lead; 0x80 = valid continuation.
     * Forces path to "if (cur[2] == 0)" which reads buf[2] = OOB. */
    buf[0] = 0xE0;
    buf[1] = 0x80;

    ctxt->input = input;
    ctxt->instate = 0;
    ctxt->charset = 1;

    input->base = buf;
    input->cur  = buf;
    input->end  = buf + 2;
    input->buf  = NULL;

    xmlCurrentChar(ctxt, &len);
    return 0;
}
ENDC
run_replay "$DIR541" "/tmp/replay_541.c" "541"
echo ""

# ── Spec 1379: tree.c:3710 xmlFreeNodeList (use-after-free) ──
echo "[Spec 1379] tree.c:3710 xmlFreeNodeList use-after-free"
DIR1379="$SE_BASE/1379_tree.c_3708_sailor_cpp_pattern_free-then-use_intra"
cat > /tmp/replay_1379.c << 'ENDC'
/* Manual replay driver: spec 1379 — tree.c:3710 xmlFreeNodeList
 * Bug: use-after-free in xmlFreeNodeList when freeing element nodes.
 * The pipeline's KLEE driver calls xmlFreeDoc(doc) directly.
 * Expected: heap-use-after-free at tree.c
 */
#include <stdlib.h>
#include <string.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

int main(void) {
    xmlDocPtr  doc  = (xmlDocPtr)calloc(1, sizeof(xmlDoc));
    xmlNodePtr node = (xmlNodePtr)calloc(1, sizeof(xmlNode));
    xmlChar   *name = (xmlChar *)malloc(8);

    if (!doc || !node || !name) return 1;

    name[0] = 'A'; name[1] = '\0';

    /* Minimal doc with one child element */
    doc->type      = XML_DOCUMENT_NODE;
    doc->children  = node;
    doc->dict      = NULL;
    doc->ids       = NULL;
    doc->refs      = NULL;
    doc->extSubset = NULL;
    doc->intSubset = NULL;
    doc->oldNs     = NULL;

    node->doc        = doc;
    node->type       = XML_ELEMENT_NODE;
    node->name       = name;
    node->next       = NULL;
    node->children   = NULL;
    node->properties = NULL;
    node->content    = NULL;
    node->nsDef      = NULL;

    /* Triggers xmlFreeDoc → xmlFreeNodeList → DICT_FREE(name) + xmlFree(cur) */
    xmlFreeDoc(doc);
    return 0;
}
ENDC
run_replay "$DIR1379" "/tmp/replay_1379.c" "1379"
echo ""

# ── Spec 587: parser.c:11459 xmlParseTryOrFinish (push parser) ──
echo "[Spec 587] parser.c:11459 xmlParseTryOrFinish"
DIR587="$SE_BASE/587_parser.c_11457_local_cpp_cwe-125-cursor-lookahead-missing-bytes-check"
# Check the existing replay driver's structure
if [ -f "$DIR587/asan_real/replay_driver.c" ]; then
    cat > /tmp/replay_587.c << 'ENDC'
/* Manual replay driver: spec 587 — parser.c:11459 xmlParseTryOrFinish
 * Bug: cursor lookahead past buffer end during push-mode XML parsing.
 * Use xmlCreatePushParserCtxt + xmlParseChunk with crafted 3-byte UTF-8.
 * Expected: heap-buffer-overflow READ at parser.c
 */
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>

int main(void) {
    /* Craft minimal XML chunk with truncated 3-byte UTF-8 in element content */
    /* "<a>" followed by 0xE0 0x80 (incomplete 3-byte sequence) */
    const char chunk[] = "<a>\xE0\x80";
    int chunk_len = (int)sizeof(chunk) - 1;  /* exclude NUL */

    xmlParserCtxtPtr ctxt = xmlCreatePushParserCtxt(NULL, NULL,
                                                     chunk, chunk_len,
                                                     NULL);
    if (!ctxt) return 1;

    /* Parse with no more data — forces lookahead past end */
    xmlParseChunk(ctxt, NULL, 0, 1);  /* terminate */

    xmlFreeParserCtxt(ctxt);
    return 0;
}
ENDC
    run_replay "$DIR587" "/tmp/replay_587.c" "587"
fi
echo ""

# ── Spec 622: uri.c:2416 xmlCanonicPath ──
echo "[Spec 622] uri.c:2416 xmlCanonicPath"
DIR622="$SE_BASE/622_uri.c_2416_local_cpp_cwe-125-cursor-lookahead-missing-bytes-check"
if [ -d "$DIR622" ]; then
    cat > /tmp/replay_622.c << 'ENDC'
/* Manual replay driver: spec 622 — uri.c:2416 xmlCanonicPath
 * Bug: cursor lookahead in xmlCanonicPath past buffer end.
 * Feed a URI string with a truncated multi-byte UTF-8 sequence.
 */
#include <stdlib.h>
#include <string.h>
#include <libxml/uri.h>

int main(void) {
    /* Path ending with truncated 3-byte UTF-8 lead */
    const xmlChar *path = (const xmlChar *)"/foo/\xE0\x80";
    xmlChar *result = xmlCanonicPath(path);
    if (result) xmlFree(result);
    return 0;
}
ENDC
    run_replay "$DIR622" "/tmp/replay_622.c" "622"
fi
echo ""

echo "=== Summary ==="
echo "  Crashes (ASan confirmed): $crash"
echo "  No crash (compiled OK):   $ok"
echo "  Compile failures:         $fail"
