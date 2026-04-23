/*
 * Unified Validation Harness — libxml2
 *
 * Compile:
 *   gcc -fsanitize=address -g -O0 -w -I<libxml2_src>/include \
 *       harness_libxml2.c <libxml2_src>/.libs/libxml2.a \
 *       -lm -lz -lpthread -ldl -o test_harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/xmlschemas.h>
#include <libxml/relaxng.h>
#include <libxml/xmlmemory.h>

/* ================================================================
 * BASELINE INPUT
 * ================================================================ */

#ifndef TARGET_FUNC
#define TARGET_FUNC  "xmlParseStartTag2"
#define TARGET_FILE  "parser.c"
#define TARGET_LINE  0
#endif

#ifndef ENTRY_PATH
#define ENTRY_PATH "parse_memory"
/* Options: "parse_memory", "parse_file", "xpath", "schema_validate",
 *          "relaxng" */
#endif

/* XML input (baseline provides these) */
#ifndef INPUT_XML
#define INPUT_XML \
    "<?xml version=\"1.0\"?>\n" \
    "<root><item id=\"1\">value</item><item id=\"2\">other</item></root>"
#endif

#ifndef INPUT_XPATH
#define INPUT_XPATH "//item[@id='1']"
#endif

#ifndef INPUT_SCHEMA
#define INPUT_SCHEMA \
    "<?xml version=\"1.0\"?>\n" \
    "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">\n" \
    "  <xs:element name=\"root\">\n" \
    "    <xs:complexType><xs:sequence>\n" \
    "      <xs:element name=\"item\" maxOccurs=\"unbounded\">\n" \
    "        <xs:complexType mixed=\"true\">\n" \
    "          <xs:attribute name=\"id\" type=\"xs:string\"/>\n" \
    "        </xs:complexType>\n" \
    "      </xs:element>\n" \
    "    </xs:sequence></xs:complexType>\n" \
    "  </xs:element>\n" \
    "</xs:schema>"
#endif

#ifndef INPUT_RELAXNG
#define INPUT_RELAXNG \
    "<?xml version=\"1.0\"?>\n" \
    "<grammar xmlns=\"http://relaxng.org/ns/structure/1.0\">\n" \
    "  <start><element name=\"root\">\n" \
    "    <zeroOrMore><element name=\"item\">\n" \
    "      <optional><attribute name=\"id\"><text/></attribute></optional>\n" \
    "      <text/>\n" \
    "    </element></zeroOrMore>\n" \
    "  </element></start>\n" \
    "</grammar>"
#endif

/* ================================================================
 * Library initialization
 * ================================================================ */

static void init_libxml(void) {
    xmlInitParser();
    LIBXML_TEST_VERSION
}

static void cleanup_libxml(void) {
    xmlCleanupParser();
    xmlMemoryDump();
}

/* ================================================================
 * Entry path implementations
 * ================================================================ */

static int test_parse_memory(void) {
    const char *xml = INPUT_XML;
    xmlDocPtr doc = xmlReadMemory(xml, strlen(xml), "noname.xml", NULL, 0);
    if (!doc) {
        fprintf(stderr, "xmlReadMemory failed\n");
        return 1;
    }

    /* Walk the tree to exercise internal structures */
    xmlNodePtr root = xmlDocGetRootElement(doc);
    for (xmlNodePtr cur = root->children; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE) {
            xmlChar *content = xmlNodeGetContent(cur);
            if (content) xmlFree(content);
        }
    }

    xmlFreeDoc(doc);
    return 0;
}

static int test_parse_file(void) {
    /* Write XML to temp file, then parse */
    const char *xml = INPUT_XML;
    const char *tmppath = "/tmp/sailor_harness_libxml2.xml";
    FILE *fp = fopen(tmppath, "w");
    if (!fp) return 1;
    fwrite(xml, 1, strlen(xml), fp);
    fclose(fp);

    xmlDocPtr doc = xmlReadFile(tmppath, NULL, 0);
    if (!doc) {
        fprintf(stderr, "xmlReadFile failed\n");
        return 1;
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root) {
        xmlChar *content = xmlNodeGetContent(root);
        if (content) xmlFree(content);
    }

    xmlFreeDoc(doc);
    return 0;
}

static int test_xpath(void) {
    const char *xml = INPUT_XML;
    xmlDocPtr doc = xmlReadMemory(xml, strlen(xml), "noname.xml", NULL, 0);
    if (!doc) return 1;

    xmlXPathContextPtr xctx = xmlXPathNewContext(doc);
    if (!xctx) { xmlFreeDoc(doc); return 1; }

    xmlXPathObjectPtr result = xmlXPathEvalExpression(
        (const xmlChar *)INPUT_XPATH, xctx);
    if (result) {
        if (result->nodesetval) {
            for (int i = 0; i < result->nodesetval->nodeNr; i++) {
                xmlNodePtr node = result->nodesetval->nodeTab[i];
                xmlChar *content = xmlNodeGetContent(node);
                if (content) xmlFree(content);
            }
        }
        xmlXPathFreeObject(result);
    }

    xmlXPathFreeContext(xctx);
    xmlFreeDoc(doc);
    return 0;
}

static int test_schema_validate(void) {
    const char *xml = INPUT_XML;
    const char *xsd = INPUT_SCHEMA;

    xmlDocPtr schema_doc = xmlReadMemory(xsd, strlen(xsd), "schema.xsd", NULL, 0);
    if (!schema_doc) return 1;

    xmlSchemaParserCtxtPtr pctx = xmlSchemaNewDocParserCtxt(schema_doc);
    if (!pctx) { xmlFreeDoc(schema_doc); return 1; }

    xmlSchemaPtr schema = xmlSchemaParse(pctx);
    xmlSchemaFreeParserCtxt(pctx);
    if (!schema) { xmlFreeDoc(schema_doc); return 1; }

    xmlSchemaValidCtxtPtr vctx = xmlSchemaNewValidCtxt(schema);
    if (!vctx) {
        xmlSchemaFree(schema);
        xmlFreeDoc(schema_doc);
        return 1;
    }

    xmlDocPtr doc = xmlReadMemory(xml, strlen(xml), "test.xml", NULL, 0);
    if (doc) {
        xmlSchemaValidateDoc(vctx, doc);
        xmlFreeDoc(doc);
    }

    xmlSchemaFreeValidCtxt(vctx);
    xmlSchemaFree(schema);
    xmlFreeDoc(schema_doc);
    return 0;
}

static int test_relaxng(void) {
    const char *xml = INPUT_XML;
    const char *rng = INPUT_RELAXNG;

    xmlDocPtr rng_doc = xmlReadMemory(rng, strlen(rng), "schema.rng", NULL, 0);
    if (!rng_doc) return 1;

    xmlRelaxNGParserCtxtPtr pctx = xmlRelaxNGNewDocParserCtxt(rng_doc);
    if (!pctx) { xmlFreeDoc(rng_doc); return 1; }

    xmlRelaxNGPtr schema = xmlRelaxNGParse(pctx);
    xmlRelaxNGFreeParserCtxt(pctx);
    if (!schema) { xmlFreeDoc(rng_doc); return 1; }

    xmlRelaxNGValidCtxtPtr vctx = xmlRelaxNGNewValidCtxt(schema);
    if (!vctx) {
        xmlRelaxNGFree(schema);
        xmlFreeDoc(rng_doc);
        return 1;
    }

    xmlDocPtr doc = xmlReadMemory(xml, strlen(xml), "test.xml", NULL, 0);
    if (doc) {
        xmlRelaxNGValidateDoc(vctx, doc);
        xmlFreeDoc(doc);
    }

    xmlRelaxNGFreeValidCtxt(vctx);
    xmlRelaxNGFree(schema);
    xmlFreeDoc(rng_doc);
    return 0;
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    fprintf(stderr, "Target: %s at %s:%d\n", TARGET_FUNC, TARGET_FILE, TARGET_LINE);
    fprintf(stderr, "Entry path: %s\n", ENTRY_PATH);

    init_libxml();
    int rc = 1;

    if (strcmp(ENTRY_PATH, "parse_memory") == 0) rc = test_parse_memory();
    else if (strcmp(ENTRY_PATH, "parse_file") == 0) rc = test_parse_file();
    else if (strcmp(ENTRY_PATH, "xpath") == 0) rc = test_xpath();
    else if (strcmp(ENTRY_PATH, "schema_validate") == 0) rc = test_schema_validate();
    else if (strcmp(ENTRY_PATH, "relaxng") == 0) rc = test_relaxng();
    else fprintf(stderr, "Unknown entry path: %s\n", ENTRY_PATH);

    cleanup_libxml();
    return rc;
}
