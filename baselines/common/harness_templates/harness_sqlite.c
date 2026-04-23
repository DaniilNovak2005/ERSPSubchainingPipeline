/*
 * Unified Validation Harness — SQLite
 *
 * Provides standard library initialization for SQLite.
 * Baselines fill in TARGET and INPUT sections.
 *
 * Compile:
 *   gcc -fsanitize=address -g -O0 -w -I<sqlite_src> \
 *       harness_sqlite.c <sqlite_src>/libsqlite3.a \
 *       -lm -lpthread -ldl -o test_harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

/* ================================================================
 * BASELINE INPUT: Fill these in from the baseline's bug report
 * ================================================================ */

/* Target vulnerability location */
#ifndef TARGET_FUNC
#define TARGET_FUNC  "memdbRead"
#define TARGET_FILE  "memdb.c"
#define TARGET_LINE  266
#endif

/* Entry path — which high-level API reaches the target */
#ifndef ENTRY_PATH
#define ENTRY_PATH "deserialize"
/* Options: "exec", "prepare", "deserialize", "backup", "blob" */
#endif

/* Crashing input parameters (baseline-specific) */
#ifndef INPUT_SQL
#define INPUT_SQL "CREATE TABLE t1(x TEXT); INSERT INTO t1 VALUES(zeroblob(5000));"
#endif
#ifndef INPUT_QUERY
#define INPUT_QUERY "SELECT * FROM t1;"
#endif
#ifndef INPUT_DESERIALIZE_TRUNCATE
#define INPUT_DESERIALIZE_TRUNCATE 1  /* 1 = truncate buffer to trigger OOB */
#endif

/* ================================================================
 * Library initialization (same for all baselines)
 * ================================================================ */

static sqlite3 *init_db(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK || db == NULL) {
        fprintf(stderr, "Failed to open database: %s\n",
                db ? sqlite3_errmsg(db) : "NULL");
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

/* ================================================================
 * Entry path implementations
 * ================================================================ */

static int test_exec(sqlite3 *db) {
    char *errmsg = NULL;
    /* Set up state */
    sqlite3_exec(db, INPUT_SQL, NULL, NULL, &errmsg);
    if (errmsg) { sqlite3_free(errmsg); errmsg = NULL; }

    /* Execute the query that triggers the bug */
    sqlite3_exec(db, INPUT_QUERY, NULL, NULL, &errmsg);
    if (errmsg) sqlite3_free(errmsg);
    return 0;
}

static int test_prepare(sqlite3 *db) {
    char *errmsg = NULL;
    sqlite3_exec(db, INPUT_SQL, NULL, NULL, &errmsg);
    if (errmsg) { sqlite3_free(errmsg); errmsg = NULL; }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, INPUT_QUERY, -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt) {
        for (int i = 0; i < 100; i++) {
            if (sqlite3_step(stmt) != SQLITE_ROW) break;
        }
        sqlite3_finalize(stmt);
    }
    return 0;
}

static int test_deserialize(sqlite3 *db) {
    char *errmsg = NULL;
    /* Populate database */
    sqlite3_exec(db, INPUT_SQL, NULL, NULL, &errmsg);
    if (errmsg) { sqlite3_free(errmsg); errmsg = NULL; }

    /* Serialize */
    sqlite3_int64 sz = 0;
    unsigned char *serialized = sqlite3_serialize(db, "main", &sz, 0);
    if (!serialized || sz <= 0) {
        fprintf(stderr, "Serialize failed\n");
        return 1;
    }

    /* Close and reopen */
    sqlite3_close(db);
    db = init_db();
    if (!db) return 1;

#if INPUT_DESERIALIZE_TRUNCATE
    /* Truncate buffer to trigger OOB read in memdbRead */
    sqlite3_int64 small_sz = sz / 4;  /* much smaller than actual DB */
    unsigned char *small_buf = sqlite3_malloc64(small_sz);
    if (!small_buf) { sqlite3_close(db); return 1; }
    memcpy(small_buf, serialized, small_sz);
    sqlite3_free(serialized);

    int rc = sqlite3_deserialize(db, "main", small_buf, sz, small_sz,
                                  SQLITE_DESERIALIZE_FREEONCLOSE |
                                  SQLITE_DESERIALIZE_RESIZEABLE);
#else
    int rc = sqlite3_deserialize(db, "main", serialized, sz, sz,
                                  SQLITE_DESERIALIZE_FREEONCLOSE);
#endif

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Deserialize failed: %d\n", rc);
        sqlite3_close(db);
        return 1;
    }

    /* Query deserialized data — triggers read through memdbRead */
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, INPUT_QUERY, -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt) {
        for (int i = 0; i < 10; i++) {
            if (sqlite3_step(stmt) != SQLITE_ROW) break;
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
    return 0;
}

/* ================================================================
 * Main — selects entry path based on ENTRY_PATH
 * ================================================================ */

int main(void) {
    fprintf(stderr, "Target: %s at %s:%d\n", TARGET_FUNC, TARGET_FILE, TARGET_LINE);
    fprintf(stderr, "Entry path: %s\n", ENTRY_PATH);

    sqlite3 *db = init_db();
    if (!db) return 1;

    if (strcmp(ENTRY_PATH, "exec") == 0) {
        test_exec(db);
    } else if (strcmp(ENTRY_PATH, "prepare") == 0) {
        test_prepare(db);
    } else if (strcmp(ENTRY_PATH, "deserialize") == 0) {
        test_deserialize(db);
        return 0;  /* db already closed in test_deserialize */
    } else {
        fprintf(stderr, "Unknown entry path: %s\n", ENTRY_PATH);
    }

    sqlite3_close(db);
    return 0;
}
