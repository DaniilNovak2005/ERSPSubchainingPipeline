/*
 * Unified Validation Harness — binutils (BFD)
 *
 * Compile:
 *   gcc -fsanitize=address -g -O0 -w \
 *       -I<binutils_src>/include -I<binutils_src>/bfd \
 *       harness_binutils.c \
 *       <binutils_src>/bfd/libbfd.a <binutils_src>/libiberty/libiberty.a \
 *       <binutils_src>/libsframe/.libs/libsframe.a \
 *       -lm -lz -ldl -lpthread -o test_harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bfd.h"

/* ================================================================
 * BASELINE INPUT
 * ================================================================ */

#ifndef TARGET_FUNC
#define TARGET_FUNC  "_bfd_elf_parse_attributes"
#define TARGET_FILE  "elf-attrs.c"
#define TARGET_LINE  0
#endif

#ifndef ENTRY_PATH
#define ENTRY_PATH "bfd_open"
/* Options: "bfd_open", "bfd_check_format", "bfd_get_section" */
#endif

/* Input file to parse (baseline provides this) */
#ifndef INPUT_FILE
#define INPUT_FILE "/tmp/sailor_harness_binutils.o"
#endif

/* ================================================================
 * Minimal ELF object generator (in-memory → temp file)
 * ================================================================ */

/* Minimal 64-bit little-endian ELF header + empty section header */
static unsigned char minimal_elf[] = {
    /* ELF magic */
    0x7f, 'E', 'L', 'F',
    /* Class: 64-bit */
    2,
    /* Data: little-endian */
    1,
    /* Version */
    1,
    /* OS/ABI */
    0,
    /* Padding (8 bytes) */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* Type: ET_REL (relocatable) */
    1, 0,
    /* Machine: EM_X86_64 */
    0x3e, 0,
    /* Version */
    1, 0, 0, 0,
    /* Entry point */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* Program header offset (0 = none) */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* Section header offset (64 = right after this header) */
    64, 0, 0, 0, 0, 0, 0, 0,
    /* Flags */
    0, 0, 0, 0,
    /* ELF header size */
    64, 0,
    /* Program header entry size */
    0, 0,
    /* Program header count */
    0, 0,
    /* Section header entry size */
    64, 0,
    /* Section header count */
    1, 0,
    /* Section name string table index */
    0, 0,
    /* Section header #0 (SHN_UNDEF) — 64 zero bytes */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

static int write_test_input(const char *path) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return 1;
    fwrite(minimal_elf, 1, sizeof(minimal_elf), fp);
    fclose(fp);
    return 0;
}

/* ================================================================
 * Entry path implementations
 * ================================================================ */

static int test_bfd_open(void) {
    bfd *abfd = bfd_openr(INPUT_FILE, NULL);
    if (!abfd) {
        fprintf(stderr, "bfd_openr failed: %s\n",
                bfd_errmsg(bfd_get_error()));
        return 1;
    }

    /* Just open and close — exercises header parsing */
    if (!bfd_check_format(abfd, bfd_object)) {
        fprintf(stderr, "Not a valid object: %s\n",
                bfd_errmsg(bfd_get_error()));
    }

    bfd_close(abfd);
    return 0;
}

static int test_bfd_check_format(void) {
    bfd *abfd = bfd_openr(INPUT_FILE, NULL);
    if (!abfd) return 1;

    /* Try all format types to exercise different parsers */
    if (bfd_check_format(abfd, bfd_object)) {
        fprintf(stderr, "Format: object, target: %s\n",
                bfd_get_target(abfd));
    } else {
        bfd_set_error(bfd_error_no_error);
        if (bfd_check_format(abfd, bfd_archive)) {
            fprintf(stderr, "Format: archive\n");
        } else {
            bfd_set_error(bfd_error_no_error);
            if (bfd_check_format(abfd, bfd_core)) {
                fprintf(stderr, "Format: core\n");
            }
        }
    }

    bfd_close(abfd);
    return 0;
}

static int test_bfd_get_section(void) {
    bfd *abfd = bfd_openr(INPUT_FILE, NULL);
    if (!abfd) return 1;

    if (!bfd_check_format(abfd, bfd_object)) {
        fprintf(stderr, "Not a valid object\n");
        bfd_close(abfd);
        return 1;
    }

    /* Iterate over all sections */
    asection *sec;
    for (sec = abfd->sections; sec != NULL; sec = sec->next) {
        fprintf(stderr, "Section: %s (size: %lu, flags: 0x%x)\n",
                bfd_section_name(sec),
                (unsigned long)bfd_section_size(sec),
                (unsigned int)bfd_section_flags(sec));

        /* Read section contents if non-empty */
        bfd_size_type sz = bfd_section_size(sec);
        if (sz > 0 && sz < 1024 * 1024) {
            unsigned char *contents = malloc(sz);
            if (contents) {
                bfd_get_section_contents(abfd, sec, contents, 0, sz);
                free(contents);
            }
        }
    }

    bfd_close(abfd);
    return 0;
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    fprintf(stderr, "Target: %s at %s:%d\n", TARGET_FUNC, TARGET_FILE, TARGET_LINE);
    fprintf(stderr, "Entry path: %s\n", ENTRY_PATH);

    bfd_init();

    /* Write test input file */
    if (write_test_input(INPUT_FILE) != 0) {
        fprintf(stderr, "Failed to write test input\n");
        return 1;
    }

    if (strcmp(ENTRY_PATH, "bfd_open") == 0) return test_bfd_open();
    if (strcmp(ENTRY_PATH, "bfd_check_format") == 0) return test_bfd_check_format();
    if (strcmp(ENTRY_PATH, "bfd_get_section") == 0) return test_bfd_get_section();

    fprintf(stderr, "Unknown entry path: %s\n", ENTRY_PATH);
    return 1;
}
