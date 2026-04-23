/*
 * Unified Validation Harness — libtiff
 *
 * Compile:
 *   gcc -fsanitize=address -g -O0 -w -I<libtiff_src>/libtiff \
 *       harness_libtiff.c <libtiff_src>/build_simple/libtiff.a \
 *       -lm -lz -llzma -lpthread -o test_harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tiffio.h>

/* ================================================================
 * BASELINE INPUT
 * ================================================================ */

#ifndef TARGET_FUNC
#define TARGET_FUNC  "TIFFReadEncodedStrip"
#define TARGET_FILE  "tif_read.c"
#define TARGET_LINE  328
#endif

#ifndef ENTRY_PATH
#define ENTRY_PATH "read_strip"
/* Options: "read_strip", "read_tile", "write_strip", "write_tile",
 *          "read_rgba", "print_directory", "set_field", "get_field",
 *          "custom" */
#endif

/* Image parameters (baseline provides these) */
#ifndef IMG_WIDTH
#define IMG_WIDTH 64
#endif
#ifndef IMG_HEIGHT
#define IMG_HEIGHT 64
#endif
#ifndef IMG_BPS
#define IMG_BPS 8  /* bits per sample */
#endif
#ifndef IMG_SPP
#define IMG_SPP 1  /* samples per pixel */
#endif
#ifndef STRIP_SIZE
#define STRIP_SIZE 10  /* intentionally small for OOB */
#endif
#ifndef COMPRESSION
#define COMPRESSION COMPRESSION_NONE
#endif

/* ================================================================
 * Library initialization — create in-memory TIFF
 * ================================================================ */

/* In-memory TIFF write buffer */
static unsigned char *tiff_buf = NULL;
static tsize_t tiff_buf_size = 0;
static toff_t tiff_buf_offset = 0;

static tsize_t mem_read(thandle_t h, tdata_t buf, tsize_t size) {
    if (tiff_buf_offset + size > tiff_buf_size)
        size = tiff_buf_size - tiff_buf_offset;
    if (size > 0) memcpy(buf, tiff_buf + tiff_buf_offset, size);
    tiff_buf_offset += size;
    return size;
}

static tsize_t mem_write(thandle_t h, tdata_t buf, tsize_t size) {
    if (tiff_buf_offset + size > tiff_buf_size) {
        tiff_buf_size = tiff_buf_offset + size + 4096;
        tiff_buf = realloc(tiff_buf, tiff_buf_size);
    }
    memcpy(tiff_buf + tiff_buf_offset, buf, size);
    tiff_buf_offset += size;
    return size;
}

static toff_t mem_seek(thandle_t h, toff_t offset, int whence) {
    switch (whence) {
        case SEEK_SET: tiff_buf_offset = offset; break;
        case SEEK_CUR: tiff_buf_offset += offset; break;
        case SEEK_END: tiff_buf_offset = tiff_buf_size + offset; break;
    }
    return tiff_buf_offset;
}

static int mem_close(thandle_t h) { return 0; }
static toff_t mem_size(thandle_t h) { return tiff_buf_size; }

static TIFF *create_test_tiff(void) {
    tiff_buf = malloc(65536);
    tiff_buf_size = 65536;
    tiff_buf_offset = 0;

    TIFF *tif = TIFFClientOpen("memory", "w", NULL,
                                mem_read, mem_write, mem_seek,
                                mem_close, mem_size, NULL, NULL);
    if (!tif) return NULL;

    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, IMG_WIDTH);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, IMG_HEIGHT);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, IMG_BPS);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, IMG_SPP);
    TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
    TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, IMG_HEIGHT);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);

    /* Write dummy strip data */
    size_t row_bytes = IMG_WIDTH * IMG_SPP * (IMG_BPS / 8);
    unsigned char *row = calloc(1, row_bytes);
    for (int y = 0; y < IMG_HEIGHT; y++) {
        TIFFWriteScanline(tif, row, y, 0);
    }
    free(row);
    TIFFWriteDirectory(tif);
    TIFFClose(tif);

    /* Reopen for reading */
    tiff_buf_offset = 0;
    tif = TIFFClientOpen("memory", "r", NULL,
                          mem_read, mem_write, mem_seek,
                          mem_close, mem_size, NULL, NULL);
    return tif;
}

/* ================================================================
 * Entry path implementations
 * ================================================================ */

static int test_read_strip(TIFF *tif) {
    tstrip_t nstrips = TIFFNumberOfStrips(tif);
    for (tstrip_t s = 0; s < nstrips; s++) {
        tsize_t sz = TIFFStripSize(tif);
        /* Use baseline-specified size (may be too small → OOB) */
        unsigned char *buf = malloc(STRIP_SIZE);
        if (buf) {
            TIFFReadEncodedStrip(tif, s, buf, STRIP_SIZE);
            free(buf);
        }
    }
    return 0;
}

static int test_read_rgba(TIFF *tif) {
    uint32_t w, h;
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
    uint32_t *raster = (uint32_t *)_TIFFmalloc(w * h * sizeof(uint32_t));
    if (raster) {
        TIFFReadRGBAImage(tif, w, h, raster, 0);
        _TIFFfree(raster);
    }
    return 0;
}

static int test_print_directory(TIFF *tif) {
    TIFFPrintDirectory(tif, stdout, 0);
    return 0;
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    fprintf(stderr, "Target: %s at %s:%d\n", TARGET_FUNC, TARGET_FILE, TARGET_LINE);
    fprintf(stderr, "Entry path: %s\n", ENTRY_PATH);

    TIFF *tif = create_test_tiff();
    if (!tif) {
        fprintf(stderr, "Failed to create test TIFF\n");
        return 1;
    }

    if (strcmp(ENTRY_PATH, "read_strip") == 0) {
        test_read_strip(tif);
    } else if (strcmp(ENTRY_PATH, "read_rgba") == 0) {
        test_read_rgba(tif);
    } else if (strcmp(ENTRY_PATH, "print_directory") == 0) {
        test_print_directory(tif);
    }

    TIFFClose(tif);
    free(tiff_buf);
    return 0;
}
