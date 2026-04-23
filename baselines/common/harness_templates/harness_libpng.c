/*
 * Unified Validation Harness — libpng
 *
 * Compile:
 *   gcc -fsanitize=address -g -O0 -w -I<libpng_src> \
 *       harness_libpng.c <libpng_src>/libpng.a \
 *       -lm -lz -lpthread -o test_harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

/* ================================================================
 * BASELINE INPUT
 * ================================================================ */

#ifndef TARGET_FUNC
#define TARGET_FUNC  "png_read_row"
#define TARGET_FILE  "pngrutil.c"
#define TARGET_LINE  0
#endif

#ifndef ENTRY_PATH
#define ENTRY_PATH "read_image"
/* Options: "read_image", "write_image", "read_row", "set_transforms" */
#endif

/* Image parameters (baseline provides these) */
#ifndef IMG_WIDTH
#define IMG_WIDTH 64
#endif
#ifndef IMG_HEIGHT
#define IMG_HEIGHT 64
#endif
#ifndef IMG_BIT_DEPTH
#define IMG_BIT_DEPTH 8
#endif
#ifndef IMG_COLOR_TYPE
#define IMG_COLOR_TYPE PNG_COLOR_TYPE_RGB
#endif

/* ================================================================
 * In-memory PNG read/write callbacks
 * ================================================================ */

struct mem_buffer {
    unsigned char *data;
    size_t size;
    size_t offset;
};

static void mem_read_fn(png_structp png, png_bytep out, png_size_t count) {
    struct mem_buffer *buf = (struct mem_buffer *)png_get_io_ptr(png);
    if (buf->offset + count > buf->size)
        count = buf->size - buf->offset;
    memcpy(out, buf->data + buf->offset, count);
    buf->offset += count;
}

static void mem_write_fn(png_structp png, png_bytep data, png_size_t count) {
    struct mem_buffer *buf = (struct mem_buffer *)png_get_io_ptr(png);
    if (buf->offset + count > buf->size) {
        buf->size = buf->offset + count + 4096;
        buf->data = realloc(buf->data, buf->size);
    }
    memcpy(buf->data + buf->offset, data, count);
    buf->offset += count;
}

static void mem_flush_fn(png_structp png) { (void)png; }

static void user_error_fn(png_structp png, png_const_charp msg) {
    fprintf(stderr, "libpng error: %s\n", msg);
    longjmp(png_jmpbuf(png), 1);
}

static void user_warning_fn(png_structp png, png_const_charp msg) {
    fprintf(stderr, "libpng warning: %s\n", msg);
}

/* ================================================================
 * Library initialization — create in-memory PNG
 * ================================================================ */

static struct mem_buffer g_png_buf = {NULL, 0, 0};

static int create_test_png(void) {
    png_structp wp = png_create_write_struct(PNG_LIBPNG_VER_STRING,
                                             NULL, user_error_fn, user_warning_fn);
    if (!wp) return 1;

    png_infop wi = png_create_info_struct(wp);
    if (!wi) { png_destroy_write_struct(&wp, NULL); return 1; }

    if (setjmp(png_jmpbuf(wp))) {
        png_destroy_write_struct(&wp, &wi);
        return 1;
    }

    g_png_buf.data = malloc(65536);
    g_png_buf.size = 65536;
    g_png_buf.offset = 0;
    png_set_write_fn(wp, &g_png_buf, mem_write_fn, mem_flush_fn);

    int channels = (IMG_COLOR_TYPE == PNG_COLOR_TYPE_RGB) ? 3 :
                   (IMG_COLOR_TYPE == PNG_COLOR_TYPE_RGBA) ? 4 : 1;

    png_set_IHDR(wp, wi, IMG_WIDTH, IMG_HEIGHT, IMG_BIT_DEPTH,
                 IMG_COLOR_TYPE, PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(wp, wi);

    size_t row_bytes = IMG_WIDTH * channels * (IMG_BIT_DEPTH / 8);
    unsigned char *row = calloc(1, row_bytes);
    for (int y = 0; y < IMG_HEIGHT; y++)
        png_write_row(wp, row);
    free(row);

    png_write_end(wp, wi);
    png_destroy_write_struct(&wp, &wi);
    return 0;
}

/* ================================================================
 * Entry path implementations
 * ================================================================ */

static int test_read_image(void) {
    g_png_buf.offset = 0;

    png_structp rp = png_create_read_struct(PNG_LIBPNG_VER_STRING,
                                             NULL, user_error_fn, user_warning_fn);
    if (!rp) return 1;

    png_infop ri = png_create_info_struct(rp);
    if (!ri) { png_destroy_read_struct(&rp, NULL, NULL); return 1; }

    if (setjmp(png_jmpbuf(rp))) {
        png_destroy_read_struct(&rp, &ri, NULL);
        return 1;
    }

    png_set_read_fn(rp, &g_png_buf, mem_read_fn);
    png_read_info(rp, ri);

    png_uint_32 w = png_get_image_width(rp, ri);
    png_uint_32 h = png_get_image_height(rp, ri);
    size_t rb = png_get_rowbytes(rp, ri);

    png_bytepp rows = malloc(h * sizeof(png_bytep));
    for (png_uint_32 y = 0; y < h; y++)
        rows[y] = malloc(rb);

    png_read_image(rp, rows);
    png_read_end(rp, ri);

    for (png_uint_32 y = 0; y < h; y++)
        free(rows[y]);
    free(rows);
    png_destroy_read_struct(&rp, &ri, NULL);
    return 0;
}

static int test_write_image(void) {
    png_structp wp = png_create_write_struct(PNG_LIBPNG_VER_STRING,
                                             NULL, user_error_fn, user_warning_fn);
    if (!wp) return 1;

    png_infop wi = png_create_info_struct(wp);
    if (!wi) { png_destroy_write_struct(&wp, NULL); return 1; }

    if (setjmp(png_jmpbuf(wp))) {
        png_destroy_write_struct(&wp, &wi);
        return 1;
    }

    struct mem_buffer out = {malloc(65536), 65536, 0};
    png_set_write_fn(wp, &out, mem_write_fn, mem_flush_fn);

    int channels = (IMG_COLOR_TYPE == PNG_COLOR_TYPE_RGB) ? 3 :
                   (IMG_COLOR_TYPE == PNG_COLOR_TYPE_RGBA) ? 4 : 1;

    png_set_IHDR(wp, wi, IMG_WIDTH, IMG_HEIGHT, IMG_BIT_DEPTH,
                 IMG_COLOR_TYPE, PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(wp, wi);

    size_t row_bytes = IMG_WIDTH * channels * (IMG_BIT_DEPTH / 8);
    unsigned char *row = calloc(1, row_bytes);
    for (int y = 0; y < IMG_HEIGHT; y++)
        png_write_row(wp, row);
    free(row);

    png_write_end(wp, wi);
    png_destroy_write_struct(&wp, &wi);
    free(out.data);
    return 0;
}

static int test_read_row(void) {
    g_png_buf.offset = 0;

    png_structp rp = png_create_read_struct(PNG_LIBPNG_VER_STRING,
                                             NULL, user_error_fn, user_warning_fn);
    if (!rp) return 1;

    png_infop ri = png_create_info_struct(rp);
    if (!ri) { png_destroy_read_struct(&rp, NULL, NULL); return 1; }

    if (setjmp(png_jmpbuf(rp))) {
        png_destroy_read_struct(&rp, &ri, NULL);
        return 1;
    }

    png_set_read_fn(rp, &g_png_buf, mem_read_fn);
    png_read_info(rp, ri);

    size_t rb = png_get_rowbytes(rp, ri);
    unsigned char *row = malloc(rb);

    for (png_uint_32 y = 0; y < IMG_HEIGHT; y++)
        png_read_row(rp, row, NULL);

    free(row);
    png_destroy_read_struct(&rp, &ri, NULL);
    return 0;
}

static int test_set_transforms(void) {
    g_png_buf.offset = 0;

    png_structp rp = png_create_read_struct(PNG_LIBPNG_VER_STRING,
                                             NULL, user_error_fn, user_warning_fn);
    if (!rp) return 1;

    png_infop ri = png_create_info_struct(rp);
    if (!ri) { png_destroy_read_struct(&rp, NULL, NULL); return 1; }

    if (setjmp(png_jmpbuf(rp))) {
        png_destroy_read_struct(&rp, &ri, NULL);
        return 1;
    }

    png_set_read_fn(rp, &g_png_buf, mem_read_fn);
    png_read_info(rp, ri);

    /* Apply various transforms before reading */
    png_set_expand(rp);
    png_set_strip_16(rp);
    png_set_gray_to_rgb(rp);
    png_set_add_alpha(rp, 0xFF, PNG_FILLER_AFTER);
    png_read_update_info(rp, ri);

    size_t rb = png_get_rowbytes(rp, ri);
    unsigned char *row = malloc(rb);

    for (png_uint_32 y = 0; y < IMG_HEIGHT; y++)
        png_read_row(rp, row, NULL);

    free(row);
    png_destroy_read_struct(&rp, &ri, NULL);
    return 0;
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    fprintf(stderr, "Target: %s at %s:%d\n", TARGET_FUNC, TARGET_FILE, TARGET_LINE);
    fprintf(stderr, "Entry path: %s\n", ENTRY_PATH);

    /* Create in-memory PNG for read tests */
    if (strcmp(ENTRY_PATH, "write_image") != 0) {
        if (create_test_png() != 0) {
            fprintf(stderr, "Failed to create test PNG\n");
            return 1;
        }
    }

    if (strcmp(ENTRY_PATH, "read_image") == 0) return test_read_image();
    if (strcmp(ENTRY_PATH, "write_image") == 0) return test_write_image();
    if (strcmp(ENTRY_PATH, "read_row") == 0) return test_read_row();
    if (strcmp(ENTRY_PATH, "set_transforms") == 0) return test_set_transforms();

    fprintf(stderr, "Unknown entry path: %s\n", ENTRY_PATH);
    free(g_png_buf.data);
    return 1;
}
