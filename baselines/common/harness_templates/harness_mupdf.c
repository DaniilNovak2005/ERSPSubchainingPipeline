/*
 * Unified Validation Harness — MuPDF
 *
 * Compile:
 *   gcc -fsanitize=address -g -O0 -w \
 *       -I<mupdf_src>/include \
 *       harness_mupdf.c \
 *       <mupdf_src>/build/release/libmupdf.a \
 *       <mupdf_src>/build/release/libmupdf-third.a \
 *       -lm -lpthread -ldl -o test_harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mupdf/fitz.h>

/* ================================================================
 * BASELINE INPUT
 * ================================================================ */

#ifndef TARGET_FUNC
#define TARGET_FUNC  "pdf_load_page"
#define TARGET_FILE  "pdf-page.c"
#define TARGET_LINE  0
#endif

#ifndef ENTRY_PATH
#define ENTRY_PATH "open_document"
/* Options: "open_document", "load_page", "pixmap_ops",
 *          "buffer_ops", "path_ops" */
#endif

/* Input parameters (baseline provides these) */
#ifndef INPUT_FILE
#define INPUT_FILE "/tmp/sailor_harness_mupdf.pdf"
#endif

#ifndef PIXMAP_WIDTH
#define PIXMAP_WIDTH 64
#endif

#ifndef PIXMAP_HEIGHT
#define PIXMAP_HEIGHT 64
#endif

/* ================================================================
 * Minimal PDF generator (for document tests)
 * ================================================================ */

static const char minimal_pdf[] =
    "%PDF-1.0\n"
    "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    "3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R"
    "/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
    "4 0 obj<</Length 44>>\nstream\n"
    "BT /F1 12 Tf 100 700 Td (Hello World) Tj ET\n"
    "endstream\nendobj\n"
    "5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
    "xref\n0 6\n"
    "0000000000 65535 f \n"
    "0000000009 00000 n \n"
    "0000000058 00000 n \n"
    "0000000115 00000 n \n"
    "0000000266 00000 n \n"
    "0000000360 00000 n \n"
    "trailer<</Size 6/Root 1 0 R>>\n"
    "startxref\n430\n%%EOF\n";

static int write_test_pdf(const char *path) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return 1;
    fwrite(minimal_pdf, 1, sizeof(minimal_pdf) - 1, fp);
    fclose(fp);
    return 0;
}

/* ================================================================
 * Library initialization
 * ================================================================ */

static fz_context *init_mupdf(void) {
    fz_context *ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
    if (!ctx) {
        fprintf(stderr, "Failed to create MuPDF context\n");
        return NULL;
    }
    fz_register_document_handlers(ctx);
    return ctx;
}

/* ================================================================
 * Entry path implementations
 * ================================================================ */

static int test_open_document(fz_context *ctx) {
    write_test_pdf(INPUT_FILE);

    fz_document *doc = NULL;
    fz_try(ctx) {
        doc = fz_open_document(ctx, INPUT_FILE);
        int pages = fz_count_pages(ctx, doc);
        fprintf(stderr, "Opened document: %d pages\n", pages);
    }
    fz_catch(ctx) {
        fprintf(stderr, "Error: %s\n", fz_caught_message(ctx));
        return 1;
    }

    fz_drop_document(ctx, doc);
    return 0;
}

static int test_load_page(fz_context *ctx) {
    write_test_pdf(INPUT_FILE);

    fz_document *doc = NULL;
    fz_page *page = NULL;

    fz_try(ctx) {
        doc = fz_open_document(ctx, INPUT_FILE);
        page = fz_load_page(ctx, doc, 0);

        /* Get page bounds */
        fz_rect bounds = fz_bound_page(ctx, page);
        fprintf(stderr, "Page bounds: %.0f x %.0f\n",
                bounds.x1 - bounds.x0, bounds.y1 - bounds.y0);

        /* Render to pixmap */
        fz_matrix ctm = fz_identity;
        fz_pixmap *pix = fz_new_pixmap_from_page(ctx, page, ctm,
                                                   fz_device_rgb(ctx), 0);
        fprintf(stderr, "Rendered: %d x %d\n", pix->w, pix->h);
        fz_drop_pixmap(ctx, pix);
    }
    fz_catch(ctx) {
        fprintf(stderr, "Error: %s\n", fz_caught_message(ctx));
    }

    fz_drop_page(ctx, page);
    fz_drop_document(ctx, doc);
    return 0;
}

static int test_pixmap_ops(fz_context *ctx) {
    fz_pixmap *pix = NULL;

    fz_try(ctx) {
        /* Create pixmap and manipulate it */
        pix = fz_new_pixmap(ctx, fz_device_rgb(ctx),
                             PIXMAP_WIDTH, PIXMAP_HEIGHT, NULL, 1);
        fz_clear_pixmap_with_value(ctx, pix, 0xFF);

        /* Access pixel data directly */
        unsigned char *samples = pix->samples;
        int stride = pix->stride;
        for (int y = 0; y < PIXMAP_HEIGHT; y++) {
            for (int x = 0; x < PIXMAP_WIDTH; x++) {
                int offset = y * stride + x * pix->n;
                samples[offset + 0] = (unsigned char)(x & 0xFF);  /* R */
                samples[offset + 1] = (unsigned char)(y & 0xFF);  /* G */
                samples[offset + 2] = 0;                           /* B */
                samples[offset + 3] = 0xFF;                        /* A */
            }
        }

        /* Gamma correction */
        fz_gamma_pixmap(ctx, pix, 2.2f);

        /* Invert */
        fz_invert_pixmap(ctx, pix);
    }
    fz_catch(ctx) {
        fprintf(stderr, "Error: %s\n", fz_caught_message(ctx));
        return 1;
    }

    fz_drop_pixmap(ctx, pix);
    return 0;
}

static int test_buffer_ops(fz_context *ctx) {
    fz_buffer *buf = NULL;

    fz_try(ctx) {
        /* Create and manipulate buffer */
        buf = fz_new_buffer(ctx, 256);

        /* Write various data */
        fz_append_string(ctx, buf, "Hello MuPDF buffer test\n");
        fz_append_byte(ctx, buf, 0x42);

        unsigned char data[128];
        memset(data, 'X', sizeof(data));
        fz_append_data(ctx, buf, data, sizeof(data));

        /* Read back */
        size_t len;
        unsigned char *ptr = fz_string_from_buffer(ctx, buf);
        fprintf(stderr, "Buffer contents start: %.20s\n", ptr);

        /* Resize operations */
        fz_resize_buffer(ctx, buf, 64);
        fz_trim_buffer(ctx, buf);
    }
    fz_catch(ctx) {
        fprintf(stderr, "Error: %s\n", fz_caught_message(ctx));
        return 1;
    }

    fz_drop_buffer(ctx, buf);
    return 0;
}

static int test_path_ops(fz_context *ctx) {
    fz_path *path = NULL;

    fz_try(ctx) {
        path = fz_new_path(ctx);

        /* Build a complex path */
        fz_moveto(ctx, path, 10.0f, 10.0f);
        fz_lineto(ctx, path, 100.0f, 10.0f);
        fz_lineto(ctx, path, 100.0f, 100.0f);
        fz_curveto(ctx, path, 75.0f, 120.0f, 50.0f, 120.0f, 25.0f, 100.0f);
        fz_closepath(ctx, path);

        /* Second subpath */
        fz_moveto(ctx, path, 30.0f, 30.0f);
        fz_lineto(ctx, path, 70.0f, 30.0f);
        fz_lineto(ctx, path, 70.0f, 70.0f);
        fz_lineto(ctx, path, 30.0f, 70.0f);
        fz_closepath(ctx, path);

        /* Transform the path */
        fz_matrix m = fz_rotate(45.0f);
        fz_transform_path(ctx, path, m);

        /* Get bounds */
        fz_rect bounds = fz_bound_path(ctx, path, NULL, fz_identity);
        fprintf(stderr, "Path bounds: [%.1f, %.1f, %.1f, %.1f]\n",
                bounds.x0, bounds.y0, bounds.x1, bounds.y1);

        /* Clone path */
        fz_path *clone = fz_clone_path(ctx, path);
        fz_drop_path(ctx, clone);
    }
    fz_catch(ctx) {
        fprintf(stderr, "Error: %s\n", fz_caught_message(ctx));
        return 1;
    }

    fz_drop_path(ctx, path);
    return 0;
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    fprintf(stderr, "Target: %s at %s:%d\n", TARGET_FUNC, TARGET_FILE, TARGET_LINE);
    fprintf(stderr, "Entry path: %s\n", ENTRY_PATH);

    fz_context *ctx = init_mupdf();
    if (!ctx) return 1;

    int rc = 1;
    if (strcmp(ENTRY_PATH, "open_document") == 0) rc = test_open_document(ctx);
    else if (strcmp(ENTRY_PATH, "load_page") == 0) rc = test_load_page(ctx);
    else if (strcmp(ENTRY_PATH, "pixmap_ops") == 0) rc = test_pixmap_ops(ctx);
    else if (strcmp(ENTRY_PATH, "buffer_ops") == 0) rc = test_buffer_ops(ctx);
    else if (strcmp(ENTRY_PATH, "path_ops") == 0) rc = test_path_ops(ctx);
    else fprintf(stderr, "Unknown entry path: %s\n", ENTRY_PATH);

    fz_drop_context(ctx);
    return rc;
}
