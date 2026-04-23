/*
 * Unified Validation Harness — curl
 *
 * Compile:
 *   gcc -fsanitize=address -g -O0 -w -I<curl_src>/include \
 *       harness_curl.c <curl_src>/lib/.libs/libcurl.a \
 *       -lm -lz -lpthread -ldl -lssl -lcrypto -o test_harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

/* ================================================================
 * BASELINE INPUT
 * ================================================================ */

#ifndef TARGET_FUNC
#define TARGET_FUNC  "Curl_http_header"
#define TARGET_FILE  "http.c"
#define TARGET_LINE  0
#endif

#ifndef ENTRY_PATH
#define ENTRY_PATH "easy_perform"
/* Options: "easy_perform", "url_parse", "mime", "header_parse" */
#endif

/* Input parameters (baseline provides these) */
#ifndef INPUT_URL
#define INPUT_URL "http://localhost:1/test"
#endif

#ifndef INPUT_URL_PARSE
#define INPUT_URL_PARSE "https://user:pass@example.com:8080/path?query=1&b=2#frag"
#endif

#ifndef INPUT_HEADER
#define INPUT_HEADER "Content-Type: text/html; charset=utf-8\r\n"
#endif

/* ================================================================
 * Write callback (discard response body)
 * ================================================================ */

static size_t discard_cb(void *ptr, size_t size, size_t nmemb, void *data) {
    (void)ptr; (void)data;
    return size * nmemb;
}

/* ================================================================
 * Entry path implementations
 * ================================================================ */

static int test_easy_perform(void) {
    CURL *curl = curl_easy_init();
    if (!curl) return 1;

    curl_easy_setopt(curl, CURLOPT_URL, INPUT_URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_cb);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 50L);

    /* Perform will likely fail (no server) but exercises the code path */
    CURLcode res = curl_easy_perform(curl);
    fprintf(stderr, "curl_easy_perform result: %d (%s)\n",
            res, curl_easy_strerror(res));

    curl_easy_cleanup(curl);
    return 0;
}

static int test_url_parse(void) {
    CURLU *url = curl_url();
    if (!url) return 1;

    CURLUcode uc = curl_url_set(url, CURLUPART_URL, INPUT_URL_PARSE, 0);
    if (uc != CURLUE_OK) {
        fprintf(stderr, "curl_url_set failed: %d\n", uc);
        curl_url_cleanup(url);
        return 1;
    }

    /* Extract each component */
    char *scheme = NULL, *host = NULL, *port = NULL;
    char *path = NULL, *query = NULL, *fragment = NULL;
    char *user = NULL, *password = NULL;

    curl_url_get(url, CURLUPART_SCHEME, &scheme, 0);
    curl_url_get(url, CURLUPART_HOST, &host, 0);
    curl_url_get(url, CURLUPART_PORT, &port, 0);
    curl_url_get(url, CURLUPART_PATH, &path, 0);
    curl_url_get(url, CURLUPART_QUERY, &query, 0);
    curl_url_get(url, CURLUPART_FRAGMENT, &fragment, 0);
    curl_url_get(url, CURLUPART_USER, &user, 0);
    curl_url_get(url, CURLUPART_PASSWORD, &password, 0);

    fprintf(stderr, "Parsed: scheme=%s host=%s port=%s path=%s\n",
            scheme ? scheme : "(null)",
            host ? host : "(null)",
            port ? port : "(null)",
            path ? path : "(null)");

    curl_free(scheme); curl_free(host); curl_free(port);
    curl_free(path); curl_free(query); curl_free(fragment);
    curl_free(user); curl_free(password);
    curl_url_cleanup(url);
    return 0;
}

static int test_mime(void) {
    CURL *curl = curl_easy_init();
    if (!curl) return 1;

    curl_mime *mime = curl_mime_init(curl);
    if (!mime) { curl_easy_cleanup(curl); return 1; }

    /* Add a data part */
    curl_mimepart *part = curl_mime_addpart(mime);
    curl_mime_name(part, "field1");
    curl_mime_data(part, "value1", CURL_ZERO_TERMINATED);

    /* Add a file-like part from memory */
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_filename(part, "test.txt");
    curl_mime_data(part, "file content here", CURL_ZERO_TERMINATED);
    curl_mime_type(part, "text/plain");

    /* Add a sub-part (nested multipart) */
    curl_mime *sub = curl_mime_init(curl);
    curl_mimepart *subpart = curl_mime_addpart(sub);
    curl_mime_name(subpart, "nested_field");
    curl_mime_data(subpart, "nested_value", CURL_ZERO_TERMINATED);

    part = curl_mime_addpart(mime);
    curl_mime_subparts(part, sub);

    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_URL, INPUT_URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_cb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 50L);

    /* Perform exercises mime encoding path */
    curl_easy_perform(curl);

    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    return 0;
}

static int test_header_parse(void) {
    CURL *curl = curl_easy_init();
    if (!curl) return 1;

    /* Set up custom headers to exercise header parsing */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, INPUT_HEADER);
    headers = curl_slist_append(headers, "X-Custom: test-value");
    headers = curl_slist_append(headers, "Accept: */*");

    curl_easy_setopt(curl, CURLOPT_URL, INPUT_URL);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_cb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 50L);

    curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return 0;
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    fprintf(stderr, "Target: %s at %s:%d\n", TARGET_FUNC, TARGET_FILE, TARGET_LINE);
    fprintf(stderr, "Entry path: %s\n", ENTRY_PATH);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    int rc = 1;
    if (strcmp(ENTRY_PATH, "easy_perform") == 0) rc = test_easy_perform();
    else if (strcmp(ENTRY_PATH, "url_parse") == 0) rc = test_url_parse();
    else if (strcmp(ENTRY_PATH, "mime") == 0) rc = test_mime();
    else if (strcmp(ENTRY_PATH, "header_parse") == 0) rc = test_header_parse();
    else fprintf(stderr, "Unknown entry path: %s\n", ENTRY_PATH);

    curl_global_cleanup();
    return rc;
}
