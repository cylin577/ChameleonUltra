/*
 * Host source assertions for the tag-emulation startup reload and the
 * FDS idle-GC guard (watchdog/DFU fix).
 *
 * The real paths need the nRF52 NFCT/FDS peripherals, so they cannot be
 * linked on the host. This test reads the two firmware sources and checks
 * the exact structure the fix requires:
 *
 *   1. tag_mode_enter() calls tag_emulation_load_data() before
 *      tag_emulation_sense_run(), reproducing CMD 2020 sniff-mode's fresh
 *      slot-data reload without enabling capture.
 *   2. fds_idle_gc_maybe() bails out while g_is_tag_emulating is true, so a
 *      multi-second fds_gc_sync() busy-wait cannot stall an NFC scan and
 *      trigger a watchdog reset (which drops the device into DFU).
 *
 * Build + run:
 *   make -C firmware/application/src/tests test
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

#define RFID_SRC "../rfid_main.c"
#define MAIN_SRC "../app_main.c"

static char *read_source(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        printf("FAIL cannot open %s\n", path);
        g_fail++;
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = (char *)malloc((size_t)n + 1);
    if (buf == NULL) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

/* Restrict a search to one function body: from its definition to the next
 * top-level 'void ' / 'static void ' definition in that source file. */
static const char *function_body(const char *src, const char *signature) {
    if (src == NULL) return NULL;
    const char *start = strstr(src, signature);
    if (start == NULL) return NULL;
    const char *body = strchr(start, '{');
    if (body == NULL) return NULL;

    const char *end = strstr(body, "\nvoid ");
    const char *end2 = strstr(body, "\nstatic void ");
    if (end == NULL || (end2 != NULL && end2 < end)) end = end2;
    /* app_main.c has static helper definitions between functions; clamp there. */
    const char *end3 = strstr(body, "\nstatic ");
    if (end3 != NULL && (end == NULL || end3 < end)) end = end3;
    if (end == NULL) end = body + strlen(body);

    static char scoped[16384];
    size_t len = (size_t)(end - body);
    if (len >= sizeof(scoped)) len = sizeof(scoped) - 1;
    memcpy(scoped, body, len);
    scoped[len] = '\0';
    return scoped;
}

static bool in_order(const char *hay, const char *first, const char *second) {
    if (hay == NULL) return false;
    const char *p = strstr(hay, first);
    if (p == NULL) return false;
    return strstr(p + strlen(first), second) != NULL;
}

int main(void) {
    char *rfid = read_source(RFID_SRC);
    char *main_src = read_source(MAIN_SRC);

    /* 1. tag_mode_enter(): fresh slot-data reload immediately before sense. */
    const char *body = function_body(rfid, "void tag_mode_enter(void)");
    CHECK(body != NULL);
    CHECK(in_order(body, "tag_emulation_load_data();", "tag_emulation_sense_run();"));
    CHECK(strstr(body, "tag_emulation_load_data();") != NULL);
    CHECK(strstr(body, "tag_emulation_sense_run();") != NULL);

    /* 2. fds_idle_gc_maybe(): guard active emulating before GC, no scheduler
     *    refactor and no change to the GC trigger itself. */
    body = function_body(main_src, "static void fds_idle_gc_maybe(void)");
    CHECK(body != NULL);
    CHECK(in_order(body, "if (g_is_tag_emulating)", "fds_gc_sync();"));
    CHECK(strstr(body, "if (g_is_tag_emulating) return;") != NULL);
    CHECK(strstr(body, "fds_idle_gc_maybe();") == NULL); /* not called from itself */

    /* 3. logflash_poll() must remain untouched: it issues async fstorage ops
     *    and returns immediately when busy (no multi-second stall path). */
    body = function_body(main_src, "int main(void)");
    CHECK(body != NULL);
    CHECK(strstr(body, "logflash_poll();") != NULL);
    CHECK(!in_order(body, "if (g_is_tag_emulating)", "logflash_poll();"));

    free(rfid);
    free(main_src);
    printf("%s: %d checks, %d failures\n",
           (g_fail == 0) ? "PASS" : "FAIL", g_checks, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
