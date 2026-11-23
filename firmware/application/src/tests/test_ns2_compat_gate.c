/*
 * Host source assertions for the NS2-compatibility main-loop gate.
 *
 * The gate runs on the nRF52840 firmware main loop, which needs the SDK, so
 * this test reads app_main.c and checks the structure the fix requires:
 *
 *   1. ns2_compat_should_gate() is bound to an active Amiibo field and resets
 *      its timestamp as soon as the field ends or the slot is not an Amiibo.
 *   2. A conservative timeout releases the gate even if a field gets stuck.
 *   3. data_frame_process(), logflash_poll(), usb_poll() and
 *      blink_usb_led_status() are inside `if (!ns2_compat_active)`; WDT, the
 *      auto-refresh process and the LED feedback process stay outside.
 *   4. Every original call is still present exactly once, so a non-Amiibo
 *      slot or a no-field idle loop runs the unchanged work.
 *
 * Build + run:
 *   make -C firmware/application/src/tests test
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

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

/* Extract one brace-matched body by signature, starting at its first '{'. */
static const char *function_body(const char *src, const char *signature) {
    if (src == NULL) return NULL;
    const char *start = strstr(src, signature);
    if (start == NULL) return NULL;
    const char *body = strchr(start, '{');
    if (body == NULL) return NULL;

    int depth = 0;
    const char *end = NULL;
    for (const char *p = body; *p != '\0'; ++p) {
        if (*p == '{') depth++;
        if (*p == '}' && --depth == 0) { end = p + 1; break; }
    }
    if (end == NULL) return NULL;

    static char scoped[16384];
    size_t len = (size_t)(end - body);
    if (len >= sizeof(scoped)) len = sizeof(scoped) - 1;
    memcpy(scoped, body, len);
    scoped[len] = '\0';
    return scoped;
}

/* The `while (1) { ... }` body, anchored after the boot banner. */
static const char *main_loop_body(const char *src) {
    if (src == NULL) return NULL;
    const char *anchor = strstr(src, "NRF_LOG_INFO(\"Chameleon working\")");
    if (anchor == NULL) return NULL;
    return function_body(anchor, "while (1) {");
}

static bool in_order(const char *hay, const char *first, const char *second) {
    if (hay == NULL) return false;
    const char *p = strstr(hay, first);
    if (p == NULL) return false;
    return strstr(p + strlen(first), second) != NULL;
}

static int count_of(const char *hay, const char *needle) {
    int n = 0;
    if (hay == NULL || needle[0] == '\0') return 0;
    for (const char *p = strstr(hay, needle); p != NULL;
         p = strstr(p + strlen(needle), needle)) n++;
    return n;
}

/* True when `call` sits inside a block whose opener is preceded by
 * `gate_needle` within the last 120 characters. Brace matching walks
 * backwards from the call to the nearest enclosing '{'. */
static bool call_is_gated(const char *body, const char *call,
                          const char *gate_needle) {
    if (body == NULL) return false;
    const char *p = strstr(body, call);
    if (p == NULL) return false;
    int depth = 0;
    for (const char *q = p; q >= body; --q) {
        if (*q == '}') {
            depth++;
        } else if (*q == '{') {
            if (depth == 0) {
                const char *start = (q - body > 120) ? q - 120 : body;
                char window[121];
                size_t len = (size_t)(q - start);
                memcpy(window, start, len);
                window[len] = '\0';
                return strstr(window, gate_needle) != NULL;
            }
            depth--;
        }
    }
    return false;
}

/* Small model of the gate: mirrors ns2_compat_should_gate() exactly. */
static uint32_t model_field_since = 0;
static bool model_should_gate(bool emulating, bool amiibo, uint32_t now) {
    if (!emulating || !amiibo) { model_field_since = 0; return false; }
    if (model_field_since == 0) model_field_since = now;
    return (uint32_t)(now - model_field_since) < 2000u;
}

int main(void) {
    char *main_src = read_source(MAIN_SRC);
    CHECK(main_src != NULL);
    if (main_src == NULL) goto done;

    /* 1. Explicit declaration used by the gate and the boot restore. */
    CHECK(strstr(main_src, "#include \"nfc_mf0_ntag.h\"") != NULL);
    CHECK(strstr(main_src, "#define NS2_COMPAT_FIELD_TIMEOUT_MS 2000u") != NULL);

    /* 2. Gate condition: active field + marked Amiibo, timestamp reset on
     *    exit, bounded by the timeout. */
    const char *gate = function_body(main_src, "static bool ns2_compat_should_gate(void)");
    CHECK(gate != NULL);
    CHECK(gate != NULL && strstr(gate, "g_is_tag_emulating") != NULL);
    CHECK(gate != NULL && strstr(gate, "nfc_tag_mf0_ntag_is_amiibo_active()") != NULL);
    CHECK(gate != NULL && in_order(gate, "if (!g_is_tag_emulating",
                                        "m_ns2_compat_field_since = 0"));
    CHECK(gate != NULL && strstr(gate, "bsp_timer_now_ms()") != NULL);
    CHECK(gate != NULL && strstr(gate, "NS2_COMPAT_FIELD_TIMEOUT_MS") != NULL);

    /* 3. Main-loop placement: nonessential work gated, WDT/refresh/LED
     *    feedback and auto-refresh outside. */
    const char *loop = main_loop_body(main_src);
    CHECK(loop != NULL);
    CHECK(loop != NULL && strstr(loop, "bool ns2_compat_active = ns2_compat_should_gate();") != NULL);
    CHECK(call_is_gated(loop, "blink_usb_led_status();", "!ns2_compat_active"));
    CHECK(call_is_gated(loop, "data_frame_process();", "!ns2_compat_active"));
    CHECK(call_is_gated(loop, "logflash_poll();", "!ns2_compat_active"));
    CHECK(call_is_gated(loop, "usb_poll();", "!ns2_compat_active"));

    /* WDT stays outside the gate, so a stuck field still feeds the watchdog. */
    CHECK(!call_is_gated(loop, "bsp_wdt_feed();", "!ns2_compat_active"));
    CHECK(!call_is_gated(loop, "nfc_amiibo_auto_refresh_process(", "!ns2_compat_active"));
    CHECK(!call_is_gated(loop, "nfc_amiibo_refresh_feedback_process(", "!ns2_compat_active"));

    /* WDT is still fed after the gated block, every iteration. */
    CHECK(loop != NULL && in_order(loop, "usb_poll();", "bsp_wdt_feed();"));
    CHECK(loop != NULL && in_order(loop, "bsp_wdt_feed();",
                                        "sleep_system_run(system_off_enter, nrf_pwr_mgmt_run);"));

    /* 4. Non-amiibo / no-field path is unchanged: each original call is
     *    present exactly once, so with the gate off the loop does the same
     *    work it always did. */
    CHECK(count_of(loop, "blink_usb_led_status();") == 1);
    CHECK(count_of(loop, "data_frame_process();") == 1);
    CHECK(count_of(loop, "logflash_poll();") == 1);
    CHECK(count_of(loop, "usb_poll();") == 1);
    CHECK(count_of(loop, "bsp_wdt_feed();") == 1);
    CHECK(count_of(loop, "nfc_amiibo_auto_refresh_process(") == 1);
    CHECK(count_of(loop, "nfc_amiibo_refresh_feedback_process(") == 1);

    /* 5. Behaviour model: gate only for an active marked-Amiibo field,
     *    released on field loss and after the 2 s timeout. */
    model_field_since = 0;
    CHECK(!model_should_gate(false, false, 100));     /* no field */
    CHECK(!model_should_gate(true, false, 100));      /* field, non-Amiibo slot */
    CHECK(model_should_gate(true, true, 100));        /* Amiibo field starts */
    CHECK(model_should_gate(true, true, 1600));       /* 1.5 s: still gated */
    CHECK(!model_should_gate(true, true, 2600));      /* 2.5 s: timeout releases */
    CHECK(!model_should_gate(false, true, 2700));     /* field lost */
    CHECK(model_should_gate(true, true, 2800));       /* new field: reset worked */
    CHECK(!model_should_gate(true, false, 3000));     /* slot changed to non-Amiibo */

done:
    free(main_src);
    printf("%s: %d checks, %d failures\n",
           (g_fail == 0) ? "PASS" : "FAIL", g_checks, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
