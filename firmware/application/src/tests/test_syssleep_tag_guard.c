/*
 * Host source assertions for the tag-emulation sleep guard in syssleep.c.
 *
 * The real sleep path needs the nRF52 SoftDevice, so this test reads the
 * firmware sources and checks the structure the fix requires:
 *
 *   1. sleep_system_run() returns immediately while g_is_tag_emulating is
 *      true, so nrf_pwr_mgmt_run() -> sd_app_evt_wait() cannot add wake
 *      jitter to NFCT ATQA/anticollision replies.
 *   2. The system-off branch, the system-on branch and the sleep_timer_start()
 *      USB/BLE/tag/field guards are all still intact.
 *   3. The NFCT IRQ priority is left at its existing value and the main loop
 *      still calls sleep_system_run() in the same place.
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

#define SYSLEEP_SRC "../utils/syssleep.c"
#define MAIN_SRC "../app_main.c"
#define SDK_CONFIG "../sdk_config.h"

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

/* Extract one function body by brace matching, from its first '{'. */
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

    static char scoped[8192];
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

static int count_of(const char *hay, const char *needle) {
    int n = 0;
    if (hay == NULL || needle[0] == '\0') return 0;
    for (const char *p = strstr(hay, needle); p != NULL;
         p = strstr(p + strlen(needle), needle)) n++;
    return n;
}

/* Small model of the guard: no sleep call at all while emulating. */
typedef struct { int off; int on; } sleep_counts_t;

static void sleep_run_model(bool emulating, bool off_pending, sleep_counts_t *s) {
    if (emulating) return;
    if (off_pending) s->off++;
    else s->on++;
}

int main(void) {
    char *syssleep = read_source(SYSLEEP_SRC);
    char *main_src = read_source(MAIN_SRC);
    char *sdk_config = read_source(SDK_CONFIG);

    /* 1. g_is_tag_emulating is already declared; no new include needed. */
    CHECK(strstr(syssleep, "extern bool g_is_tag_emulating;") != NULL);

    /* 2. The guard is the first statement and skips both sleep paths. */
    const char *run_body = function_body(syssleep, "void sleep_system_run(");
    CHECK(run_body != NULL);
    CHECK(in_order(run_body, "if (g_is_tag_emulating)", "return;"));
    CHECK(in_order(run_body, "return;", "if (m_system_off_enter)"));
    CHECK(in_order(run_body, "return;", "sysOnSleep();"));

    /* 3. Other sleep branches and the timer guards remain intact. */
    CHECK(in_order(run_body, "if (m_system_off_enter)", "sysOffSleep();"));
    CHECK(strstr(run_body, "sysOnSleep();") != NULL);
    CHECK(count_of(run_body, "sysOffSleep();") == 1);
    CHECK(count_of(run_body, "sysOnSleep();") == 1);

    const char *start_body = function_body(syssleep, "void sleep_timer_start(");
    CHECK(start_body != NULL);
    CHECK(strstr(start_body, "NRFX_POWER_USB_STATE_DISCONNECTED") != NULL);
    CHECK(strstr(start_body,
                 "g_is_ble_connected == false && g_is_tag_emulating == false && m_is_field_on == false") != NULL);
    CHECK(strstr(start_body, "app_timer_start(") != NULL);

    /* 4. Optional NFCT IRQ priority change intentionally not applied. */
    CHECK(strstr(sdk_config, "#define NRFX_NFCT_CONFIG_IRQ_PRIORITY 6") != NULL);
    CHECK(strstr(sdk_config, "#define NRFX_NFCT_CONFIG_IRQ_PRIORITY 2") == NULL);

    /* 5. Main loop call site / ordering untouched. */
    CHECK(main_src != NULL);
    CHECK(strstr(main_src, "sleep_system_run(system_off_enter, nrf_pwr_mgmt_run);") != NULL);
    CHECK(in_order(main_src, "data_frame_process();",
                   "sleep_system_run(system_off_enter, nrf_pwr_mgmt_run);"));

    /* 6. Model: emulating never sleeps; every other state sleeps as before. */
    sleep_counts_t s = {0, 0};
    sleep_run_model(true, false, &s);
    sleep_run_model(true, true, &s);
    CHECK(s.off == 0 && s.on == 0);
    sleep_run_model(false, true, &s);
    CHECK(s.off == 1 && s.on == 0);
    sleep_run_model(false, false, &s);
    CHECK(s.off == 1 && s.on == 1);

    free(syssleep);
    free(main_src);
    free(sdk_config);
    printf("%s: %d checks, %d failures\n",
           (g_fail == 0) ? "PASS" : "FAIL", g_checks, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
