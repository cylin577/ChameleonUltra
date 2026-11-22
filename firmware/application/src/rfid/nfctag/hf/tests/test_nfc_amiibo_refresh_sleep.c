/*
 * Host test for the shared "refresh then reset sleep" seam used by every
 * Amiibo UID refresh path (CMD 1070, auto-refresh hook, button action).
 * Refresh and sleep reset are injected, so no NFC hardware/SDK is needed.
 */
#include "../nfc_amiibo_refresh_sleep.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

typedef struct {
    int calls;
    bool persist_seen;
    bool uid_args_seen;
    uint16_t status;
    int order;
} refresh_stub_t;

static refresh_stub_t g_refresh;
static int g_sleep_calls;
static int g_step;

static uint16_t fake_refresh(bool persist, uint8_t old_uid[7], uint8_t new_uid[7]) {
    g_refresh.calls++;
    g_refresh.persist_seen = persist;
    if ((old_uid != NULL) && (new_uid != NULL)) {
        memset(old_uid, 0xA5, 7);
        memset(new_uid, 0x5A, 7);
        g_refresh.uid_args_seen = true;
    }
    g_refresh.order = ++g_step;
    return g_refresh.status;
}

static void fake_sleep_reset(void) {
    g_sleep_calls++;
    g_step++;
}

static void check_attempt(uint16_t status, bool persist) {
    uint8_t old_uid[7] = { 0 };
    uint8_t new_uid[7] = { 0 };
    memset(&g_refresh, 0, sizeof(g_refresh));
    g_refresh.status = status;
    g_sleep_calls = 0;
    g_step = 0;

    uint16_t result = nfc_amiibo_refresh_with_sleep_reset(
        fake_refresh, persist, old_uid, new_uid, fake_sleep_reset);

    CHECK(result == status);                 /* response/status unchanged */
    CHECK(g_refresh.calls == 1);
    CHECK(g_refresh.persist_seen == persist);
    CHECK(g_refresh.uid_args_seen);
    CHECK(g_sleep_calls == 1);               /* reset on every attempt */
    CHECK(g_refresh.order == 1 && g_step == 2); /* refresh before reset */
}

/* The production reset callback is static in nfc_amiibo_refresh_slot.c, so it
 * cannot be called from this header-only host test. Assert its wiring by
 * inspecting the source: the callback must use the configured sleep timeout,
 * never the fixed FIELD_NFC_LOST window. */
static void check_production_reset_wiring(void) {
    const char *path = "../nfc_amiibo_refresh_slot.c";
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    if (f == NULL) {
        return;
    }
    char line[256];
    bool uses_config = false;
    bool uses_fixed = false;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, "sleep_timer_start(settings_get_sleep_timeout())") != NULL) {
            uses_config = true;
        }
        if (strstr(line, "sleep_timer_start(SLEEP_DELAY_MS_FIELD_NFC_LOST)") != NULL) {
            uses_fixed = true;
        }
    }
    fclose(f);
    CHECK(uses_config);
    CHECK(!uses_fixed);
}

int main(void) {
    check_production_reset_wiring();

    /* Success path. */
    check_attempt(0x0000u, true);   /* STATUS_SUCCESS */
    check_attempt(0x0000u, false);

    /* Failure paths: reset still happens so feedback stays readable. */
    const uint16_t failures[] = {
        0x0012u,  /* STATUS_DEVICE_MODE_ERROR */
        0x0002u,  /* STATUS_PAR_ERR */
        0x0005u,  /* STATUS_FLASH_WRITE_FAIL */
        0x0031u,  /* STATUS_AMIIBO_KEYS_MISSING */
        0x0033u,  /* STATUS_AMIIBO_UID_INVALID */
        0x0034u,  /* STATUS_AMIIBO_UID_FAIL */
        0xFFFFu,  /* arbitrary failure */
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
        check_attempt(failures[i], true);
    }

    printf("test_nfc_amiibo_refresh_sleep: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
