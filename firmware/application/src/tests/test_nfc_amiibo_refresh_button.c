/*
 * Host test for the "Refresh amiibo UID now" button action.
 *
 * The real decision logic from nfc_amiibo_refresh_button.h is compiled with
 * an injected refresh callback, so no NFC hardware, crypto or FDS is used.
 * LED feedback lives in the shared refresh wrapper (tested separately); this
 * test only checks that the helper triggers exactly one refresh attempt.
 */
#include "../nfc_amiibo_refresh_button.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

typedef struct {
    int      calls;
    bool     persist_seen;
    bool     uid_args_seen;
    uint16_t status;
} refresh_stub_t;

static refresh_stub_t g_refresh;

static uint16_t fake_refresh(bool persist, uint8_t old_uid[7], uint8_t new_uid[7]) {
    g_refresh.calls++;
    g_refresh.persist_seen = persist;
    if ((old_uid != NULL) && (new_uid != NULL)) {
        memset(old_uid, 0xA5, 7);
        memset(new_uid, 0x5A, 7);
        g_refresh.uid_args_seen = true;
    }
    return g_refresh.status;
}

static void reset_world(uint16_t status) {
    memset(&g_refresh, 0, sizeof(g_refresh));
    g_refresh.status = status;
}

int main(void) {
    /* Field generator on: skip the refresh entirely (no feedback either). */
    reset_world(STATUS_SUCCESS);
    nfc_amiibo_refresh_button_run(true, fake_refresh);
    CHECK(g_refresh.calls == 0);

    /* Field off: exactly one refresh with persist=true and both UID buffers. */
    reset_world(STATUS_SUCCESS);
    nfc_amiibo_refresh_button_run(false, fake_refresh);
    CHECK(g_refresh.calls == 1);
    CHECK(g_refresh.persist_seen);
    CHECK(g_refresh.uid_args_seen);

    /* Any refresh status: still exactly one attempt, the wrapper handles it. */
    const uint16_t failures[] = {
        STATUS_DEVICE_MODE_ERROR,
        STATUS_PAR_ERR,
        STATUS_NOT_IMPLEMENTED,
        STATUS_FLASH_WRITE_FAIL,
        STATUS_AMIIBO_KEYS_MISSING,
        STATUS_AMIIBO_UID_INVALID,
        STATUS_AMIIBO_UID_FAIL,
        0u,
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
        reset_world(failures[i]);
        nfc_amiibo_refresh_button_run(false, fake_refresh);
        CHECK(g_refresh.calls == 1);
        CHECK(g_refresh.persist_seen);
    }

    printf("test_nfc_amiibo_refresh_button: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
