/*
 * Host test for the shared Amiibo UID refresh feedback wrapper.
 *
 * Refresh, sleep reset and both status LEDs are injected, so no hardware,
 * crypto or FDS is used. Covers: one OK blink on success, one error blink for
 * every failure status, exactly one blink per attempt, and no blink from the
 * ISR-safe field/command edges (only the main-loop process() path refreshes).
 */
#include "../nfc_amiibo_refresh_sleep.h"
#include "../nfc_amiibo_refresh_feedback.h"
#include "../nfc_amiibo_auto_refresh.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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
static int g_ok_calls;
static int g_error_calls;
static int g_blink_order;
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

static void fake_ok(void) {
    g_ok_calls++;
    g_blink_order = ++g_step;
}

static void fake_error(void) {
    g_error_calls++;
    g_blink_order = ++g_step;
}

static void reset_world(uint16_t status) {
    memset(&g_refresh, 0, sizeof(g_refresh));
    g_refresh.status = status;
    g_sleep_calls = 0;
    g_ok_calls = 0;
    g_error_calls = 0;
    g_blink_order = 0;
    g_step = 0;
}

static void check_attempt(uint16_t status, bool persist, bool expect_ok) {
    uint8_t old_uid[7] = { 0 };
    uint8_t new_uid[7] = { 0 };
    reset_world(status);

    uint16_t result = nfc_amiibo_refresh_with_feedback(
        fake_refresh, persist, old_uid, new_uid, fake_sleep_reset,
        fake_ok, fake_error);

    CHECK(result == status);                     /* response/status unchanged */
    CHECK(g_refresh.calls == 1);
    CHECK(g_refresh.persist_seen == persist);
    CHECK(g_refresh.uid_args_seen);
    CHECK(g_sleep_calls == 1);                   /* sleep still re-armed */
    CHECK(g_ok_calls + g_error_calls == 1);      /* exactly one blink */
    if (expect_ok) {
        CHECK(g_ok_calls == 1 && g_error_calls == 0);
    } else {
        CHECK(g_ok_calls == 0 && g_error_calls == 1);
    }
    CHECK(g_refresh.order == 1 && g_blink_order == 3 && g_step == 3);
}

/* Adapter: the auto-refresh core supplies (slot, persist, uid); route it
 * through the same shared wrapper so all three paths are covered. */
static nfc_amiibo_uid_refresh_status_t auto_refresh_via_wrapper(
    uint8_t slot, bool persist, uint8_t uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE]) {
    (void)slot;
    uint8_t old_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE] = { 0 };
    uint16_t status = nfc_amiibo_refresh_with_feedback(
        fake_refresh, persist, old_uid, uid, fake_sleep_reset,
        fake_ok, fake_error);
    return status == STATUS_SUCCESS ? NFC_AMIIBO_UID_REFRESH_OK
                                    : NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR;
}

static void check_isr_edges_do_not_blink(void) {
    reset_world(STATUS_SUCCESS);
    nfc_amiibo_auto_refresh_init();
    nfc_amiibo_auto_refresh_set_refresh_fn(auto_refresh_via_wrapper);
    nfc_amiibo_auto_refresh_arm(2, false);

    /* ISR-safe field/command edges only record state. */
    nfc_amiibo_auto_refresh_on_field(true, 1000);
    nfc_amiibo_auto_refresh_on_command(0x1Bu);
    nfc_amiibo_auto_refresh_on_field(false, 1020);
    CHECK(g_refresh.calls == 0);
    CHECK(g_ok_calls + g_error_calls == 0);
    CHECK(g_sleep_calls == 0);

    /* Only the main-loop process() refresh blinks, exactly once. */
    CHECK(!nfc_amiibo_auto_refresh_process(1119));  /* loss not yet stable */
    CHECK(g_ok_calls + g_error_calls == 0);
    CHECK(nfc_amiibo_auto_refresh_process(1120));
    CHECK(g_refresh.calls == 1);
    CHECK(g_ok_calls == 1 && g_error_calls == 0);
    CHECK(g_sleep_calls == 1);
    CHECK(!nfc_amiibo_auto_refresh_process(2000));
    CHECK(g_refresh.calls == 1);
    CHECK(g_ok_calls + g_error_calls == 1);
}

/* ---- Command path: deferred feedback, no busy-wait --------------------- */

static bool file_contains(const char *path, const char *needle) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return false;
    }
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, needle) != NULL) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

static void check_command_path_wiring(void) {
    /* CMD 1070 must bind the deferred request helpers, never the blocking
     * offline_status_* blink (140 ms busy-wait before the response). */
    CHECK(file_contains("../../../../app_main.c",
                        "nfc_amiibo_refresh_set_status_led(refresh_feedback_ok, refresh_feedback_error)"));
    CHECK(file_contains("../../../../app_main.c",
                        "nfc_amiibo_refresh_feedback_request(&m_amiibo_refresh_fb,"));
    CHECK(file_contains("../../../../app_main.c",
                        "nfc_amiibo_refresh_feedback_process(&m_amiibo_refresh_fb,"));
    CHECK(!file_contains("../../../../app_main.c",
                         "nfc_amiibo_refresh_set_status_led(offline_status_ok, offline_status_error)"));
    CHECK(!file_contains("../../../../app_main.c",
                         "nfc_amiibo_auto_refresh_arm_blinks(offline_status_ok)"));
    CHECK(!file_contains("../../../../app_main.c",
                         "nfc_amiibo_auto_refresh_disarm_blinks(offline_status_error)"));
    /* CMD 1071 arm/disarm still request exactly one feedback each. */
    CHECK(file_contains("../../../../app_cmd.c", "nfc_amiibo_auto_refresh_arm_led();"));
    CHECK(file_contains("../../../../app_cmd.c", "nfc_amiibo_auto_refresh_disarm_led();"));
    /* All-slot arming: no slot-mismatch disarm in the CMD hook or in the HF
     * slot-data load callback. */
    CHECK(!file_contains("../../../../app_cmd.c", "tag_emulation_get_slot() != slot"));
    CHECK(!file_contains("../nfc_mf0_ntag.c", "nfc_amiibo_auto_refresh_disarm();"));
}

static nfc_amiibo_refresh_feedback_state_t g_deferred_state;

static void deferred_ok(void) {
    nfc_amiibo_refresh_feedback_request(&g_deferred_state,
                                        NFC_AMIIBO_REFRESH_FB_REFRESH_OK, 0u);
}

static void deferred_error(void) {
    nfc_amiibo_refresh_feedback_request(&g_deferred_state,
                                        NFC_AMIIBO_REFRESH_FB_REFRESH_ERROR, 0u);
}

static double elapsed_ms(clock_t a, clock_t b) {
    return (double)(b - a) * 1000.0 / CLOCKS_PER_SEC;
}

/* The feedback callbacks used by the command path must only stamp state:
 * no LED loop, no bsp_delay_ms(), no measurable wait before the response. */
static void check_feedback_is_low_delay(void) {
    uint8_t old_uid[7] = { 0 };
    uint8_t new_uid[7] = { 0 };
    memset(&g_deferred_state, 0, sizeof(g_deferred_state));
    reset_world(STATUS_SUCCESS);
    clock_t t0 = clock();
    uint16_t result = nfc_amiibo_refresh_with_feedback(
        fake_refresh, true, old_uid, new_uid, fake_sleep_reset,
        deferred_ok, deferred_error);
    clock_t t1 = clock();
    CHECK(result == STATUS_SUCCESS);           /* response/status unchanged */
    CHECK(g_ok_calls == 0 && g_error_calls == 0);  /* not the blocking hook */
    CHECK(g_deferred_state.kind == NFC_AMIIBO_REFRESH_FB_REFRESH_OK);
    CHECK(elapsed_ms(t0, t1) < 2.0);            /* < 2 ms, not ~140 ms */
}

int main(void) {
    check_command_path_wiring();
    check_feedback_is_low_delay();

    check_attempt(STATUS_SUCCESS, true, true);
    check_attempt(STATUS_SUCCESS, false, true);

    /* Every failure status blinks error exactly once, sleep still re-armed. */
    const uint16_t failures[] = {
        STATUS_DEVICE_MODE_ERROR,
        STATUS_PAR_ERR,
        STATUS_NOT_IMPLEMENTED,
        STATUS_FLASH_WRITE_FAIL,
        STATUS_INVALID_SLOT_TYPE,
        STATUS_AMIIBO_KEYS_MISSING,
        STATUS_AMIIBO_KEYS_INVALID,
        STATUS_AMIIBO_UID_INVALID,
        STATUS_AMIIBO_UID_FAIL,
        0xFFFFu,  /* arbitrary failure */
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
        check_attempt(failures[i], true, false);
        check_attempt(failures[i], false, false);
    }

    check_isr_edges_do_not_blink();

    printf("test_nfc_amiibo_refresh_feedback: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
