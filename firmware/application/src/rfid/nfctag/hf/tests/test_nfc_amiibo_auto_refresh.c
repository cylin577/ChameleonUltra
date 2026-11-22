/*
 * Native unit tests for the hardware-free nfc_amiibo_auto_refresh core.
 * Build + run:  make -C firmware/application/src/rfid/nfctag/hf/tests test
 */
#include "../nfc_amiibo_auto_refresh.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

#define CMD_PWD_AUTH  0x1Bu
#define CMD_READ      0x30u
#define CMD_FAST_READ 0x3Au

/* ---- injected refresh hook / fake clock ------------------------------- */
static unsigned g_calls;
static uint8_t  g_slot;
static bool     g_persist;
static bool     g_busy_inside_hook;
static nfc_amiibo_uid_refresh_status_t g_status;
static uint8_t g_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE];

static nfc_amiibo_uid_refresh_status_t fake_refresh(
    uint8_t slot, bool persist, uint8_t uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE]) {
    g_calls++;
    g_slot = slot;
    g_persist = persist;
    g_busy_inside_hook = nfc_amiibo_auto_refresh_is_busy();
    memcpy(uid, g_uid, NFC_AMIIBO_UID_REFRESH_UID_SIZE);
    return g_status;
}

static void reset(void) {
    memset(g_uid, 0, sizeof(g_uid));
    g_uid[0] = 0x04;
    g_uid[6] = 0x42;
    g_status = NFC_AMIIBO_UID_REFRESH_OK;
    g_calls = 0;
    g_slot = 0;
    g_persist = false;
    g_busy_inside_hook = false;
    nfc_amiibo_auto_refresh_init();
    nfc_amiibo_auto_refresh_set_refresh_fn(fake_refresh);
}

static uint8_t last_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE];

/* ---- tests ------------------------------------------------------------ */
static void test_short_field_ignored(void) {
    reset();
    nfc_amiibo_auto_refresh_arm(3, true);
    nfc_amiibo_auto_refresh_on_field(true, 100);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH); /* qualifying activity */
    nfc_amiibo_auto_refresh_on_field(false, 119); /* 19 ms < 20 ms */
    CHECK(!nfc_amiibo_auto_refresh_scan_pending());
    CHECK(!nfc_amiibo_auto_refresh_process(500));
    CHECK(g_calls == 0);
    CHECK(nfc_amiibo_auto_refresh_scan_count() == 0);
}

static void test_stable_loss_triggers_once(void) {
    reset();
    nfc_amiibo_auto_refresh_arm(1, false);
    nfc_amiibo_auto_refresh_on_field(true, 1000);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 1020); /* exactly 20 ms */
    CHECK(nfc_amiibo_auto_refresh_scan_pending());

    CHECK(!nfc_amiibo_auto_refresh_process(1119)); /* 99 ms of loss */
    CHECK(g_calls == 0);
    CHECK(nfc_amiibo_auto_refresh_process(1120));   /* exactly 100 ms */
    CHECK(g_calls == 1);
    CHECK(g_slot == 1 && !g_persist);
    CHECK(g_busy_inside_hook);
    CHECK(!nfc_amiibo_auto_refresh_is_busy());
    CHECK(nfc_amiibo_auto_refresh_scan_count() == 1);
    CHECK(nfc_amiibo_auto_refresh_last_status() == NFC_AMIIBO_UID_REFRESH_OK);
    nfc_amiibo_auto_refresh_last_uid(last_uid);
    CHECK(memcmp(last_uid, g_uid, sizeof(last_uid)) == 0);
    CHECK(nfc_amiibo_auto_refresh_session_refreshed());
    CHECK(nfc_amiibo_auto_refresh_activity_byte() == 0x80u);

    /* Repeated process() in the same session never refreshes twice. */
    CHECK(!nfc_amiibo_auto_refresh_process(2000));
    CHECK(g_calls == 1);
    CHECK(nfc_amiibo_auto_refresh_scan_count() == 1);
}

static void test_field_return_cancels_pending(void) {
    reset();
    nfc_amiibo_auto_refresh_arm(2, false);
    nfc_amiibo_auto_refresh_on_field(true, 0);
    nfc_amiibo_auto_refresh_on_command(CMD_READ);
    nfc_amiibo_auto_refresh_on_command(CMD_READ);
    nfc_amiibo_auto_refresh_on_field(false, 50);
    CHECK(nfc_amiibo_auto_refresh_scan_pending());

    nfc_amiibo_auto_refresh_on_field(true, 80);
    CHECK(!nfc_amiibo_auto_refresh_scan_pending());
    CHECK(nfc_amiibo_auto_refresh_field_present());
    CHECK(!nfc_amiibo_auto_refresh_process(500));
    CHECK(g_calls == 0);
}

static void test_busy_blocks_mark_and_consume(void) {
    reset();
    nfc_amiibo_auto_refresh_arm(4, false);

    /* Busy at FIELD_LOST: no pending scan is marked at all. */
    nfc_amiibo_auto_refresh_set_busy(true);
    nfc_amiibo_auto_refresh_on_field(true, 0);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 50);
    CHECK(!nfc_amiibo_auto_refresh_scan_pending());
    CHECK(!nfc_amiibo_auto_refresh_process(500));
    nfc_amiibo_auto_refresh_set_busy(false);

    /* Free again: a fresh session produces a pending scan. */
    nfc_amiibo_auto_refresh_on_field(true, 600);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 650);
    CHECK(nfc_amiibo_auto_refresh_scan_pending());

    /* Busy at process() time: the pending scan is not consumed. */
    nfc_amiibo_auto_refresh_set_busy(true);
    CHECK(!nfc_amiibo_auto_refresh_process(1000));
    CHECK(nfc_amiibo_auto_refresh_scan_pending());
    CHECK(g_calls == 0);
    nfc_amiibo_auto_refresh_set_busy(false);
    CHECK(nfc_amiibo_auto_refresh_process(1000));
    CHECK(g_calls == 1);
}

static void test_arm_slot_disarm(void) {
    reset();
    /* Disarmed: field activity never triggers a refresh. */
    CHECK(!nfc_amiibo_auto_refresh_is_armed());
    nfc_amiibo_auto_refresh_on_field(true, 0);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 50);
    CHECK(!nfc_amiibo_auto_refresh_process(500));
    CHECK(g_calls == 0);

    nfc_amiibo_auto_refresh_arm(7, true);
    CHECK(nfc_amiibo_auto_refresh_is_armed());
    CHECK(nfc_amiibo_auto_refresh_slot() == 7);
    CHECK(nfc_amiibo_auto_refresh_persist());
    CHECK(nfc_amiibo_auto_refresh_process(500));
    CHECK(g_calls == 1 && g_slot == 7 && g_persist);

    /* Disarm clears any pending scan for the next session. */
    nfc_amiibo_auto_refresh_on_field(true, 2000);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 2050);
    CHECK(nfc_amiibo_auto_refresh_scan_pending());
    nfc_amiibo_auto_refresh_disarm();
    CHECK(!nfc_amiibo_auto_refresh_is_armed());
    CHECK(!nfc_amiibo_auto_refresh_scan_pending());
    CHECK(!nfc_amiibo_auto_refresh_process(3000));
    CHECK(g_calls == 1);

    /* Re-arm with a new slot/persist value works. */
    nfc_amiibo_auto_refresh_arm(9, false);
    nfc_amiibo_auto_refresh_on_field(true, 4000);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 4050);
    CHECK(nfc_amiibo_auto_refresh_process(4200));
    CHECK(g_calls == 2 && g_slot == 9 && !g_persist);
}

/* All-slot arming passes the sentinel through to the hook unchanged: the hook
 * resolves the real active slot at refresh time, so a slot switch cannot
 * disarm the detector. */
static void test_all_slot_arm_passes_sentinel(void) {
    reset();
    CHECK(!nfc_amiibo_auto_refresh_is_armed());
    nfc_amiibo_auto_refresh_arm(NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL, true);
    CHECK(nfc_amiibo_auto_refresh_is_armed());
    CHECK(nfc_amiibo_auto_refresh_slot() == NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL);

    nfc_amiibo_auto_refresh_on_field(true, 0);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 50);
    CHECK(nfc_amiibo_auto_refresh_process(200));
    CHECK(g_calls == 1);
    CHECK(g_slot == NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL);
    CHECK(g_persist);
    CHECK(nfc_amiibo_auto_refresh_is_armed());  /* still armed after refresh */
}

static void test_last_status_and_new_session_guard(void) {
    reset();
    nfc_amiibo_auto_refresh_arm(5, true);
    g_status = NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR;

    nfc_amiibo_auto_refresh_on_field(true, 0);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 50);
    CHECK(nfc_amiibo_auto_refresh_process(200));
    CHECK(g_calls == 1);
    CHECK(nfc_amiibo_auto_refresh_last_status() ==
          NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR);

    /* Repeated FIELD_LOST (bounce) with no new FIELD_DETECTED: no refresh. */
    nfc_amiibo_auto_refresh_on_field(false, 300);
    CHECK(!nfc_amiibo_auto_refresh_process(500));
    CHECK(g_calls == 1);

    /* A new field session clears the one-refresh-per-session guard, but still
     * needs its own qualifying command activity. */
    nfc_amiibo_auto_refresh_on_field(true, 1000);
    CHECK(!nfc_amiibo_auto_refresh_session_refreshed());
    nfc_amiibo_auto_refresh_on_field(false, 1050);
    CHECK(!nfc_amiibo_auto_refresh_scan_pending());
    CHECK(!nfc_amiibo_auto_refresh_process(1200));
    CHECK(g_calls == 1);

    nfc_amiibo_auto_refresh_on_field(true, 2000);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 2050);
    CHECK(nfc_amiibo_auto_refresh_process(2200));
    CHECK(g_calls == 2);
}

static void test_saturating_count(void) {
    reset();
    nfc_amiibo_auto_refresh_set_scan_count(UINT32_MAX - 1);
    nfc_amiibo_auto_refresh_arm(6, false);

    nfc_amiibo_auto_refresh_on_field(true, 0);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 50);
    CHECK(nfc_amiibo_auto_refresh_process(200));
    CHECK(nfc_amiibo_auto_refresh_scan_count() == UINT32_MAX);

    nfc_amiibo_auto_refresh_on_field(true, 1000);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 1050);
    CHECK(nfc_amiibo_auto_refresh_process(1200));
    CHECK(g_calls == 2);
    CHECK(nfc_amiibo_auto_refresh_scan_count() == UINT32_MAX);
}

/* The field callback feeds ms derived from the 24-bit RTC clock, which wraps
 * every ~1024000 ms. Unsigned subtraction in the core must stay correct. */
static void test_callback_ms_clock_wrap(void) {
    reset();
    nfc_amiibo_auto_refresh_arm(2, true);
    uint32_t wrap = 1024000u;
    nfc_amiibo_auto_refresh_on_field(true, wrap - 100);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, wrap - 80);   /* 20 ms held */
    CHECK(nfc_amiibo_auto_refresh_scan_pending());
    CHECK(!nfc_amiibo_auto_refresh_process(wrap + 19));   /* 99 ms of loss */
    CHECK(g_calls == 0);
    CHECK(nfc_amiibo_auto_refresh_process(wrap + 20));    /* 100 ms of loss */
    CHECK(g_calls == 1 && g_slot == 2 && g_persist);
}

/* Command activity gate: a bare field is not enough. */
static void test_command_activity_gate(void) {
    /* Field only: no refresh. */
    reset();
    nfc_amiibo_auto_refresh_arm(1, false);
    nfc_amiibo_auto_refresh_on_field(true, 1000);
    nfc_amiibo_auto_refresh_on_field(false, 1020);
    CHECK(!nfc_amiibo_auto_refresh_scan_pending());
    CHECK(!nfc_amiibo_auto_refresh_process(1200));
    CHECK(g_calls == 0);
    CHECK(nfc_amiibo_auto_refresh_activity_byte() == 0u);

    /* One READ: still not enough. */
    reset();
    nfc_amiibo_auto_refresh_arm(1, false);
    nfc_amiibo_auto_refresh_on_field(true, 1000);
    nfc_amiibo_auto_refresh_on_command(CMD_READ);
    nfc_amiibo_auto_refresh_on_field(false, 1020);
    CHECK(!nfc_amiibo_auto_refresh_scan_pending());
    CHECK(!nfc_amiibo_auto_refresh_process(1200));
    CHECK(g_calls == 0);
    CHECK(nfc_amiibo_auto_refresh_activity_byte() == 1u);

    /* Two READs: trigger. */
    reset();
    nfc_amiibo_auto_refresh_arm(1, false);
    nfc_amiibo_auto_refresh_on_field(true, 1000);
    nfc_amiibo_auto_refresh_on_command(CMD_READ);
    nfc_amiibo_auto_refresh_on_command(CMD_READ);
    nfc_amiibo_auto_refresh_on_field(false, 1020);
    CHECK(nfc_amiibo_auto_refresh_scan_pending());
    CHECK(nfc_amiibo_auto_refresh_process(1200));
    CHECK(g_calls == 1);
    CHECK(nfc_amiibo_auto_refresh_activity_byte() == 2u);

    /* FAST_READ frames count toward the same threshold. */
    reset();
    nfc_amiibo_auto_refresh_arm(1, false);
    nfc_amiibo_auto_refresh_on_field(true, 1000);
    nfc_amiibo_auto_refresh_on_command(CMD_FAST_READ);
    nfc_amiibo_auto_refresh_on_command(CMD_FAST_READ);
    nfc_amiibo_auto_refresh_on_field(false, 1020);
    CHECK(nfc_amiibo_auto_refresh_scan_pending());
    CHECK(nfc_amiibo_auto_refresh_process(1200));
    CHECK(g_calls == 1);
    CHECK(nfc_amiibo_auto_refresh_activity_byte() == 2u);

    /* One PWD_AUTH alone triggers. */
    reset();
    nfc_amiibo_auto_refresh_arm(1, false);
    nfc_amiibo_auto_refresh_on_field(true, 1000);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 1020);
    CHECK(nfc_amiibo_auto_refresh_scan_pending());
    CHECK(nfc_amiibo_auto_refresh_process(1200));
    CHECK(g_calls == 1);
    CHECK(nfc_amiibo_auto_refresh_activity_byte() == 0x80u);

    /* Qualifying activity cannot rescue a too-short field hold. */
    reset();
    nfc_amiibo_auto_refresh_arm(1, false);
    nfc_amiibo_auto_refresh_on_field(true, 1000);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_command(CMD_READ);
    nfc_amiibo_auto_refresh_on_command(CMD_READ);
    nfc_amiibo_auto_refresh_on_field(false, 1019); /* 19 ms < 20 ms */
    CHECK(!nfc_amiibo_auto_refresh_scan_pending());
    CHECK(!nfc_amiibo_auto_refresh_process(1200));
    CHECK(g_calls == 0);
    CHECK(nfc_amiibo_auto_refresh_activity_byte() == 0x82u);
}

/* Activity is per-session: late frames, field return and new sessions all
 * clear or ignore it. */
static void test_activity_session_scope(void) {
    reset();
    nfc_amiibo_auto_refresh_arm(2, false);

    /* Session 1: PWD_AUTH triggers a refresh. */
    nfc_amiibo_auto_refresh_on_field(true, 0);
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 50);
    CHECK(nfc_amiibo_auto_refresh_scan_pending());
    CHECK(nfc_amiibo_auto_refresh_process(200));
    CHECK(g_calls == 1);

    /* Late frames after FIELD_LOST are ignored. */
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 300);
    CHECK(!nfc_amiibo_auto_refresh_scan_pending());
    CHECK(nfc_amiibo_auto_refresh_activity_byte() == 0x80u);

    /* Session 2 with no activity: nothing carries over from session 1. */
    nfc_amiibo_auto_refresh_on_field(true, 1000);
    nfc_amiibo_auto_refresh_on_field(false, 1050);
    CHECK(!nfc_amiibo_auto_refresh_scan_pending());
    CHECK(!nfc_amiibo_auto_refresh_process(1200));
    CHECK(g_calls == 1);
    CHECK(nfc_amiibo_auto_refresh_activity_byte() == 0u);

    /* Field return cancels and resets activity accumulated in a session. */
    nfc_amiibo_auto_refresh_on_field(true, 2000);
    nfc_amiibo_auto_refresh_on_command(CMD_READ);
    nfc_amiibo_auto_refresh_on_command(CMD_READ);
    nfc_amiibo_auto_refresh_on_field(false, 2050);
    CHECK(nfc_amiibo_auto_refresh_scan_pending());

    nfc_amiibo_auto_refresh_on_field(true, 2100);
    CHECK(!nfc_amiibo_auto_refresh_scan_pending());
    nfc_amiibo_auto_refresh_on_field(false, 2150);
    CHECK(!nfc_amiibo_auto_refresh_scan_pending());
    CHECK(!nfc_amiibo_auto_refresh_process(2300));
    CHECK(g_calls == 1);
    CHECK(nfc_amiibo_auto_refresh_activity_byte() == 0u);
}

/* Activity byte packs "auth seen" in bit 7 and min(read_count, 127) below. */
static void test_activity_byte_clamp(void) {
    reset();
    nfc_amiibo_auto_refresh_arm(1, false);
    nfc_amiibo_auto_refresh_on_field(true, 0);
    for (int i = 0; i < 200; i++) {
        nfc_amiibo_auto_refresh_on_command(CMD_READ);
    }
    nfc_amiibo_auto_refresh_on_command(CMD_PWD_AUTH);
    nfc_amiibo_auto_refresh_on_field(false, 50);
    CHECK(nfc_amiibo_auto_refresh_activity_byte() == 0xFFu);
}

int main(void) {
    test_short_field_ignored();
    test_stable_loss_triggers_once();
    test_field_return_cancels_pending();
    test_busy_blocks_mark_and_consume();
    test_arm_slot_disarm();
    test_all_slot_arm_passes_sentinel();
    test_last_status_and_new_session_guard();
    test_saturating_count();
    test_callback_ms_clock_wrap();
    test_command_activity_gate();
    test_activity_session_scope();
    test_activity_byte_clamp();

    printf("nfc_amiibo_auto_refresh: %d checks, %d failures\n",
           g_checks, g_fail);
    return g_fail ? 1 : 0;
}
