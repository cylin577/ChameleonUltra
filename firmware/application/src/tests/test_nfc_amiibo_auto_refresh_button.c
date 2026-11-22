/*
 * Host test for the "Toggle amiibo auto-refresh" button action (ID 11).
 *
 * The real decision logic from nfc_amiibo_auto_refresh_button.h is compiled
 * with injected arm/disarm/LED callbacks, so no NFC hardware, crypto or FDS is
 * used. The arm/disarm callbacks stand in for the main-loop wrappers that also
 * save/clear the FDS record; this test proves the helper picks exactly one path
 * and fires exactly one animation per actionable press.
 */
#include "../nfc_amiibo_auto_refresh_button.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

typedef struct {
    int  arm_calls;
    int  disarm_calls;
    bool persist_seen;
    uint8_t slot_seen;
} action_t;

static action_t g_action;
static int g_arm_led;
static int g_disarm_led;
static int g_error_led;

static void fake_arm(uint8_t slot, bool persist) {
    g_action.arm_calls++;
    g_action.persist_seen = persist;
    g_action.slot_seen = slot;
}
static void fake_disarm(void) { g_action.disarm_calls++; }
static void fake_arm_led(void) { g_arm_led++; }
static void fake_disarm_led(void) { g_disarm_led++; }
static void fake_error_led(void) { g_error_led++; }

static void reset_world(void) {
    memset(&g_action, 0, sizeof(g_action));
    g_arm_led = 0;
    g_disarm_led = 0;
    g_error_led = 0;
}

static int led_total(void) { return g_arm_led + g_disarm_led + g_error_led; }

static void run(bool field_on, bool armed, bool ntag, uint8_t slot) {
    nfc_amiibo_auto_refresh_button_run(field_on, armed, ntag, slot,
                                       fake_arm, fake_disarm,
                                       fake_arm_led, fake_disarm_led, fake_error_led);
}

int main(void) {
    /* Field generator on: no action, no animation (even when armed). */
    reset_world();
    run(true, true, true, 3);
    CHECK(g_action.arm_calls == 0);
    CHECK(g_action.disarm_calls == 0);
    CHECK(led_total() == 0);

    /* Armed -> disarm + clear (wrapper callback) + disarm animation only. */
    reset_world();
    run(false, true, true, 3);
    CHECK(g_action.disarm_calls == 1);
    CHECK(g_action.arm_calls == 0);
    CHECK(g_disarm_led == 1);
    CHECK(g_arm_led == 0 && g_error_led == 0);
    CHECK(led_total() == 1);  /* no double animation */

    /* Disarmed + NTAG215 -> arm(persist=true) + save (wrapper) + arm anim. */
    reset_world();
    run(false, false, true, 5);
    CHECK(g_action.arm_calls == 1);
    CHECK(g_action.persist_seen);
    CHECK(g_action.slot_seen == 5);
    CHECK(g_action.disarm_calls == 0);
    CHECK(g_arm_led == 1);
    CHECK(g_disarm_led == 0 && g_error_led == 0);
    CHECK(led_total() == 1);  /* no double animation */

    /* Disarmed + non-NTAG215 -> error animation, no arm and no disarm. */
    reset_world();
    run(false, false, false, 3);
    CHECK(g_error_led == 1);
    CHECK(g_action.arm_calls == 0 && g_action.disarm_calls == 0);
    CHECK(g_arm_led == 0 && g_disarm_led == 0);
    CHECK(led_total() == 1);

    /* Armed + non-NTAG215 still disarms: the toggle wins over slot type. */
    reset_world();
    run(false, true, false, 3);
    CHECK(g_action.disarm_calls == 1);
    CHECK(g_action.arm_calls == 0);
    CHECK(g_disarm_led == 1 && led_total() == 1);

    printf("test_nfc_amiibo_auto_refresh_button: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
