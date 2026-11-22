/*
 * Host test for the arm/disarm LED cues introduced for auto-refresh.
 *
 * Every LED is injected, so no hardware, crypto or FDS is used. Proves:
 *   - arm   -> double blink
 *   - disarm-> triple blink
 *   - refresh still emits exactly one blink (success and failure)
 * so none of the three actions can be confused with another. Also checks the
 * button ID 11 path routes its success cue through the double-blink animation
 * while leaving the field-on and non-NTAG215 edges unchanged.
 */
#include "../nfc_amiibo_auto_refresh_feedback.h"
#include "../rfid/nfctag/hf/nfc_amiibo_refresh_sleep.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static int g_blinks;
static int g_arm_calls;
static int g_disarm_calls;
static uint16_t g_refresh_status;

static void record_blink(void) { g_blinks++; }

/* Adapters so the pattern helpers fit void(void) injected-callback slots. */
static void arm_blink(void) { nfc_amiibo_auto_refresh_arm_blinks(record_blink); }
static void disarm_blink(void) { nfc_amiibo_auto_refresh_disarm_blinks(record_blink); }

static void fake_arm(uint8_t slot, bool persist) {
    (void)slot; (void)persist;
    g_arm_calls++;
}

static void fake_disarm(void) { g_disarm_calls++; }

static uint16_t fake_refresh(bool persist, uint8_t old_uid[7], uint8_t new_uid[7]) {
    (void)persist; (void)old_uid; (void)new_uid;
    return g_refresh_status;
}

static void fake_sleep_reset(void) {}

static void reset_world(uint16_t status) {
    g_blinks = 0;
    g_arm_calls = 0;
    g_disarm_calls = 0;
    g_refresh_status = status;
}

static void button_run(bool field_on, bool armed, bool ntag, uint8_t slot) {
    nfc_amiibo_auto_refresh_button_run(field_on, armed, ntag, slot,
                                       fake_arm, fake_disarm,
                                       arm_blink, disarm_blink, record_blink);
}

static void check_refresh_single_blink(uint16_t status) {
    uint8_t old_uid[7] = { 0 };
    uint8_t new_uid[7] = { 0 };
    reset_world(status);

    uint16_t result = nfc_amiibo_refresh_with_feedback(
        fake_refresh, true, old_uid, new_uid, fake_sleep_reset,
        record_blink, record_blink);

    CHECK(result == status);                /* status/response unchanged */
    CHECK(g_blinks == 1);                   /* exactly one blink, as before */
}

/* ---- Deferred, non-blocking sequencer ---------------------------------- */

typedef struct {
    int on_steps;
    int off_steps;
    int done_steps;
    int steps;
    bool last_green;
} seq_trace_t;

static void seq_step(bool on, bool green, bool done, void *ctx) {
    seq_trace_t *t = (seq_trace_t *)ctx;
    t->steps++;
    t->last_green = green;
    if (done) {
        t->done_steps++;
    } else if (on) {
        t->on_steps++;
    } else {
        t->off_steps++;
    }
}

/* A pattern is requested in one call (no blink work in the command path) and
 * then driven purely by timestamps from the main loop. */
static void check_deferred_pattern(nfc_amiibo_refresh_feedback_kind_t kind,
                                   uint8_t expected_blinks, bool green) {
    nfc_amiibo_refresh_feedback_state_t state = { 0 };
    seq_trace_t trace = { 0 };
    const uint32_t t0 = 1000u;

    nfc_amiibo_refresh_feedback_request(&state, kind, t0);
    CHECK(state.kind == kind);       /* request only stamps state */
    CHECK(state.start_ms == t0);

    nfc_amiibo_refresh_feedback_process(&state, t0, seq_step, &trace);
    CHECK(trace.on_steps == 1);      /* first phase starts immediately */
    CHECK(trace.steps == 1);

    /* Repeated ticks inside the same phase never re-emit the step. */
    nfc_amiibo_refresh_feedback_process(&state, t0 + 10u, seq_step, &trace);
    CHECK(trace.steps == 1);

    for (uint8_t i = 0; i < expected_blinks; i++) {
        uint32_t base = t0 + (uint32_t)i * NFC_AMIIBO_FB_PERIOD_MS;
        nfc_amiibo_refresh_feedback_process(&state, base + NFC_AMIIBO_FB_ON_MS,
                                            seq_step, &trace);
        nfc_amiibo_refresh_feedback_process(&state, base + NFC_AMIIBO_FB_PERIOD_MS,
                                            seq_step, &trace);
    }
    CHECK(trace.on_steps == expected_blinks);
    CHECK(trace.off_steps == expected_blinks);
    CHECK(trace.last_green == green);

    /* Terminal step restores the LEDs once; state is then idle. */
    nfc_amiibo_refresh_feedback_process(
        &state, t0 + (uint32_t)expected_blinks * NFC_AMIIBO_FB_PERIOD_MS,
        seq_step, &trace);
    CHECK(trace.done_steps == 1);
    CHECK(state.kind == NFC_AMIIBO_REFRESH_FB_NONE);
    nfc_amiibo_refresh_feedback_process(&state, t0 + 10000u, seq_step, &trace);
    CHECK(trace.steps == 2 * expected_blinks + 1);  /* no phantom animation */
}

/* A new attempt replaces any in-flight animation: exactly one feedback. */
static void check_one_feedback_per_attempt(void) {
    nfc_amiibo_refresh_feedback_state_t state = { 0 };
    seq_trace_t trace = { 0 };

    nfc_amiibo_refresh_feedback_request(&state, NFC_AMIIBO_REFRESH_FB_ARM, 0u);
    nfc_amiibo_refresh_feedback_process(&state, 0u, seq_step, &trace);
    CHECK(trace.on_steps == 1);

    nfc_amiibo_refresh_feedback_request(&state, NFC_AMIIBO_REFRESH_FB_REFRESH_OK, 10u);
    CHECK(state.kind == NFC_AMIIBO_REFRESH_FB_REFRESH_OK);
    CHECK(state.last_phase == NFC_AMIIBO_FB_PHASE_NONE);

    nfc_amiibo_refresh_feedback_process(&state, 200u, seq_step, &trace);
    CHECK(trace.done_steps == 1);          /* only the new pattern completes */
    CHECK(state.kind == NFC_AMIIBO_REFRESH_FB_NONE);
    nfc_amiibo_refresh_feedback_process(&state, 5000u, seq_step, &trace);
    CHECK(trace.done_steps == 1);
}

int main(void) {
    /* Arm pattern: double blink. */
    reset_world(STATUS_SUCCESS);
    nfc_amiibo_auto_refresh_arm_blinks(record_blink);
    CHECK(g_blinks == NFC_AMIIBO_ARM_BLINK_COUNT);
    int arm_count = g_blinks;

    /* Disarm pattern: triple blink. */
    reset_world(STATUS_SUCCESS);
    nfc_amiibo_auto_refresh_disarm_blinks(record_blink);
    CHECK(g_blinks == NFC_AMIIBO_DISARM_BLINK_COUNT);
    int disarm_count = g_blinks;

    /* All three animations are pairwise distinct. */
    CHECK(arm_count != disarm_count);

    /* Refresh: still exactly one blink on success and on failure. */
    check_refresh_single_blink(STATUS_SUCCESS);
    CHECK(g_blinks == 1 && g_blinks != arm_count && g_blinks != disarm_count);
    check_refresh_single_blink(STATUS_AMIIBO_KEYS_MISSING);
    CHECK(g_blinks == 1);

    /* Button ID 11 arm goes through the double-blink animation, once. */
    reset_world(STATUS_SUCCESS);
    button_run(false, false, true, 5);
    CHECK(g_arm_calls == 1);
    CHECK(g_disarm_calls == 0);
    CHECK(g_blinks == arm_count);            /* double, not a single refresh blink */

    /* Button ID 11 disarm (already armed) goes through the triple blink, once. */
    reset_world(STATUS_SUCCESS);
    button_run(false, true, true, 5);
    CHECK(g_disarm_calls == 1);
    CHECK(g_arm_calls == 0);
    CHECK(g_blinks == disarm_count);         /* triple, not the arm double blink */

    /* Field generator on: no action, no cue. */
    reset_world(STATUS_SUCCESS);
    button_run(true, true, true, 5);
    CHECK(g_arm_calls == 0);
    CHECK(g_disarm_calls == 0);
    CHECK(g_blinks == 0);

    /* Disarmed + non-NTAG215 slot: single error blink, no arm. */
    reset_world(STATUS_SUCCESS);
    button_run(false, false, false, 5);
    CHECK(g_arm_calls == 0);
    CHECK(g_disarm_calls == 0);
    CHECK(g_blinks == 1);

    /* Disarm cue via a void(void) wrapper is the triple blink. */
    reset_world(STATUS_SUCCESS);
    disarm_blink();
    CHECK(g_blinks == disarm_count);
    CHECK(g_blinks != arm_count);

    /* Deferred sequencer: request is non-blocking, patterns stay distinct. */
    CHECK(nfc_amiibo_refresh_feedback_blink_count(NFC_AMIIBO_REFRESH_FB_REFRESH_OK) == 1u);
    CHECK(nfc_amiibo_refresh_feedback_blink_count(NFC_AMIIBO_REFRESH_FB_ARM) == 2u);
    CHECK(nfc_amiibo_refresh_feedback_blink_count(NFC_AMIIBO_REFRESH_FB_DISARM) == 3u);
    check_deferred_pattern(NFC_AMIIBO_REFRESH_FB_REFRESH_OK, 1u, true);
    check_deferred_pattern(NFC_AMIIBO_REFRESH_FB_REFRESH_ERROR, 1u, false);
    check_deferred_pattern(NFC_AMIIBO_REFRESH_FB_ARM, 2u, true);
    check_deferred_pattern(NFC_AMIIBO_REFRESH_FB_DISARM, 3u, false);
    check_one_feedback_per_attempt();

    printf("test_nfc_amiibo_auto_refresh_feedback: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
