/*
 * Native unit tests for app_button_tap. Build + run:
 *   make -C firmware/application/src/tests
 */
#include "../app_button_tap.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

/* RTC1 counter width (24 bit) and the tick rate of this project
 * (APP_TIMER_CONFIG_RTC_FREQUENCY == 1 -> 32768 / 2 = 16384 Hz). */
#define TICKS_PER_SECOND 16384u

/* No multi-tap binding at all: the 1-tap action runs immediately. */
static const uint8_t NO_BINDINGS[4] = {0, 0, 0, 0};

/* A button with any 2..5 binding set must wait for the threshold before its
 * 1-tap action runs, otherwise a 2-tap press would fire the 1-tap action
 * first. These tables cover the interesting slots. */
static const uint8_t BIND_AT_2[4] = {4, 0, 0, 0};
static const uint8_t BIND_AT_3[4] = {0, 4, 0, 0};
static const uint8_t BIND_AT_4[4] = {0, 0, 4, 0};
static const uint8_t BIND_AT_5[4] = {0, 0, 0, 4};
/* Two slots on the same button: the lower one has to wait for the threshold,
 * otherwise the higher slot could never be reached. */
static const uint8_t BIND_AT_2_AND_3[4] = {4, 5, 0, 0};
static const uint8_t BIND_AT_4_AND_5[4] = {0, 0, 4, 5};

/* Without any 2..5 binding the short press fires on the first release. */
static void test_first_tap_without_binding_fires_short(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, NO_BINDINGS);
    CHECK(r.run == APP_BUTTON_TAP_RUN_SHORT);
    CHECK(r.function == 1);
    CHECK(r.count == 1);
    /* The sequence is complete: it is reset by the state machine itself. */
    CHECK(st.count == 0);
    CHECK(!st.fired);
}

/* With a 2..5 binding the 1-tap action is deferred until the threshold. */
static void test_first_tap_with_binding_waits(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 1);
    CHECK(!st.fired);
}

/* A disabled short press with a multi-tap binding still waits (and runs
 * nothing at the end of the sequence). */
static void test_first_tap_with_binding_waits_when_short_disabled(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 0, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(!st.fired);
}

/* The 2-tap binding fires on the second release. */
static void test_second_tap_fires_binding(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(r.function == 4);
    CHECK(r.count == 2);
    CHECK(st.fired);
}

/* The 3-tap binding fires on the third release (the 2-tap slot is free). */
static void test_third_tap_fires_binding(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    CHECK(r.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(r.function == 4);
    CHECK(r.count == 3);
    CHECK(st.fired);
}

/* The 5-tap binding fires on the fifth release. */
static void test_fifth_tap_fires_binding(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_5);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_5);
    CHECK(r.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(r.function == 4);
    CHECK(r.count == 5);
    CHECK(st.fired);
}

/* The 4-tap binding fires on the fourth release. */
static void test_fourth_tap_fires_binding(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_4);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_4);
    CHECK(r.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(r.function == 4);
    CHECK(r.count == 4);
    CHECK(st.fired);
}

/* The 4-tap and the 5-tap slot are bound: a 4-tap press runs the 4-tap
 * action when the threshold expires (the 5-tap slot may still come). */
static void test_four_taps_run_the_fourth_slot_at_the_timeout(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    /* the 5-tap slot may still come: the 4-tap action has to wait */
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 4);
    CHECK(!st.fired);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_4_AND_5);
    CHECK(t.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(t.function == 4);
    CHECK(st.count == 0);
    CHECK(!st.fired);
}

/* The 4-tap and the 5-tap slot are bound: a 5-tap press runs the 5-tap
 * action on the fifth release. */
static void test_five_taps_reach_the_fifth_slot(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    CHECK(r.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(r.function == 5);
    CHECK(r.count == 5);
    CHECK(st.fired);
}

/* The tap counter never runs past 5. */
static void test_count_clamps_at_five(void) {
    app_button_tap_state_t st = {0, false};
    for (int i = 0; i < 5; i++) {
        app_button_tap_on_short_press(&st, 0, NO_BINDINGS);
    }
    CHECK(st.count == 5);
    app_button_tap_on_short_press(&st, 0, NO_BINDINGS);
    CHECK(st.count == 5);
}

/* A tap count without a binding runs nothing and keeps the sequence open. */
static void test_unbound_tap_count_does_not_fire(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 2);
    CHECK(!st.fired);
}

/* Once a binding fired, the sequence is consumed: a further tap inside the
 * window triggers nothing. */
static void test_fired_sequence_ignores_extra_taps(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 3);
    CHECK(st.fired);
}

/* A single tap that never fired runs the short-press function when the
 * threshold expires, and the sequence is reset. */
static void test_timeout_single_tap_runs_short(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_timeout(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_SHORT);
    CHECK(r.function == 1);
    CHECK(st.count == 0);
    CHECK(!st.fired);
}

/* A sequence that already fired runs nothing when it expires. */
static void test_timeout_after_fire_runs_nothing(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_timeout(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(st.count == 0);
    CHECK(!st.fired);
}

/* A multi-tap sequence that matched no binding runs nothing when it
 * expires (the user aimed at a multi-tap gesture). */
static void test_timeout_multi_tap_never_fired_runs_nothing(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_result_t r = app_button_tap_timeout(&st, 1, BIND_AT_3);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(st.count == 0);
    CHECK(!st.fired);
}

/* The timeout resets the sequence so the next tap starts a fresh one. */
static void test_timeout_resets_state(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_timeout(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_SHORT);
    CHECK(st.count == 0);
    CHECK(!st.fired);
}

/* A disabled short press runs nothing when the sequence expires. */
static void test_timeout_with_disabled_short_runs_nothing(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 0, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_timeout(&st, 0, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(!st.fired);
}

/* Both the 2-tap and the 3-tap slot are bound: on a 3-tap press the 3-tap
 * action runs and the 2-tap action must not. */
static void test_three_taps_reach_the_third_slot(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_result_t r1 = app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    CHECK(r1.run == APP_BUTTON_TAP_RUN_NONE);
    app_button_tap_result_t r2 = app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    /* the 3-tap slot may still come: the 2-tap action has to wait */
    CHECK(r2.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r2.count == 2);
    CHECK(!st.fired);
    app_button_tap_result_t r3 = app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    CHECK(r3.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(r3.function == 5);
    CHECK(r3.count == 3);
    CHECK(st.fired);
}

/* Both the 2-tap and the 3-tap slot are bound: a 2-tap press runs the 2-tap
 * action when the threshold expires (the final tap count is 2). */
static void test_two_taps_run_the_second_slot_at_the_timeout(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 2);
    CHECK(!st.fired);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_2_AND_3);
    CHECK(t.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(t.function == 4);
    CHECK(st.count == 0);
    CHECK(!st.fired);
}

/* Only the 2-tap slot is bound: the action runs immediately on the 2nd tap
 * (no higher slot can still come). */
static void test_only_second_slot_bound_fires_immediately(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(r.function == 4);
    CHECK(r.count == 2);
    CHECK(st.fired);
}

/* Only the 3-tap slot is bound: a 2-tap press runs nothing at all. */
static void test_only_third_slot_bound_two_taps_run_nothing(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 2);
    CHECK(!st.fired);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_3);
    CHECK(t.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(st.count == 0);
    CHECK(!st.fired);
}

/* Only the 3-tap slot is bound: the 3rd tap runs it right away. */
static void test_only_third_slot_bound_fires_on_the_third_tap(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    CHECK(r.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(r.function == 4);
    CHECK(r.count == 3);
    CHECK(st.fired);
}

/* Only the 2-tap slot is bound: a single tap still runs the short-press
 * function, but only when the threshold expires. */
static void test_only_second_slot_bound_single_tap_runs_short_at_timeout(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 1);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_2);
    CHECK(t.run == APP_BUTTON_TAP_RUN_SHORT);
    CHECK(t.function == 1);
    CHECK(st.count == 0);
    CHECK(!st.fired);
}

/* Without any binding the short press runs on every tap: the state is reset
 * so the next tap starts a fresh 1-tap gesture that fires again immediately. */
static void test_short_press_without_bindings_resets_the_state(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_result_t r1 = app_button_tap_on_short_press(&st, 1, NO_BINDINGS);
    CHECK(r1.run == APP_BUTTON_TAP_RUN_SHORT);
    CHECK(st.count == 0);
    CHECK(!st.fired);
    app_button_tap_result_t r2 = app_button_tap_on_short_press(&st, 1, NO_BINDINGS);
    CHECK(r2.run == APP_BUTTON_TAP_RUN_SHORT);
    CHECK(r2.function == 1);
    CHECK(r2.count == 1);
    CHECK(st.count == 0);
    CHECK(!st.fired);
}

/* A sequence whose binding already ran runs nothing when it expires. */
static void test_timeout_after_a_fired_binding_runs_nothing(void) {
    app_button_tap_state_t st = {0, false};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    CHECK(st.fired);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_2_AND_3);
    CHECK(t.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(st.count == 0);
    CHECK(!st.fired);
}

/* pack/unpack is lossless. */
static void test_pack_unpack_round_trip(void) {
    uint8_t fn[8] = {0, 1, 2, 3, 4, 5, 6, 9};
    uint8_t packed[4];
    uint8_t out[8];
    app_button_tap_pack(fn, packed);
    app_button_tap_unpack(packed, out);
    CHECK(memcmp(fn, out, sizeof(fn)) == 0);
    uint8_t zero[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t packed_zero[4];
    app_button_tap_pack(zero, packed_zero);
    CHECK(packed_zero[0] == 0 && packed_zero[1] == 0 && packed_zero[2] == 0 && packed_zero[3] == 0);
}

/* The packed layout is 4 bits per function code, low nibble first. */
static void test_pack_nibble_layout(void) {
    uint8_t fn[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t packed[4];
    app_button_tap_pack(fn, packed);
    CHECK(packed[0] == 0x21);
    CHECK(packed[1] == 0x43);
    CHECK(packed[2] == 0x65);
    CHECK(packed[3] == 0x87);
}

/* Single slots can be read and written without touching the neighbours. */
static void test_get_set_binding(void) {
    uint8_t packed[4] = {0, 0, 0, 0};
    app_button_tap_set(packed, 0, 4);
    CHECK(app_button_tap_get(packed, 0) == 4);
    app_button_tap_set(packed, 7, 9);
    CHECK(app_button_tap_get(packed, 7) == 9);
    app_button_tap_set(packed, 3, 7);
    CHECK(app_button_tap_get(packed, 3) == 7);
    CHECK(app_button_tap_get(packed, 0) == 4);
}

/* the tick -> millisecond conversion used by the firmware */
static void test_elapsed_ms_conversion(void) {
    CHECK(app_button_tap_elapsed_ms(0, TICKS_PER_SECOND) == 0);
    CHECK(app_button_tap_elapsed_ms(TICKS_PER_SECOND, TICKS_PER_SECOND) == 1000);
    CHECK(app_button_tap_elapsed_ms(1638, TICKS_PER_SECOND) == 99); /* floor */
    CHECK(app_button_tap_elapsed_ms(TICKS_PER_SECOND * 2, TICKS_PER_SECOND) == 2000);
    CHECK(app_button_tap_elapsed_ms(1000, 0) == 0);                 /* no division by zero */
}

int main(void) {
    test_first_tap_without_binding_fires_short();
    test_first_tap_with_binding_waits();
    test_first_tap_with_binding_waits_when_short_disabled();
    test_second_tap_fires_binding();
    test_third_tap_fires_binding();
    test_fifth_tap_fires_binding();
    test_fourth_tap_fires_binding();
    test_four_taps_run_the_fourth_slot_at_the_timeout();
    test_five_taps_reach_the_fifth_slot();
    test_count_clamps_at_five();
    test_unbound_tap_count_does_not_fire();
    test_fired_sequence_ignores_extra_taps();
    test_timeout_single_tap_runs_short();
    test_timeout_after_fire_runs_nothing();
    test_timeout_multi_tap_never_fired_runs_nothing();
    test_timeout_resets_state();
    test_timeout_with_disabled_short_runs_nothing();
    test_three_taps_reach_the_third_slot();
    test_two_taps_run_the_second_slot_at_the_timeout();
    test_only_second_slot_bound_fires_immediately();
    test_only_third_slot_bound_two_taps_run_nothing();
    test_only_third_slot_bound_fires_on_the_third_tap();
    test_only_second_slot_bound_single_tap_runs_short_at_timeout();
    test_short_press_without_bindings_resets_the_state();
    test_timeout_after_a_fired_binding_runs_nothing();
    test_pack_unpack_round_trip();
    test_pack_nibble_layout();
    test_get_set_binding();
    test_elapsed_ms_conversion();
    printf("%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
