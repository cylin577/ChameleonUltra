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
#define MS_TICKS(ms) (((ms) * TICKS_PER_SECOND) / 1000u)

/* The firmware values: a press shorter than 40 ms is contact bounce, a
 * press of 1000 ms or more is a long press. */
#define MIN_TAP_TICKS MS_TICKS(APP_BUTTON_GESTURE_MIN_TAP_MS)
#define LONG_TICKS    MS_TICKS(1000)

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

/* Without any multi-tap binding the short press fires on the first release. */
static void test_first_tap_without_binding_fires_short(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, NO_BINDINGS);
    CHECK(r.run == APP_BUTTON_TAP_RUN_SHORT);
    CHECK(r.function == 1);
    CHECK(r.count == 1);
    /* The sequence is complete: it is reset by the state machine itself. */
    CHECK(st.count == 0);
}

/* With a 2..5 binding the 1-tap action is deferred until the threshold. */
static void test_first_tap_with_binding_waits(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 1);
}

/* A disabled short press with a multi-tap binding still waits (and runs
 * nothing at the end of the sequence). */
static void test_first_tap_with_binding_waits_when_short_disabled(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 0, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
}

/* A 2-tap action NEVER runs on the second release: the final tap count is
 * only known when the threshold expires. */
static void test_second_tap_never_fires_before_the_threshold(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 2);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_2);
    CHECK(t.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(t.function == 4);
    CHECK(st.count == 0);
}

/* The 3-tap action also waits for the threshold. */
static void test_third_tap_never_fires_before_the_threshold(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 3);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_3);
    CHECK(t.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(t.function == 4);
    CHECK(st.count == 0);
}

/* The 4-tap action also waits for the threshold. */
static void test_fourth_tap_never_fires_before_the_threshold(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_4);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_4);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 4);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_4);
    CHECK(t.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(t.function == 4);
    CHECK(st.count == 0);
}

/* The 5-tap action also waits for the threshold. */
static void test_fifth_tap_never_fires_before_the_threshold(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_5);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_5);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 5);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_5);
    CHECK(t.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(t.function == 4);
    CHECK(st.count == 0);
}

/* The 4-tap and the 5-tap slot are bound: a 4-tap press runs the 4-tap
 * action when the threshold expires (the 5-tap slot may still come). */
static void test_four_taps_run_the_fourth_slot_at_the_timeout(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    /* the 5-tap slot may still come: the 4-tap action has to wait */
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 4);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_4_AND_5);
    CHECK(t.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(t.function == 4);
    CHECK(st.count == 0);
}

/* The 4-tap and the 5-tap slot are bound: a 5-tap press runs the 5-tap
 * action when the threshold expires. */
static void test_five_taps_reach_the_fifth_slot(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_4_AND_5);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 5);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_4_AND_5);
    CHECK(t.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(t.function == 5);
    CHECK(st.count == 0);
}

/* The tap counter never runs past 5. */
static void test_count_clamps_at_five(void) {
    app_button_tap_state_t st = {0};
    for (int i = 0; i < 5; i++) {
        app_button_tap_on_short_press(&st, 0, NO_BINDINGS);
    }
    CHECK(st.count == 5);
    app_button_tap_on_short_press(&st, 0, NO_BINDINGS);
    CHECK(st.count == 5);
}

/* A tap count without a binding runs nothing and keeps the sequence open. */
static void test_unbound_tap_count_does_not_fire(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 2);
}

/* Extra taps inside the window never fire the lower slot: the final count
 * decides, and the 3-tap slot of BIND_AT_2 is unbound. */
static void test_extra_taps_never_fire(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    /* the 2-tap action must not run before the threshold */
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 3);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_2);
    /* the final count is 3 and the 3-tap slot is unbound: nothing runs */
    CHECK(t.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(st.count == 0);
}

/* A single tap that never fired runs the short-press function when the
 * threshold expires, and the sequence is reset. */
static void test_timeout_single_tap_runs_short(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_timeout(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_SHORT);
    CHECK(r.function == 1);
    CHECK(st.count == 0);
}

/* A multi-tap sequence that matched no binding runs nothing when it
 * expires (the user aimed at a multi-tap gesture). */
static void test_timeout_multi_tap_never_fired_runs_nothing(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_result_t r = app_button_tap_timeout(&st, 1, BIND_AT_3);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(st.count == 0);
}

/* The timeout resets the sequence so the next tap starts a fresh one. */
static void test_timeout_resets_state(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_timeout(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_SHORT);
    CHECK(st.count == 0);
}

/* A disabled short press runs nothing when the sequence expires. */
static void test_timeout_with_disabled_short_runs_nothing(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 0, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_timeout(&st, 0, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
}

/* Both the 2-tap and the 3-tap slot are bound: on a 3-tap press the 3-tap
 * action runs at the threshold and the 2-tap action must not. */
static void test_three_taps_run_the_third_slot_at_the_timeout(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_result_t r1 = app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    CHECK(r1.run == APP_BUTTON_TAP_RUN_NONE);
    app_button_tap_result_t r2 = app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    /* the 3-tap slot may still come: the 2-tap action has to wait */
    CHECK(r2.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r2.count == 2);
    app_button_tap_result_t r3 = app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    CHECK(r3.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r3.count == 3);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_2_AND_3);
    /* the 3-tap action runs, the 2-tap action never does */
    CHECK(t.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(t.function == 5);
    CHECK(t.function != 4);
    CHECK(st.count == 0);
}

/* Both the 2-tap and the 3-tap slot are bound: a 2-tap press runs the 2-tap
 * action when the threshold expires (the final tap count is 2). */
static void test_two_taps_run_the_second_slot_at_the_timeout(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_2_AND_3);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 2);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_2_AND_3);
    CHECK(t.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(t.function == 4);
    CHECK(st.count == 0);
}

/* Only the 2-tap slot is bound: the action waits for the threshold too. */
static void test_only_second_slot_bound_waits_for_the_threshold(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 2);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_2);
    CHECK(t.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(t.function == 4);
    CHECK(st.count == 0);
}

/* Only the 3-tap slot is bound: a 2-tap press runs nothing at all. */
static void test_only_third_slot_bound_two_taps_run_nothing(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 2);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_3);
    CHECK(t.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(st.count == 0);
}

/* Only the 3-tap slot is bound: the 3rd tap waits for the threshold. */
static void test_only_third_slot_bound_waits_for_the_threshold(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_3);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 3);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_3);
    CHECK(t.run == APP_BUTTON_TAP_RUN_BINDING);
    CHECK(t.function == 4);
    CHECK(st.count == 0);
}

/* Only the 2-tap slot is bound: a single tap still runs the short-press
 * function, but only when the threshold expires. */
static void test_only_second_slot_bound_single_tap_runs_short_at_timeout(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_result_t r = app_button_tap_on_short_press(&st, 1, BIND_AT_2);
    CHECK(r.run == APP_BUTTON_TAP_RUN_NONE);
    CHECK(r.count == 1);
    app_button_tap_result_t t = app_button_tap_timeout(&st, 1, BIND_AT_2);
    CHECK(t.run == APP_BUTTON_TAP_RUN_SHORT);
    CHECK(t.function == 1);
    CHECK(st.count == 0);
}

/* Without any binding the short press runs on every tap: the state is reset
 * so the next tap starts a fresh 1-tap gesture that fires again immediately. */
static void test_short_press_without_bindings_resets_the_state(void) {
    app_button_tap_state_t st = {0};
    app_button_tap_result_t r1 = app_button_tap_on_short_press(&st, 1, NO_BINDINGS);
    CHECK(r1.run == APP_BUTTON_TAP_RUN_SHORT);
    CHECK(st.count == 0);
    app_button_tap_result_t r2 = app_button_tap_on_short_press(&st, 1, NO_BINDINGS);
    CHECK(r2.run == APP_BUTTON_TAP_RUN_SHORT);
    CHECK(r2.function == 1);
    CHECK(r2.count == 1);
    CHECK(st.count == 0);
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

/* A contact bounce burst makes no gesture at all: every press of the burst
 * is shorter than a tap. */
static void test_bounce_burst_makes_no_gesture(void) {
    app_button_gesture_state_t g;
    app_button_gesture_init(&g);
    uint32_t t = 1000;
    /* the contact closes and bounces: press, release, press, release */
    CHECK(app_button_gesture_on_edge(&g, true, t, MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, false, t + MS_TICKS(2), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, true, t + MS_TICKS(3), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, false, t + MS_TICKS(5), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    /* the state follows the last edge: no dangling press */
    CHECK(g.level_known);
    CHECK(!g.pressed);
}

/* A real tap makes exactly one SHORT gesture. */
static void test_real_tap_makes_one_short_gesture(void) {
    app_button_gesture_state_t g;
    app_button_gesture_init(&g);
    uint32_t t = 1000;
    CHECK(app_button_gesture_on_edge(&g, true, t, MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, false, t + MS_TICKS(60), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_SHORT);
    /* an edge with the same level is not a transition */
    CHECK(app_button_gesture_on_edge(&g, false, t + MS_TICKS(80), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
}

/* A hold of at least a second is a long press. */
static void test_long_hold_makes_a_long_gesture(void) {
    app_button_gesture_state_t g;
    app_button_gesture_init(&g);
    uint32_t t = 1000;
    CHECK(app_button_gesture_on_edge(&g, true, t, MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, false, t + LONG_TICKS, MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_LONG);
}

/* A bounce burst leaves no dangling state: the tap that comes after it is
 * still counted exactly once. */
static void test_no_dangling_state_after_a_bounce_burst(void) {
    app_button_gesture_state_t g;
    app_button_gesture_init(&g);
    uint32_t t = 1000;
    /* the contact bounces and settles closed */
    CHECK(app_button_gesture_on_edge(&g, true, t, MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, false, t + MS_TICKS(2), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, true, t + MS_TICKS(3), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, false, t + MS_TICKS(5), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, true, t + MS_TICKS(6), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(g.pressed);
    /* the real release: the tap is counted once */
    CHECK(app_button_gesture_on_edge(&g, false, t + MS_TICKS(60), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_SHORT);
    CHECK(!g.pressed);
    /* and the next tap is counted once too */
    CHECK(app_button_gesture_on_edge(&g, true, t + MS_TICKS(100), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, false, t + MS_TICKS(160), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_SHORT);
}

/* One physical press with a bounce burst makes exactly ONE tap.
 *
 * press@0, release@2 ms, press@3 ms, release@25 ms, press@26 ms,
 * release@80 ms: the pressed segment from 3 to 25 ms (22 ms) is the bounce
 * burst, the segment from 26 to 80 ms (54 ms) is the real press. With the
 * old 20 ms floor the 22 ms segment was a tap too, so a single press
 * counted as two taps and the 2-tap action fired. */
static void test_bounce_burst_counts_exactly_one_tap(void) {
    app_button_gesture_state_t g;
    app_button_gesture_init(&g);
    uint32_t t = 1000;
    int taps = 0;
    CHECK(app_button_gesture_on_edge(&g, true, t, MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, false, t + MS_TICKS(2), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, true, t + MS_TICKS(3), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, false, t + MS_TICKS(25), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    CHECK(app_button_gesture_on_edge(&g, true, t + MS_TICKS(26), MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    app_button_gesture_kind_t kind = app_button_gesture_on_edge(&g, false, t + MS_TICKS(80), MIN_TAP_TICKS, LONG_TICKS);
    if (kind == APP_BUTTON_GESTURE_SHORT) {
        taps++;
    }
    CHECK(kind == APP_BUTTON_GESTURE_SHORT);
    CHECK(taps == 1);
    CHECK(!g.pressed);
}

/* The segment length is measured edge-to-edge and survives the wrap of the
 * 24 bit RTC counter. */
static void test_gesture_survives_the_counter_wrap(void) {
    app_button_gesture_state_t g;
    app_button_gesture_init(&g);
    uint32_t near_wrap = 0x00FFFFF0u;
    CHECK(app_button_gesture_on_edge(&g, true, near_wrap, MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_NONE);
    uint32_t after_wrap = (near_wrap + MS_TICKS(60)) & 0x00FFFFFFu;
    CHECK(after_wrap < near_wrap);
    CHECK(app_button_gesture_on_edge(&g, false, after_wrap, MIN_TAP_TICKS, LONG_TICKS) == APP_BUTTON_GESTURE_SHORT);
}

int main(void) {
    test_first_tap_without_binding_fires_short();
    test_first_tap_with_binding_waits();
    test_first_tap_with_binding_waits_when_short_disabled();
    test_second_tap_never_fires_before_the_threshold();
    test_third_tap_never_fires_before_the_threshold();
    test_fourth_tap_never_fires_before_the_threshold();
    test_fifth_tap_never_fires_before_the_threshold();
    test_four_taps_run_the_fourth_slot_at_the_timeout();
    test_five_taps_reach_the_fifth_slot();
    test_count_clamps_at_five();
    test_unbound_tap_count_does_not_fire();
    test_extra_taps_never_fire();
    test_timeout_single_tap_runs_short();
    test_timeout_multi_tap_never_fired_runs_nothing();
    test_timeout_resets_state();
    test_timeout_with_disabled_short_runs_nothing();
    test_three_taps_run_the_third_slot_at_the_timeout();
    test_two_taps_run_the_second_slot_at_the_timeout();
    test_only_second_slot_bound_waits_for_the_threshold();
    test_only_third_slot_bound_two_taps_run_nothing();
    test_only_third_slot_bound_waits_for_the_threshold();
    test_only_second_slot_bound_single_tap_runs_short_at_timeout();
    test_short_press_without_bindings_resets_the_state();
    test_pack_unpack_round_trip();
    test_pack_nibble_layout();
    test_get_set_binding();
    test_elapsed_ms_conversion();
    test_bounce_burst_makes_no_gesture();
    test_real_tap_makes_one_short_gesture();
    test_long_hold_makes_a_long_gesture();
    test_no_dangling_state_after_a_bounce_burst();
    test_bounce_burst_counts_exactly_one_tap();
    test_gesture_survives_the_counter_wrap();
    printf("%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
