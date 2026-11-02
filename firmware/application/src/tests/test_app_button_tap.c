/*
 * Native unit tests for app_button_tap. Build + run:
 *   make -C firmware/application/src/tests
 */
#include "../app_button_tap.h"

#include <stdio.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

#define THRESHOLD_MS 250u

/* RTC1 counter width (24 bit) and the tick rate of this project
 * (APP_TIMER_CONFIG_RTC_FREQUENCY == 1 -> 32768 / 2 = 16384 Hz). */
#define RTC_COUNTER_MASK 0x00FFFFFFu
#define TICKS_PER_SECOND 16384u

static uint32_t ticks_to_ms(uint32_t ticks) {
    return (ticks * 1000u) / TICKS_PER_SECOND;
}

/* Same wrap-safe subtraction the SDK's app_timer_cnt_diff_compute() does. */
static uint32_t diff_ticks(uint32_t ticks_to, uint32_t ticks_from) {
    return (ticks_to - ticks_from) & RTC_COUNTER_MASK;
}

/* required == 1 fires on the very first tap (current behaviour) */
static void test_required_one_fires_immediately(void) {
    app_button_tap_result_t r = app_button_tap_on_short_press(0, 0, 1, THRESHOLD_MS);
    CHECK(r.fire);
    CHECK(r.count == 0);
}

/* required == 0 is treated like required == 1 */
static void test_zero_required_behaves_like_one(void) {
    app_button_tap_result_t r = app_button_tap_on_short_press(0, 0, 0, THRESHOLD_MS);
    CHECK(r.fire);
    CHECK(r.count == 0);
}

/* the first tap of a sequence ignores the elapsed value entirely */
static void test_first_tap_ignores_elapsed(void) {
    app_button_tap_result_t r = app_button_tap_on_short_press(1000000, 0, 2, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 1);
}

/* a gap exactly equal to the threshold still continues the sequence */
static void test_gap_exactly_threshold_continues(void) {
    app_button_tap_result_t r = app_button_tap_on_short_press(0, 0, 2, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 1);

    r = app_button_tap_on_short_press(THRESHOLD_MS, r.count, 2, THRESHOLD_MS);
    CHECK(r.fire);
    CHECK(r.count == 0);
}

/* a gap one ms over the threshold restarts the sequence */
static void test_gap_one_ms_over_threshold_restarts(void) {
    app_button_tap_result_t r = app_button_tap_on_short_press(0, 0, 2, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 1);

    r = app_button_tap_on_short_press(THRESHOLD_MS + 1u, r.count, 2, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 1);
}

/* required == 2 fires on the 2nd tap, 200 ms after the 1st */
static void test_double_tap(void) {
    app_button_tap_result_t r = app_button_tap_on_short_press(0, 0, 2, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 1);

    r = app_button_tap_on_short_press(200, r.count, 2, THRESHOLD_MS);
    CHECK(r.fire);
    CHECK(r.count == 0);
}

/* required == 3 fires on the 3rd tap only */
static void test_triple_tap(void) {
    app_button_tap_result_t r = app_button_tap_on_short_press(0, 0, 3, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 1);

    r = app_button_tap_on_short_press(100, r.count, 3, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 2);

    r = app_button_tap_on_short_press(100, r.count, 3, THRESHOLD_MS);
    CHECK(r.fire);
    CHECK(r.count == 0);
}

/* required == 5 fires on the 5th tap only */
static void test_five_taps(void) {
    app_button_tap_result_t r = app_button_tap_on_short_press(0, 0, 5, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 1);

    r = app_button_tap_on_short_press(100, r.count, 5, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 2);

    r = app_button_tap_on_short_press(100, r.count, 5, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 3);

    r = app_button_tap_on_short_press(100, r.count, 5, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 4);

    r = app_button_tap_on_short_press(100, r.count, 5, THRESHOLD_MS);
    CHECK(r.fire);
    CHECK(r.count == 0);
}

/* a gap far over the threshold restarts the sequence */
static void test_stale_gap_restarts(void) {
    app_button_tap_result_t r = app_button_tap_on_short_press(0, 0, 2, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 1);

    r = app_button_tap_on_short_press(100000, r.count, 2, THRESHOLD_MS);
    CHECK(!r.fire);
    CHECK(r.count == 1);
}

/* The caller owns the measurement. This mirrors the firmware: the gap runs
 * from the previous tap's RELEASE to this tap's PRESS, is measured in ticks
 * with the SDK's wrap-safe diff, and the hold time is not part of it. */
static uint32_t caller_elapsed_ms(uint32_t press_ticks, uint32_t prev_release_ticks, uint8_t counter) {
    if (counter == 0) {
        return 0;
    }
    return ticks_to_ms(diff_ticks(press_ticks, prev_release_ticks));
}

static void test_caller_measures_release_to_press(void) {
    uint32_t tap1_release = 100000;
    uint32_t tap2_press = tap1_release + (TICKS_PER_SECOND * 125u / 1000u); /* 125 ms gap */
    uint32_t tap2_release = tap2_press + (TICKS_PER_SECOND / 2);            /* 500 ms hold */

    uint32_t elapsed = caller_elapsed_ms(tap2_press, tap1_release, 1);
    CHECK(elapsed == 125);                                                  /* hold time excluded */
    CHECK(elapsed != ticks_to_ms(diff_ticks(tap2_release, tap1_release)));

    app_button_tap_result_t r = app_button_tap_on_short_press(elapsed, 1, 2, THRESHOLD_MS);
    CHECK(r.fire);
    CHECK(r.count == 0);
}

static void test_caller_gap_survives_counter_wrap(void) {
    /* the previous release sits just below the 24 bit counter wrap and the
     * next press lands just after it */
    uint32_t tap1_release = 0x00FFFFF0u;
    uint32_t tap2_press = 0x00000020u;   /* 48 ticks (~2.9 ms) later, wrapped */

    uint32_t elapsed = caller_elapsed_ms(tap2_press, tap1_release, 1);
    CHECK(elapsed <= 5);
    CHECK(elapsed <= THRESHOLD_MS);

    app_button_tap_result_t r = app_button_tap_on_short_press(elapsed, 1, 2, THRESHOLD_MS);
    CHECK(r.fire);
    CHECK(r.count == 0);
}

int main(void) {
    test_required_one_fires_immediately();
    test_zero_required_behaves_like_one();
    test_first_tap_ignores_elapsed();
    test_gap_exactly_threshold_continues();
    test_gap_one_ms_over_threshold_restarts();
    test_double_tap();
    test_triple_tap();
    test_five_taps();
    test_stale_gap_restarts();
    test_caller_measures_release_to_press();
    test_caller_gap_survives_counter_wrap();
    printf("%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
