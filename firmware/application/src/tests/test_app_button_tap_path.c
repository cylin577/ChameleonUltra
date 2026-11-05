/*
 * Full-path host test: GPIO edges -> app_button_edge queue -> gesture layer
 * (app_button_gesture_on_edge) -> tap engine (app_button_tap_on_short_press
 * / app_button_tap_timeout). The segment logic and the tap engine are the
 * real firmware code, only the drain loop belongs to the test, so the
 * 3-tap misfire is caught without hardware.
 */
#include "../app_button_edge.h"
#include "../app_button_tap.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

#define TICKS_PER_SECOND 16384u
#define MS_TICKS(ms) (((ms) * TICKS_PER_SECOND) / 1000u)
#define TICK_MASK 0x00FFFFFFu

/* The firmware values: a press shorter than 40 ms is contact bounce, a
 * press of 1000 ms or more is a long press. */
#define MIN_TAP_TICKS MS_TICKS(APP_BUTTON_GESTURE_MIN_TAP_MS)
#define LONG_TICKS    MS_TICKS(1000)

/* Button A: 2 taps -> fn 4, 3 taps -> fn 5, 1 tap -> fn 1. */
static const uint8_t BINDINGS[4] = {4, 5, 0, 0};
#define SHORT_FN 1
#define THRESHOLD_MS 250

typedef struct {
    app_button_edge_queue_t queue;
    app_button_gesture_state_t gesture;
    app_button_tap_state_t tap;
    uint32_t press_ticks;    /* press edge of the current tap */
    uint32_t release_ticks;  /* release edge of the last tap */
    uint32_t next_ticks;     /* where the next edge is placed */
    uint8_t runs[8];
    uint8_t run_count;
} sim_t;

static void sim_init(sim_t *s) {
    memset(s, 0, sizeof(*s));
    app_button_edge_queue_init(&s->queue);
    app_button_gesture_init(&s->gesture);
    s->next_ticks = 1000;
}

static app_button_edge_push_result_t sim_edge(sim_t *s, bool pressed, uint32_t ticks) {
    return app_button_edge_push(&s->queue, pressed, ticks);
}

/* The drain of app_main.c: every queued edge goes through the gesture layer,
 * a short tap goes into the tap sequence and the sequence is resolved when
 * the inter-tap threshold expired. */
static void sim_drain(sim_t *s, uint32_t now) {
    app_button_edge_t e;
    while (app_button_edge_pop(&s->queue, &e)) {
        bool was_pressed = s->gesture.level_known && s->gesture.pressed;
        app_button_gesture_kind_t kind = app_button_gesture_on_edge(&s->gesture, e.pressed, e.ticks,
                                                                     MIN_TAP_TICKS, LONG_TICKS);
        if (!was_pressed && s->gesture.pressed) {
            s->press_ticks = e.ticks;
        }
        if (kind == APP_BUTTON_GESTURE_SHORT) {
            /* The gap since the previous release is longer than the
             * threshold: the previous sequence is resolved first. The
             * previous release is read before it is overwritten. */
            if (s->tap.count > 0) {
                uint32_t elapsed = (s->press_ticks - s->release_ticks) & TICK_MASK;
                if (elapsed > MS_TICKS(THRESHOLD_MS)) {
                    app_button_tap_result_t t = app_button_tap_timeout(&s->tap, SHORT_FN, BINDINGS);
                    if (t.run != APP_BUTTON_TAP_RUN_NONE) {
                        s->runs[s->run_count++] = t.function;
                    }
                }
            }
            s->release_ticks = e.ticks;
            app_button_tap_result_t r = app_button_tap_on_short_press(&s->tap, SHORT_FN, BINDINGS);
            if (r.run != APP_BUTTON_TAP_RUN_NONE) {
                s->runs[s->run_count++] = r.function;
            }
        } else if (kind == APP_BUTTON_GESTURE_LONG) {
            s->tap.count = 0;   /* long press: not a tap */
        }
    }
    if (s->tap.count > 0 && !s->gesture.pressed) {
        uint32_t elapsed = (now - s->release_ticks) & TICK_MASK;
        if (elapsed >= MS_TICKS(THRESHOLD_MS)) {
            app_button_tap_result_t t = app_button_tap_timeout(&s->tap, SHORT_FN, BINDINGS);
            if (t.run != APP_BUTTON_TAP_RUN_NONE) {
                s->runs[s->run_count++] = t.function;
            }
        }
    }
}

/* Press the button n times: every tap is held for press_ms, the gap
 * between the release and the next press is gap_ms. */
static void sim_taps(sim_t *s, int n, uint32_t press_ms, uint32_t gap_ms) {
    uint32_t t = s->next_ticks;
    for (int i = 0; i < n; i++) {
        CHECK(sim_edge(s, true, t) == APP_BUTTON_EDGE_PUSH_OK);
        uint32_t rel = t + MS_TICKS(press_ms);
        CHECK(sim_edge(s, false, rel) == APP_BUTTON_EDGE_PUSH_OK);
        sim_drain(s, rel);
        t = rel + MS_TICKS(gap_ms);
    }
    s->next_ticks = t;
}

/* The 3-tap gesture must run the 3-tap action, never the 2-tap action.
 * The gap is the time between the release of a tap and the press of the
 * next one: the old edge debounce dropped a press that came less than
 * 20 ms after the release, so the 3-tap gesture ran the 2-tap action. */
static void test_three_taps_run_the_third_action_only(uint32_t gap_ms) {
    sim_t s;
    sim_init(&s);
    sim_taps(&s, 3, 60, gap_ms);
    /* nothing may run before the threshold expires */
    CHECK(s.run_count == 0);
    uint32_t last_release = s.next_ticks - MS_TICKS(gap_ms);
    sim_drain(&s, last_release + MS_TICKS(THRESHOLD_MS) - 1);
    CHECK(s.run_count == 0);
    sim_drain(&s, last_release + MS_TICKS(THRESHOLD_MS));
    CHECK(s.run_count == 1);
    CHECK(s.runs[0] == 5);                    /* the 3-tap action */
    CHECK(s.runs[0] != 4);                    /* the 2-tap action must not run */
    printf("3 taps, gap %u ms -> fn %u\n", (unsigned)gap_ms, (unsigned)s.runs[0]);
}

static void test_two_taps_run_the_second_action_only(void) {
    sim_t s;
    sim_init(&s);
    sim_taps(&s, 2, 60, 40);
    CHECK(s.run_count == 0);
    uint32_t last_release = s.next_ticks - MS_TICKS(40);
    sim_drain(&s, last_release + MS_TICKS(THRESHOLD_MS));
    CHECK(s.run_count == 1);
    CHECK(s.runs[0] == 4);
    CHECK(s.runs[0] != 5);
}

/* A contact bounce burst is no tap: the tap that follows it is counted
 * exactly once. */
static void test_bounce_does_not_add_a_tap(void) {
    sim_t s;
    sim_init(&s);
    uint32_t t = s.next_ticks;
    /* the contact bounces for a few ms and settles closed */
    CHECK(sim_edge(&s, true, t) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(sim_edge(&s, false, t + MS_TICKS(2)) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(sim_edge(&s, true, t + MS_TICKS(3)) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(sim_edge(&s, false, t + MS_TICKS(5)) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(sim_edge(&s, true, t + MS_TICKS(6)) == APP_BUTTON_EDGE_PUSH_OK);
    uint32_t rel = t + MS_TICKS(60);
    CHECK(sim_edge(&s, false, rel) == APP_BUTTON_EDGE_PUSH_OK);
    sim_drain(&s, rel);
    CHECK(s.run_count == 0);
    CHECK(s.tap.count == 1);                 /* exactly one tap */
    CHECK(!s.gesture.pressed);               /* no dangling press */
    sim_drain(&s, rel + MS_TICKS(THRESHOLD_MS));
    CHECK(s.run_count == 1);
    CHECK(s.runs[0] == SHORT_FN);
}

/* One physical press with a bounce burst counts exactly ONE tap, so the
 * 2-tap action can never fire from a single press.
 *
 * press@0, release@2 ms, press@3 ms, release@25 ms, press@26 ms,
 * release@80 ms: the pressed segment from 3 to 25 ms (22 ms) is the bounce
 * burst. With the old 20 ms floor it was counted as a tap, the single
 * press counted as two taps and the 2-tap action (fn 4) fired. */
static void test_bounce_burst_counts_exactly_one_tap(void) {
    sim_t s;
    sim_init(&s);
    uint32_t t = s.next_ticks;
    CHECK(sim_edge(&s, true, t) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(sim_edge(&s, false, t + MS_TICKS(2)) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(sim_edge(&s, true, t + MS_TICKS(3)) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(sim_edge(&s, false, t + MS_TICKS(25)) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(sim_edge(&s, true, t + MS_TICKS(26)) == APP_BUTTON_EDGE_PUSH_OK);
    uint32_t rel = t + MS_TICKS(80);
    CHECK(sim_edge(&s, false, rel) == APP_BUTTON_EDGE_PUSH_OK);
    sim_drain(&s, rel);
    /* exactly one tap: the bounce burst is not a second one */
    CHECK(s.tap.count == 1);
    CHECK(s.run_count == 0);
    sim_drain(&s, rel + MS_TICKS(THRESHOLD_MS));
    /* the 1-tap action runs, the 2-tap action must not */
    CHECK(s.run_count == 1);
    CHECK(s.runs[0] == SHORT_FN);
    CHECK(s.runs[0] != 4);
    printf("bounce burst -> fn %u\n", (unsigned)s.runs[0]);
}

/* A single tap runs the 1-tap action when the threshold expires. */
static void test_single_tap_runs_the_short_action(void) {
    sim_t s;
    sim_init(&s);
    sim_taps(&s, 1, 60, 40);
    CHECK(s.run_count == 0);
    uint32_t last_release = s.next_ticks - MS_TICKS(40);
    sim_drain(&s, last_release + MS_TICKS(THRESHOLD_MS));
    CHECK(s.run_count == 1);
    CHECK(s.runs[0] == SHORT_FN);
}

static void test_buttons_are_independent(void) {
    sim_t a, b;
    sim_init(&a);
    sim_init(&b);
    CHECK(sim_edge(&a, true, 1000) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(sim_edge(&b, true, 1000) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(sim_edge(&a, false, 1000 + MS_TICKS(60)) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(sim_edge(&b, false, 1000 + MS_TICKS(60)) == APP_BUTTON_EDGE_PUSH_OK);
    sim_drain(&a, 1000 + MS_TICKS(60));
    CHECK(a.tap.count == 1);
    CHECK(b.tap.count == 0);
    sim_drain(&b, 1000 + MS_TICKS(60));
    CHECK(b.tap.count == 1);
}

int main(void) {
    test_three_taps_run_the_third_action_only(20);
    test_three_taps_run_the_third_action_only(10);
    test_three_taps_run_the_third_action_only(100);
    test_two_taps_run_the_second_action_only();
    test_bounce_does_not_add_a_tap();
    test_bounce_burst_counts_exactly_one_tap();
    test_single_tap_runs_the_short_action();
    test_buttons_are_independent();
    printf("%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
