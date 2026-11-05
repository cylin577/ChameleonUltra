/*
 * Native unit tests for app_button_edge. Build + run:
 *   make -C firmware/application/src/tests
 */
#include "../app_button_edge.h"

#include <stdio.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static void test_init_gives_an_empty_queue(void) {
    app_button_edge_queue_t q;
    app_button_edge_queue_init(&q);
    app_button_edge_t e;
    CHECK(app_button_edge_pending(&q) == 0);
    CHECK(!app_button_edge_pop(&q, &e));
}

static void test_push_then_pop_keeps_the_edge(void) {
    app_button_edge_queue_t q;
    app_button_edge_queue_init(&q);
    CHECK(app_button_edge_push(&q, true, 1234) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(app_button_edge_pending(&q) == 1);
    app_button_edge_t e;
    CHECK(app_button_edge_pop(&q, &e));
    CHECK(e.pressed);
    CHECK(e.ticks == 1234);
    CHECK(app_button_edge_pending(&q) == 0);
    CHECK(!app_button_edge_pop(&q, &e));
}

static void test_edges_keep_their_order(void) {
    app_button_edge_queue_t q;
    app_button_edge_queue_init(&q);
    CHECK(app_button_edge_push(&q, true, 1000) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(app_button_edge_push(&q, false, 2000) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(app_button_edge_push(&q, true, 3000) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(app_button_edge_pending(&q) == 3);
    app_button_edge_t e;
    CHECK(app_button_edge_pop(&q, &e) && e.pressed && e.ticks == 1000);
    CHECK(app_button_edge_pop(&q, &e) && !e.pressed && e.ticks == 2000);
    CHECK(app_button_edge_pop(&q, &e) && e.pressed && e.ticks == 3000);
    CHECK(!app_button_edge_pop(&q, &e));
}

/* No edge is dropped by time: a contact bounce and a fast tap have to
 * reach the gesture layer, which filters the bounce by press duration. */
static void test_every_edge_is_accepted(void) {
    app_button_edge_queue_t q;
    app_button_edge_queue_init(&q);
    CHECK(app_button_edge_push(&q, true, 1000) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(app_button_edge_push(&q, false, 1001) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(app_button_edge_push(&q, true, 1002) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(app_button_edge_pending(&q) == 3);
    app_button_edge_t e;
    CHECK(app_button_edge_pop(&q, &e) && e.pressed && e.ticks == 1000);
    CHECK(app_button_edge_pop(&q, &e) && !e.pressed && e.ticks == 1001);
    CHECK(app_button_edge_pop(&q, &e) && e.pressed && e.ticks == 1002);
}

/* A contact bounce burst fits into the queue. */
static void test_bounce_burst_fits_into_the_queue(void) {
    app_button_edge_queue_t q;
    app_button_edge_queue_init(&q);
    for (uint32_t i = 0; i < 16; i++) {
        CHECK(app_button_edge_push(&q, (i % 2) == 0, 1000 + i) == APP_BUTTON_EDGE_PUSH_OK);
    }
    CHECK(app_button_edge_pending(&q) == 16);
}

static void test_full_queue_never_overwrites(void) {
    app_button_edge_queue_t q;
    app_button_edge_queue_init(&q);
    for (uint32_t i = 0; i < APP_BUTTON_EDGE_QUEUE_CAPACITY; i++) {
        CHECK(app_button_edge_push(&q, true, 1000 + i) == APP_BUTTON_EDGE_PUSH_OK);
    }
    CHECK(app_button_edge_pending(&q) == APP_BUTTON_EDGE_QUEUE_CAPACITY);
    /* the queue is full: the edge is refused, not silently dropped */
    CHECK(app_button_edge_push(&q, false, 999999) == APP_BUTTON_EDGE_PUSH_FULL);
    CHECK(app_button_edge_pending(&q) == APP_BUTTON_EDGE_QUEUE_CAPACITY);
    app_button_edge_t e;
    CHECK(app_button_edge_pop(&q, &e) && e.ticks == 1000);
    CHECK(app_button_edge_pop(&q, &e) && e.ticks == 1001);
    /* the refused edge never made it into the queue */
    for (uint32_t i = 2; i < APP_BUTTON_EDGE_QUEUE_CAPACITY; i++) {
        CHECK(app_button_edge_pop(&q, &e) && e.ticks == 1000 + i);
    }
    CHECK(!app_button_edge_pop(&q, &e));
}

static void test_queues_are_independent(void) {
    app_button_edge_queue_t a, b;
    app_button_edge_queue_init(&a);
    app_button_edge_queue_init(&b);
    CHECK(app_button_edge_push(&a, true, 1000) == APP_BUTTON_EDGE_PUSH_OK);
    CHECK(app_button_edge_pending(&a) == 1);
    CHECK(app_button_edge_pending(&b) == 0);
    app_button_edge_t e;
    CHECK(!app_button_edge_pop(&b, &e));
    CHECK(app_button_edge_pending(&a) == 1);
}

/* The edge timestamps are the raw 24 bit RTC counter: they are stored
 * verbatim, the wrap is handled by the difference in the gesture layer. */
static void test_tick_counter_wrap_is_handled(void) {
    app_button_edge_queue_t q;
    app_button_edge_queue_init(&q);
    uint32_t near_wrap = 0x00FFFFF0u;
    CHECK(app_button_edge_push(&q, true, near_wrap) == APP_BUTTON_EDGE_PUSH_OK);
    uint32_t after_wrap = (near_wrap + 100u) & APP_BUTTON_EDGE_TICK_MASK;
    CHECK(after_wrap < near_wrap);
    CHECK(app_button_edge_push(&q, false, after_wrap) == APP_BUTTON_EDGE_PUSH_OK);
    app_button_edge_t e;
    CHECK(app_button_edge_pop(&q, &e) && e.ticks == near_wrap);
    CHECK(app_button_edge_pop(&q, &e) && e.ticks == after_wrap);
}

int main(void) {
    test_init_gives_an_empty_queue();
    test_push_then_pop_keeps_the_edge();
    test_edges_keep_their_order();
    test_every_edge_is_accepted();
    test_bounce_burst_fits_into_the_queue();
    test_full_queue_never_overwrites();
    test_queues_are_independent();
    test_tick_counter_wrap_is_handled();
    printf("%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
