#include "app_button_edge.h"

/* The producer writes the entry and then publishes head; the consumer reads
 * head and then the entry. The fence keeps the entry visible across the
 * ISR boundary (ARMv7-M may reorder stores/loads). */
static inline void app_button_edge_fence(void) {
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

void app_button_edge_queue_init(app_button_edge_queue_t *q) {
    q->head = 0;
    q->tail = 0;
    /* entries[] needs no clearing: head == tail means "empty". */
}

/* Every edge is queued: dropping an edge by time loses a tap (the release
 * of a fast tap lands inside the window of the next press). Contact bounce
 * is filtered later, by the press duration, in the gesture layer. */
app_button_edge_push_result_t app_button_edge_push(app_button_edge_queue_t *q,
                                                   bool pressed, uint32_t ticks) {
    uint32_t head = q->head;
    uint32_t tail = q->tail;
    if ((head - tail) >= APP_BUTTON_EDGE_QUEUE_CAPACITY) {
        /* Full: refuse the edge, keep the queued ones. */
        return APP_BUTTON_EDGE_PUSH_FULL;
    }
    q->entries[head % APP_BUTTON_EDGE_QUEUE_CAPACITY].pressed = pressed;
    q->entries[head % APP_BUTTON_EDGE_QUEUE_CAPACITY].ticks = ticks;
    app_button_edge_fence();
    q->head = head + 1;
    return APP_BUTTON_EDGE_PUSH_OK;
}

bool app_button_edge_pop(app_button_edge_queue_t *q, app_button_edge_t *out) {
    uint32_t tail = q->tail;
    uint32_t head = q->head;
    if (tail == head) {
        return false;
    }
    app_button_edge_fence();
    *out = q->entries[tail % APP_BUTTON_EDGE_QUEUE_CAPACITY];
    q->tail = tail + 1;
    return true;
}

uint32_t app_button_edge_pending(const app_button_edge_queue_t *q) {
    return q->head - q->tail;   /* no shared count field */
}
