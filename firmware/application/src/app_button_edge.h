#ifndef APP_BUTTON_EDGE_H
#define APP_BUTTON_EDGE_H

#include <stdbool.h>
#include <stdint.h>

/* Edges one button can queue. Producer = GPIO ISR, consumer = main loop,
 * which drains the queue every iteration: 32 fits a contact-bounce burst
 * (a few edges) with room to spare. */
#define APP_BUTTON_EDGE_QUEUE_CAPACITY 32u

/* App-timer tick rate: 32768 Hz / (APP_TIMER_CONFIG_RTC_FREQUENCY + 1) with
 * APP_TIMER_CONFIG_RTC_FREQUENCY == 1 (firmware/application/src/sdk_config.h:6299)
 * => 16384 Hz. */
#define APP_BUTTON_EDGE_TICKS_PER_SECOND 16384u

/* The edge timestamps are the raw 24 bit RTC counter: it wraps every
 * 1024 s (0x01000000 ticks / 16384 Hz). The gesture layer compares the
 * timestamps with a masked difference, so a wrap is harmless. */
#define APP_BUTTON_EDGE_TICK_MASK 0x00FFFFFFu

typedef struct {
    bool pressed;    /* true = button went down, false = button came up */
    uint32_t ticks;  /* exact edge timestamp (RTC ticks) */
} app_button_edge_t;

typedef struct {
    app_button_edge_t entries[APP_BUTTON_EDGE_QUEUE_CAPACITY];
    volatile uint32_t head;  /* producer (ISR) */
    volatile uint32_t tail;  /* consumer (main loop) */
} app_button_edge_queue_t;

typedef enum {
    APP_BUTTON_EDGE_PUSH_OK = 0,  /* edge queued */
    APP_BUTTON_EDGE_PUSH_FULL,    /* dropped: queue full, nothing overwritten */
} app_button_edge_push_result_t;

void app_button_edge_queue_init(app_button_edge_queue_t *q);
app_button_edge_push_result_t app_button_edge_push(app_button_edge_queue_t *q,
                                                   bool pressed, uint32_t ticks);
bool app_button_edge_pop(app_button_edge_queue_t *q, app_button_edge_t *out);
uint32_t app_button_edge_pending(const app_button_edge_queue_t *q);

#endif
