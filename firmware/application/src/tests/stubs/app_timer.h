/* Host stub for the SDK's app_timer.h. */
#ifndef STUB_APP_TIMER_H
#define STUB_APP_TIMER_H

#include <stdint.h>

#define APP_TIMER_TICKS(ms) ((uint32_t)(ms))

static inline uint32_t app_timer_cnt_diff_compute(uint32_t now, uint32_t then) {
    return (uint32_t)(now - then);
}

#endif /* STUB_APP_TIMER_H */
