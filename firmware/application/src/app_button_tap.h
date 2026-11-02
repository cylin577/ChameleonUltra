#ifndef APP_BUTTON_TAP_H
#define APP_BUTTON_TAP_H

#include <stdbool.h>
#include <stdint.h>

#define APP_BUTTON_TAP_MIN_COUNT 1u
#define APP_BUTTON_TAP_MAX_COUNT 5u

typedef struct {
    uint8_t count;  /* pending taps after this tap (0 = sequence finished) */
    bool    fire;   /* true when the configured function must run now */
} app_button_tap_result_t;

/* Register a short-press release in a multi-tap sequence.
 *
 * @param elapsed_ms  Time since the previous tap's release, in milliseconds.
 *                    The caller owns the measurement so it can use the
 *                    wrap-safe timer diff; it is ignored for the first tap
 *                    of a sequence (counter == 0).
 * @param counter     Taps already pending in the current sequence.
 * @param required    Taps needed to fire (1..5).
 * @param threshold_ms Maximum gap between taps, in milliseconds.
 */
app_button_tap_result_t app_button_tap_on_short_press(uint32_t elapsed_ms,
                                                      uint8_t counter,
                                                      uint8_t required,
                                                      uint32_t threshold_ms);

#endif
