#ifndef APP_BUTTON_TAP_H
#define APP_BUTTON_TAP_H

#include <stdbool.h>
#include <stdint.h>

#define APP_BUTTON_TAP_MAX_COUNT      5u
#define APP_BUTTON_TAP_BIND_MIN_COUNT 2u
#define APP_BUTTON_TAP_BIND_COUNT     4u  /* tap counts 2,3,4,5 */
#define APP_BUTTON_TAP_BIND_TOTAL     8u  /* 2 buttons x 4 tap counts */

/* Per-button tap-sequence state. */
typedef struct {
    uint8_t count;  /* taps in the current sequence (0 = no sequence) */
    bool    fired;  /* a binding already ran in this sequence */
} app_button_tap_state_t;

/* What the firmware should run right now. */
typedef enum {
    APP_BUTTON_TAP_RUN_NONE = 0,  /* nothing yet: wait for a tap or the threshold */
    APP_BUTTON_TAP_RUN_SHORT,     /* run the button's short-press function (the 1-tap action) */
    APP_BUTTON_TAP_RUN_BINDING,   /* run the binding of the current tap count */
} app_button_tap_run_t;

typedef struct {
    app_button_tap_run_t run;  /* what to do now */
    uint8_t function;          /* the function code to run (0 = none) */
    uint8_t count;             /* the tap count after this event */
} app_button_tap_result_t;

/* Register a short-press release in the button's tap sequence.
 *
 * The caller owns the timing: it must resolve an already-expired sequence
 * with app_button_tap_timeout() before calling this.
 *
 * @param state        in/out: the button's tap-sequence state
 * @param short_fn     the button's short-press function code (the 1-tap action)
 * @param bindings     the 4 function codes for tap counts 2..5 (0 = Disable)
 */
app_button_tap_result_t app_button_tap_on_short_press(app_button_tap_state_t *state,
                                                      uint8_t short_fn,
                                                      const uint8_t *bindings);

/* Resolve a sequence whose inter-tap threshold expired.
 *
 * The action is chosen by the FINAL tap count: count == 1 runs the short-press
 * function; count >= 2 runs the binding of that exact tap count (nothing runs
 * when that slot is unbound). The state is reset.
 */
app_button_tap_result_t app_button_tap_timeout(app_button_tap_state_t *state,
                                               uint8_t short_fn,
                                               const uint8_t *bindings);

/* Pack/unpack the 8 bindable function codes into 4 bytes (4 bits each).
 * packed[0] = fn[0] | fn[1]<<4, packed[1] = fn[2] | fn[3]<<4, ... */
void app_button_tap_pack(const uint8_t fn[APP_BUTTON_TAP_BIND_TOTAL], uint8_t packed[4]);
void app_button_tap_unpack(const uint8_t packed[4], uint8_t fn[APP_BUTTON_TAP_BIND_TOTAL]);
uint8_t app_button_tap_get(const uint8_t packed[4], uint8_t index);
void app_button_tap_set(uint8_t packed[4], uint8_t index, uint8_t fn);

/* Convert a timer tick count to milliseconds. */
uint32_t app_button_tap_elapsed_ms(uint32_t elapsed_ticks, uint32_t ticks_per_second);

#endif
