#ifndef APP_BUTTON_TAP_H
#define APP_BUTTON_TAP_H

#include <stdbool.h>
#include <stdint.h>

#define APP_BUTTON_TAP_MAX_COUNT      5u
#define APP_BUTTON_TAP_BIND_MIN_COUNT 2u
#define APP_BUTTON_TAP_BIND_COUNT     4u  /* tap counts 2,3,4,5 */
#define APP_BUTTON_TAP_BIND_TOTAL     8u  /* 2 buttons x 4 tap counts */

/* A press shorter than this is contact bounce, not a tap.
 *
 * A human tap lasts 50-150 ms and a single contact bounce 1-5 ms, but a
 * bounce burst can hold the contact closed for a few tens of ms: with a
 * 20 ms floor such a burst was counted as an extra tap. The floor is
 * 40 ms, so one physical press can never count as two taps.
 *
 * The floor is on the PRESS DURATION only: the gap between two taps is not
 * limited, so a fast sequence of taps is still accepted. This replaces the
 * old firmware's 50 ms anti-shake window, which swallowed every press
 * shorter than 50 ms: the floor is still more permissive than that was. */
#define APP_BUTTON_GESTURE_MIN_TAP_MS 40u

/* What the gesture layer makes of a level segment. */
typedef enum {
    APP_BUTTON_GESTURE_NONE = 0,  /* nothing (bounce, or a segment that started) */
    APP_BUTTON_GESTURE_SHORT,     /* a short tap: feed the tap sequence */
    APP_BUTTON_GESTURE_LONG,      /* a long press */
} app_button_gesture_kind_t;

/* The level segment the button is currently in. */
typedef struct {
    bool level_known;      /* a level has been seen */
    bool pressed;          /* current level (true = pressed) */
    uint32_t segment_ticks; /* tick at which the current level segment started */
} app_button_gesture_state_t;

/* Reset the gesture state (no level seen yet). */
void app_button_gesture_init(app_button_gesture_state_t *st);

/* Feed one edge. Returns the gesture when a tap/hold completes.
 * The level segment is measured edge-to-edge, so a long press is exact.
 *
 * An edge whose level equals the stored level is ignored (no transition).
 * On a transition the segment that just ended lasted
 * (ticks - segment_ticks):
 *  - a pressed segment shorter than min_tap_ticks is contact bounce,
 *  - a pressed segment of min_tap_ticks .. long_press_ticks is a SHORT tap,
 *  - a pressed segment of long_press_ticks or more is a LONG press,
 *  - a released segment never makes a gesture.
 * The state always matches the last edge, so a bounce burst can never leave
 * a dangling press or release. */
app_button_gesture_kind_t app_button_gesture_on_edge(app_button_gesture_state_t *st,
                                                     bool pressed, uint32_t ticks,
                                                     uint32_t min_tap_ticks,
                                                     uint32_t long_press_ticks);

/* Per-button tap-sequence state. */
typedef struct {
    uint8_t count;  /* taps in the current sequence (0 = no sequence) */
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
 * Rules:
 *  - count >= 2 NEVER runs an action here. The final tap count is only
 *    known when the threshold expires, so the action of the final count is
 *    run by app_button_tap_timeout(). This is what stops a 3-tap gesture
 *    from firing the 2-tap action.
 *  - count == 1 runs the short-press function immediately ONLY when the
 *    button has no multi-tap binding at all. Otherwise the 1-tap action
 *    also waits for the threshold.
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
 * The action is chosen by the FINAL tap count: count == 1 runs the
 * short-press function; count >= 2 runs the binding of that exact tap count
 * (nothing runs when that slot is unbound). The state is reset.
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
