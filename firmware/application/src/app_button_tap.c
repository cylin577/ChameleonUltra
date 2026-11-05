#include "app_button_tap.h"

static bool bindings_have_any(const uint8_t *bindings) {
    for (uint8_t i = 0; i < APP_BUTTON_TAP_BIND_COUNT; i++) {
        if (bindings[i] != 0) {
            return true;
        }
    }
    return false;
}

/* Is any tap count above `count` bound? */
static bool bindings_have_any_above(const uint8_t *bindings, uint8_t count) {
    for (uint8_t taps = (uint8_t)(count + 1); taps <= APP_BUTTON_TAP_MAX_COUNT; taps++) {
        if (bindings[taps - APP_BUTTON_TAP_BIND_MIN_COUNT] != 0) {
            return true;
        }
    }
    return false;
}

app_button_tap_result_t app_button_tap_on_short_press(app_button_tap_state_t *state,
                                                      uint8_t short_fn,
                                                      const uint8_t *bindings) {
    app_button_tap_result_t r = {APP_BUTTON_TAP_RUN_NONE, 0, state->count};

    if (state->count < APP_BUTTON_TAP_MAX_COUNT) {
        state->count++;
    }
    r.count = state->count;

    if (state->fired) {
        /* The sequence already ran: keep it open until the threshold expires
         * so a further tap does not start a fresh 1-tap sequence. */
        return r;
    }

    if (state->count == 1) {
        /* The 1-tap action has to wait for the threshold when a multi-tap
         * gesture is possible on this button, otherwise a 2-tap press would
         * fire the 1-tap action first. With no multi-tap binding the action
         * runs immediately (unchanged legacy behaviour, no added latency) and
         * the sequence is complete: every tap is an independent 1-tap gesture. */
        if (!bindings_have_any(bindings)) {
            if (short_fn != 0) {
                r.run = APP_BUTTON_TAP_RUN_SHORT;
                r.function = short_fn;
                state->count = 0;
                state->fired = false;
            }
        }
        return r;
    }

    uint8_t fn = bindings[state->count - APP_BUTTON_TAP_BIND_MIN_COUNT];
    if (fn == 0) {
        /* No function is bound to this tap count. Keep waiting: the user may
         * still be tapping and a higher count may be bound. */
        return r;
    }
    if (bindings_have_any_above(bindings, state->count)) {
        /* A higher tap count is bound, so the user may still be tapping: this
         * action only runs when the threshold expires and the final tap count
         * is known. */
        return r;
    }
    r.run = APP_BUTTON_TAP_RUN_BINDING;
    r.function = fn;
    state->fired = true;
    return r;
}

app_button_tap_result_t app_button_tap_timeout(app_button_tap_state_t *state,
                                               uint8_t short_fn,
                                               const uint8_t *bindings) {
    app_button_tap_result_t r = {APP_BUTTON_TAP_RUN_NONE, 0, state->count};
    if (!state->fired && (state->count > 0)) {
        if (state->count == 1) {
            if (short_fn != 0) {
                r.run = APP_BUTTON_TAP_RUN_SHORT;
                r.function = short_fn;
            }
        } else {
            uint8_t fn = bindings[state->count - APP_BUTTON_TAP_BIND_MIN_COUNT];
            if (fn != 0) {
                r.run = APP_BUTTON_TAP_RUN_BINDING;
                r.function = fn;
            }
        }
    }
    state->count = 0;
    state->fired = false;
    return r;
}

void app_button_tap_pack(const uint8_t fn[APP_BUTTON_TAP_BIND_TOTAL], uint8_t packed[4]) {
    for (uint8_t i = 0; i < 4; i++) {
        packed[i] = (uint8_t)((fn[i * 2] & 0x0F) | ((fn[i * 2 + 1] & 0x0F) << 4));
    }
}

void app_button_tap_unpack(const uint8_t packed[4], uint8_t fn[APP_BUTTON_TAP_BIND_TOTAL]) {
    for (uint8_t i = 0; i < 4; i++) {
        fn[i * 2] = (uint8_t)(packed[i] & 0x0F);
        fn[i * 2 + 1] = (uint8_t)(packed[i] >> 4);
    }
}

uint8_t app_button_tap_get(const uint8_t packed[4], uint8_t index) {
    if (index >= APP_BUTTON_TAP_BIND_TOTAL) {
        return 0;
    }
    return (uint8_t)((packed[index / 2] >> ((index % 2) * 4)) & 0x0F);
}

void app_button_tap_set(uint8_t packed[4], uint8_t index, uint8_t fn) {
    if (index >= APP_BUTTON_TAP_BIND_TOTAL) {
        return;
    }
    uint8_t shift = (uint8_t)((index % 2) * 4);
    packed[index / 2] = (uint8_t)((packed[index / 2] & ~(0x0F << shift)) | ((fn & 0x0F) << shift));
}

uint32_t app_button_tap_elapsed_ms(uint32_t elapsed_ticks, uint32_t ticks_per_second) {
    if (ticks_per_second == 0) { return 0; }
    return (uint32_t)(((uint64_t)elapsed_ticks * 1000ULL) / ticks_per_second);
}
