#include "app_button_tap.h"

app_button_tap_result_t app_button_tap_on_short_press(uint32_t elapsed_ms,
                                                      uint8_t counter, uint8_t required,
                                                      uint32_t threshold_ms) {
    app_button_tap_result_t r = {0, false};
    if (required <= APP_BUTTON_TAP_MIN_COUNT) { r.count = 0; r.fire = true; return r; }
    if (counter == 0) { r.count = 1; return r; }
    if (elapsed_ms > threshold_ms) { r.count = 1; return r; }
    r.count = (uint8_t)(counter + 1);
    if (r.count >= required) { r.count = 0; r.fire = true; }
    return r;
}
