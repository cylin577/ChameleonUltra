#ifndef NFC_AMIIBO_REFRESH_BUTTON_H
#define NFC_AMIIBO_REFRESH_BUTTON_H

#include <stdbool.h>
#include <stdint.h>

#include "app_status.h"

typedef uint16_t (*nfc_amiibo_refresh_cb_t)(bool persist, uint8_t old_uid[7], uint8_t new_uid[7]);
typedef void (*nfc_amiibo_status_led_cb_t)(void);

/**
 * Decision logic for the "Refresh amiibo UID now" button action.
 *
 * The refresh and LED callbacks are injected so this can be tested without
 * NFC hardware, crypto or FDS. In firmware they are bound to
 * nfc_amiibo_refresh_slot() and the bounded offline_status_ok/error() blinks.
 * This runs in the main-loop button handler, never in an ISR. There is no
 * verify step: the refresh core validates keys/HMAC/signature before mutation.
 */
static inline void nfc_amiibo_refresh_button_run(bool field_on,
                                                 nfc_amiibo_refresh_cb_t refresh,
                                                 nfc_amiibo_status_led_cb_t show_ok,
                                                 nfc_amiibo_status_led_cb_t show_error) {
    if (field_on) {
        return;  /* field generator active: leave the simulated tag alone */
    }

    uint8_t old_uid[7];
    uint8_t new_uid[7];
    uint16_t status = refresh(true, old_uid, new_uid);  /* persist the refresh */
    if (status == STATUS_SUCCESS) {
        show_ok();
    } else {
        show_error();
    }
}

#endif
