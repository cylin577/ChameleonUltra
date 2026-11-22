#ifndef NFC_AMIIBO_REFRESH_BUTTON_H
#define NFC_AMIIBO_REFRESH_BUTTON_H

#include <stdbool.h>
#include <stdint.h>

#include "app_status.h"

typedef uint16_t (*nfc_amiibo_refresh_cb_t)(bool persist, uint8_t old_uid[7], uint8_t new_uid[7]);

/**
 * Decision logic for the "Refresh amiibo UID now" button action.
 *
 * The refresh callback is injected so this can be tested without NFC
 * hardware, crypto or FDS. In firmware it is bound to
 * nfc_amiibo_refresh_slot(), whose shared wrapper owns the single bounded
 * OK/error blink. This helper only guards the field-on case; it must not add
 * a second blink. Runs in the main-loop button handler, never in an ISR.
 */
static inline void nfc_amiibo_refresh_button_run(bool field_on,
                                                 nfc_amiibo_refresh_cb_t refresh) {
    if (field_on) {
        return;  /* field generator active: leave the simulated tag alone */
    }

    uint8_t old_uid[7];
    uint8_t new_uid[7];
    (void)refresh(true, old_uid, new_uid);  /* persist the refresh */
}

#endif
