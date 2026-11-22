#ifndef NFC_AMIIBO_AUTO_REFRESH_BUTTON_H
#define NFC_AMIIBO_AUTO_REFRESH_BUTTON_H

#include <stdbool.h>
#include <stdint.h>

typedef void (*nfc_amiibo_auto_refresh_arm_cb_t)(uint8_t slot, bool persist);
typedef void (*nfc_amiibo_auto_refresh_disarm_cb_t)(void);
typedef void (*nfc_amiibo_auto_refresh_led_cb_t)(void);

/**
 * Decision logic for the "Toggle amiibo auto-refresh" button action (ID 11).
 *
 * `armed` is the current detector state (nfc_amiibo_auto_refresh_is_armed()
 * in firmware, injected here so the decision is host-testable). Every side
 * effect sits behind an injected callback:
 *   arm(slot, true)   -> main-loop wrapper: init if needed, arm, save FDS record
 *   disarm()          -> main-loop wrapper: disarm, clear the FDS record
 *   show_arm/show_disarm/show_error -> bounded LED animations
 *
 * Exactly one LED callback runs for an actionable press, none when the field
 * generator is on. No FDS/crypto/hardware here and no ISR: this is called from
 * the main-loop button handler only.
 */
static inline void nfc_amiibo_auto_refresh_button_run(bool field_on,
                                                       bool armed,
                                                       bool slot_is_ntag215,
                                                       uint8_t slot,
                                                       nfc_amiibo_auto_refresh_arm_cb_t arm,
                                                       nfc_amiibo_auto_refresh_disarm_cb_t disarm,
                                                       nfc_amiibo_auto_refresh_led_cb_t show_arm,
                                                       nfc_amiibo_auto_refresh_led_cb_t show_disarm,
                                                       nfc_amiibo_auto_refresh_led_cb_t show_error) {
    if (field_on) {
        return;  /* field generator active: leave the simulated tag alone */
    }
    if (armed) {
        disarm();        /* wrapper disarms and clears the persisted record */
        show_disarm();
        return;
    }
    if (!slot_is_ntag215) {
        show_error();    /* only an NTAG215 slot can be armed */
        return;
    }
    arm(slot, true);     /* wrapper arms with persist and saves the FDS record */
    show_arm();
}

#endif /* NFC_AMIIBO_AUTO_REFRESH_BUTTON_H */
