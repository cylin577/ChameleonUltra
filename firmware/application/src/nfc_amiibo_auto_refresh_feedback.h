#ifndef NFC_AMIIBO_AUTO_REFRESH_FEEDBACK_H
#define NFC_AMIIBO_AUTO_REFRESH_FEEDBACK_H

#include <stdint.h>

#include "nfc_amiibo_auto_refresh_button.h"  /* nfc_amiibo_auto_refresh_led_cb_t */
#include "rfid/nfctag/hf/nfc_amiibo_refresh_feedback.h"  /* blink counts */

/* Distinct blink patterns for arm/disarm: the UID-refresh path emits exactly
 * one blink, so a double for arm and a triple for disarm read as different
 * actions. These helpers are the host-test adapters for the pattern counts;
 * the firmware arm/disarm bindings only REQUEST the deferred animation, so no
 * command response waits on these blinks. */


static inline void nfc_amiibo_auto_refresh_arm_blinks(nfc_amiibo_auto_refresh_led_cb_t blink) {
    for (uint8_t i = 0; i < NFC_AMIIBO_ARM_BLINK_COUNT; i++) {
        blink();
    }
}

static inline void nfc_amiibo_auto_refresh_disarm_blinks(nfc_amiibo_auto_refresh_led_cb_t blink) {
    for (uint8_t i = 0; i < NFC_AMIIBO_DISARM_BLINK_COUNT; i++) {
        blink();
    }
}

/* Firmware bindings (defined in app_main.c): arm requests a double green
 * blink, disarm a triple red blink, both deferred to the main loop. Declared
 * here so app_cmd.c can use them at the CMD 1071 action sites without
 * duplicating the pattern or touching hardware. Host tests exercise the two
 * pattern helpers above with injected callbacks. */
void nfc_amiibo_auto_refresh_arm_led(void);
void nfc_amiibo_auto_refresh_disarm_led(void);

#endif /* NFC_AMIIBO_AUTO_REFRESH_FEEDBACK_H */
