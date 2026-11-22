#ifndef NFC_AMIIBO_REFRESH_SLEEP_H
#define NFC_AMIIBO_REFRESH_SLEEP_H

#include <stdbool.h>
#include <stdint.h>

#include "../../../app_status.h"

/* Refresh entry shape shared with nfc_amiibo_refresh_slot(). */
typedef uint16_t (*nfc_amiibo_sleep_refresh_cb_t)(bool persist, uint8_t old_uid[7], uint8_t new_uid[7]);

/* Sleep reset hook. Firmware binds this to the configured sleep timeout. */
typedef void (*nfc_amiibo_sleep_reset_cb_t)(void);

/* Bounded status LED hook: offline_status_ok/error() in firmware. */
typedef void (*nfc_amiibo_status_led_cb_t)(void);

/**
 * Run one Amiibo refresh attempt and reset the sleep timer afterwards,
 * regardless of the refresh status. Both success and failure reset sleep so
 * the user stays awake long enough to read the LED blink or command response.
 * Shared by the CMD 1070, auto-refresh and button paths via the refresh core.
 */
static inline uint16_t nfc_amiibo_refresh_with_sleep_reset(
    nfc_amiibo_sleep_refresh_cb_t refresh,
    bool persist,
    uint8_t old_uid[7],
    uint8_t new_uid[7],
    nfc_amiibo_sleep_reset_cb_t reset_sleep) {
    uint16_t status = refresh(persist, old_uid, new_uid);
    reset_sleep();
    return status;
}

/**
 * Production refresh wrapper: one attempt, one bounded LED blink, one sleep
 * reset. Shared by CMD 1070, the main-loop auto-refresh hook and the button
 * action via nfc_amiibo_refresh_slot(), so each attempt blinks exactly once.
 * Both hooks are injected for host tests; in firmware they are bound to
 * offline_status_ok/error() and the configured sleep timeout. Call only from
 * main-loop/command context, never from an ISR.
 */
static inline uint16_t nfc_amiibo_refresh_with_feedback(
    nfc_amiibo_sleep_refresh_cb_t refresh,
    bool persist,
    uint8_t old_uid[7],
    uint8_t new_uid[7],
    nfc_amiibo_sleep_reset_cb_t reset_sleep,
    nfc_amiibo_status_led_cb_t show_ok,
    nfc_amiibo_status_led_cb_t show_error) {
    uint16_t status = nfc_amiibo_refresh_with_sleep_reset(
        refresh, persist, old_uid, new_uid, reset_sleep);
    if (status == STATUS_SUCCESS) {
        show_ok();
    } else {
        show_error();
    }
    return status;
}

#endif
