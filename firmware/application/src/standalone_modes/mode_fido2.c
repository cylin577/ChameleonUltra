/*
 * mode_fido2.c
 *
 * Standalone mode: FIDO2 / CTAP2 authenticator (Ultra only).
 *
 * This file is the thin glue between the standalone framework and the FIDO2
 * library. All CTAP2 logic, credential storage and transport framing live in
 * src/fido2/; none of it is driven from here beyond arming the transports and
 * pumping them from the 5 ms mode tick.
 *
 * Transport ownership:
 *   USB HID  - initialised at boot by usb_main.c (f2_usb_hid_init()). This
 *              mode only arms/polls it; it must not init it a second time.
 *   BLE      - f2_ble_init() is called from ble_main.c services_init().
 *   NFC      - f2_nfc_init() is called once here, then armed/disarmed with the
 *              mode. The library owns the NFCT handler and installs it in
 *              init(); disarming is the way to hand the field back.
 *
 * User presence / verification:
 *   Any physical press (A or B) while armed -> grant UP + UV together, via
 *   mode_fido2_raw_press_grant() from the app_main button edge hook. No
 *   `hw settings btnpress` binding is required.
 *   TOGGLE (long press) -> framework arm/disarm, never intercepted here
 *   No CLEAR / very-long-press gesture is used for UV.
 *
 * There is no result blob: the debug surface is `hw fido2 ...` plus the
 * `get_status` lines from f2_core_status(). This mode writes no standalone
 * FDS results, and it does not write emulation slots or tag memory.
 *
 * Note: a button press is NOT FIDO-certified user verification. UV granted
 * from a button is a local convenience for bench use, not a biometric or PIN.
 */

#include "app_standalone.h"
#include "standalone_led.h"

#include "standalone_modes/mode_fido2.h"

#include "nrf_log.h"
#include "bsp/bsp_time.h"
#include "utils/syssleep.h"

#include "fido2/fido2_types.h"
#include "fido2/fido2_core.h"
#include "fido2/fido2_usb_hid.h"
#include "fido2/fido2_nfc.h"
#include "fido2/fido2_ble.h"

#if defined(PROJECT_CHAMELEON_ULTRA)

/* -------------------------------------------------------------------------
 * State
 * ------------------------------------------------------------------------- */

static bool s_active = false;
static bool s_nfc_inited = false;

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    (void)cfg;
    (void)cfg_len;

    f2_core_init();

    /* USB HID and BLE are initialised elsewhere at boot; NFC is ours. */
    if (!s_nfc_inited) {
        f2_nfc_init();
        s_nfc_inited = true;
    }

    f2_nfc_set_armed(true);
    f2_usb_hid_set_armed(true);
    f2_ble_set_armed(true);

    /* Authenticator traffic is latency-sensitive; do not let the device fall
     * asleep while armed (same policy as relay). */
    sleep_timer_stop();
    standalone_led_set_mode_color(STANDALONE_MODE_FIDO2, RGB_MAGENTA);

    s_active = true;
    NRF_LOG_INFO("fido2: armed");
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    if (!s_active) return STANDALONE_RC_OK;

    /* Drop any gate that was waiting on a button when the mode was disarmed. */
    f2_core_cancel();

    f2_nfc_set_armed(false);
    f2_usb_hid_set_armed(false);
    f2_ble_set_armed(false);

    s_active = false;
    sleep_timer_start(SLEEP_DELAY_MS_BUTTON_CLICK);
    NRF_LOG_INFO("fido2: disarmed");
    return STANDALONE_RC_OK;
}

/* -------------------------------------------------------------------------
 * Buttons
 * ------------------------------------------------------------------------- */

/* Raw press hook from app_main: grants UP then UV on any physical press.
 * UV is granted last because the core treats UV as satisfying a UP gate too,
 * so one press works for either ceremony. No CLEAR / very-long UV gesture. */
void mode_fido2_raw_press_grant(void) {
    if (!s_active) return;

    (void)f2_core_grant(FIDO2_GATE_UP);
    bool granted = (f2_core_grant(FIDO2_GATE_UV) == FIDO2_ST_OK);
    standalone_feedback(granted ? SL_FB_SUCCESS : SL_FB_DENIED);
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    /* STANDALONE_BTN_BOTH_LONG is the framework's arm/disarm toggle; it is
     * never intercepted here. UP/UV are now owned by the raw press hook. */
    (void)evt;
    return STANDALONE_RC_OK;
}

/* -------------------------------------------------------------------------
 * Tick (5 ms) - pump all transports. No FDS, no blocking, no extra WDT feed.
 * ------------------------------------------------------------------------- */

static standalone_rc_t on_tick(uint32_t now_ms) {
    (void)now_ms;
    if (!s_active) return STANDALONE_RC_OK;

    f2_core_tick(bsp_timer_now_ms());
    f2_usb_hid_poll();
    f2_ble_poll();
    f2_nfc_poll();
    return STANDALONE_RC_OK;
}

/* -------------------------------------------------------------------------
 * Results / status
 *
 * No result blob: credentials live in the FIDO2 library's own FDS records and
 * the debug surface is the `hw fido2 ...` command group. get_status delegates
 * to the core so `standalone status` reports live gate/transport state.
 * ------------------------------------------------------------------------- */

static size_t get_result_size(void) { return 0; }

static standalone_rc_t read_result(uint8_t *out, size_t out_max, size_t *out_len) {
    (void)out;
    (void)out_max;
    if (out_len != NULL) *out_len = 0;
    return STANDALONE_RC_NO_RESULT;
}

static void clear_result(void) { /* nothing to clear */ }

static size_t get_status(char *out, size_t out_max) {
    return f2_core_status(out, out_max);
}

/* -------------------------------------------------------------------------
 * Descriptor
 * ------------------------------------------------------------------------- */

const standalone_mode_iface_t mode_fido2_iface = {
    .id                              = STANDALONE_MODE_FIDO2,
    .name                            = "FIDO2",
    .writes_tag                      = false,
    .writes_slot                     = false,
    .wants_tick                      = true,
    .requires_physical_user_presence = true,
    .tick_interval_ms                = 5u,
    .on_enter                        = on_enter,
    .on_exit                         = on_exit,
    .on_button                       = on_button,
    .on_tick                         = on_tick,
    .get_result_size                 = get_result_size,
    .read_result                     = read_result,
    .clear_result                    = clear_result,
    .ensure_loaded                   = NULL,
    .get_status                      = get_status,
};

#endif /* PROJECT_CHAMELEON_ULTRA */
