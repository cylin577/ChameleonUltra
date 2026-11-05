#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "crc_utils.h"
#include "app_status.h"
#include "settings.h"
#include "app_button_tap.h"
#include "fds_ids.h"
#include "fds_util.h"

_Static_assert(sizeof(settings_data_t) == 40, "settings record size must stay 40 bytes (10 FDS words)");
_Static_assert(sizeof(settings_data_t) % 4 == 0, "settings record must be a whole number of FDS words");
_Static_assert(offsetof(settings_data_t, multi_tap_bindings) == 33, "multi-tap bindings must start @33");
_Static_assert(offsetof(settings_data_t, multi_tap_threshold) == 37, "threshold must be @37");
_Static_assert(offsetof(settings_data_t, reserved1) == 38, "reserved tail must start @38");

#define NRF_LOG_MODULE_NAME settings
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();


static settings_data_t config;
static uint16_t m_config_crc;
static bool m_ble_pairing_enable_first_load_value;

static void update_config_crc(void) {
    calc_14a_crc_lut((uint8_t *)&config, sizeof(config), (uint8_t *)&m_config_crc);
}

static bool config_did_change(void) {
    uint16_t new_calc_crc;
    calc_14a_crc_lut((uint8_t *)&config, sizeof(config), (uint8_t *)&new_calc_crc);
    return new_calc_crc != m_config_crc;
}

void settings_update_version_for_config(void) {
    config.version = SETTINGS_CURRENT_VERSION;
}

// add on version2
void settings_init_button_press_config(void) {
    config.button_a_press = SettingsButtonCycleSlot;
    config.button_b_press = SettingsButtonCycleSlotDec;
}

// add on version3
void settings_init_button_long_press_config(void) {
    config.button_a_long_press = SettingsButtonCloneIcUid;
    config.button_b_long_press = SettingsButtonShowBattery;
}

// add on version4
void settings_init_ble_connect_key_config(void) {
    uint8_t p_key_u8[] = DEFAULT_BLE_PAIRING_KEY;
    settings_set_ble_connect_key(p_key_u8);
}

// add on version5
void settings_init_ble_pairing_enable_config(void) {
    config.ble_pairing_enable = false;
}

// add on version6
void settings_init_sleep_timeout_config(void) {
    config.sleep_timeout = SETTINGS_SLEEP_TIMEOUT_DEFAULT_S;
}

// add on version7
void settings_init_ble_name_config(void) {
    memset(config.ble_name, 0, sizeof(config.ble_name)); // empty = use firmware default name
}

// add on version8
void settings_init_multi_tap_config(void) {
    config.multi_tap_threshold = SETTINGS_MULTI_TAP_DEFAULT_MS / SETTINGS_MULTI_TAP_UNIT_MS;
}

// add on version9
void settings_init_multi_tap_bindings(void) {
    memset(config.multi_tap_bindings, 0, sizeof(config.multi_tap_bindings)); // every binding = Disable
}

void settings_init_config(void) {
    settings_update_version_for_config();
    config.animation_config = SettingsAnimationModeFull; // add on version1
    settings_init_button_press_config();
    settings_init_button_long_press_config();
    settings_init_ble_connect_key_config();
    settings_init_ble_pairing_enable_config();
    settings_init_sleep_timeout_config();
    settings_init_ble_name_config();
    settings_init_multi_tap_config();
    settings_init_multi_tap_bindings();
}

void settings_migrate(void) {
    switch (config.version) {
        case 0:
            NRF_LOG_ERROR("Unexpected configuration version detected!");
            settings_init_config();

        case 1:
            settings_init_button_press_config();

        case 2:
            settings_init_button_long_press_config();

        case 3:
            settings_init_ble_connect_key_config();

        case 4:
            settings_init_ble_pairing_enable_config();

        case 5:
            settings_init_sleep_timeout_config();

        case 6:
            settings_init_ble_name_config();

        case 7:
            // version<=7 records carry garbage in the struct's tail padding
            // bytes, so the multi-tap config is always re-initialized here.
            settings_init_multi_tap_config();

        case 8:
            // version8 records carry the retired per-button tap-count bytes;
            // the new binding table (bytes 33..36 of the version8 layout) is
            // always re-initialized here. The version8 threshold byte moves
            // from @35 to @37, so the threshold is reset to the default too.
            settings_init_multi_tap_config();
            settings_init_multi_tap_bindings();

            /*
             * Add new migration steps ABOVE THIS COMMENT
             * `settings_update_version_for_config()` and `break` statements should only be used on the last migration step, all the previous steps must fall
             * through to the next case.
             */

            settings_update_version_for_config();
            break;
        default:
            NRF_LOG_ERROR("Unsupported configuration migration attempted! (%d -> %d)", config.version, SETTINGS_CURRENT_VERSION);
            break;
    }
}

void settings_load_config(void) {
    uint16_t length = sizeof(config);
    bool ret = fds_read_sync(FDS_SETTINGS_FILE_ID, FDS_SETTINGS_RECORD_KEY, &length, (uint8_t *)&config);
    if (ret) {
        NRF_LOG_INFO("Load config done.");
        // After the reading is complete, we first save a copy of the current CRC, which can be used as a reference for comparison of changes when saving later
        update_config_crc();
    } else {
        NRF_LOG_WARNING("Config does not exist, loading default values...");
        settings_init_config();
    }
    if (config.version > SETTINGS_CURRENT_VERSION) {
        NRF_LOG_WARNING("Config version %d is greater than current firmware supports (%d). Default config will be loaded.", config.version, SETTINGS_CURRENT_VERSION);
        settings_init_config();
    }
    if (config.version < SETTINGS_CURRENT_VERSION) {
        NRF_LOG_INFO("Config version (%d) is not latest, performing migration to %d", config.version, SETTINGS_CURRENT_VERSION);
        settings_migrate();
    }
    if (config_did_change()) {
        settings_save_config();
    }

    // Assign values only after the first configuration load.
    m_ble_pairing_enable_first_load_value = config.ble_pairing_enable;
}

uint8_t settings_save_config(void) {
    // We are saving the configuration, we need to calculate the crc code of the current configuration to judge whether the following data is updated
    if (config_did_change()) {    // Before saving, make sure that the configuration has changed
        NRF_LOG_INFO("Save config start.");
        bool ret = fds_write_sync(FDS_SETTINGS_FILE_ID, FDS_SETTINGS_RECORD_KEY, sizeof(config), (uint8_t *)&config);
        if (ret) {
            NRF_LOG_INFO("Save config success.");
            update_config_crc();
        } else {
            NRF_LOG_ERROR("Save config error.");
            return STATUS_FLASH_WRITE_FAIL;
        }
    } else {
        NRF_LOG_INFO("Config did not change.");
    }

    return STATUS_SUCCESS;
}

uint8_t settings_get_animation_config() {
    return config.animation_config;
}

void settings_set_animation_config(uint8_t value) {
    config.animation_config = value;
}

/**
 * @brief check the button type is valid?
 *
 * @param type Button type, 'a' or 'b' or 'A' or 'B'
 * @return true Button type valid.
 * @return false Button type Invalid.
 */
bool is_settings_button_type_valid(char type) {
    switch (type) {
        case 'a':
        case 'b':
        case 'A':
        case 'B':
            return true;
        default:
            return false;
    }
}

/**
 * @brief Get the button press config
 *
 * @param which 'a' or 'b'
 * @return uint8_t @link{ settings_button_function_t }
 */
uint8_t settings_get_button_press_config(char which) {
    switch (which) {
        case 'a':
        case 'A':
            return config.button_a_press;

        case 'b':
        case 'B':
            return config.button_b_press;

        default:
            // can't to here.
            APP_ERROR_CHECK_BOOL(false);
            break;
    }
    // can't to here.
    return SettingsButtonDisable;
}

/**
 * @brief Get the long button press config
 *
 * @param which 'a' or 'b'
 * @return uint8_t @link{ settings_button_function_t }
 */
uint8_t settings_get_long_button_press_config(char which) {
    switch (which) {
        case 'a':
        case 'A':
            return config.button_a_long_press;

        case 'b':
        case 'B':
            return config.button_b_long_press;

        default:
            // can't to here.
            APP_ERROR_CHECK_BOOL(false);
            break;
    }
    // can't to here.
    return SettingsButtonDisable;
}

/**
 * @brief Set the button press config
 *
 * @param which 'a' or 'b'
 * @param value @link{ settings_button_function_t }
 */
void settings_set_button_press_config(char which, uint8_t value) {
    switch (which) {
        case 'a':
        case 'A':
            config.button_a_press = value;
            break;

        case 'b':
        case 'B':
            config.button_b_press = value;
            break;

        default:
            // can't to here.
            APP_ERROR_CHECK_BOOL(false);
            break;
    }
}

/**
 * @brief Set the long button press config
 *
 * @param which 'a' or 'b'
 * @param value @link{ settings_button_function_t }
 */
void settings_set_long_button_press_config(char which, uint8_t value) {
    switch (which) {
        case 'a':
        case 'A':
            config.button_a_long_press = value;
            break;

        case 'b':
        case 'B':
            config.button_b_long_press = value;
            break;

        default:
            // can't to here.
            APP_ERROR_CHECK_BOOL(false);
            break;
    }
}

uint8_t *settings_get_ble_connect_key(void) {
    return config.ble_connect_key;
}

/**
 * @brief Pointer to 6-digit ASCII string (digit 0..9 only, no NULL termination) passkey to be used during pairing.
 *
 * @param key Ble connect key for your device
 */
void settings_set_ble_connect_key(uint8_t *key) {
    memcpy(config.ble_connect_key, key, BLE_PAIRING_KEY_LEN);
}

void settings_set_ble_pairing_enable(bool enable) {
    config.ble_pairing_enable = enable;
}

bool settings_get_ble_pairing_enable(void) {
    return config.ble_pairing_enable;
}

bool settings_get_ble_pairing_enable_first_load(void) {
    return m_ble_pairing_enable_first_load_value;
}

uint32_t settings_get_sleep_timeout(void) {
    return config.sleep_timeout * 1000U;
}

void settings_set_sleep_timeout(uint8_t seconds) {
    config.sleep_timeout = seconds;
}

uint8_t settings_get_log_level(void) {
    return config.log_level <= 4 ? config.log_level : 0;
}

void settings_set_log_level(uint8_t level) {
    config.log_level = level;
}

/**
 * @brief Get the custom BLE advertised name.
 *
 * @return const char* NUL-terminated string; empty ("") means "use firmware default name".
 */
const char *settings_get_ble_name(void) {
    return config.ble_name;
}

/**
 * @brief Set the custom BLE advertised name.
 *
 * @param name Pointer to the name bytes (not necessarily NUL-terminated on the wire).
 * @param len Number of bytes in `name`. Pass 0 to reset to the firmware default name.
 * @return true if the name was accepted and stored in RAM (caller must still `hw settings store`).
 * @return false if `len` exceeds BLE_NAME_MAX_LEN.
 */
bool settings_set_ble_name(const char *name, uint8_t len) {
    if (len > BLE_NAME_MAX_LEN) {
        return false;
    }
    memset(config.ble_name, 0, sizeof(config.ble_name));
    memcpy(config.ble_name, name, len);
    return true;
}

/**
 * @brief Map a (button, tap count) pair to its slot in the binding table.
 *
 * The table holds 8 four-bit function codes: A2,A3,A4,A5,B2,B3,B4,B5.
 *
 * @param which      'a' or 'b'
 * @param tap_count  2..5 (1 is the short-press binding, not stored here)
 * @return the slot index (0..7) or 0xFF when the pair is invalid
 */
static uint8_t multi_tap_binding_index(char which, uint8_t tap_count) {
    if ((tap_count < SETTINGS_MULTI_TAP_COUNT_MIN) || (tap_count > SETTINGS_MULTI_TAP_COUNT_MAX)) {
        APP_ERROR_CHECK_BOOL(false);
        return 0xFF;
    }
    if ((which == 'a') || (which == 'A')) {
        return (uint8_t)(tap_count - SETTINGS_MULTI_TAP_COUNT_MIN);
    }
    if ((which == 'b') || (which == 'B')) {
        return (uint8_t)(SETTINGS_MULTI_TAP_BIND_COUNT + tap_count - SETTINGS_MULTI_TAP_COUNT_MIN);
    }
    APP_ERROR_CHECK_BOOL(false);
    return 0xFF;
}

/**
 * @brief Get the function bound to a (button, tap count) multi-tap slot.
 *
 * @param which      'a' or 'b'
 * @param tap_count  2..5 (1 is the short-press binding, not stored here)
 * @return the function code (SettingsButtonDisable == 0 when unbound)
 */
uint8_t settings_get_multi_tap_binding(char which, uint8_t tap_count) {
    uint8_t index = multi_tap_binding_index(which, tap_count);
    if (index == 0xFF) {
        return SettingsButtonDisable;
    }
    return app_button_tap_get(config.multi_tap_bindings, index);
}

/**
 * @brief Bind a function to a (button, tap count) multi-tap slot.
 *
 * @param which      'a' or 'b'
 * @param tap_count  2..5 (1 is the short-press binding, not stored here)
 * @param function   @link{ settings_button_function_t }
 */
void settings_set_multi_tap_binding(char which, uint8_t tap_count, uint8_t function) {
    uint8_t index = multi_tap_binding_index(which, tap_count);
    if (index == 0xFF) {
        return;
    }
    app_button_tap_set(config.multi_tap_bindings, index, function & 0x0F);
}

/**
 * @brief Get all 8 multi-tap function codes.
 *
 * @param fn out: A2,A3,A4,A5,B2,B3,B4,B5 (0 = Disable)
 */
void settings_get_multi_tap_bindings(uint8_t fn[SETTINGS_MULTI_TAP_BIND_TOTAL]) {
    app_button_tap_unpack(config.multi_tap_bindings, fn);
}

/**
 * @brief Set all 8 multi-tap function codes.
 *
 * @param fn in: A2,A3,A4,A5,B2,B3,B4,B5 (0 = Disable)
 */
void settings_set_multi_tap_bindings(const uint8_t fn[SETTINGS_MULTI_TAP_BIND_TOTAL]) {
    app_button_tap_pack(fn, config.multi_tap_bindings);
}

/**
 * @brief Is any tap count 2..5 bound for this button?
 *
 * A button with a multi-tap binding must wait for the inter-tap threshold
 * before running its 1-tap (short-press) action.
 */
bool settings_has_multi_tap_binding(char which) {
    for (uint8_t taps = SETTINGS_MULTI_TAP_COUNT_MIN; taps <= SETTINGS_MULTI_TAP_COUNT_MAX; taps++) {
        if (settings_get_multi_tap_binding(which, taps) != SettingsButtonDisable) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Get the maximum gap between two consecutive taps.
 *
 * @return threshold in milliseconds (50..1000)
 */
uint16_t settings_get_multi_tap_threshold_ms(void) {
    uint8_t units = config.multi_tap_threshold;
    uint8_t min_units = SETTINGS_MULTI_TAP_MIN_MS / SETTINGS_MULTI_TAP_UNIT_MS;
    uint8_t max_units = SETTINGS_MULTI_TAP_MAX_MS / SETTINGS_MULTI_TAP_UNIT_MS;
    if (units < min_units) {
        units = min_units;
    }
    if (units > max_units) {
        units = max_units;
    }
    return (uint16_t)units * SETTINGS_MULTI_TAP_UNIT_MS;
}

/**
 * @brief Set the maximum gap between two consecutive taps.
 *
 * @param ms threshold in milliseconds, clamped to 50..1000
 */
void settings_set_multi_tap_threshold_ms(uint16_t ms) {
    if (ms < SETTINGS_MULTI_TAP_MIN_MS) {
        ms = SETTINGS_MULTI_TAP_MIN_MS;
    }
    if (ms > SETTINGS_MULTI_TAP_MAX_MS) {
        ms = SETTINGS_MULTI_TAP_MAX_MS;
    }
    config.multi_tap_threshold = (uint8_t)(ms / SETTINGS_MULTI_TAP_UNIT_MS);
}

/**
 * @brief Check the button function is valid?
 *
 * @param function @link{ settings_button_function_t }
 * @return true Button function valid.
 * @return false Button function invalid.
 */
bool is_settings_button_function_valid(uint8_t function) {
    return function <= SettingsButtonStandaloneClear;
}
