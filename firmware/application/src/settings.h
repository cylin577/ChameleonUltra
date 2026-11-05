#ifndef SETTINGS_H
#define SETTINGS_H

#include <stdint.h>

#include "utils.h"

#define SETTINGS_CURRENT_VERSION 9
#define SETTINGS_SLEEP_TIMEOUT_DEFAULT_S 8   // default wake timeout in seconds (matches SLEEP_DELAY_MS_BUTTON_WAKEUP)
#define SETTINGS_SLEEP_TIMEOUT_MIN_S      5
#define SETTINGS_SLEEP_TIMEOUT_MAX_S      60
#define BLE_PAIRING_KEY_LEN 6
#define DEFAULT_BLE_PAIRING_KEY "123456"  // length must == 6
#define BLE_NAME_MAX_LEN 20   // keep comfortably under BLE_GAP_DEVNAME_MAX_LEN (31 with default GAP cfg)

/* Multi-tap button bindings (added on version9) */
#define SETTINGS_MULTI_TAP_COUNT_MIN       2   /* tap counts 2..5 are bindable; 1 tap == the short-press binding */
#define SETTINGS_MULTI_TAP_COUNT_MAX       5
#define SETTINGS_MULTI_TAP_UNIT_MS         10  /* stored in units of 10 ms */
#define SETTINGS_MULTI_TAP_DEFAULT_MS      250
#define SETTINGS_MULTI_TAP_MIN_MS          50
#define SETTINGS_MULTI_TAP_MAX_MS          1000
#define SETTINGS_MULTI_TAP_BIND_COUNT      4   /* tap counts 2,3,4,5 */
#define SETTINGS_MULTI_TAP_BIND_TOTAL      8   /* 2 buttons x 4 tap counts */

typedef enum {
    SettingsAnimationModeFull = 0U,
    SettingsAnimationModeMinimal = 1U,
    SettingsAnimationModeSymmetric = 3U,
    SettingsAnimationModeNone = 2U,
    SettingsAnimationModeMAX = 4U,
} settings_animation_mode_t;

typedef enum {
    // Set this button to have no function
    //    (But always can wakeup device, why didn't to disable this function? i dont known, you can ask chatgpt.)
    SettingsButtonDisable = 0U,
    // Card slot number sequence will increase after pressing
    SettingsButtonCycleSlot = 1U,
    // Card slot number sequence decreases after pressing
    SettingsButtonCycleSlotDec = 2U,
    // Read the UID card number immediately after pressing, continue searching, and simulate immediately after reading the card
    SettingsButtonCloneIcUid = 3U,
    SettingsButtonShowBattery = 4U,
    // Toggle NFC field generator on/off (Ultra only, must be in reader mode)
    SettingsButtonNfcFieldGenerator = 5U,
    SettingsButtonStandaloneDisarm  = 6U,  /* disarm active standalone mode */
    SettingsButtonStandaloneToggle  = 7U,  /* arm / disarm */
    SettingsButtonStandaloneAction  = 8U,  /* run the armed mode */
    SettingsButtonStandaloneClear   = 9U,  /* clear stored results */
} settings_button_function_t;

typedef struct ALIGN_U32 {
    uint16_t version;

    // 1 byte
    uint8_t animation_config : 2;
    uint8_t ble_pairing_enable : 1;
    uint8_t log_level : 3; // persistent debug log level 0..4 (0 = off)
    uint8_t reserved0 : 2; // If you are add switch field, reallocating me.

    // 1 byte
    uint8_t button_a_press : 4;
    uint8_t button_b_press : 4;

    // 1 byte
    uint8_t button_a_long_press : 4;
    uint8_t button_b_long_press : 4;

    // 6 byte
    uint8_t ble_connect_key[6];

    // 1 byte (add on version6)
    uint8_t sleep_timeout; // wake timeout in seconds after button wakeup

    // BLE_NAME_MAX_LEN + 1 bytes (add on version7)
    char ble_name[BLE_NAME_MAX_LEN + 1]; // NUL-terminated custom BLE name; empty string = use firmware default

    // 4 bytes (add on version9) -- 8 packed 4-bit function codes for the
    // multi-tap bindings (A2,A3,A4,A5,B2,B3,B4,B5). A tap count of 1 is the
    // button's short-press binding and lives in button_a_press /
    // button_b_press, so it is NOT duplicated here.
    uint8_t multi_tap_bindings[4];

    // 1 byte (add on version8) -- max gap between taps, in units of 10 ms (5..100)
    uint8_t multi_tap_threshold;

    // 2 bytes (add on version9) -- the retired version8 per-button tap-count
    // bytes. Reserved: they pad the record to a whole number of FDS words
    // (the threshold moved from @35 to @37, so the tail grew by 2 bytes).
    uint8_t reserved1[2];

    /*
     * Warning !!!!!!!!!!!!!!!!!!!!!! <-------------
     * If you need to add settings,
     * please be sure to consult the documentation of the bit field
     * and fully use the space of this structure before considering reallocating memory space.
     *
     * The record size must stay a multiple of 4: fds_write_sync() rounds the
     * length up to whole FDS words and fds_read_sync() copies
     * length_words*4 bytes into this struct, so a non-multiple-of-4 size
     * makes the record unreadable (the settings would reset on every boot).
     */
} settings_data_t;

void settings_init_config(void);
void settings_migrate(void);
void settings_load_config(void);
uint8_t settings_save_config(void);
uint8_t settings_get_animation_config(void);
void settings_set_animation_config(uint8_t value);
uint8_t settings_get_button_press_config(char which);
uint8_t settings_get_long_button_press_config(char which);
void settings_set_button_press_config(char which, uint8_t value);
void settings_set_long_button_press_config(char which, uint8_t value);
bool is_settings_button_type_valid(char type);
uint8_t *settings_get_ble_connect_key(void);
void settings_set_ble_connect_key(uint8_t *key);
void settings_set_ble_pairing_enable(bool enable);
bool settings_get_ble_pairing_enable(void);
bool settings_get_ble_pairing_enable_first_load(void);
uint32_t settings_get_sleep_timeout(void);
void settings_set_sleep_timeout(uint8_t seconds);
void settings_init_sleep_timeout_config(void);
const char *settings_get_ble_name(void);
bool settings_set_ble_name(const char *name, uint8_t len);
void settings_init_ble_name_config(void);
uint8_t settings_get_log_level(void);
void settings_set_log_level(uint8_t level);
void settings_init_multi_tap_config(void);
void settings_init_multi_tap_bindings(void);
uint16_t settings_get_multi_tap_threshold_ms(void);
void settings_set_multi_tap_threshold_ms(uint16_t ms);
uint8_t settings_get_multi_tap_binding(char which, uint8_t tap_count);
void settings_set_multi_tap_binding(char which, uint8_t tap_count, uint8_t function);
void settings_get_multi_tap_bindings(uint8_t fn[SETTINGS_MULTI_TAP_BIND_TOTAL]);
void settings_set_multi_tap_bindings(const uint8_t fn[SETTINGS_MULTI_TAP_BIND_TOTAL]);
bool settings_has_multi_tap_binding(char which);
bool is_settings_button_function_valid(uint8_t function);
#endif
