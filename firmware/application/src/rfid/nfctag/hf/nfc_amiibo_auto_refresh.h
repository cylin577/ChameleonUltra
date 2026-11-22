/*
 * nfc_amiibo_auto_refresh.h
 *
 * Hardware-free core that turns an HF field session into a deferred Amiibo
 * UID-refresh trigger. A scan is:
 *
 *   FIELD_DETECTED -> field held >= 20 ms -> stable FIELD_LOST >= 100 ms
 *   AND (one PWD_AUTH or >= 2 READ/FAST_READ frames in that field session)
 *
 * on_field() and on_command() are ISR-safe edges (no crypto, FDS, allocation
 * or locking). process() runs in the main loop and is the only place that may
 * call a refresh hook.
 * The hook is injected here (or supplied as a strong
 * nfc_amiibo_auto_refresh_do_refresh() symbol by firmware), so this core has
 * no SDK/crypto dependency and is unit-testable on the host with a fake clock.
 *
 * `ticks` arguments are milliseconds and are compared with unsigned subtraction
 * so they stay correct across a 32-bit wrap.
 */
#ifndef NFC_AMIIBO_AUTO_REFRESH_H
#define NFC_AMIIBO_AUTO_REFRESH_H

#include <stdbool.h>
#include <stdint.h>

#include "nfc_amiibo_uid_refresh.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NFC_AMIIBO_AUTO_REFRESH_FIELD_MIN_MS   20u
#define NFC_AMIIBO_AUTO_REFRESH_LOSS_STABLE_MS 100u

/* Sentinel slot: arm refresh for every NTAG215 slot. The hook resolves the
 * actual slot at refresh time; 0xFF is never a real slot index. */
enum { NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL = 0xFFu };

/* Refresh hook. The core never touches crypto/FDS itself. Firmware supplies a
 * strong nfc_amiibo_auto_refresh_do_refresh(); host tests inject one with
 * nfc_amiibo_auto_refresh_set_refresh_fn(). The hook fills uid[] with the UID
 * actually written so the core can store it as the last UID. */
typedef nfc_amiibo_uid_refresh_status_t (*nfc_amiibo_auto_refresh_fn)(
    uint8_t slot, bool persist, uint8_t uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE]);

/* Weak default keeps this core linkable on its own; firmware overrides it. */
nfc_amiibo_uid_refresh_status_t nfc_amiibo_auto_refresh_do_refresh(
    uint8_t slot, bool persist, uint8_t uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE]);

/* Reset all detector state (does not change the injected hook). */
void nfc_amiibo_auto_refresh_init(void);

void nfc_amiibo_auto_refresh_set_refresh_fn(nfc_amiibo_auto_refresh_fn fn);
void nfc_amiibo_auto_refresh_set_busy(bool busy);

/* Test/debug hook: seed the saturating count near its limit. */
void nfc_amiibo_auto_refresh_set_scan_count(uint32_t count);

void nfc_amiibo_auto_refresh_arm(uint8_t slot, bool persist);
void nfc_amiibo_auto_refresh_disarm(void);

/* ISR-safe field edge. `present` stamps the session start, clears the
 * per-session command activity and cancels a pending scan; FIELD_LOST marks one
 * pending scan only if the field was held long enough, saw qualifying command
 * activity, and the detector is free for this session. */
void nfc_amiibo_auto_refresh_on_field(bool present, uint32_t ticks);

/* ISR-safe command edge. Ignored while the field is absent. 0x1B (PWD_AUTH)
 * sets the auth flag; 0x30/0x3A (READ/FAST_READ) saturating-increment the read
 * counter. Both reset on every new field-on session. */
void nfc_amiibo_auto_refresh_on_command(uint8_t cmd);

/* Main loop. Returns true exactly when a pending scan was consumed and the
 * refresh hook was called. */
bool nfc_amiibo_auto_refresh_process(uint32_t ticks);

/* Status getters */
bool nfc_amiibo_auto_refresh_is_armed(void);
uint8_t nfc_amiibo_auto_refresh_slot(void);
bool nfc_amiibo_auto_refresh_persist(void);
bool nfc_amiibo_auto_refresh_is_busy(void);
bool nfc_amiibo_auto_refresh_field_present(void);
bool nfc_amiibo_auto_refresh_scan_pending(void);
bool nfc_amiibo_auto_refresh_session_refreshed(void);
uint32_t nfc_amiibo_auto_refresh_scan_count(void);
/* Activity seen in the last completed field session, packed for CMD 1072
 * byte 20: bit 7 = PWD_AUTH seen, bits 6..0 = min(read frames, 127). */
uint8_t nfc_amiibo_auto_refresh_activity_byte(void);
nfc_amiibo_uid_refresh_status_t nfc_amiibo_auto_refresh_last_status(void);
void nfc_amiibo_auto_refresh_last_uid(
    uint8_t out[NFC_AMIIBO_UID_REFRESH_UID_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* NFC_AMIIBO_AUTO_REFRESH_H */
