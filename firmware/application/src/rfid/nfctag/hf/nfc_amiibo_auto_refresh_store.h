#ifndef NFC_AMIIBO_AUTO_REFRESH_STORE_H
#define NFC_AMIIBO_AUTO_REFRESH_STORE_H

#include <stdbool.h>
#include <stdint.h>

/* Persisted CMD 1071 arming state.
 *
 * FDS file 0x1071, record key 0x0001, 8 bytes / 2 words:
 *   word 0: magic/version 0x41465231 ("AFR1")
 *   word 1: bit 0 = enabled, bit 1 = persist,
 *           bits 8..15 = slot, all other bits reserved (must be zero).
 */
#define NFC_AMIIBO_AUTO_REFRESH_FDS_FILE_ID      0x1071u
#define NFC_AMIIBO_AUTO_REFRESH_FDS_KEY          0x0001u
#define NFC_AMIIBO_AUTO_REFRESH_STORE_RECORD_SIZE 8u
#define NFC_AMIIBO_AUTO_REFRESH_STORE_MAGIC       0x41465231u
/* Mirrors TAG_MAX_SLOT_NUM; kept local so the store stays host-testable. */
#define NFC_AMIIBO_AUTO_REFRESH_STORE_MAX_SLOT    8u

/* Storage backend; firmware binds this to the FDS helpers at boot. Host
 * tests bind a RAM fake so load/save/clear/restore can be exercised. */
typedef bool (*nfc_amiibo_auto_refresh_read_fn)(
    uint16_t id, uint16_t key, uint16_t *length, uint8_t *buffer);
typedef bool (*nfc_amiibo_auto_refresh_write_fn)(
    uint16_t id, uint16_t key, uint16_t length, void *buffer);
typedef int (*nfc_amiibo_auto_refresh_delete_fn)(uint16_t id, uint16_t key);

void nfc_amiibo_auto_refresh_store_set_backend(
    nfc_amiibo_auto_refresh_read_fn read,
    nfc_amiibo_auto_refresh_write_fn write,
    nfc_amiibo_auto_refresh_delete_fn del);

/* Decode and validate the record into the output arguments. Returns false
 * when absent, wrong length, bad magic, reserved bits set, or slot out of
 * range. Outputs are only written on success. */
bool nfc_amiibo_auto_refresh_store_load(bool *enabled, bool *persist, uint8_t *slot);

/* Encode and persist the arming state. Invalid slot or write failure fail. */
bool nfc_amiibo_auto_refresh_store_save(bool enabled, uint8_t slot, bool persist);

/* Drop the persisted record (best effort). */
bool nfc_amiibo_auto_refresh_store_clear(void);

/* Re-arm from the persisted record at boot. A valid, enabled record whose
 * slot matches an NTAG215 active slot re-arms from a clean detector state
 * (scan count 0). Anything else (absent/corrupt/disabled/mismatched slot or
 * non-NTAG215) disarms and clears the record. */
void nfc_amiibo_auto_refresh_store_restore(uint8_t active_slot, bool active_slot_is_ntag215);

#endif /* NFC_AMIIBO_AUTO_REFRESH_STORE_H */
