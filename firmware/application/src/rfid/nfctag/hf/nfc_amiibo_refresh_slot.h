#ifndef NFC_AMIIBO_REFRESH_SLOT_H
#define NFC_AMIIBO_REFRESH_SLOT_H

#include <stdbool.h>
#include <stdint.h>

/**
 * Refresh the active NTAG215 Amiibo slot with a freshly generated UID.
 *
 * Shared core behind CMD 1070: loads/validates retail keys, checks the
 * emulating/slot/signature preconditions, applies the signed UID refresh,
 * persists FDS-first when requested, then commits the RAM/reader-visible
 * UID and CRC. Sense is disabled for the critical section and always
 * re-enabled before returning.
 *
 * Returns a firmware STATUS_* code. On STATUS_SUCCESS the old and new UIDs
 * (7 bytes each) are written to old_uid/new_uid; on failure they are left
 * untouched.
 */
uint16_t nfc_amiibo_refresh_slot(bool persist, uint8_t old_uid[7], uint8_t new_uid[7]);

/* Verify result reasons, reported in the payload byte [1] of CMD 1073. */
typedef enum {
    NFC_AMIIBO_VERIFY_REASON_VALID = 0,
    NFC_AMIIBO_VERIFY_REASON_NOT_NTAG215 = 1,
    NFC_AMIIBO_VERIFY_REASON_KEYS_MISSING = 2,
    NFC_AMIIBO_VERIFY_REASON_TAG_HMAC_MISMATCH = 3,
    NFC_AMIIBO_VERIFY_REASON_DATA_HMAC_MISMATCH = 4,
    NFC_AMIIBO_VERIFY_REASON_SIGNATURE_PRESENT = 5,
    NFC_AMIIBO_VERIFY_REASON_OTHER = 6,
} nfc_amiibo_verify_reason_t;

#define NFC_AMIIBO_VERIFY_RESPONSE_SIZE 9

/**
 * Non-mutating verification of the active Amiibo slot (CMD 1073 core).
 *
 * Restores persisted keys if needed, applies the same NTAG215/buffer/signature
 * preconditions as nfc_amiibo_refresh_slot(), then validates the dump with the
 * persisted-RAM-key validate wrapper. No sense switching, RNG, FDS, CRC, or
 * tag writes are performed.
 *
 * Returns STATUS_DEVICE_MODE_ERROR when emulating. A completed check always
 * returns STATUS_SUCCESS: validity is reported via *reason (0 = valid), and
 * the current UID is written to out_uid (all zero when invalid). The handler
 * emits [valid, reason, uid[7]] as the response payload.
 */
uint16_t nfc_amiibo_verify_slot(uint8_t out_uid[7], uint8_t *reason);

#endif
