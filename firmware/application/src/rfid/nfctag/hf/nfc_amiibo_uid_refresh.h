#ifndef NFC_AMIIBO_UID_REFRESH_H
#define NFC_AMIIBO_UID_REFRESH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NFC_AMIIBO_UID_REFRESH_DUMP_SIZE        540
#define NFC_AMIIBO_UID_REFRESH_UID_SIZE         7
#define NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE 80
#define NFC_AMIIBO_UID_REFRESH_SIGNATURE_SIZE   32
#define NFC_AMIIBO_UID_REFRESH_FLAG_PERSIST     0x01
/* Size of the decrypted data stream; plaintext_out buffers must hold this many bytes. */
#define NFC_AMIIBO_UID_REFRESH_PLAINTEXT_SIZE   392

/* Apply this only to the FDS copy so live RAM detection state stays unchanged. */
#define NFC_AMIIBO_UID_REFRESH_PREPARE_PERSISTED_CONFIG(prepared) \
    ((prepared)->config.detection_enable = false)

typedef enum {
    NFC_AMIIBO_UID_REFRESH_OK = 0,
    NFC_AMIIBO_UID_REFRESH_INVALID_ARGUMENT,
    NFC_AMIIBO_UID_REFRESH_RETAIL_KEYS_MISSING,
    NFC_AMIIBO_UID_REFRESH_INVALID_UID,
    NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS,
    NFC_AMIIBO_UID_REFRESH_SIGNATURE_PRESENT,
    NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR,
    NFC_AMIIBO_UID_REFRESH_TAG_HMAC_MISMATCH,
    NFC_AMIIBO_UID_REFRESH_DATA_HMAC_MISMATCH,
} nfc_amiibo_uid_refresh_status_t;

bool nfc_amiibo_uid_refresh_parse_request(
    uint16_t length,
    const uint8_t *data,
    bool *persist);

nfc_amiibo_uid_refresh_status_t nfc_amiibo_uid_refresh_set_retail_keys(
    const uint8_t data_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
    const uint8_t tag_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE]);

void nfc_amiibo_uid_refresh_clear_retail_keys(void);

/* Whether a validated retail-key working copy is currently installed in RAM. */
bool nfc_amiibo_uid_refresh_keys_ready(void);

/**
 * Validate and install the two 80-byte retail master keys.
 *
 * A 160-byte payload is the data retail key followed by the tag retail key.
 * An empty payload clears the RAM working copy. Invalid input leaves the
 * current retail keys unchanged. Persistence is handled by the caller.
 */
nfc_amiibo_uid_refresh_status_t nfc_amiibo_uid_refresh_upload_retail_keys(
    uint16_t length,
    const uint8_t *data);

nfc_amiibo_uid_refresh_status_t nfc_amiibo_uid_refresh_apply(
    const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
    const uint8_t new_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE],
    const uint8_t *signature,
    uint8_t refreshed_dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE]);

/**
 * Validate a dump without modifying it or writing any output buffer until all
 * checks pass. Derives the old HMAC/AES keys, decrypts the old data stream,
 * verifies the tag and data HMACs, and reports the current UID taken from
 * dump bytes [0..2] and [4..7] (the BCC bytes are skipped).
 *
 * plaintext_out may be NULL; when non-NULL it receives the decrypted stream
 * (NFC_AMIIBO_UID_REFRESH_PLAINTEXT_SIZE bytes) so a caller can reuse it.
 * signature may be NULL; a non-blank signature is rejected.
 */
nfc_amiibo_uid_refresh_status_t nfc_amiibo_uid_refresh_validate(
    const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
    const uint8_t data_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
    const uint8_t tag_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
    const uint8_t *signature,
    uint8_t current_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE],
    uint8_t plaintext_out[NFC_AMIIBO_UID_REFRESH_PLAINTEXT_SIZE]);

/* Persisted-RAM-key counterpart of nfc_amiibo_uid_refresh_validate(). */
nfc_amiibo_uid_refresh_status_t nfc_amiibo_uid_refresh_validate_apply(
    const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
    const uint8_t *signature,
    uint8_t current_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE],
    uint8_t plaintext_out[NFC_AMIIBO_UID_REFRESH_PLAINTEXT_SIZE]);

/**
 * Refresh a standard 540-byte NTAG215 Amiibo dump with a new UID.
 *
 * The data and tag retail keys are the 80-byte unfixed-info and locked-secret
 * master-key records respectively. signature may be NULL for a standard
 * dump, or point to the separate 32-byte NTAG215 signature. A non-blank
 * signature is rejected because it cannot be regenerated on-device.
 *
 * refreshed_dump is committed only after all old HMACs have been verified
 * and the refreshed dump has been encrypted successfully.
 */
nfc_amiibo_uid_refresh_status_t nfc_amiibo_uid_refresh(
    const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
    const uint8_t new_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE],
    const uint8_t data_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
    const uint8_t tag_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
    const uint8_t *signature,
    uint8_t refreshed_dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE]);

bool nfc_amiibo_uid_refresh_signature_is_blank(
    const uint8_t signature[NFC_AMIIBO_UID_REFRESH_SIGNATURE_SIZE]);

void nfc_amiibo_uid_refresh_set_uid(
    uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
    const uint8_t uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE]);

void nfc_amiibo_uid_refresh_set_password(
    uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
    const uint8_t uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE]);

#endif
