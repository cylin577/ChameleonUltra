#ifndef NFC_AMIIBO_KEYS_STORE_H
#define NFC_AMIIBO_KEYS_STORE_H

#include <stdbool.h>
#include <stdint.h>

/* Two 80-byte retail master keys in the CMD 1069 payload order. */
#define NFC_AMIIBO_KEYS_STORE_BLOB_SIZE 160

/* Reserved in fds_ids.h for the 0x1069 amiibo-key record. */
#define NFC_AMIIBO_KEYS_FDS_FILE_ID     0x1069
#define NFC_AMIIBO_KEYS_FDS_KEY         0x1069

/* Storage backend; firmware binds this to the FDS helpers at boot. Host
 * tests bind a RAM fake so the same load/clear path can be exercised. */
typedef bool (*nfc_amiibo_keys_read_fn)(
    uint16_t id, uint16_t key, uint16_t *length, uint8_t *buffer);
typedef bool (*nfc_amiibo_keys_write_fn)(
    uint16_t id, uint16_t key, uint16_t length, void *buffer);
typedef int (*nfc_amiibo_keys_delete_fn)(uint16_t id, uint16_t key);

void nfc_amiibo_keys_store_set_backend(
    nfc_amiibo_keys_read_fn read,
    nfc_amiibo_keys_write_fn write,
    nfc_amiibo_keys_delete_fn del);

/* Read the persisted blob, validate it, and install it as the RAM working
 * copy. Returns false when absent, malformed, or when no backend is set. */
bool nfc_amiibo_keys_store_load(void);

/* Validate, install, and persist the 160-byte CMD 1069 payload. */
bool nfc_amiibo_keys_store_save(const uint8_t blob[NFC_AMIIBO_KEYS_STORE_BLOB_SIZE]);

/* Drop the RAM working copy and delete the FDS record. */
bool nfc_amiibo_keys_store_clear(void);

#endif
