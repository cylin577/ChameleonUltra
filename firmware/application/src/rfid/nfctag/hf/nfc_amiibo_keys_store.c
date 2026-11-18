#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "nfc_amiibo_keys_store.h"
#include "nfc_amiibo_uid_refresh.h"

/* FDS writes need a word-aligned buffer; the same buffer is reused for reads
 * so a 160-byte key record never lands on the stack. */
static uint32_t m_blob_words[(NFC_AMIIBO_KEYS_STORE_BLOB_SIZE + 3) / 4];
static uint8_t *const m_blob = (uint8_t *)m_blob_words;

static nfc_amiibo_keys_read_fn m_read;
static nfc_amiibo_keys_write_fn m_write;
static nfc_amiibo_keys_delete_fn m_delete;

void nfc_amiibo_keys_store_set_backend(
    nfc_amiibo_keys_read_fn read,
    nfc_amiibo_keys_write_fn write,
    nfc_amiibo_keys_delete_fn del) {
    m_read = read;
    m_write = write;
    m_delete = del;
}

bool nfc_amiibo_keys_store_load(void) {
    if (m_read == NULL) {
        return false;
    }
    uint16_t length = NFC_AMIIBO_KEYS_STORE_BLOB_SIZE;
    if (!m_read(NFC_AMIIBO_KEYS_FDS_FILE_ID, NFC_AMIIBO_KEYS_FDS_KEY,
                &length, m_blob) ||
        length != NFC_AMIIBO_KEYS_STORE_BLOB_SIZE) {
        return false;
    }
    return nfc_amiibo_uid_refresh_upload_retail_keys(length, m_blob) ==
           NFC_AMIIBO_UID_REFRESH_OK;
}

bool nfc_amiibo_keys_store_save(const uint8_t blob[NFC_AMIIBO_KEYS_STORE_BLOB_SIZE]) {
    if (blob == NULL || m_write == NULL) {
        return false;
    }
    if (nfc_amiibo_uid_refresh_upload_retail_keys(
            NFC_AMIIBO_KEYS_STORE_BLOB_SIZE, blob) !=
        NFC_AMIIBO_UID_REFRESH_OK) {
        return false;
    }
    memcpy(m_blob, blob, NFC_AMIIBO_KEYS_STORE_BLOB_SIZE);
    return m_write(NFC_AMIIBO_KEYS_FDS_FILE_ID, NFC_AMIIBO_KEYS_FDS_KEY,
                   NFC_AMIIBO_KEYS_STORE_BLOB_SIZE, m_blob_words);
}

bool nfc_amiibo_keys_store_clear(void) {
    nfc_amiibo_uid_refresh_clear_retail_keys();
    memset(m_blob, 0, NFC_AMIIBO_KEYS_STORE_BLOB_SIZE);
    if (m_delete == NULL) {
        return false;
    }
    return m_delete(NFC_AMIIBO_KEYS_FDS_FILE_ID, NFC_AMIIBO_KEYS_FDS_KEY) > 0;
}
