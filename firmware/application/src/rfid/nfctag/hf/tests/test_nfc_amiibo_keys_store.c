/* Host tests for retail-key FDS persistence, clear, and reboot reload. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nfc_amiibo_keys_store.h"
#include "nfc_amiibo_uid_refresh.h"

extern const uint8_t amiibo_test_old_dump[540];
extern const uint8_t amiibo_test_expected_dump[540];
extern const uint8_t amiibo_test_data_retail_key[80];
extern const uint8_t amiibo_test_tag_retail_key[80];

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return false; \
    } \
} while (0)

static const uint8_t new_uid[7] = {0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42};

static uint8_t m_fake_flash[256];
static uint16_t m_fake_len;
static bool m_fake_present;
static bool m_fake_delete_fails;

static void fake_reset(void) {
    memset(m_fake_flash, 0, sizeof(m_fake_flash));
    m_fake_len = 0;
    m_fake_present = false;
    m_fake_delete_fails = false;
    nfc_amiibo_uid_refresh_clear_retail_keys();
}

static bool fake_read(uint16_t id, uint16_t key, uint16_t *len, uint8_t *buffer) {
    if (id != NFC_AMIIBO_KEYS_FDS_FILE_ID || key != NFC_AMIIBO_KEYS_FDS_KEY ||
        !m_fake_present || *len < m_fake_len) {
        return false;
    }
    memcpy(buffer, m_fake_flash, m_fake_len);
    *len = m_fake_len;
    return true;
}

static bool fake_write(uint16_t id, uint16_t key, uint16_t len, void *buffer) {
    if (id != NFC_AMIIBO_KEYS_FDS_FILE_ID || key != NFC_AMIIBO_KEYS_FDS_KEY ||
        len > sizeof(m_fake_flash)) {
        return false;
    }
    memcpy(m_fake_flash, buffer, len);
    m_fake_len = len;
    m_fake_present = true;
    return true;
}

static int fake_delete(uint16_t id, uint16_t key) {
    if (id != NFC_AMIIBO_KEYS_FDS_FILE_ID || key != NFC_AMIIBO_KEYS_FDS_KEY ||
        m_fake_delete_fails) {
        return 0;
    }
    int removed = m_fake_present ? 1 : 0;
    m_fake_present = false;
    m_fake_len = 0;
    return removed;
}

static void make_blob(uint8_t blob[NFC_AMIIBO_KEYS_STORE_BLOB_SIZE]) {
    memcpy(blob, amiibo_test_data_retail_key, 80);
    memcpy(blob + 80, amiibo_test_tag_retail_key, 80);
}

static void bind_fake_backend(void) {
    nfc_amiibo_keys_store_set_backend(fake_read, fake_write, fake_delete);
}

static bool test_save_persists_and_reload_restores_keys(void) {
    uint8_t blob[NFC_AMIIBO_KEYS_STORE_BLOB_SIZE];
    uint8_t output[540];
    fake_reset();
    bind_fake_backend();
    make_blob(blob);

    CHECK(nfc_amiibo_keys_store_save(blob));
    CHECK(m_fake_present);
    CHECK(m_fake_len == NFC_AMIIBO_KEYS_STORE_BLOB_SIZE);
    CHECK(nfc_amiibo_uid_refresh_keys_ready());

    /* Reboot equivalent: only the RAM working copy is lost. */
    nfc_amiibo_uid_refresh_clear_retail_keys();
    CHECK(!nfc_amiibo_uid_refresh_keys_ready());
    CHECK(nfc_amiibo_keys_store_load());
    CHECK(nfc_amiibo_uid_refresh_keys_ready());
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(memcmp(output, amiibo_test_expected_dump, sizeof(output)) == 0);
    return true;
}

static bool test_clear_removes_record_and_keys(void) {
    uint8_t blob[NFC_AMIIBO_KEYS_STORE_BLOB_SIZE];
    fake_reset();
    bind_fake_backend();
    make_blob(blob);
    CHECK(nfc_amiibo_keys_store_save(blob));
    CHECK(m_fake_present);

    CHECK(nfc_amiibo_keys_store_clear());
    CHECK(!m_fake_present);
    CHECK(!nfc_amiibo_uid_refresh_keys_ready());
    CHECK(!nfc_amiibo_keys_store_load());
    return true;
}

static bool test_clear_reports_delete_failure_but_clears_ram(void) {
    uint8_t blob[NFC_AMIIBO_KEYS_STORE_BLOB_SIZE];
    fake_reset();
    bind_fake_backend();
    make_blob(blob);
    CHECK(nfc_amiibo_keys_store_save(blob));
    CHECK(nfc_amiibo_uid_refresh_keys_ready());

    m_fake_delete_fails = true;
    CHECK(!nfc_amiibo_keys_store_clear());
    CHECK(!nfc_amiibo_uid_refresh_keys_ready());
    CHECK(m_fake_present);
    return true;
}

static bool test_load_rejects_corrupt_record(void) {
    uint8_t blob[NFC_AMIIBO_KEYS_STORE_BLOB_SIZE];
    uint8_t output[540];
    fake_reset();
    bind_fake_backend();
    make_blob(blob);
    CHECK(nfc_amiibo_keys_store_save(blob));

    m_fake_flash[0] ^= 0x01;
    nfc_amiibo_uid_refresh_clear_retail_keys();
    CHECK(!nfc_amiibo_keys_store_load());
    CHECK(!nfc_amiibo_uid_refresh_keys_ready());
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_RETAIL_KEYS_MISSING);
    return true;
}

static bool test_save_rejects_invalid_blob(void) {
    uint8_t blob[NFC_AMIIBO_KEYS_STORE_BLOB_SIZE];
    fake_reset();
    bind_fake_backend();
    make_blob(blob);
    blob[0] ^= 0x01;

    CHECK(!nfc_amiibo_keys_store_save(blob));
    CHECK(!m_fake_present);
    CHECK(!nfc_amiibo_uid_refresh_keys_ready());
    return true;
}

static bool test_load_without_backend(void) {
    uint8_t blob[NFC_AMIIBO_KEYS_STORE_BLOB_SIZE];
    fake_reset();
    make_blob(blob);
    nfc_amiibo_keys_store_set_backend(NULL, NULL, NULL);
    CHECK(!nfc_amiibo_keys_store_load());
    CHECK(!nfc_amiibo_keys_store_save(blob));
    return true;
}

int main(void) {
    struct {
        const char *name;
        bool (*fn)(void);
    } tests[] = {
        {"save persists and reload restores keys after reboot", test_save_persists_and_reload_restores_keys},
        {"clear removes the record and the keys", test_clear_removes_record_and_keys},
        {"clear reports delete failure but still clears RAM keys", test_clear_reports_delete_failure_but_clears_ram},
        {"load rejects a corrupt record", test_load_rejects_corrupt_record},
        {"save rejects an invalid blob", test_save_rejects_invalid_blob},
        {"load and save without a backend fail", test_load_without_backend},
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (!tests[i].fn()) {
            fprintf(stderr, "FAIL: %s\n", tests[i].name);
            failed++;
        } else {
            printf("ok: %s\n", tests[i].name);
        }
    }
    return failed ? 1 : 0;
}
