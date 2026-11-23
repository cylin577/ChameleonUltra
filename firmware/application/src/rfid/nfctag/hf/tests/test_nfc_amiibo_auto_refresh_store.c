/* Host tests for CMD 1071 arm-state persistence (FDS record load/save/restore). */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nfc_amiibo_auto_refresh.h"
#include "nfc_amiibo_auto_refresh_store.h"

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return false; \
    } \
} while (0)

#define FILE_ID NFC_AMIIBO_AUTO_REFRESH_FDS_FILE_ID
#define KEY     NFC_AMIIBO_AUTO_REFRESH_FDS_KEY

static uint8_t m_flash[32];
static uint16_t m_flash_len;
static bool m_present;
static bool m_write_fails;
static bool m_delete_fails;

/* Mimics fds_read_sync: refuses a record that does not fit the caller's buffer. */
static bool fake_read(uint16_t id, uint16_t key, uint16_t *len, uint8_t *buffer) {
    if (id != FILE_ID || key != KEY || !m_present || m_flash_len > *len) {
        *len = 0;
        return false;
    }
    memcpy(buffer, m_flash, m_flash_len);
    *len = m_flash_len;
    return true;
}

static bool fake_write(uint16_t id, uint16_t key, uint16_t len, void *buffer) {
    if (id != FILE_ID || key != KEY || m_write_fails || len > sizeof(m_flash)) {
        return false;
    }
    memcpy(m_flash, buffer, len);
    m_flash_len = len;
    m_present = true;
    return true;
}

static int fake_delete(uint16_t id, uint16_t key) {
    if (id != FILE_ID || key != KEY || m_delete_fails) {
        return 0;
    }
    int removed = m_present ? 1 : 0;
    m_present = false;
    m_flash_len = 0;
    return removed;
}

static void reset(void) {
    memset(m_flash, 0, sizeof(m_flash));
    m_flash_len = 0;
    m_present = false;
    m_write_fails = false;
    m_delete_fails = false;
    nfc_amiibo_auto_refresh_init();
    nfc_amiibo_auto_refresh_store_set_backend(fake_read, fake_write, fake_delete);
}

static bool test_save_load_round_trip(void) {
    bool enabled = false;
    bool persist = false;
    uint8_t slot = 0;
    uint32_t w0 = 0;
    uint32_t w1 = 0;

    reset();
    CHECK(nfc_amiibo_auto_refresh_store_save(true, 5, true));
    CHECK(m_present);
    CHECK(m_flash_len == NFC_AMIIBO_AUTO_REFRESH_STORE_RECORD_SIZE);

    memcpy(&w0, m_flash, 4);
    memcpy(&w1, m_flash + 4, 4);
    CHECK(w0 == 0x41465231u);
    CHECK(w1 == (0x00000001u | 0x00000002u | (5u << 8)));

    CHECK(nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot));
    CHECK(enabled && persist && slot == 5);

    enabled = true; persist = false; slot = 99;
    CHECK(nfc_amiibo_auto_refresh_store_save(false, 1, true));
    CHECK(nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot));
    CHECK(!enabled && persist && slot == 1);

    /* All-slot sentinel survives the 8-byte / AFR1 record round trip. */
    CHECK(nfc_amiibo_auto_refresh_store_save(true, NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL, false));
    CHECK(m_flash_len == NFC_AMIIBO_AUTO_REFRESH_STORE_RECORD_SIZE);
    memcpy(&w0, m_flash, 4);
    memcpy(&w1, m_flash + 4, 4);
    CHECK(w0 == 0x41465231u);
    CHECK(w1 == (0x00000001u | ((uint32_t)NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL << 8)));
    enabled = false; persist = true; slot = 0;
    CHECK(nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot));
    CHECK(enabled && !persist && slot == NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL);
    return true;
}

static bool test_restore_rearms_with_count_zero(void) {
    reset();
    /* A legacy single-slot record restores as all-slot, regardless of the
     * active slot at boot. */
    CHECK(nfc_amiibo_auto_refresh_store_save(true, 2, false));

    /* Simulate fresh RAM: stale non-zero count, not armed. */
    nfc_amiibo_auto_refresh_disarm();
    nfc_amiibo_auto_refresh_set_scan_count(7);
    CHECK(nfc_amiibo_auto_refresh_scan_count() == 7);

    CHECK(!nfc_amiibo_auto_refresh_store_restore(5, true));  /* different slot: still arms */
    CHECK(nfc_amiibo_auto_refresh_is_armed());
    CHECK(nfc_amiibo_auto_refresh_slot() == NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL);
    CHECK(!nfc_amiibo_auto_refresh_persist());
    CHECK(nfc_amiibo_auto_refresh_scan_count() == 0);

    /* A native 0xFF record restores the same way, keeping persistence. */
    reset();
    CHECK(nfc_amiibo_auto_refresh_store_save(true, NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL, true));
    nfc_amiibo_auto_refresh_disarm();
    nfc_amiibo_auto_refresh_set_scan_count(9);
    CHECK(!nfc_amiibo_auto_refresh_store_restore(0, true));
    CHECK(nfc_amiibo_auto_refresh_is_armed());
    CHECK(nfc_amiibo_auto_refresh_slot() == NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL);
    CHECK(nfc_amiibo_auto_refresh_persist());
    CHECK(nfc_amiibo_auto_refresh_scan_count() == 0);
    return true;
}

static bool test_restore_clears_corrupt_record(void) {
    bool enabled = false;
    bool persist = false;
    uint8_t slot = 0;

    reset();
    CHECK(nfc_amiibo_auto_refresh_store_save(true, 3, false));
    nfc_amiibo_auto_refresh_arm(3, false);
    m_flash[0] ^= 0x01;  /* corrupt the magic word */
    CHECK(!nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot));

    CHECK(!nfc_amiibo_auto_refresh_store_restore(3, true));  /* corrupt: no armed state to cue */
    CHECK(!nfc_amiibo_auto_refresh_is_armed());
    CHECK(!m_present);  /* bad record was cleared */
    return true;
}

static bool test_disable_clear_removes_record(void) {
    bool enabled = false;
    bool persist = false;
    uint8_t slot = 0;

    reset();
    CHECK(nfc_amiibo_auto_refresh_store_save(true, 1, true));
    nfc_amiibo_auto_refresh_arm(1, true);

    nfc_amiibo_auto_refresh_disarm();
    CHECK(nfc_amiibo_auto_refresh_store_clear());
    CHECK(!m_present);
    CHECK(!nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot));
    CHECK(!nfc_amiibo_auto_refresh_is_armed());
    return true;
}

static bool test_restore_ignores_slot_and_keeps_record_off_ntag(void) {
    reset();
    /* A legacy single-slot record no longer conflicts with another active slot. */
    CHECK(nfc_amiibo_auto_refresh_store_save(true, 3, false));
    nfc_amiibo_auto_refresh_arm(3, false);
    CHECK(!nfc_amiibo_auto_refresh_store_restore(2, true));  /* no cue */
    CHECK(nfc_amiibo_auto_refresh_is_armed());
    CHECK(nfc_amiibo_auto_refresh_slot() == NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL);
    CHECK(m_present);  /* record kept */

    reset();
    CHECK(nfc_amiibo_auto_refresh_store_save(true, NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL, true));
    nfc_amiibo_auto_refresh_arm(NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL, true);
    CHECK(nfc_amiibo_auto_refresh_store_restore(2, false));  /* non-Amiibo: cue */
    CHECK(!nfc_amiibo_auto_refresh_is_armed());
    CHECK(m_present);  /* record kept for a later Amiibo boot */
    return true;
}

static bool test_absent_and_no_backend_are_safe(void) {
    bool enabled = false;
    bool persist = false;
    uint8_t slot = 0;

    reset();
    CHECK(!nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot));
    CHECK(!nfc_amiibo_auto_refresh_store_restore(0, true));  /* no record: no cue */
    CHECK(!nfc_amiibo_auto_refresh_is_armed());
    CHECK(!m_present);

    nfc_amiibo_auto_refresh_store_set_backend(NULL, NULL, NULL);
    CHECK(!nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot));
    CHECK(!nfc_amiibo_auto_refresh_store_save(true, 0, false));
    CHECK(!nfc_amiibo_auto_refresh_store_restore(0, true));  /* must not crash */
    CHECK(!nfc_amiibo_auto_refresh_is_armed());
    CHECK(!nfc_amiibo_auto_refresh_store_clear());
    return true;
}

static bool test_repeated_restore_no_double_arm(void) {
    reset();
    CHECK(nfc_amiibo_auto_refresh_store_save(true, 4, true));
    CHECK(!nfc_amiibo_auto_refresh_store_restore(4, true));
    nfc_amiibo_auto_refresh_set_scan_count(3);
    CHECK(!nfc_amiibo_auto_refresh_store_restore(4, true));  /* again, no double arm */
    CHECK(nfc_amiibo_auto_refresh_is_armed());
    CHECK(nfc_amiibo_auto_refresh_slot() == NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL);
    CHECK(nfc_amiibo_auto_refresh_persist());
    CHECK(nfc_amiibo_auto_refresh_scan_count() == 0);
    return true;
}

static bool test_load_rejects_malformed_records(void) {
    bool enabled = false;
    bool persist = false;
    uint8_t slot = 0;
    uint32_t w1 = 0;

    reset();
    CHECK(nfc_amiibo_auto_refresh_store_save(true, 2, false));
    m_flash_len = 4;  /* truncated */
    CHECK(!nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot));

    m_flash_len = 12;  /* oversized: fake read mimics fds buffer guard */
    CHECK(!nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot));

    reset();
    CHECK(nfc_amiibo_auto_refresh_store_save(true, 2, false));
    m_flash[4] |= 0x04u;  /* reserved bit 2 set in word 1 */
    CHECK(!nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot));

    reset();
    CHECK(nfc_amiibo_auto_refresh_store_save(true, 2, false));
    w1 = 0x00000001u | (8u << 8);  /* slot 8 out of range */
    memcpy(&m_flash[4], &w1, 4);
    CHECK(!nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot));

    w1 = 0x00000001u | (254u << 8);  /* 254 is not the 0xFF sentinel */
    memcpy(&m_flash[4], &w1, 4);
    CHECK(!nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot));

    CHECK(!nfc_amiibo_auto_refresh_store_save(true, 8, false));
    CHECK(!nfc_amiibo_auto_refresh_store_save(true, 254, false));
    return true;
}

static bool test_write_delete_failures(void) {
    reset();
    m_write_fails = true;
    CHECK(!nfc_amiibo_auto_refresh_store_save(true, 0, false));
    CHECK(!m_present);

    m_write_fails = false;
    CHECK(nfc_amiibo_auto_refresh_store_save(true, 0, false));
    m_delete_fails = true;
    CHECK(!nfc_amiibo_auto_refresh_store_clear());
    CHECK(m_present);  /* record survives a delete failure */
    return true;
}

int main(void) {
    struct {
        const char *name;
        bool (*fn)(void);
    } tests[] = {
        {"save/load round trip and word encoding", test_save_load_round_trip},
        {"restore re-arms with scan count 0", test_restore_rearms_with_count_zero},
        {"restore disarms and clears a corrupt record", test_restore_clears_corrupt_record},
        {"disable clear removes the persisted record", test_disable_clear_removes_record},
        {"restore ignores active slot and keeps record off NTAG215", test_restore_ignores_slot_and_keeps_record_off_ntag},
        {"absent record and no backend are safe", test_absent_and_no_backend_are_safe},
        {"repeated restore does not double-arm", test_repeated_restore_no_double_arm},
        {"load rejects malformed records", test_load_rejects_malformed_records},
        {"write and delete failures are reported", test_write_delete_failures},
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
