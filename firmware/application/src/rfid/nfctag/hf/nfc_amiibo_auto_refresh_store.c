/* nfc_amiibo_auto_refresh_store.c - see nfc_amiibo_auto_refresh_store.h */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "nfc_amiibo_auto_refresh.h"
#include "nfc_amiibo_auto_refresh_store.h"

/* FDS writes need a word-aligned buffer; the same buffer is reused for reads
 * so the 8-byte record never lands on the stack. */
static uint32_t m_record_words[2];
static uint8_t *const m_record = (uint8_t *)m_record_words;

static nfc_amiibo_auto_refresh_read_fn m_read;
static nfc_amiibo_auto_refresh_write_fn m_write;
static nfc_amiibo_auto_refresh_delete_fn m_delete;

/* bit 0 enabled, bit 1 persist, bits 8..15 slot; everything else reserved. */
#define WORD1_ALLOWED_MASK (0x00000003u | 0x0000FF00u)
#define WORD1_ENABLED_BIT  0x00000001u
#define WORD1_PERSIST_BIT  0x00000002u
#define WORD1_SLOT_SHIFT   8u

/* Legacy records carry a single slot (0..7); new arming uses the all-slot
 * sentinel. Both are valid on disk so old records still restore. */
static bool slot_is_valid(uint8_t slot) {
    return slot < NFC_AMIIBO_AUTO_REFRESH_STORE_MAX_SLOT ||
           slot == NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL;
}

void nfc_amiibo_auto_refresh_store_set_backend(
    nfc_amiibo_auto_refresh_read_fn read,
    nfc_amiibo_auto_refresh_write_fn write,
    nfc_amiibo_auto_refresh_delete_fn del) {
    m_read = read;
    m_write = write;
    m_delete = del;
}

bool nfc_amiibo_auto_refresh_store_load(bool *enabled, bool *persist, uint8_t *slot) {
    if (m_read == NULL) {
        return false;
    }
    uint16_t length = NFC_AMIIBO_AUTO_REFRESH_STORE_RECORD_SIZE;
    if (!m_read(NFC_AMIIBO_AUTO_REFRESH_FDS_FILE_ID,
                NFC_AMIIBO_AUTO_REFRESH_FDS_KEY, &length, m_record) ||
        length != NFC_AMIIBO_AUTO_REFRESH_STORE_RECORD_SIZE) {
        return false;
    }
    if (m_record_words[0] != NFC_AMIIBO_AUTO_REFRESH_STORE_MAGIC) {
        return false;
    }
    uint32_t word1 = m_record_words[1];
    if ((word1 & ~WORD1_ALLOWED_MASK) != 0u) {
        return false;
    }
    uint8_t decoded_slot = (uint8_t)((word1 >> WORD1_SLOT_SHIFT) & 0xFFu);
    if (!slot_is_valid(decoded_slot)) {
        return false;
    }
    if (enabled != NULL) {
        *enabled = (word1 & WORD1_ENABLED_BIT) != 0u;
    }
    if (persist != NULL) {
        *persist = (word1 & WORD1_PERSIST_BIT) != 0u;
    }
    if (slot != NULL) {
        *slot = decoded_slot;
    }
    return true;
}

bool nfc_amiibo_auto_refresh_store_save(bool enabled, uint8_t slot, bool persist) {
    if (!slot_is_valid(slot) || m_write == NULL) {
        return false;
    }
    m_record_words[0] = NFC_AMIIBO_AUTO_REFRESH_STORE_MAGIC;
    m_record_words[1] = (enabled ? WORD1_ENABLED_BIT : 0u) |
                        (persist ? WORD1_PERSIST_BIT : 0u) |
                        ((uint32_t)slot << WORD1_SLOT_SHIFT);
    return m_write(NFC_AMIIBO_AUTO_REFRESH_FDS_FILE_ID,
                   NFC_AMIIBO_AUTO_REFRESH_FDS_KEY,
                   NFC_AMIIBO_AUTO_REFRESH_STORE_RECORD_SIZE, m_record_words);
}

bool nfc_amiibo_auto_refresh_store_clear(void) {
    memset(m_record_words, 0, sizeof(m_record_words));
    if (m_delete == NULL) {
        return false;
    }
    return m_delete(NFC_AMIIBO_AUTO_REFRESH_FDS_FILE_ID,
                    NFC_AMIIBO_AUTO_REFRESH_FDS_KEY) > 0;
}

bool nfc_amiibo_auto_refresh_store_restore(uint8_t active_slot, bool active_slot_is_amiibo) {
    bool enabled = false;
    bool persist = false;
    uint8_t slot = 0;
    bool loaded = nfc_amiibo_auto_refresh_store_load(&enabled, &persist, &slot);

    (void)active_slot;           /* all-slot arming no longer depends on the active slot */
    (void)active_slot_is_amiibo; /* non-Amiibo sessions are filtered at refresh time, not boot */
    (void)slot;                  /* legacy single-slot records restore as all-slot too */

    if (!loaded || !enabled) {
        /* Absent, corrupt or disabled: nothing to re-arm, clear as before. */
        nfc_amiibo_auto_refresh_disarm();
        (void)nfc_amiibo_auto_refresh_store_clear();
        return false;
    }

    /* Valid persisted arming: re-arm every slot from a clean detector state so
     * the scan counter starts at 0 and no field session carries over reboot. */
    nfc_amiibo_auto_refresh_init();
    nfc_amiibo_auto_refresh_arm(NFC_AMIIBO_AUTO_REFRESH_SLOT_ALL, persist);
    return false;
}
