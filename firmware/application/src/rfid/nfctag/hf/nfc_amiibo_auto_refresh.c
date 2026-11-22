/* nfc_amiibo_auto_refresh.c - see nfc_amiibo_auto_refresh.h */

#include <string.h>

#include "nfc_amiibo_auto_refresh.h"

#define CMD_PWD_AUTH       0x1Bu
#define CMD_READ           0x30u
#define CMD_FAST_READ      0x3Au
#define READ_FRAMES_MIN    2
#define ACTIVITY_AUTH_BIT  0x80
#define ACTIVITY_READ_MAX  127

static bool  m_armed;
static bool  m_busy;
static bool  m_persist;
static bool  m_field_present;
static bool  m_scan_pending;
static bool  m_session_refreshed;
static bool  m_auth_seen;
static uint8_t  m_read_count;
static bool  m_last_auth_seen;
static uint8_t  m_last_read_count;
static uint8_t  m_slot;
static uint32_t m_field_start;
static uint32_t m_quiet_since;
static uint32_t m_pending_since;
static uint32_t m_scan_count;
static nfc_amiibo_uid_refresh_status_t m_last_status;
static uint8_t m_last_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE];
static nfc_amiibo_auto_refresh_fn m_refresh_fn;

__attribute__((weak))
nfc_amiibo_uid_refresh_status_t nfc_amiibo_auto_refresh_do_refresh(
    uint8_t slot, bool persist, uint8_t uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE]) {
    (void)slot;
    (void)persist;
    memset(uid, 0, NFC_AMIIBO_UID_REFRESH_UID_SIZE);
    return NFC_AMIIBO_UID_REFRESH_OK;
}

void nfc_amiibo_auto_refresh_init(void) {
    m_armed = false;
    m_busy = false;
    m_persist = false;
    m_field_present = false;
    m_scan_pending = false;
    m_session_refreshed = false;
    m_auth_seen = false;
    m_read_count = 0;
    m_last_auth_seen = false;
    m_last_read_count = 0;
    m_slot = 0;
    m_field_start = 0;
    m_quiet_since = 0;
    m_pending_since = 0;
    m_scan_count = 0;
    m_last_status = NFC_AMIIBO_UID_REFRESH_OK;
    memset(m_last_uid, 0, sizeof(m_last_uid));
    /* m_refresh_fn survives init so tests bind the hook once. */
}

void nfc_amiibo_auto_refresh_set_refresh_fn(nfc_amiibo_auto_refresh_fn fn) {
    m_refresh_fn = fn;
}

void nfc_amiibo_auto_refresh_set_busy(bool busy) {
    m_busy = busy;
}

void nfc_amiibo_auto_refresh_set_scan_count(uint32_t count) {
    m_scan_count = count;
}

void nfc_amiibo_auto_refresh_arm(uint8_t slot, bool persist) {
    m_slot = slot;
    m_persist = persist;
    m_armed = true;
}

void nfc_amiibo_auto_refresh_disarm(void) {
    m_armed = false;
    m_scan_pending = false;
}

void nfc_amiibo_auto_refresh_on_slot_data_load(bool explicit_slot_data_write) {
    /* Slot switches reload the same data through the generic load callback and
     * pass false here: global arming must survive them. Only a real slot data
     * write/upload/generate disarms the arm captured for the old slot. */
    if (explicit_slot_data_write) {
        nfc_amiibo_auto_refresh_disarm();
    }
}

void nfc_amiibo_auto_refresh_on_field(bool present, uint32_t ticks) {
    if (present) {
        if (!m_field_present) {
            /* A new field session starts its hold timer and clears command
             * activity, but it does NOT re-arm by itself. Only a genuinely
             * quiet gap between sessions clears the one-refresh latch, so a
             * rapid polling burst cannot chain multiple UID rewrites. */
            if ((uint32_t)(ticks - m_quiet_since) >=
                    NFC_AMIIBO_AUTO_REFRESH_QUIET_MS) {
                m_session_refreshed = false;
            }
            m_field_present = true;
            m_field_start = ticks;
            m_auth_seen = false;
            m_read_count = 0;
        }
        /* Any FIELD_DETECTED cancels a scan waiting in the loss window. */
        m_scan_pending = false;
        return;
    }

    if (!m_field_present) {
        return;
    }
    m_field_present = false;
    /* Start (or restart) the no-field quiet window on every real loss. */
    m_quiet_since = ticks;

    /* Snapshot this session's activity for the CMD 1072 diagnostic byte.
     * Late command frames after FIELD_LOST are ignored by on_command(). */
    m_last_auth_seen = m_auth_seen;
    m_last_read_count = m_read_count;

    uint32_t held = ticks - m_field_start;
    if (held >= NFC_AMIIBO_AUTO_REFRESH_FIELD_MIN_MS &&
            (m_auth_seen || m_read_count >= READ_FRAMES_MIN) &&
            !m_busy && !m_session_refreshed) {
        m_scan_pending = true;
        m_pending_since = ticks;
    }
}

void nfc_amiibo_auto_refresh_on_command(uint8_t cmd) {
    if (!m_field_present) {
        return;
    }
    if (cmd == CMD_PWD_AUTH) {
        m_auth_seen = true;
    } else if (cmd == CMD_READ || cmd == CMD_FAST_READ) {
        if (m_read_count < UINT8_MAX) {
            m_read_count++;
        }
    }
}

bool nfc_amiibo_auto_refresh_process(uint32_t ticks) {
    if (!m_scan_pending || m_busy || m_field_present || !m_armed ||
            m_session_refreshed) {
        return false;
    }
    if ((uint32_t)(ticks - m_pending_since) <
            NFC_AMIIBO_AUTO_REFRESH_LOSS_STABLE_MS) {
        return false;
    }

    m_scan_pending = false;
    m_busy = true;

    nfc_amiibo_auto_refresh_fn fn =
        (m_refresh_fn != NULL) ? m_refresh_fn : nfc_amiibo_auto_refresh_do_refresh;
    uint8_t uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE];
    nfc_amiibo_uid_refresh_status_t status = fn(m_slot, m_persist, uid);

    m_last_status = status;
    memcpy(m_last_uid, uid, sizeof(m_last_uid));
    if (m_scan_count < UINT32_MAX) {
        m_scan_count++;
    }
    m_session_refreshed = true;
    m_busy = false;
    return true;
}

bool nfc_amiibo_auto_refresh_is_armed(void) { return m_armed; }
uint8_t nfc_amiibo_auto_refresh_slot(void) { return m_slot; }
bool nfc_amiibo_auto_refresh_persist(void) { return m_persist; }
bool nfc_amiibo_auto_refresh_is_busy(void) { return m_busy; }
bool nfc_amiibo_auto_refresh_field_present(void) { return m_field_present; }
bool nfc_amiibo_auto_refresh_scan_pending(void) { return m_scan_pending; }
bool nfc_amiibo_auto_refresh_session_refreshed(void) { return m_session_refreshed; }
uint32_t nfc_amiibo_auto_refresh_scan_count(void) { return m_scan_count; }
uint8_t nfc_amiibo_auto_refresh_activity_byte(void) {
    uint8_t reads = m_last_read_count < ACTIVITY_READ_MAX ? m_last_read_count : ACTIVITY_READ_MAX;
    return (uint8_t)((m_last_auth_seen ? ACTIVITY_AUTH_BIT : 0u) | reads);
}

nfc_amiibo_uid_refresh_status_t nfc_amiibo_auto_refresh_last_status(void) {
    return m_last_status;
}

void nfc_amiibo_auto_refresh_last_uid(
    uint8_t out[NFC_AMIIBO_UID_REFRESH_UID_SIZE]) {
    memcpy(out, m_last_uid, NFC_AMIIBO_UID_REFRESH_UID_SIZE);
}
