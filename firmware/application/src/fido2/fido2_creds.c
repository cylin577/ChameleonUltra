#include "fido2/fido2_creds.h"

#include <stdio.h>
#include <string.h>

#include "utils/fds_ids.h"
#include "utils/fds_util.h"

#define NRF_LOG_MODULE_NAME f2_creds
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

#define F2_CREDS_SLOTS     16u
#define F2_CREDS_KEY_BASE  0x0001u
#define F2_RP_HASH_SIZE    32u

/* Device-local FDS, no secure-element binding: private keys stored in clear. */
static uint32_t m_scratch[(sizeof(fido2_cred_rec_t) + 3) / 4];

static uint16_t slot_key(uint16_t slot) {
    return (uint16_t)(F2_CREDS_KEY_BASE + slot);
}

static bool slot_valid(const fido2_cred_rec_t *rec) {
    return rec->cred_id_len > 0 && rec->cred_id_len <= FIDO2_CRED_ID_MAX &&
           rec->user_id_len <= FIDO2_USER_ID_MAX;
}

static bool slot_load(uint16_t slot, fido2_cred_rec_t *out) {
    uint16_t len = sizeof(fido2_cred_rec_t);
    if (!fds_read_sync(FDS_FIDO2_FILE_ID, slot_key(slot), &len, (uint8_t *)m_scratch)) {
        return false;
    }
    if (len != sizeof(fido2_cred_rec_t)) {
        return false;
    }
    memcpy(out, m_scratch, sizeof(*out));
    return true;
}

static bool slot_store(uint16_t slot, const fido2_cred_rec_t *rec) {
    memcpy(m_scratch, rec, sizeof(*rec));
    return fds_write_sync(FDS_FIDO2_FILE_ID, slot_key(slot), sizeof(*rec), m_scratch);
}

static bool cred_id_equal(const fido2_cred_rec_t *rec, const uint8_t *id, size_t id_len) {
    return (size_t)rec->cred_id_len == id_len && memcmp(rec->cred_id, id, id_len) == 0;
}

fido2_status_t f2_creds_find_by_rp_user(const uint8_t *rp, const uint8_t *uid,
                                        size_t uid_len, fido2_cred_rec_t *out) {
    if (rp == NULL || out == NULL || uid_len > FIDO2_USER_ID_MAX ||
        (uid_len > 0 && uid == NULL)) {
        return FIDO2_ST_INVALID_PARAM;
    }

    for (uint16_t slot = 0; slot < F2_CREDS_SLOTS; slot++) {
        fido2_cred_rec_t rec;
        if (!slot_load(slot, &rec) || !slot_valid(&rec)) {
            continue;
        }
        if ((size_t)rec.user_id_len != uid_len ||
            (uid_len > 0 && memcmp(rec.user_id, uid, uid_len) != 0) ||
            memcmp(rec.rp_hash, rp, F2_RP_HASH_SIZE) != 0) {
            continue;
        }
        *out = rec;
        return FIDO2_ST_OK;
    }
    return FIDO2_ST_NO_CREDENTIALS;
}

fido2_status_t f2_creds_find_by_id(const uint8_t *id, size_t id_len,
                                   fido2_cred_rec_t *out) {
    if (id == NULL || out == NULL || id_len == 0 || id_len > FIDO2_CRED_ID_MAX) {
        return FIDO2_ST_INVALID_PARAM;
    }

    for (uint16_t slot = 0; slot < F2_CREDS_SLOTS; slot++) {
        fido2_cred_rec_t rec;
        if (!slot_load(slot, &rec) || !slot_valid(&rec)) {
            continue;
        }
        if (cred_id_equal(&rec, id, id_len)) {
            *out = rec;
            return FIDO2_ST_OK;
        }
    }
    return FIDO2_ST_NO_CREDENTIALS;
}

fido2_status_t f2_creds_add(const fido2_cred_rec_t *rec) {
    if (rec == NULL || !slot_valid(rec)) {
        return FIDO2_ST_INVALID_PARAM;
    }

    uint16_t free_slot = F2_CREDS_SLOTS;
    for (uint16_t slot = 0; slot < F2_CREDS_SLOTS; slot++) {
        fido2_cred_rec_t old;
        if (!slot_load(slot, &old) || !slot_valid(&old)) {
            if (free_slot == F2_CREDS_SLOTS) {
                free_slot = slot;
            }
            continue;
        }
        if (cred_id_equal(&old, rec->cred_id, rec->cred_id_len)) {
            return FIDO2_ST_EXCLUDED;
        }
    }
    if (free_slot == F2_CREDS_SLOTS) {
        NRF_LOG_ERROR("f2_creds: add failed, no free slot");
        return FIDO2_ST_OTHER;
    }
    if (!slot_store(free_slot, rec)) {
        NRF_LOG_ERROR("f2_creds: add failed, slot_store(%u) failed", (unsigned)free_slot);
        return FIDO2_ST_OTHER;
    }
    return FIDO2_ST_OK;
}

fido2_status_t f2_creds_bump_sign_count(const uint8_t *id, size_t id_len,
                                        uint32_t *new_count) {
    if (id == NULL || new_count == NULL || id_len == 0 || id_len > FIDO2_CRED_ID_MAX) {
        return FIDO2_ST_INVALID_PARAM;
    }

    for (uint16_t slot = 0; slot < F2_CREDS_SLOTS; slot++) {
        fido2_cred_rec_t rec;
        if (!slot_load(slot, &rec) || !slot_valid(&rec)) {
            continue;
        }
        if (!cred_id_equal(&rec, id, id_len)) {
            continue;
        }
        if (rec.sign_count != UINT32_MAX) {
            rec.sign_count++;
        }
        if (!slot_store(slot, &rec)) {
            NRF_LOG_ERROR("f2_creds: bump_sign_count failed, slot_store(%u) failed", (unsigned)slot);
            return FIDO2_ST_OTHER;
        }
        *new_count = rec.sign_count;
        return FIDO2_ST_OK;
    }
    return FIDO2_ST_NO_CREDENTIALS;
}

fido2_status_t f2_creds_next(uint16_t *cursor, fido2_cred_rec_t *out) {
    if (cursor == NULL || out == NULL) {
        return FIDO2_ST_INVALID_PARAM;
    }
    if (*cursor >= F2_CREDS_SLOTS) {
        *cursor = F2_CREDS_SLOTS;
        return FIDO2_ST_NO_CREDENTIALS;
    }

    for (uint16_t slot = *cursor; slot < F2_CREDS_SLOTS; slot++) {
        fido2_cred_rec_t rec;
        if (!slot_load(slot, &rec) || !slot_valid(&rec)) {
            continue;
        }
        *out = rec;
        *cursor = (uint16_t)(slot + 1);
        return FIDO2_ST_OK;
    }
    *cursor = F2_CREDS_SLOTS;
    return FIDO2_ST_NO_CREDENTIALS;
}

void f2_creds_reset(void) {
    for (uint16_t slot = 0; slot < F2_CREDS_SLOTS; slot++) {
        (void)fds_delete_sync(FDS_FIDO2_FILE_ID, slot_key(slot));
    }
}

static void list_append(uint8_t *out, size_t cap, size_t *used, const char *s) {
    while (*s != '\0' && (*used + 1) < cap) {
        out[(*used)++] = (uint8_t)*s++;
    }
}

size_t f2_creds_list(uint8_t *out, size_t cap) {
    if (out == NULL || cap == 0) {
        return 0;
    }

    size_t used = 0;
    list_append(out, cap, &used, "slot idlen userlen count\n");
    for (uint16_t slot = 0; slot < F2_CREDS_SLOTS; slot++) {
        char line[64];
        fido2_cred_rec_t rec;
        if (slot_load(slot, &rec) && slot_valid(&rec)) {
            (void)snprintf(line, sizeof(line), "%u %u %u %lu\n", (unsigned)slot,
                           (unsigned)rec.cred_id_len, (unsigned)rec.user_id_len,
                           (unsigned long)rec.sign_count);
        } else {
            (void)snprintf(line, sizeof(line), "%u -\n", (unsigned)slot);
        }
        list_append(out, cap, &used, line);
    }
    out[used] = '\0';
    return used;
}
