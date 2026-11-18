/* nfc_amiibo_refresh_slot.c - shared CMD 1070 Amiibo UID refresh core. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "app_status.h"
#include "crc_utils.h"
#include "fds_util.h"
#include "nfc_amiibo_keys_store.h"
#include "nfc_amiibo_refresh_slot.h"
#include "nfc_amiibo_uid_refresh.h"
#include "nfc_mf0_ntag.h"
#include "nrf_drv_rng.h"
#include "tag_emulation.h"
#include "tag_persistence.h"

#define AMIIBO_NTAG215_INFO_SIZE \
    (offsetof(nfc_tag_mf0_ntag_information_t, memory) + \
     (NTAG215_TOTAL_PAGES * NFC_TAG_MF0_NTAG_DATA_SIZE))

/* Large scratch buffers: fully written before read, so keep them out of .bss
 * (ultra-standalone has almost no RAM headroom for the stack). */
static __attribute__((section(".noinit"))) uint8_t m_amiibo_old_dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE];
static __attribute__((section(".noinit"))) uint8_t m_amiibo_new_dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE];
static __attribute__((section(".noinit"))) uint32_t m_amiibo_fds_record[(AMIIBO_NTAG215_INFO_SIZE + 3) / 4];

static uint16_t amiibo_refresh_core_status(nfc_amiibo_uid_refresh_status_t status) {
    switch (status) {
        case NFC_AMIIBO_UID_REFRESH_OK:
            return STATUS_SUCCESS;
        case NFC_AMIIBO_UID_REFRESH_RETAIL_KEYS_MISSING:
            return STATUS_AMIIBO_KEYS_MISSING;
        case NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS:
            return STATUS_AMIIBO_KEYS_INVALID;
        case NFC_AMIIBO_UID_REFRESH_INVALID_UID:
        case NFC_AMIIBO_UID_REFRESH_SIGNATURE_PRESENT:
        case NFC_AMIIBO_UID_REFRESH_TAG_HMAC_MISMATCH:
        case NFC_AMIIBO_UID_REFRESH_DATA_HMAC_MISMATCH:
            return STATUS_AMIIBO_UID_INVALID;
        default:
            return STATUS_AMIIBO_UID_FAIL;
    }
}

/* Validity is carried by the response payload, never by the protocol status. */
static uint8_t amiibo_verify_reason(nfc_amiibo_uid_refresh_status_t status) {
    switch (status) {
        case NFC_AMIIBO_UID_REFRESH_OK:
            return NFC_AMIIBO_VERIFY_REASON_VALID;
        case NFC_AMIIBO_UID_REFRESH_RETAIL_KEYS_MISSING:
        case NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS:
            return NFC_AMIIBO_VERIFY_REASON_KEYS_MISSING;
        case NFC_AMIIBO_UID_REFRESH_TAG_HMAC_MISMATCH:
            return NFC_AMIIBO_VERIFY_REASON_TAG_HMAC_MISMATCH;
        case NFC_AMIIBO_UID_REFRESH_DATA_HMAC_MISMATCH:
            return NFC_AMIIBO_VERIFY_REASON_DATA_HMAC_MISMATCH;
        case NFC_AMIIBO_UID_REFRESH_SIGNATURE_PRESENT:
            return NFC_AMIIBO_VERIFY_REASON_SIGNATURE_PRESENT;
        default:
            return NFC_AMIIBO_VERIFY_REASON_OTHER;
    }
}

uint16_t nfc_amiibo_refresh_slot(bool persist, uint8_t out_old_uid[7], uint8_t out_new_uid[7]) {
    /* Restore the persisted keys if the RAM working copy is empty (reboot). */
    if (!nfc_amiibo_uid_refresh_keys_ready()) {
        nfc_amiibo_keys_store_load();
    }
    if (g_is_tag_emulating) {
        return STATUS_DEVICE_MODE_ERROR;
    }

    uint8_t active_slot = tag_emulation_get_slot();
    tag_slot_specific_type_t active_slot_tag_types;
    tag_emulation_get_specific_types_by_slot(active_slot, &active_slot_tag_types);
    if (active_slot_tag_types.tag_hf != TAG_TYPE_NTAG_215) {
        return STATUS_INVALID_SLOT_TYPE;
    }

    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_NTAG_215);
    if (buffer == NULL) {
        return STATUS_INVALID_SLOT_TYPE;
    }
    nfc_tag_mf0_ntag_information_t *info = (nfc_tag_mf0_ntag_information_t *)buffer->buffer;
    uint8_t *signature = nfc_tag_mf0_ntag_get_signature_data();
    if (signature == NULL) {
        return STATUS_AMIIBO_UID_INVALID;
    }

    memcpy(m_amiibo_old_dump, info->memory[0], sizeof(m_amiibo_old_dump));
    uint8_t old_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE] = {
        m_amiibo_old_dump[0], m_amiibo_old_dump[1], m_amiibo_old_dump[2],
        m_amiibo_old_dump[4], m_amiibo_old_dump[5], m_amiibo_old_dump[6],
        m_amiibo_old_dump[7],
    };
    uint8_t new_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE];
    do {
        nrf_drv_rng_block_rand(new_uid, sizeof(new_uid));
        new_uid[0] = 0x04;
    } while (memcmp(old_uid, new_uid, sizeof(old_uid)) == 0);

    nfc_amiibo_uid_refresh_status_t refresh_status = nfc_amiibo_uid_refresh_apply(
        m_amiibo_old_dump, new_uid, signature, m_amiibo_new_dump);
    if (refresh_status != NFC_AMIIBO_UID_REFRESH_OK) {
        return amiibo_refresh_core_status(refresh_status);
    }
    if (g_is_tag_emulating) {
        return STATUS_DEVICE_MODE_ERROR;
    }

    tag_emulation_sense_switch(TAG_SENSE_HF, false);
    if (g_is_tag_emulating) {
        tag_emulation_sense_switch(TAG_SENSE_HF, true);
        return STATUS_DEVICE_MODE_ERROR;
    }

    bool commit_ok = true;
    if (persist) {
        memcpy(m_amiibo_fds_record, info, AMIIBO_NTAG215_INFO_SIZE);
        nfc_tag_mf0_ntag_information_t *prepared =
            (nfc_tag_mf0_ntag_information_t *)m_amiibo_fds_record;
        memcpy(prepared->memory[0], m_amiibo_new_dump, sizeof(m_amiibo_new_dump));
        memcpy(prepared->res_coll.uid, new_uid, sizeof(new_uid));
        NFC_AMIIBO_UID_REFRESH_PREPARE_PERSISTED_CONFIG(prepared);

        fds_slot_record_map_t map_info;
        get_fds_map_by_slot_sense_type_for_dump(active_slot, TAG_SENSE_HF, &map_info);
        commit_ok = fds_write_sync(map_info.id, map_info.key,
                                   AMIIBO_NTAG215_INFO_SIZE, m_amiibo_fds_record);
    }

    if (commit_ok) {
        memcpy(info->memory[0], m_amiibo_new_dump, sizeof(m_amiibo_new_dump));
        memcpy(info->res_coll.uid, new_uid, sizeof(new_uid));
        uint16_t crc;
        calc_14a_crc_lut((uint8_t *)info, AMIIBO_NTAG215_INFO_SIZE, (uint8_t *)&crc);
        *buffer->crc = crc;
    }
    tag_emulation_sense_switch(TAG_SENSE_HF, true);

    if (!commit_ok) {
        return STATUS_FLASH_WRITE_FAIL;
    }

    memcpy(out_old_uid, old_uid, sizeof(old_uid));
    memcpy(out_new_uid, new_uid, sizeof(new_uid));
    return STATUS_SUCCESS;
}

uint16_t nfc_amiibo_verify_slot(uint8_t out_uid[7], uint8_t *reason) {
    uint8_t uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE] = { 0 };
    uint8_t verify_reason = NFC_AMIIBO_VERIFY_REASON_OTHER;
    uint16_t result = STATUS_SUCCESS;
    tag_slot_specific_type_t types;

    /* Restore the persisted keys if the RAM working copy is empty (reboot). */
    if (!nfc_amiibo_uid_refresh_keys_ready()) {
        nfc_amiibo_keys_store_load();
    }

    if (g_is_tag_emulating) {
        result = STATUS_DEVICE_MODE_ERROR;
    } else {
        tag_emulation_get_specific_types_by_slot(tag_emulation_get_slot(), &types);
        tag_data_buffer_t *buffer = NULL;
        uint8_t *signature = NULL;
        if (types.tag_hf != TAG_TYPE_NTAG_215) {
            verify_reason = NFC_AMIIBO_VERIFY_REASON_NOT_NTAG215;
        } else if ((buffer = get_buffer_by_tag_type(TAG_TYPE_NTAG_215)) == NULL) {
            verify_reason = NFC_AMIIBO_VERIFY_REASON_NOT_NTAG215;
        } else if ((signature = nfc_tag_mf0_ntag_get_signature_data()) == NULL) {
            verify_reason = NFC_AMIIBO_VERIFY_REASON_OTHER;
        } else {
            nfc_tag_mf0_ntag_information_t *info = (nfc_tag_mf0_ntag_information_t *)buffer->buffer;
            uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE];
            memcpy(dump, info->memory, sizeof(dump));
            nfc_amiibo_uid_refresh_status_t status = nfc_amiibo_uid_refresh_validate_apply(
                dump, signature, uid, NULL);
            verify_reason = amiibo_verify_reason(status);
            if (status != NFC_AMIIBO_UID_REFRESH_OK) {
                memset(uid, 0, sizeof(uid));
            }
        }
    }

    *reason = verify_reason;
    memcpy(out_uid, uid, sizeof(uid));
    return result;
}
