#include "nfc_amiibo_slot_mark.h"

bool nfc_amiibo_slot_mark_detect(uint16_t tag_type, const uint8_t page4[4]) {
    return tag_type == NFC_AMIIBO_SLOT_MARK_NTAG215_TYPE &&
           page4 != NULL && page4[0] == NFC_AMIIBO_SLOT_MARK_PAGE4_MAGIC;
}

void nfc_amiibo_slot_mark_update(bool locked, bool detected, bool *is_amiibo) {
    if (is_amiibo == NULL) return;
    if (!locked) *is_amiibo = detected;
}

bool nfc_amiibo_slot_mark_is_active(bool slot_is_ntag215, bool cached_is_ntag215,
                                    bool info_present, bool marked) {
    return slot_is_ntag215 && cached_is_ntag215 && info_present && marked;
}

bool nfc_amiibo_slot_mark_parse_set(uint16_t length, const uint8_t *data,
                                    uint8_t *slot, bool *mark) {
    if (length != 2 || data == NULL || slot == NULL || mark == NULL) return false;
    if (data[0] >= NFC_AMIIBO_SLOT_MARK_MAX_SLOT || data[1] > 1) return false;
    *slot = data[0];
    *mark = data[1] != 0;
    return true;
}

bool nfc_amiibo_slot_mark_parse_get(uint16_t length, const uint8_t *data,
                                    uint8_t *slot) {
    if (length != 1 || data == NULL || slot == NULL) return false;
    if (data[0] >= NFC_AMIIBO_SLOT_MARK_MAX_SLOT) return false;
    *slot = data[0];
    return true;
}
