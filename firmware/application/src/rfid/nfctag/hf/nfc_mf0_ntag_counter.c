#include "nfc_mf0_ntag_counter.h"

void nfc_mf0_ntag_counter_on_read(uint16_t tag_type, uint8_t access,
                                  bool *first_read, uint8_t counter[3],
                                  bool is_amiibo) {
    if (first_read == NULL || *first_read) return;
    *first_read = true;

    if ((access & NFC_MF0_NTAG_COUNTER_ACCESS_NFC_CNT_EN) == 0) return;

    /* pixl.js-style NTAG215 Amiibo emulation: never bump the counter on a
     * field read, so the same value is presented on every scan (required for
     * NS2 acceptance). Explicit counter APIs still own the stored value. */
    if (tag_type == NFC_MF0_NTAG_COUNTER_TAG_TYPE_NTAG215 && is_amiibo) return;
    if (counter == NULL) return;

    uint32_t value = ((uint32_t)counter[0] << 16) |
                     ((uint32_t)counter[1] << 8) |
                     ((uint32_t)counter[2]);
    if (value < 0xFFFFFFu) value++;
    counter[0] = (uint8_t)(value >> 16);
    counter[1] = (uint8_t)(value >> 8);
    counter[2] = (uint8_t)value;
}
