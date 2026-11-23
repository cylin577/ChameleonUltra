#include "nfc_mf0_ntag_pwd_auth.h"

bool nfc_mf0_ntag_pwd_auth_decide(uint16_t tag_type,
                                  const uint8_t supplied_pwd[4],
                                  const uint8_t stored_pwd[4],
                                  const uint8_t stored_pack[2],
                                  bool is_amiibo,
                                  uint8_t pack_out[2]) {
    /* pixl.js-style NTAG215 Amiibo emulation: ignore whatever the reader
     * sends, always ACK with PACK 80 80 so NS2 accepts the tag. The configured
     * PWD/PACK in the dump stay untouched. A plain (unmarked) NTAG215 and all
     * other MF0/NTAG types keep the strict PWD/PACK comparison below. */
    if (tag_type == NFC_MF0_NTAG_PWD_AUTH_TAG_TYPE_NTAG215 && is_amiibo) {
        if (pack_out != NULL) {
            pack_out[0] = NFC_MF0_NTAG_PWD_AUTH_AMIBO_PACK_BYTE;
            pack_out[1] = NFC_MF0_NTAG_PWD_AUTH_AMIBO_PACK_BYTE;
        }
        return true;
    }

    if (supplied_pwd == NULL || stored_pwd == NULL || stored_pack == NULL) return false;
    for (size_t i = 0; i < 4; i++) {
        if (supplied_pwd[i] != stored_pwd[i]) return false;
    }
    if (pack_out != NULL) {
        pack_out[0] = stored_pack[0];
        pack_out[1] = stored_pack[1];
    }
    return true;
}
