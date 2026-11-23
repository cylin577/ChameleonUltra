#ifndef NFC_MF0_NTAG_PWD_AUTH_H
#define NFC_MF0_NTAG_PWD_AUTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Pure PWD_AUTH response policy for MF0/NTAG emulation.
 * No SDK/hardware dependencies so it can be unit-tested on the host. */

/* Mirrors TAG_TYPE_NTAG_215 (tag_base_type.h); kept numeric to stay pure. */
#define NFC_MF0_NTAG_PWD_AUTH_TAG_TYPE_NTAG215 1101u

/* PACK returned for NTAG215 Amiibo emulation, matching pixl.js. */
#define NFC_MF0_NTAG_PWD_AUTH_AMIBO_PACK_BYTE 0x80u

/* Decide the PWD_AUTH response.
 *
 * `tag_type`     - emulated tag type (numeric TAG_TYPE_* value).
 * `supplied_pwd` - 4 password bytes from the reader.
 * `stored_pwd`   - 4 configured PWD bytes (read-only).
 * `stored_pack`  - 2 configured PACK bytes (read-only).
 * `is_amiibo`    - true only when the active slot is a marked NTAG215 Amiibo.
 * `pack_out`     - receives the 2 PACK bytes when the function returns true.
 *
 * Returns true to authenticate (ACK + PACK in `pack_out`), false to reject
 * (NAK). Only an active NTAG215 Amiibo (`is_amiibo`) ignores the supplied
 * password and answers with a fixed PACK 80 80, like pixl.js; the stored
 * PWD/PACK bytes are never read for the response nor modified. A plain
 * NTAG215 and every other tag type keep strict password comparison and return
 * the configured PACK. */
bool nfc_mf0_ntag_pwd_auth_decide(uint16_t tag_type,
                                  const uint8_t supplied_pwd[4],
                                  const uint8_t stored_pwd[4],
                                  const uint8_t stored_pack[2],
                                  bool is_amiibo,
                                  uint8_t pack_out[2]);

#endif
