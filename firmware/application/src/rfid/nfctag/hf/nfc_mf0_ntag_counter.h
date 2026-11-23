#ifndef NFC_MF0_NTAG_COUNTER_H
#define NFC_MF0_NTAG_COUNTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Pure per-field-session counter policy for MF0/NTAG emulation.
 * No SDK/hardware dependencies so it can be unit-tested on the host. */

/* Mirrors TAG_TYPE_NTAG_215 (tag_base_type.h); kept numeric to stay pure. */
#define NFC_MF0_NTAG_COUNTER_TAG_TYPE_NTAG215 1101u
/* Mirrors CONF_ACCESS_NFC_CNT_EN in nfc_mf0_ntag.c. */
#define NFC_MF0_NTAG_COUNTER_ACCESS_NFC_CNT_EN 0x10u

/* Called once per READ/FAST_READ. `first_read` is the firmware's per-field
 * session flag; `counter` points at the 3-byte NFC counter. Only an active
 * NTAG215 Amiibo (`is_amiibo`) keeps the counter fixed (pixl.js behavior: NS2
 * rejects tags whose counter advances between scans). A plain (unmarked)
 * NTAG215 and every other NTAG type keep the old one-per-session increment. */
void nfc_mf0_ntag_counter_on_read(uint16_t tag_type, uint8_t access,
                                  bool *first_read, uint8_t counter[3],
                                  bool is_amiibo);

#endif
