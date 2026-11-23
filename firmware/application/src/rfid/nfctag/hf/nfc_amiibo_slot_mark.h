#ifndef NFC_AMIIBO_SLOT_MARK_H
#define NFC_AMIIBO_SLOT_MARK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Pure, SDK-free policy for the persistent per-slot Amiibo marker.
 * No hardware/FDS dependencies so it can be unit-tested on the host. */

/* Mirrors TAG_TYPE_NTAG_215 (tag_base_type.h); kept numeric to stay pure. */
#define NFC_AMIIBO_SLOT_MARK_NTAG215_TYPE 1101u
/* Amiibo dumps carry 0xA5 as the first byte of page 4. */
#define NFC_AMIIBO_SLOT_MARK_PAGE4_MAGIC  0xA5u
/* Mirrors TAG_MAX_SLOT_NUM (tag_emulation.h). */
#define NFC_AMIIBO_SLOT_MARK_MAX_SLOT     8u

/* True only for NTAG215 whose page 4 starts with the Amiibo 0xA5 marker. */
bool nfc_amiibo_slot_mark_detect(uint16_t tag_type, const uint8_t page4[4]);

/* A locked marker keeps its explicit value; an unlocked one follows detection. */
void nfc_amiibo_slot_mark_update(bool locked, bool detected, bool *is_amiibo);

/* Active-slot gate: every condition must hold. */
bool nfc_amiibo_slot_mark_is_active(bool slot_is_ntag215, bool cached_is_ntag215,
                                    bool info_present, bool marked);

/* Wire parsing for CMD 1074/1075. */
bool nfc_amiibo_slot_mark_parse_set(uint16_t length, const uint8_t *data,
                                    uint8_t *slot, bool *mark);
bool nfc_amiibo_slot_mark_parse_get(uint16_t length, const uint8_t *data,
                                    uint8_t *slot);

#endif
