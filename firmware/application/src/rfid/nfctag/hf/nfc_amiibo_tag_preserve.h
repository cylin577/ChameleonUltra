#ifndef NFC_AMIIBO_TAG_PRESERVE_H
#define NFC_AMIIBO_TAG_PRESERVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Pure golden-snapshot bookkeeping for active NTAG215 Amiibo emulation.
 * No SDK/hardware dependencies so it can be unit-tested on the host. */

/* Mirrors TAG_TYPE_NTAG_215 (tag_base_type.h); kept numeric to stay pure. */
#define NFC_AMIIBO_TAG_PRESERVE_NTAG215_TYPE 1101u
/* Holds the full NTAG215 information record (~864 B) with a little headroom. */
#define NFC_AMIIBO_TAG_PRESERVE_SIZE         1024u

typedef struct {
    uint32_t magic;
    uint8_t bytes[NFC_AMIIBO_TAG_PRESERVE_SIZE];
    size_t size;
    bool dirty;
} nfc_amiibo_tag_preserve_t;

/* Target = an active, marked NTAG215 Amiibo slot. The signature is irrelevant:
 * an unsigned but marked Amiibo still gets a golden snapshot, while any
 * unmarked NTAG215 (even with a valid signature) does not. */
bool nfc_amiibo_tag_preserve_is_target(uint16_t tag_type, bool is_amiibo);

bool nfc_amiibo_tag_preserve_is_valid(const nfc_amiibo_tag_preserve_t *ctx);
void nfc_amiibo_tag_preserve_invalidate(nfc_amiibo_tag_preserve_t *ctx);

/* Copy src into the golden snapshot. Ignored when src is too big. */
void nfc_amiibo_tag_preserve_capture(nfc_amiibo_tag_preserve_t *ctx,
                                     const void *src, size_t size);
/* Intentional modification: make the current live state the new golden. */
void nfc_amiibo_tag_preserve_commit(nfc_amiibo_tag_preserve_t *ctx,
                                    const void *src, size_t size);

void nfc_amiibo_tag_preserve_mark_dirty(nfc_amiibo_tag_preserve_t *ctx);
void nfc_amiibo_tag_preserve_mark_clean(nfc_amiibo_tag_preserve_t *ctx);
bool nfc_amiibo_tag_preserve_is_dirty(const nfc_amiibo_tag_preserve_t *ctx);

/* Restore the golden snapshot into dst. No-op when no valid snapshot exists. */
void nfc_amiibo_tag_preserve_take(const nfc_amiibo_tag_preserve_t *ctx, void *dst);

/* Field-edge policy. No-op when golden is inactive (e.g. unsigned Guardian).
 * DETECTED while dirty means the previous session was interrupted without a
 * FIELD_LOST commit: restore golden into `live`. LOST while dirty means a
 * completed session: commit `live` as the new golden so console page writes
 * and the read counter survive into the next scan. */
typedef enum {
    NFC_AMIIBO_PRESERVE_FIELD_NONE = 0,
    NFC_AMIIBO_PRESERVE_FIELD_RESTORE,
    NFC_AMIIBO_PRESERVE_FIELD_COMMIT,
} nfc_amiibo_preserve_field_action_t;

nfc_amiibo_preserve_field_action_t nfc_amiibo_tag_preserve_on_field(
    nfc_amiibo_tag_preserve_t *ctx, bool present, void *live, size_t size);

#endif
