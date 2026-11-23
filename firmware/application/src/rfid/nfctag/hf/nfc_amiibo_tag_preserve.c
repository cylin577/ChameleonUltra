#include <string.h>

#include "nfc_amiibo_tag_preserve.h"

#define PRESERVE_MAGIC 0x414D6955u /* "AMiU" */

bool nfc_amiibo_tag_preserve_is_target(uint16_t tag_type, bool is_amiibo) {
    return tag_type == NFC_AMIIBO_TAG_PRESERVE_NTAG215_TYPE && is_amiibo;
}

bool nfc_amiibo_tag_preserve_is_valid(const nfc_amiibo_tag_preserve_t *ctx) {
    return ctx != NULL && ctx->magic == PRESERVE_MAGIC &&
           ctx->size > 0 && ctx->size <= NFC_AMIIBO_TAG_PRESERVE_SIZE;
}

void nfc_amiibo_tag_preserve_invalidate(nfc_amiibo_tag_preserve_t *ctx) {
    if (ctx == NULL) return;
    ctx->magic = 0;
    ctx->size = 0;
    ctx->dirty = false;
}

void nfc_amiibo_tag_preserve_capture(nfc_amiibo_tag_preserve_t *ctx,
                                     const void *src, size_t size) {
    if (ctx == NULL || src == NULL || size == 0 || size > NFC_AMIIBO_TAG_PRESERVE_SIZE) {
        nfc_amiibo_tag_preserve_invalidate(ctx);
        return;
    }
    memcpy(ctx->bytes, src, size);
    ctx->size = size;
    ctx->dirty = false;
    ctx->magic = PRESERVE_MAGIC;
}

void nfc_amiibo_tag_preserve_commit(nfc_amiibo_tag_preserve_t *ctx,
                                    const void *src, size_t size) {
    nfc_amiibo_tag_preserve_capture(ctx, src, size);
}

void nfc_amiibo_tag_preserve_mark_dirty(nfc_amiibo_tag_preserve_t *ctx) {
    if (nfc_amiibo_tag_preserve_is_valid(ctx)) ctx->dirty = true;
}

void nfc_amiibo_tag_preserve_mark_clean(nfc_amiibo_tag_preserve_t *ctx) {
    if (ctx != NULL) ctx->dirty = false;
}

bool nfc_amiibo_tag_preserve_is_dirty(const nfc_amiibo_tag_preserve_t *ctx) {
    return nfc_amiibo_tag_preserve_is_valid(ctx) && ctx->dirty;
}

void nfc_amiibo_tag_preserve_take(const nfc_amiibo_tag_preserve_t *ctx, void *dst) {
    if (!nfc_amiibo_tag_preserve_is_valid(ctx) || dst == NULL) return;
    memcpy(dst, ctx->bytes, ctx->size);
}

nfc_amiibo_preserve_field_action_t nfc_amiibo_tag_preserve_on_field(
        nfc_amiibo_tag_preserve_t *ctx, bool present, void *live, size_t size) {
    if (!nfc_amiibo_tag_preserve_is_valid(ctx) || live == NULL) {
        return NFC_AMIIBO_PRESERVE_FIELD_NONE;
    }
    if (present) {
        /* Only an interrupted session leaves the live tag dirty. A clean
         * session was committed on FIELD_LOST, so a normal next scan must not
         * be reverted to the pre-session snapshot. */
        if (!ctx->dirty) return NFC_AMIIBO_PRESERVE_FIELD_NONE;
        nfc_amiibo_tag_preserve_take(ctx, live);
        nfc_amiibo_tag_preserve_mark_clean(ctx);
        return NFC_AMIIBO_PRESERVE_FIELD_RESTORE;
    }
    if (!ctx->dirty) return NFC_AMIIBO_PRESERVE_FIELD_NONE;
    /* Completed session: keep the console writes / incremented counter. */
    nfc_amiibo_tag_preserve_commit(ctx, live, size);
    return NFC_AMIIBO_PRESERVE_FIELD_COMMIT;
}
