/* Definite-length, shortest-form CBOR. No tags, floats or indefinite items. */
#include "fido2_cbor.h"

#include <string.h>

/* ---- encoder ------------------------------------------------------------ */

static void cw_write(fido2_cbor_w_t *w, const uint8_t *p, size_t n)
{
    if (w->failed || w->buf == NULL || n > w->cap - w->len) {
        w->failed = true;
        return;
    }
    memcpy(w->buf + w->len, p, n);
    w->len += n;
}

static void put_be(uint8_t *p, uint64_t v, unsigned bytes)
{
    for (unsigned i = 0; i < bytes; i++) {
        p[i] = (uint8_t)(v >> (8u * (bytes - 1u - i)));
    }
}

static void cw_head(fido2_cbor_w_t *w, unsigned major, uint64_t v)
{
    uint8_t h[9];
    unsigned n;

    h[0] = (uint8_t)(major << 5);
    if (v < 24u) {
        h[0] = (uint8_t)(h[0] | (uint8_t)v);
        n = 1u;
    } else if (v <= 0xFFu) {
        h[0] = (uint8_t)(h[0] | 24u);
        h[1] = (uint8_t)v;
        n = 2u;
    } else if (v <= 0xFFFFu) {
        h[0] = (uint8_t)(h[0] | 25u);
        put_be(h + 1u, v, 2u);
        n = 3u;
    } else if (v <= 0xFFFFFFFFu) {
        h[0] = (uint8_t)(h[0] | 26u);
        put_be(h + 1u, v, 4u);
        n = 5u;
    } else {
        h[0] = (uint8_t)(h[0] | 27u);
        put_be(h + 1u, v, 8u);
        n = 9u;
    }
    cw_write(w, h, n);
}

void cw_init(fido2_cbor_w_t *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0u;
    w->failed = (buf == NULL);
}

void cw_uint(fido2_cbor_w_t *w, uint64_t v)
{
    cw_head(w, 0u, v);
}

void cw_int(fido2_cbor_w_t *w, int64_t v)
{
    if (v < 0) {
        /* -1 - v avoids overflow on INT64_MIN. */
        cw_head(w, 1u, (uint64_t)(-(v + 1)));
    } else {
        cw_head(w, 0u, (uint64_t)v);
    }
}

void cw_bytes(fido2_cbor_w_t *w, const uint8_t *data, size_t len)
{
    if (data == NULL && len != 0u) {
        w->failed = true;
        return;
    }
    cw_head(w, 2u, (uint64_t)len);
    cw_write(w, data, len);
}

void cw_text(fido2_cbor_w_t *w, const char *data, size_t len)
{
    if (data == NULL && len != 0u) {
        w->failed = true;
        return;
    }
    cw_head(w, 3u, (uint64_t)len);
    cw_write(w, (const uint8_t *)data, len);
}

void cw_bool(fido2_cbor_w_t *w, bool v)
{
    cw_head(w, 7u, v ? 21u : 20u);
}

void cw_array(fido2_cbor_w_t *w, size_t n)
{
    cw_head(w, 4u, (uint64_t)n);
}

void cw_map(fido2_cbor_w_t *w, size_t n)
{
    cw_head(w, 5u, (uint64_t)n);
}

size_t cw_finish(fido2_cbor_w_t *w)
{
    return (!w->failed && w->buf != NULL) ? w->len : 0u;
}

/* ---- decoder ------------------------------------------------------------ */

static uint64_t get_be(const uint8_t *p, unsigned bytes)
{
    uint64_t v = 0u;
    for (unsigned i = 0; i < bytes; i++) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static bool cr_head(fido2_cbor_r_t *r, unsigned *major, unsigned *ai, uint64_t *value)
{
    uint8_t b;
    unsigned n;
    uint64_t v;

    if (r->failed || r->buf == NULL || r->pos >= r->len) {
        r->failed = true;
        return false;
    }
    b = r->buf[r->pos];
    *major = (unsigned)(b >> 5);
    *ai = (unsigned)(b & 0x1Fu);
    if (*ai < 24u) {
        v = (uint64_t)*ai;
        n = 0u;
    } else if (*ai <= 27u) {
        n = 1u << (*ai - 24u);
        if (n > r->len - r->pos - 1u) {
            r->failed = true;
            return false;
        }
        v = get_be(r->buf + r->pos + 1u, n);
    } else {
        /* 28..30 reserved, 31 indefinite: neither is supported. */
        r->failed = true;
        return false;
    }

    /* Reject non-shortest argument encodings (CTAP2 canonical CBOR). */
    if ((*ai == 24u && v < 24u) || (*ai == 25u && v < 256u) ||
        (*ai == 26u && v < 0x10000u) || (*ai == 27u && v <= 0xFFFFFFFFu)) {
        r->failed = true;
        return false;
    }
    r->pos += 1u + (size_t)n;
    *value = v;
    return true;
}

void cr_init(fido2_cbor_r_t *r, const uint8_t *buf, size_t len)
{
    r->buf = buf;
    r->len = len;
    r->pos = 0u;
    r->failed = (buf == NULL);
}

bool cr_uint(fido2_cbor_r_t *r, uint64_t *out)
{
    unsigned major, ai;
    uint64_t v;

    if (out == NULL || !cr_head(r, &major, &ai, &v)) return false;
    if (major != 0u) {
        r->failed = true;
        return false;
    }
    *out = v;
    return true;
}

bool cr_int(fido2_cbor_r_t *r, int64_t *out)
{
    unsigned major, ai;
    uint64_t v;

    if (out == NULL || !cr_head(r, &major, &ai, &v)) return false;
    if (major == 0u && v <= (uint64_t)INT64_MAX) {
        *out = (int64_t)v;
        return true;
    }
    if (major == 1u && v <= (uint64_t)INT64_MAX + 1u) {
        *out = (v == (uint64_t)INT64_MAX + 1u) ? INT64_MIN : (-(int64_t)v - 1);
        return true;
    }
    r->failed = true;
    return false;
}

static bool cr_string(fido2_cbor_r_t *r, unsigned want_major,
                      const uint8_t **out, size_t *out_len)
{
    unsigned major, ai;
    uint64_t v;

    if (out == NULL || out_len == NULL || !cr_head(r, &major, &ai, &v)) return false;
    if (major != want_major || v > (uint64_t)SIZE_MAX ||
        v > (uint64_t)(r->len - r->pos)) {
        r->failed = true;
        return false;
    }
    *out = r->buf + r->pos;
    *out_len = (size_t)v;
    r->pos += (size_t)v;
    return true;
}

bool cr_bytes(fido2_cbor_r_t *r, const uint8_t **out, size_t *out_len)
{
    return cr_string(r, 2u, out, out_len);
}

bool cr_text(fido2_cbor_r_t *r, const uint8_t **out, size_t *out_len)
{
    return cr_string(r, 3u, out, out_len);
}

bool cr_bool(fido2_cbor_r_t *r, bool *out)
{
    unsigned major, ai;
    uint64_t v;

    if (out == NULL || !cr_head(r, &major, &ai, &v)) return false;
    if (major != 7u || (ai != 20u && ai != 21u)) {
        r->failed = true;
        return false;
    }
    *out = (ai == 21u);
    return true;
}

static bool cr_count(fido2_cbor_r_t *r, unsigned want_major, size_t *out)
{
    unsigned major, ai;
    uint64_t v;

    if (out == NULL || !cr_head(r, &major, &ai, &v)) return false;
    if (major != want_major || v > (uint64_t)SIZE_MAX) {
        r->failed = true;
        return false;
    }
    *out = (size_t)v;
    return true;
}

bool cr_array(fido2_cbor_r_t *r, size_t *out)
{
    return cr_count(r, 4u, out);
}

bool cr_map(fido2_cbor_r_t *r, size_t *out)
{
    return cr_count(r, 5u, out);
}
