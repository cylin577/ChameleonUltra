/*
 * Native unit tests for the FIDO2 / CTAP2 core. Build + run:
 *   make -C firmware/application/src/standalone_modes/tests test
 */
#include "../fido2_core.h"
#include "uECC.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

/* ---- fake platform (FDS + RNG) ---------------------------------------- */
static uint8_t  g_mk[32];
static uint32_t g_ctr;
static uint32_t g_rng = 0xC0FFEE01u;
static uint32_t g_now_ms;
static bool     g_mk_present = true;
static bool     g_mk_store_fails;

static bool io_load_mk(uint8_t mk[32]) {
    if (!g_mk_present) return false;
    memcpy(mk, g_mk, sizeof g_mk);
    return true;
}
static bool io_store_mk(const uint8_t mk[32]) {
    if (g_mk_store_fails) return false;
    memcpy(g_mk, mk, sizeof g_mk);
    g_mk_present = true;
    return true;
}
static bool io_load_ctr(uint32_t *ctr) { *ctr = g_ctr; return true; }
static void io_store_ctr(uint32_t ctr) { g_ctr = ctr; }
static bool io_random(uint8_t *dst, size_t len) {
    for (size_t i = 0; i < len; i++) {
        g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5;
        dst[i] = (uint8_t)(g_rng >> 24);
    }
    return true;
}
static uint32_t io_now_ms(void) { return g_now_ms; }
static const fido2_core_io_t g_io = {
    .load_master_key  = io_load_mk,
    .store_master_key = io_store_mk,
    .load_counter     = io_load_ctr,
    .store_counter    = io_store_ctr,
    .random_bytes     = io_random,
    .now_ms           = io_now_ms,
};

/* ---- tiny CBOR decoder (test side) ------------------------------------ */
typedef struct { const uint8_t *p, *end; } dec_t;

static bool dec_head(dec_t *d, uint8_t *major, uint64_t *val, size_t *used) {
    if (d->p >= d->end) return false;
    const uint8_t *start = d->p;
    uint8_t ib = *d->p++, ai = ib & 0x1F;
    *major = ib >> 5;
    if (ai < 24) { *val = ai; }
    else {
        uint8_t nb = (ai == 24) ? 1 : (ai == 25) ? 2 : (ai == 26) ? 4 : (ai == 27) ? 8 : 0xFF;
        if (nb == 0xFF || (size_t)(d->end - d->p) < nb) return false;
        uint64_t v = 0;
        for (uint8_t i = 0; i < nb; i++) v = (v << 8) | *d->p++;
        *val = v;
    }
    *used = (size_t)(d->p - start);
    return true;
}

static bool dec_skip(dec_t *d) {
    uint8_t m; uint64_t v; size_t used;
    if (!dec_head(d, &m, &v, &used)) return false;
    switch (m) {
    case 0: case 1: case 7: return true;
    case 2: case 3:
        if (v > (uint64_t)(d->end - d->p)) return false;
        d->p += v; return true;
    case 4:
        for (uint64_t i = 0; i < v; i++) if (!dec_skip(d)) return false;
        return true;
    case 5:
        for (uint64_t i = 0; i < 2 * v; i++) if (!dec_skip(d)) return false;
        return true;
    default: return false;
    }
}

/* Find the value of a map entry whose key is the raw byte sequence
 * key[0..keylen). Returns a pointer to the value item, or NULL. */
static const uint8_t *map_find(const uint8_t *p, const uint8_t *end,
                               const uint8_t *key, size_t keylen,
                               const uint8_t **val_end) {
    dec_t d = { p, end };
    uint8_t m; uint64_t n; size_t used;
    if (!dec_head(&d, &m, &n, &used) || m != 5) return NULL;
    for (uint64_t i = 0; i < n; i++) {
        const uint8_t *kstart = d.p;
        uint8_t km; uint64_t kv; size_t kused;
        if (!dec_head(&d, &km, &kv, &kused)) return NULL;
        size_t ktotal = kused;
        if (km == 2 || km == 3) {
            if (kv > (uint64_t)(d.end - d.p)) return NULL;
            ktotal += (size_t)kv;
        }
        bool match = (ktotal == keylen) && (memcmp(kstart, key, keylen) == 0);
        if (km == 2 || km == 3) d.p += kv;
        if (match) { *val_end = d.end; return d.p; }
        if (!dec_skip(&d)) return NULL;
    }
    return NULL;
}

/* Decode a byte/text string item at p. item_len gets the full encoded size. */
static bool dec_str(const uint8_t *p, const uint8_t *end, uint8_t *major,
                    const uint8_t **body, uint64_t *len, size_t *item_len) {
    dec_t d = { p, end };
    uint8_t m; uint64_t v; size_t used;
    if (!dec_head(&d, &m, &v, &used)) return false;
    if (m != 2 && m != 3) return false;
    if (v > (uint64_t)(d.end - d.p)) return false;
    *major = m; *body = d.p; *len = v;
    if (item_len) *item_len = used + (size_t)v;
    return true;
}

/* ---- helpers ----------------------------------------------------------- */
static const uint8_t RP_ID[] = "example.com";
#define RP_ID_LEN 11

static size_t run_ctap(uint8_t cmd, const uint8_t *body, size_t body_len,
                       uint8_t *out, size_t out_max) {
    uint8_t req[1 + 512];
    req[0] = cmd;
    if (body_len) memcpy(req + 1, body, body_len);
    if (!fido2_submit(FIDO2_OWNER_HOST, req, body_len + 1)) return 0;
    fido2_tick();
    size_t len = 0;
    if (!fido2_take_response(FIDO2_OWNER_HOST, out, out_max, &len)) return 0;
    return len;
}

/* MakeCredential request: {1: clientDataHash, 2: {"id": rpId},
 * 4: [{"alg": -7, "type": "public-key"}]}. */
static size_t build_make_cred(uint8_t *buf, const uint8_t cdh[32]) {
    size_t i = 0;
    buf[i++] = 0xA3;                       /* map(3) */
    buf[i++] = 0x01; buf[i++] = 0x58; buf[i++] = 0x20;
    memcpy(buf + i, cdh, 32); i += 32;
    buf[i++] = 0x02; buf[i++] = 0xA1;      /* rp: map(1) */
    buf[i++] = 0x62; buf[i++] = 'i'; buf[i++] = 'd';
    buf[i++] = (uint8_t)(0x60 | RP_ID_LEN);
    memcpy(buf + i, RP_ID, RP_ID_LEN); i += RP_ID_LEN;
    buf[i++] = 0x04; buf[i++] = 0x81; buf[i++] = 0xA2;
    buf[i++] = 0x63; buf[i++] = 'a'; buf[i++] = 'l'; buf[i++] = 'g';
    buf[i++] = 0x26;                       /* ES256 */
    buf[i++] = 0x64; buf[i++] = 't'; buf[i++] = 'y'; buf[i++] = 'p'; buf[i++] = 'e';
    buf[i++] = 0x6A;                       /* text(10) */
    memcpy(buf + i, "public-key", 10); i += 10;
    return i;
}

static size_t build_make_cred_opts(uint8_t *buf, const uint8_t cdh[32],
                                   int32_t alg, bool rk) {
    size_t i = 0;
    buf[i++] = 0xA4;
    buf[i++] = 0x01; buf[i++] = 0x58; buf[i++] = 0x20;
    memcpy(buf + i, cdh, 32); i += 32;
    buf[i++] = 0x02; buf[i++] = 0xA1;
    buf[i++] = 0x62; buf[i++] = 'i'; buf[i++] = 'd';
    buf[i++] = (uint8_t)(0x60 | RP_ID_LEN);
    memcpy(buf + i, RP_ID, RP_ID_LEN); i += RP_ID_LEN;
    buf[i++] = 0x04; buf[i++] = 0x81; buf[i++] = 0xA2;
    buf[i++] = 0x63; buf[i++] = 'a'; buf[i++] = 'l'; buf[i++] = 'g';
    if (alg == -7) {
        buf[i++] = 0x26;
    } else {
        buf[i++] = 0x39; buf[i++] = 0x01; buf[i++] = 0x00; /* -257 */
    }
    buf[i++] = 0x64; buf[i++] = 't'; buf[i++] = 'y'; buf[i++] = 'p'; buf[i++] = 'e';
    buf[i++] = 0x6A;
    memcpy(buf + i, "public-key", 10); i += 10;
    buf[i++] = 0x07; buf[i++] = 0xA1;
    buf[i++] = 0x62; buf[i++] = 'r'; buf[i++] = 'k';
    buf[i++] = rk ? 0xF5 : 0xF4;
    return i;
}

/* GetAssertion request: {1: rpId, 2: clientDataHash, 3: [{id, type}]} */
static size_t build_get_assert(uint8_t *buf, const uint8_t cdh[32], const uint8_t cred[64]) {
    size_t i = 0;
    buf[i++] = 0xA3;                       /* map(3) */
    buf[i++] = 0x01; buf[i++] = (uint8_t)(0x60 | RP_ID_LEN);
    memcpy(buf + i, RP_ID, RP_ID_LEN); i += RP_ID_LEN;
    buf[i++] = 0x02; buf[i++] = 0x58; buf[i++] = 0x20;
    memcpy(buf + i, cdh, 32); i += 32;
    buf[i++] = 0x03; buf[i++] = 0x81; buf[i++] = 0xA2;
    buf[i++] = 0x62; buf[i++] = 'i'; buf[i++] = 'd';
    buf[i++] = 0x58; buf[i++] = 0x40;
    memcpy(buf + i, cred, 64); i += 64;
    buf[i++] = 0x64; buf[i++] = 't'; buf[i++] = 'y'; buf[i++] = 'p'; buf[i++] = 'e';
    buf[i++] = 0x6A;                       /* text(10) */
    memcpy(buf + i, "public-key", 10); i += 10;
    return i;
}

static size_t build_get_assert_two(uint8_t *buf, const uint8_t cdh[32],
                                   const uint8_t foreign[64], const uint8_t own[64]) {
    size_t i = 0;
    buf[i++] = 0xA3;
    buf[i++] = 0x01; buf[i++] = (uint8_t)(0x60 | RP_ID_LEN);
    memcpy(buf + i, RP_ID, RP_ID_LEN); i += RP_ID_LEN;
    buf[i++] = 0x02; buf[i++] = 0x58; buf[i++] = 0x20;
    memcpy(buf + i, cdh, 32); i += 32;
    buf[i++] = 0x03; buf[i++] = 0x82;
    for (int entry = 0; entry < 2; entry++) {
        const uint8_t *id = entry == 0 ? foreign : own;
        buf[i++] = 0xA2;
        buf[i++] = 0x62; buf[i++] = 'i'; buf[i++] = 'd';
        buf[i++] = 0x58; buf[i++] = 0x40;
        memcpy(buf + i, id, 64); i += 64;
        buf[i++] = 0x64; buf[i++] = 't'; buf[i++] = 'y'; buf[i++] = 'p'; buf[i++] = 'e';
        buf[i++] = 0x6A;
        memcpy(buf + i, "public-key", 10); i += 10;
    }
    return i;
}

/* DER SEQUENCE { INTEGER r, INTEGER s } -> raw 64-byte r||s */
static bool der_to_raw(const uint8_t *der, size_t len, uint8_t raw[64]) {
    if (len < 8 || der[0] != 0x30) return false;
    size_t p = 2;
    if (der[p++] != 0x02) return false;
    uint8_t rl = der[p++];
    if (rl == 0 || rl > 33 || p + rl > len) return false;
    const uint8_t *r = der + p; p += rl;
    if (p >= len || der[p++] != 0x02) return false;
    uint8_t sl = der[p++];
    if (sl == 0 || sl > 33 || p + sl > len) return false;
    const uint8_t *s = der + p;
    memset(raw, 0, 64);
    if (rl == 33 && r[0] == 0) { r++; rl--; }
    if (sl == 33 && s[0] == 0) { s++; sl--; }
    memcpy(raw + 32 - rl, r, rl);
    memcpy(raw + 64 - sl, s, sl);
    return true;
}

/* ---- tests ------------------------------------------------------------- */
static void test_get_info(void) {
    fido2_core_arm(FIDO2_TRANSPORT_USB | FIDO2_TRANSPORT_NFC | FIDO2_TRANSPORT_BLE);

    uint8_t out[512];
    size_t len = run_ctap(FIDO2_CMD_GET_INFO, NULL, 0, out, sizeof out);
    CHECK(len > 1);
    CHECK(out[0] == FIDO2_OK);

    const uint8_t *cend;
    const uint8_t *v = map_find(out + 1, out + len, (const uint8_t[]){0x01}, 1, &cend);
    CHECK(v != NULL);
    if (v) {
        /* versions: array(2) of "FIDO_2_0", "U2F_V2" */
        dec_t d = { v, cend };
        uint8_t m; uint64_t n; size_t used, ilen;
        CHECK(dec_head(&d, &m, &n, &used) && m == 4 && n == 2);
        const uint8_t *body; uint64_t blen; uint8_t sm;
        CHECK(dec_str(d.p, cend, &sm, &body, &blen, &ilen) && sm == 3 && blen == 8 &&
              memcmp(body, "FIDO_2_0", 8) == 0);
        d.p += ilen;
        CHECK(dec_str(d.p, cend, &sm, &body, &blen, &ilen) && sm == 3 && blen == 6 &&
              memcmp(body, "U2F_V2", 6) == 0);
    }

    /* aaguid: 16 zero bytes */
    v = map_find(out + 1, out + len, (const uint8_t[]){0x03}, 1, &cend);
    CHECK(v != NULL);
    if (v) {
        const uint8_t *body; uint64_t blen; uint8_t sm; size_t ilen;
        CHECK(dec_str(v, cend, &sm, &body, &blen, &ilen) && sm == 2 && blen == 16);
        int zeros = 1;
        for (uint64_t i = 0; i < blen; i++) if (body[i]) zeros = 0;
        CHECK(zeros);
    }

    /* options */
    v = map_find(out + 1, out + len, (const uint8_t[]){0x04}, 1, &cend);
    CHECK(v != NULL);
    if (v) {
        const uint8_t *e2;
        const uint8_t *rk = map_find(v, cend, (const uint8_t[]){0x62,'r','k'}, 3, &e2);
        const uint8_t *up = map_find(v, cend, (const uint8_t[]){0x62,'u','p'}, 3, &e2);
        const uint8_t *cp = map_find(v, cend,
                                     (const uint8_t[]){0x69,'c','l','i','e','n','t','P','i','n'}, 10, &e2);
        CHECK(rk && *rk == 0xF4);                  /* false */
        CHECK(up && *up == 0xF5);                  /* true  */
        CHECK(cp && *cp == 0xF4);                  /* false */
    }

    /* transports: usb, nfc, ble */
    v = map_find(out + 1, out + len, (const uint8_t[]){0x09}, 1, &cend);
    CHECK(v != NULL);
    if (v) {
        dec_t d = { v, cend };
        uint8_t m; uint64_t n; size_t used, ilen;
        CHECK(dec_head(&d, &m, &n, &used) && m == 4 && n == 3);
        const uint8_t *body; uint64_t blen; uint8_t sm;
        CHECK(dec_str(d.p, cend, &sm, &body, &blen, &ilen) && sm == 3 && blen == 3 &&
              memcmp(body, "usb", 3) == 0);
        d.p += ilen;
        CHECK(dec_str(d.p, cend, &sm, &body, &blen, &ilen) && sm == 3 && blen == 3 &&
              memcmp(body, "nfc", 3) == 0);
        d.p += ilen;
        CHECK(dec_str(d.p, cend, &sm, &body, &blen, &ilen) && sm == 3 && blen == 3 &&
              memcmp(body, "ble", 3) == 0);
    }
}

static void test_get_info_transport_mask(void) {
    fido2_core_arm(FIDO2_TRANSPORT_NFC);
    uint8_t out[512];
    size_t len = run_ctap(FIDO2_CMD_GET_INFO, NULL, 0, out, sizeof out);
    CHECK(len > 1 && out[0] == FIDO2_OK);

    const uint8_t *cend;
    const uint8_t *v = map_find(out + 1, out + len, (const uint8_t[]){0x09}, 1, &cend);
    CHECK(v != NULL);
    if (v) {
        dec_t d = { v, cend };
        uint8_t m; uint64_t n; size_t used, ilen;
        CHECK(dec_head(&d, &m, &n, &used) && m == 4 && n == 1);
        const uint8_t *body; uint64_t blen; uint8_t sm;
        CHECK(dec_str(d.p, cend, &sm, &body, &blen, &ilen) && sm == 3 && blen == 3 &&
              memcmp(body, "nfc", 3) == 0);
    }
}

static void test_make_cred_and_assertion(void) {
    fido2_core_arm(FIDO2_TRANSPORT_USB | FIDO2_TRANSPORT_NFC | FIDO2_TRANSPORT_BLE);

    uint8_t cdh[32];
    for (int i = 0; i < 32; i++) cdh[i] = (uint8_t)(i + 1);

    uint8_t req[512];
    size_t rlen = build_make_cred(req, cdh);
    uint8_t out[1024];
    CHECK(fido2_grant_user_presence());
    size_t len = run_ctap(FIDO2_CMD_MAKE_CREDENTIAL, req, rlen, out, sizeof out);
    CHECK(len > 1);
    CHECK(out[0] == FIDO2_OK);

    const uint8_t *cend;
    /* attestation statement is "none" */
    const uint8_t *fmt = map_find(out + 1, out + len, (const uint8_t[]){0x01}, 1, &cend);
    CHECK(fmt != NULL);
    if (fmt) {
        const uint8_t *body; uint64_t blen; uint8_t sm; size_t ilen;
        CHECK(dec_str(fmt, cend, &sm, &body, &blen, &ilen) && sm == 3 && blen == 4 &&
              memcmp(body, "none", 4) == 0);
    }

    /* authData */
    const uint8_t *adp = map_find(out + 1, out + len, (const uint8_t[]){0x02}, 1, &cend);
    CHECK(adp != NULL);
    uint8_t cred[64], pub[64];
    if (!adp) return;
    const uint8_t *ad; uint64_t adlen; uint8_t sm; size_t ilen;
    CHECK(dec_str(adp, cend, &sm, &ad, &adlen, &ilen) && sm == 2);
    CHECK(adlen == 32 + 1 + 4 + 16 + 2 + 64 + 77);
    if (adlen < 32 + 1 + 4 + 16 + 2 + 64) return;

    /* rpIdHash = sha256(rpId) */
    uint8_t rpHash[32];
    fido2_sha256(RP_ID, RP_ID_LEN, rpHash);
    CHECK(memcmp(ad, rpHash, 32) == 0);
    CHECK(ad[32] == 0x41);                       /* UP | AT */
    int zeros = 1;
    for (int i = 0; i < 16; i++) if (ad[37 + i]) zeros = 0;
    CHECK(zeros);                                /* aaguid all zero */
    CHECK(ad[53] == 0 && ad[54] == 64);          /* credential id length */
    memcpy(cred, ad + 55, 64);

    /* COSE key at the end: {1:2, 3:-7, -1:1, -2:x, -3:y} */
    const uint8_t *cose = ad + 55 + 64;
    const uint8_t *e2;
    const uint8_t *xv = map_find(cose, ad + adlen, (const uint8_t[]){0x21}, 1, &e2);
    const uint8_t *yv = map_find(cose, ad + adlen, (const uint8_t[]){0x22}, 1, &e2);
    CHECK(xv && yv);
    if (!xv || !yv) return;
    const uint8_t *xb, *yb; uint64_t xl, yl;
    CHECK(dec_str(xv, e2, &sm, &xb, &xl, &ilen) && xl == 32);
    CHECK(dec_str(yv, e2, &sm, &yb, &yl, &ilen) && yl == 32);
    memcpy(pub, xb, 32);
    memcpy(pub + 32, yb, 32);

    /* the derived private key must match the advertised public key */
    uint8_t priv[32];
    fido2_derive_priv(rpHash, cred, priv);
    uint8_t pub2[64];
    CHECK(uECC_compute_public_key(priv, pub2, uECC_secp256r1()));
    CHECK(memcmp(pub, pub2, 64) == 0);

    /* GetAssertion */
    rlen = build_get_assert(req, cdh, cred);
    CHECK(fido2_grant_user_presence());
    len = run_ctap(FIDO2_CMD_GET_ASSERTION, req, rlen, out, sizeof out);
    CHECK(len > 1);
    CHECK(out[0] == FIDO2_OK);

    const uint8_t *ad2p = map_find(out + 1, out + len, (const uint8_t[]){0x02}, 1, &cend);
    const uint8_t *sigp = map_find(out + 1, out + len, (const uint8_t[]){0x03}, 1, &cend);
    CHECK(ad2p && sigp);
    if (!ad2p || !sigp) return;
    const uint8_t *ad2, *sig; uint64_t ad2len, siglen;
    CHECK(dec_str(ad2p, cend, &sm, &ad2, &ad2len, &ilen) && ad2len == 37);
    CHECK(dec_str(sigp, cend, &sm, &sig, &siglen, &ilen) && siglen > 8 && siglen <= 72);

    /* verify the signature over authData || clientDataHash */
    uint8_t hash[32];
    {
        uint8_t buf[37 + 32];
        memcpy(buf, ad2, 37);
        memcpy(buf + 37, cdh, 32);
        fido2_sha256(buf, sizeof buf, hash);
    }
    uint8_t raw[64];
    CHECK(der_to_raw(sig, siglen, raw));
    CHECK(uECC_verify(pub, hash, 32, raw, uECC_secp256r1()) == 1);

    /* A foreign first entry must not hide our credential in the second entry. */
    uint8_t foreign[64];
    memset(foreign, 0x33, sizeof foreign);
    rlen = build_get_assert_two(req, cdh, foreign, cred);
    CHECK(fido2_grant_user_presence());
    len = run_ctap(FIDO2_CMD_GET_ASSERTION, req, rlen, out, sizeof out);
    CHECK(len > 1 && out[0] == FIDO2_OK);
}

static void test_foreign_credential(void) {
    fido2_core_arm(FIDO2_TRANSPORT_USB);
    uint8_t cdh[32];
    memset(cdh, 0x5A, sizeof cdh);

    uint8_t cred[64];
    memset(cred, 0x11, sizeof cred);
    cred[63] ^= 0xFF;                          /* break the MAC */

    uint8_t req[512];
    size_t rlen = build_get_assert(req, cdh, cred);
    uint8_t out[256];
    size_t len = run_ctap(FIDO2_CMD_GET_ASSERTION, req, rlen, out, sizeof out);
    CHECK(len == 1);
    CHECK(out[0] == FIDO2_ERR_NO_CREDENTIALS);
}

static void test_bad_cbor(void) {
    fido2_core_arm(FIDO2_TRANSPORT_USB);
    uint8_t out[256];
    /* not a map */
    uint8_t bad[] = { 0x01, 0x02, 0x03 };
    size_t len = run_ctap(FIDO2_CMD_MAKE_CREDENTIAL, bad, sizeof bad, out, sizeof out);
    CHECK(len == 1 && out[0] == FIDO2_ERR_INVALID_CBOR);
    /* truncated map */
    uint8_t trunc[] = { 0xA2, 0x01, 0x58, 0x20 };
    len = run_ctap(FIDO2_CMD_MAKE_CREDENTIAL, trunc, sizeof trunc, out, sizeof out);
    CHECK(len == 1 && out[0] == FIDO2_ERR_INVALID_CBOR);
}

static void test_missing_client_data_hash(void) {
    fido2_core_arm(FIDO2_TRANSPORT_USB);
    /* {2: {"id": rpId}} — no clientDataHash */
    uint8_t req[64];
    size_t i = 0;
    req[i++] = 0xA1;
    req[i++] = 0x02; req[i++] = 0xA1;
    req[i++] = 0x62; req[i++] = 'i'; req[i++] = 'd';
    req[i++] = (uint8_t)(0x60 | RP_ID_LEN);
    memcpy(req + i, RP_ID, RP_ID_LEN); i += RP_ID_LEN;

    uint8_t out[256];
    size_t len = run_ctap(FIDO2_CMD_MAKE_CREDENTIAL, req, i, out, sizeof out);
    CHECK(len == 1 && out[0] == FIDO2_ERR_MISSING_PARAMETER);
}

static void test_user_presence_and_cancel(void) {
    fido2_core_arm(FIDO2_TRANSPORT_USB);
    uint8_t cdh[32];
    memset(cdh, 0x42, sizeof cdh);
    uint8_t req[512];
    size_t rlen = build_make_cred(req, cdh);
    uint8_t cmd[512] = { FIDO2_CMD_MAKE_CREDENTIAL, 0x00 };
    memcpy(cmd + 1, req, rlen);

    CHECK(fido2_submit(FIDO2_OWNER_USB, cmd, rlen + 1));
    fido2_tick();
    CHECK(fido2_waiting_for_presence(FIDO2_OWNER_USB));
    CHECK(fido2_busy());
    CHECK(!fido2_response_ready(FIDO2_OWNER_USB));

    CHECK(fido2_grant_user_presence());
    fido2_tick();
    CHECK(!fido2_waiting_for_presence(FIDO2_OWNER_USB));
    uint8_t out[512];
    size_t len = 0;
    CHECK(fido2_take_response(FIDO2_OWNER_USB, out, sizeof out, &len));
    CHECK(len > 1 && out[0] == FIDO2_OK);

    /* The gesture authorizes one operation only. */
    CHECK(fido2_submit(FIDO2_OWNER_USB, cmd, rlen + 1));
    fido2_tick();
    CHECK(fido2_waiting_for_presence(FIDO2_OWNER_USB));
    CHECK(fido2_cancel(FIDO2_OWNER_USB));
    CHECK(fido2_take_response(FIDO2_OWNER_USB, out, sizeof out, &len));
    CHECK(len == 1 && out[0] == FIDO2_ERR_KEEPALIVE_CANCEL);

    /* A stale grant cannot authorize a later operation. */
    g_now_ms += 100;
    CHECK(fido2_grant_user_presence());
    g_now_ms += FIDO2_UP_GRANT_MS + 1;
    CHECK(fido2_submit(FIDO2_OWNER_USB, cmd, rlen + 1));
    fido2_tick();
    CHECK(fido2_waiting_for_presence(FIDO2_OWNER_USB));
    CHECK(fido2_cancel(FIDO2_OWNER_USB));
    CHECK(fido2_take_response(FIDO2_OWNER_USB, out, sizeof out, &len));
    CHECK(len == 1 && out[0] == FIDO2_ERR_KEEPALIVE_CANCEL);
}

static void test_user_presence_timeout(void) {
    fido2_core_arm(FIDO2_TRANSPORT_USB);
    uint8_t cdh[32];
    memset(cdh, 0x43, sizeof cdh);
    uint8_t req[512];
    size_t rlen = build_make_cred(req, cdh);
    uint8_t cmd[512] = { FIDO2_CMD_MAKE_CREDENTIAL, 0x00 };
    memcpy(cmd + 1, req, rlen);

    CHECK(fido2_submit(FIDO2_OWNER_USB, cmd, rlen + 1));
    fido2_tick();
    CHECK(fido2_waiting_for_presence(FIDO2_OWNER_USB));

    g_now_ms += FIDO2_UP_WAIT_TIMEOUT_MS + 1;
    fido2_tick();
    CHECK(!fido2_waiting_for_presence(FIDO2_OWNER_USB));
    CHECK(fido2_response_ready(FIDO2_OWNER_USB));

    uint8_t out[256];
    size_t len = 0;
    CHECK(fido2_take_response(FIDO2_OWNER_USB, out, sizeof out, &len));
    CHECK(len == 1 && out[0] == FIDO2_ERR_KEEPALIVE_CANCEL);

    /* The timed-out request must not leave the single request slot busy. */
    uint8_t info = FIDO2_CMD_GET_INFO;
    CHECK(fido2_submit(FIDO2_OWNER_USB, &info, 1));
    fido2_tick();
    CHECK(fido2_take_response(FIDO2_OWNER_USB, out, sizeof out, &len));
    CHECK(len > 1 && out[0] == FIDO2_OK);
}

static void test_algorithm_and_option(void) {
    fido2_core_arm(FIDO2_TRANSPORT_USB);
    uint8_t cdh[32];
    memset(cdh, 0x24, sizeof cdh);
    uint8_t req[512];
    uint8_t out[64];

    size_t rlen = build_make_cred_opts(req, cdh, -257, false);
    size_t len = run_ctap(FIDO2_CMD_MAKE_CREDENTIAL, req, rlen, out, sizeof out);
    CHECK(len == 1 && out[0] == FIDO2_ERR_UNSUPPORTED_ALGORITHM);

    rlen = build_make_cred_opts(req, cdh, -7, true);
    len = run_ctap(FIDO2_CMD_MAKE_CREDENTIAL, req, rlen, out, sizeof out);
    CHECK(len == 1 && out[0] == FIDO2_ERR_UNSUPPORTED_OPTION);
}

static void test_master_key_store_failure(void) {
    fido2_core_disarm();
    g_mk_present = false;
    g_mk_store_fails = true;
    CHECK(!fido2_core_arm(FIDO2_TRANSPORT_USB));
    g_mk_store_fails = false;
    g_mk_present = true;
}

static void test_invalid_command(void) {
    fido2_core_arm(FIDO2_TRANSPORT_USB);
    uint8_t out[256];
    size_t len = run_ctap(0x7F, NULL, 0, out, sizeof out);
    CHECK(len == 1 && out[0] == FIDO2_ERR_INVALID_CMD);
}

static void test_busy(void) {
    fido2_core_arm(FIDO2_TRANSPORT_USB);
    uint8_t cmd = FIDO2_CMD_GET_INFO;
    CHECK(fido2_submit(FIDO2_OWNER_USB, &cmd, 1));
    CHECK(!fido2_submit(FIDO2_OWNER_USB, &cmd, 1));   /* slot busy */
    CHECK(fido2_busy());
    fido2_tick();
    uint8_t out[256];
    size_t len = 0;
    CHECK(fido2_take_response(FIDO2_OWNER_USB, out, sizeof out, &len));
    CHECK(len > 1 && out[0] == FIDO2_OK);
    CHECK(!fido2_busy());
    /* wrong owner gets nothing */
    fido2_submit(FIDO2_OWNER_USB, &cmd, 1);
    fido2_tick();
    CHECK(!fido2_take_response(FIDO2_OWNER_BLE, out, sizeof out, &len));
    CHECK(fido2_take_response(FIDO2_OWNER_USB, out, sizeof out, &len));
}

static void test_disarmed(void) {
    fido2_core_disarm();
    uint8_t cmd = FIDO2_CMD_GET_INFO;
    CHECK(!fido2_submit(FIDO2_OWNER_USB, &cmd, 1));
    CHECK(!fido2_busy());
}

int main(void) {
    fido2_core_init(&g_io);
    memset(g_mk, 0xA5, sizeof g_mk);

    test_get_info();
    test_get_info_transport_mask();
    test_make_cred_and_assertion();
    test_foreign_credential();
    test_bad_cbor();
    test_missing_client_data_hash();
    test_user_presence_and_cancel();
    test_user_presence_timeout();
    test_algorithm_and_option();
    test_master_key_store_failure();
    test_invalid_command();
    test_busy();
    test_disarmed();

    printf("%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
