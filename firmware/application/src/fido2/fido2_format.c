/* Plain-C byte encoders shared by every FIDO2 transport. */
#include "fido2_format.h"

#include "fido2_cbor.h"
#include "fido2_types.h"

#include <string.h>

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

size_t fmt_cose_key(uint8_t out[77], const uint8_t pub[64])
{
    fido2_cbor_w_t w;

    if (out == NULL || pub == NULL) return 0u;
    cw_init(&w, out, 77u);
    cw_map(&w, 5u);
    cw_uint(&w, 1u);  cw_uint(&w, 2u);        /* kty: EC2 */
    cw_uint(&w, 3u);  cw_int(&w, -7);         /* alg: ES256 */
    cw_int(&w, -1);   cw_uint(&w, 1u);        /* crv: P-256 */
    cw_int(&w, -2);   cw_bytes(&w, pub, 32u);
    cw_int(&w, -3);   cw_bytes(&w, pub + 32u, 32u);
    return cw_finish(&w) == 77u ? 77u : 0u;
}

size_t fmt_auth_data(uint8_t *out, size_t cap, const uint8_t rp_hash[32],
                     uint8_t flags, uint32_t sign_count,
                     const uint8_t *cred_id, size_t cred_id_len,
                     const uint8_t *cose, size_t cose_len)
{
    static const uint8_t aaguid[FIDO2_AAGUID_LEN] = FIDO2_AAGUID_BYTES;
    size_t need = 32u + 1u + 4u;
    size_t off;

    if (out == NULL || rp_hash == NULL) return 0u;
    if (cred_id != NULL) {
        size_t extra;
        if ((cred_id_len != 0u && cred_id == NULL) ||
            (cose_len != 0u && cose == NULL) ||
            cred_id_len > 0xFFFFu || cose_len > SIZE_MAX - 18u) return 0u;
        extra = 18u + cose_len;
        if (cred_id_len > SIZE_MAX - extra || need > SIZE_MAX - extra - cred_id_len) return 0u;
        need += extra + cred_id_len;
    }
    if (cap < need) return 0u;

    memcpy(out, rp_hash, 32u);
    out[32] = flags;
    put_be32(out + 33u, sign_count);
    if (cred_id == NULL) return need;

    off = 37u;
    memcpy(out + off, aaguid, FIDO2_AAGUID_LEN);
    off += FIDO2_AAGUID_LEN;
    put_be16(out + off, (uint16_t)cred_id_len);
    off += 2u;
    if (cred_id_len != 0u) {
        memcpy(out + off, cred_id, cred_id_len);
        off += cred_id_len;
    }
    if (cose_len != 0u) memcpy(out + off, cose, cose_len);
    return need;
}

/* Encode one DER INTEGER with a leading 0x00 when the MSB would be set. */
static size_t der_int(const uint8_t raw[32], uint8_t out[33])
{
    size_t i = 0u, n;

    while (i < 32u && raw[i] == 0u) i++;
    if (i == 32u) {
        out[0] = 0u;              /* zero is encoded as a single 0x00 */
        return 1u;
    }
    n = 32u - i;
    if ((raw[i] & 0x80u) != 0u) {
        out[0] = 0u;
        memcpy(out + 1u, raw + i, n);
        return n + 1u;
    }
    memcpy(out, raw + i, n);
    return n;
}

size_t fmt_raw_sig_to_der(const uint8_t raw[64], uint8_t der[72])
{
    uint8_t r[33], s[33];
    size_t rlen, slen, total, p;

    if (raw == NULL || der == NULL) return 0u;
    rlen = der_int(raw, r);
    slen = der_int(raw + 32u, s);
    total = 6u + rlen + slen;
    if (total > 72u) return 0u;

    der[0] = 0x30u;
    der[1] = (uint8_t)(total - 2u);   /* <= 70, one-byte DER length */
    der[2] = 0x02u;
    der[3] = (uint8_t)rlen;
    memcpy(der + 4u, r, rlen);
    p = 4u + rlen;
    der[p++] = 0x02u;
    der[p++] = (uint8_t)slen;
    memcpy(der + p, s, slen);
    return total;
}

size_t fmt_u2f_reg_base(uint8_t *out, size_t cap, const uint8_t app[32],
                        const uint8_t chal[32], const uint8_t *kh, size_t kh_len,
                        const uint8_t pub[65])
{
    size_t need;

    if (out == NULL || app == NULL || chal == NULL || pub == NULL ||
        (kh == NULL && kh_len != 0u) || kh_len > 0xFFu) return 0u;
    need = 131u + kh_len;         /* 0x00 | app | chal | khLen | kh | pub65 */
    if (cap < need) return 0u;

    out[0] = 0x00u;
    memcpy(out + 1u, app, 32u);
    memcpy(out + 33u, chal, 32u);
    out[65] = (uint8_t)kh_len;
    if (kh_len != 0u) memcpy(out + 66u, kh, kh_len);
    memcpy(out + 66u + kh_len, pub, 65u);
    return need;
}

size_t fmt_u2f_auth_base(uint8_t out[69], const uint8_t app[32],
                         uint8_t up_byte, uint32_t counter_be,
                         const uint8_t chal[32])
{
    if (out == NULL || app == NULL || chal == NULL) return 0u;
    memcpy(out, app, 32u);
    out[32] = up_byte;
    put_be32(out + 33u, counter_be);
    memcpy(out + 37u, chal, 32u);
    return 69u;
}

size_t fmt_ctaphid_init(uint8_t out[64], uint32_t cid, uint8_t cmd,
                        const uint8_t *data, size_t len)
{
    if (out == NULL || (data == NULL && len != 0u) || len > 57u) return 0u;
    memset(out, 0, 64u);
    put_be32(out, cid);
    out[4] = (uint8_t)(cmd | 0x80u);
    put_be16(out + 5u, (uint16_t)len);
    if (len != 0u) memcpy(out + 7u, data, len);
    return 64u;
}

size_t fmt_ctaphid_cont(uint8_t out[64], uint32_t cid, uint8_t seq,
                        const uint8_t *data, size_t len)
{
    if (out == NULL || (data == NULL && len != 0u) || len > 59u) return 0u;
    memset(out, 0, 64u);
    put_be32(out, cid);
    out[4] = (uint8_t)(seq & 0x7Fu);
    if (len != 0u) memcpy(out + 5u, data, len);
    return 64u;
}

size_t fmt_ble_init(uint8_t *out, size_t cap, uint8_t cmd,
                    const uint8_t *data, size_t len)
{
    if (out == NULL || (data == NULL && len != 0u) ||
        len > 0xFFFFu || len > SIZE_MAX - 3u || cap < 3u + len) return 0u;
    out[0] = (uint8_t)(0x80u | cmd);
    put_be16(out + 1u, (uint16_t)len);
    if (len != 0u) memcpy(out + 3u, data, len);
    return 3u + len;
}

size_t fmt_ble_cont(uint8_t *out, size_t cap, uint8_t seq,
                    const uint8_t *data, size_t len)
{
    if (out == NULL || (data == NULL && len != 0u) ||
        len > SIZE_MAX - 1u || cap < 1u + len) return 0u;
    out[0] = (uint8_t)(seq & 0x7Fu);
    if (len != 0u) memcpy(out + 1u, data, len);
    return 1u + len;
}
