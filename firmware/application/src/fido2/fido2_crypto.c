#include "fido2/fido2_crypto.h"

#include <string.h>

#include "nrf_crypto.h"
#include "nrf_drv_rng.h"

#define NRF_LOG_MODULE_NAME f2_crypto
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

#define F2_PRIV_SIZE 32u
#define F2_PUB_SIZE  64u
#define F2_DER_MAX   72u
#define F2_RNG_CHUNK 251u

ret_code_t f2_crypto_init(void) {
    if (!nrf_crypto_is_initialized()) {
        return nrf_crypto_init();
    }
    return NRF_SUCCESS;
}

/* One big-endian integer, minimally encoded with a sign pad when needed.
   Returns 0 for an all-zero (degenerate) value. */
static size_t priv_int_encode(const uint8_t *raw, size_t len, uint8_t out[33]) {
    size_t skip = 0;
    while (skip < len && raw[skip] == 0) {
        skip++;
    }
    size_t n = len - skip;
    if (n == 0) {
        return 0;
    }

    size_t out_len = 0;
    if ((raw[skip] & 0x80u) != 0) {
        out[out_len++] = 0;
    }
    memcpy(out + out_len, raw + skip, n);
    out_len += n;
    return out_len;
}

/* Local r||s (CC310) to ASN.1 DER. Kept private to this translation unit. */
static ret_code_t priv_raw_sig_to_der(const uint8_t raw[64], uint8_t der[72], size_t *der_len) {
    uint8_t r[33];
    uint8_t s[33];
    size_t r_len = priv_int_encode(raw, 32, r);
    size_t s_len = priv_int_encode(raw + 32, 32, s);
    if (r_len == 0 || s_len == 0) {
        return NRF_ERROR_INVALID_PARAM;
    }

    size_t total = 6u + r_len + s_len;
    if (total > F2_DER_MAX || total > *der_len) {
        return NRF_ERROR_NO_MEM;
    }

    size_t p = 0;
    der[p++] = 0x30;
    der[p++] = (uint8_t)(total - 2u);
    der[p++] = 0x02;
    der[p++] = (uint8_t)r_len;
    memcpy(der + p, r, r_len);
    p += r_len;
    der[p++] = 0x02;
    der[p++] = (uint8_t)s_len;
    memcpy(der + p, s, s_len);
    p += s_len;

    *der_len = p;
    return NRF_SUCCESS;
}

ret_code_t f2_crypto_keygen(uint8_t priv[32], uint8_t pub[64]) {
    if (priv == NULL || pub == NULL) {
        return NRF_ERROR_INVALID_PARAM;
    }
    ret_code_t rc = f2_crypto_init();
    if (rc != NRF_SUCCESS) {
        NRF_LOG_ERROR("f2_crypto: init failed in keygen: 0x%x", (unsigned)rc);
        return rc;
    }

    nrf_crypto_ecc_private_key_t priv_key;
    nrf_crypto_ecc_public_key_t pub_key;
    nrf_crypto_ecc_key_pair_generate_context_t context;
    rc = nrf_crypto_ecc_key_pair_generate(&context, &g_nrf_crypto_ecc_secp256r1_curve_info,
                                          &priv_key, &pub_key);
    if (rc != NRF_SUCCESS) {
        NRF_LOG_ERROR("f2_crypto: key_pair_generate failed: 0x%x", (unsigned)rc);
        return rc;
    }

    size_t priv_len = F2_PRIV_SIZE;
    size_t pub_len = F2_PUB_SIZE;
    ret_code_t rc_priv = nrf_crypto_ecc_private_key_to_raw(&priv_key, priv, &priv_len);
    ret_code_t rc_pub = nrf_crypto_ecc_public_key_to_raw(&pub_key, pub, &pub_len);
    (void)nrf_crypto_ecc_private_key_free(&priv_key);
    (void)nrf_crypto_ecc_public_key_free(&pub_key);

    if (rc_priv != NRF_SUCCESS || rc_pub != NRF_SUCCESS ||
        priv_len != F2_PRIV_SIZE || pub_len != F2_PUB_SIZE) {
        NRF_LOG_ERROR("f2_crypto: key export failed: priv=0x%x pub=0x%x len=%u/%u",
                      (unsigned)rc_priv, (unsigned)rc_pub,
                      (unsigned)priv_len, (unsigned)pub_len);
        return NRF_ERROR_INTERNAL;
    }
    return NRF_SUCCESS;
}

ret_code_t f2_crypto_sign(const uint8_t priv[32], const uint8_t hash32[32],
                          uint8_t der[72], size_t *der_len) {
    if (priv == NULL || hash32 == NULL || der == NULL || der_len == NULL || *der_len == 0) {
        return NRF_ERROR_INVALID_PARAM;
    }
    ret_code_t rc = f2_crypto_init();
    if (rc != NRF_SUCCESS) {
        NRF_LOG_ERROR("f2_crypto: init failed in sign: 0x%x", (unsigned)rc);
        return rc;
    }

    nrf_crypto_ecc_private_key_t priv_key;
    rc = nrf_crypto_ecc_private_key_from_raw(&g_nrf_crypto_ecc_secp256r1_curve_info,
                                              &priv_key, priv, F2_PRIV_SIZE);
    if (rc != NRF_SUCCESS) {
        NRF_LOG_ERROR("f2_crypto: private_key_from_raw failed: 0x%x", (unsigned)rc);
        return rc;
    }

    uint8_t raw_sig[NRF_CRYPTO_ECDSA_SECP256R1_SIGNATURE_SIZE];
    size_t raw_sig_len = sizeof(raw_sig);
    nrf_crypto_ecdsa_sign_context_t context;
    rc = nrf_crypto_ecdsa_sign(&context, &priv_key, hash32, 32, raw_sig, &raw_sig_len);
    (void)nrf_crypto_ecc_private_key_free(&priv_key);
    if (rc != NRF_SUCCESS) {
        NRF_LOG_ERROR("f2_crypto: ecdsa_sign failed: 0x%x", (unsigned)rc);
        return rc;
    }

    if (raw_sig_len == (F2_PRIV_SIZE + F2_PRIV_SIZE)) {
        return priv_raw_sig_to_der(raw_sig, der, der_len);
    }

    /* A software backend may already produce DER; accept it as-is. */
    if (raw_sig[0] == 0x30 && raw_sig_len >= 8 && raw_sig_len <= *der_len &&
        (size_t)raw_sig[1] + 2u == raw_sig_len) {
        memcpy(der, raw_sig, raw_sig_len);
        *der_len = raw_sig_len;
        return NRF_SUCCESS;
    }
    return NRF_ERROR_INTERNAL;
}

ret_code_t f2_crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    if (data == NULL || out == NULL) {
        return NRF_ERROR_INVALID_PARAM;
    }
    ret_code_t rc = f2_crypto_init();
    if (rc != NRF_SUCCESS) {
        NRF_LOG_ERROR("f2_crypto: init failed in sha256: 0x%x", (unsigned)rc);
        return rc;
    }

    size_t out_len = 32;
    nrf_crypto_hash_context_t context;
    rc = nrf_crypto_hash_calculate(&context, &g_nrf_crypto_hash_sha256_info,
                                   data, len, out, &out_len);
    if (rc != NRF_SUCCESS) {
        NRF_LOG_ERROR("f2_crypto: hash_calculate failed: 0x%x", (unsigned)rc);
        return rc;
    }
    if (out_len != 32u) {
        NRF_LOG_ERROR("f2_crypto: sha256 bad length: %u", (unsigned)out_len);
        return NRF_ERROR_INTERNAL;
    }
    return NRF_SUCCESS;
}

ret_code_t f2_crypto_random(uint8_t *out, size_t len) {
    if (out == NULL) {
        return NRF_ERROR_INVALID_PARAM;
    }
    /* nrf_drv_rng_rand() takes a uint8_t length internally; stay well below it. */
    while (len > 0) {
        size_t chunk = (len > F2_RNG_CHUNK) ? F2_RNG_CHUNK : len;
        nrf_drv_rng_block_rand(out, (uint32_t)chunk);
        out += chunk;
        len -= chunk;
    }
    return NRF_SUCCESS;
}
