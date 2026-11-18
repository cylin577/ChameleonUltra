#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "nfc_amiibo_uid_refresh.h"

#if defined(AMIIBO_UID_REFRESH_HOST_BUILD)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#else
#include <nrf_crypto.h>
#endif

#define DUMP_UID_CL1_OFFSET       0x00
#define DUMP_UID_BCC1_OFFSET      0x03
#define DUMP_UID_CL2_OFFSET       0x04
#define DUMP_UID_BCC2_OFFSET      0x08
#define DUMP_CRYPT1_OFFSET        0x14
#define DUMP_CRYPT1_SIZE          0x20
#define DUMP_TAG_HMAC_OFFSET      0x34
#define DUMP_TAG_CONFIG_OFFSET    0x54
#define DUMP_TAG_CONFIG_SIZE      0x2C
#define DUMP_DATA_HMAC_OFFSET     0x80
#define DUMP_CRYPT2_OFFSET        0xA0
#define DUMP_CRYPT2_SIZE          0x168
#define DUMP_PWD_OFFSET           0x214
#define DUMP_PACK_OFFSET          0x218

#define CRYPT_BUFFER_SIZE         NFC_AMIIBO_UID_REFRESH_PLAINTEXT_SIZE
#define HMAC_SIZE                 32
#define DERIVED_KEY_SIZE          16
#define SEED_SIZE                 78

#define RETAIL_KEY_MASTER_OFFSET  0x00
#define RETAIL_KEY_TYPE_OFFSET    0x10
#define RETAIL_KEY_TYPE_SIZE      0x0E
#define RETAIL_KEY_RFU_OFFSET     0x1E
#define RETAIL_KEY_MAGIC_SIZE     0x1F
#define RETAIL_KEY_MAGIC_OFFSET   0x20
#define RETAIL_KEY_XOR_OFFSET     0x30
#define SHA256_DIGEST_SIZE        32

/* Public pyamiibo retail master-key digests. Host tests override these with
 * synthetic-vector digests so no retail master-key bytes enter the repository. */
#ifndef AMIIBO_UID_REFRESH_DATA_RETAIL_KEY_SHA256
#define AMIIBO_UID_REFRESH_DATA_RETAIL_KEY_SHA256 { \
    0x86, 0x81, 0x06, 0x13, 0x59, 0x41, 0xcb, 0xca, \
    0xb3, 0x55, 0x2b, 0xd1, 0x48, 0x80, 0xa7, 0xa3, \
    0x43, 0x04, 0xef, 0x34, 0x09, 0x58, 0xa6, 0x99, \
    0x8b, 0x61, 0xa3, 0x8b, 0xa3, 0xce, 0x13, 0xd3 }
#endif
#ifndef AMIIBO_UID_REFRESH_TAG_RETAIL_KEY_SHA256
#define AMIIBO_UID_REFRESH_TAG_RETAIL_KEY_SHA256 { \
    0xb4, 0x87, 0x27, 0x79, 0x7c, 0xd2, 0x54, 0x82, \
    0x00, 0xb9, 0x9c, 0x66, 0x5b, 0x20, 0xa7, 0x81, \
    0x90, 0x47, 0x01, 0x63, 0xcc, 0xb8, 0xe5, 0x68, \
    0x21, 0x49, 0xf1, 0xb2, 0xf7, 0xa0, 0x06, 0xcf }
#endif

#define CASCADE_TAG               0x88

typedef struct {
    const uint8_t *data;
    size_t size;
} hmac_part_t;

/* RAM working copy; the store layer mirrors validated keys into FDS. */
static uint8_t m_data_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE];
static uint8_t m_tag_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE];
static bool m_retail_keys_ready;

static const uint8_t m_data_retail_key_sha256[SHA256_DIGEST_SIZE] =
    AMIIBO_UID_REFRESH_DATA_RETAIL_KEY_SHA256;
static const uint8_t m_tag_retail_key_sha256[SHA256_DIGEST_SIZE] =
    AMIIBO_UID_REFRESH_TAG_RETAIL_KEY_SHA256;

static bool retail_key_structure_is_valid(
    const uint8_t retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE]) {
    return retail_key[RETAIL_KEY_RFU_OFFSET] == 0 &&
           retail_key[RETAIL_KEY_MAGIC_SIZE] <= 16;
}

static bool sha256_digest(const uint8_t *data, size_t size,
                          uint8_t digest[SHA256_DIGEST_SIZE]) {
#if defined(AMIIBO_UID_REFRESH_HOST_BUILD)
    unsigned int digest_size = 0;
    return EVP_Digest(data, size, digest, &digest_size, EVP_sha256(), NULL) == 1 &&
           digest_size == SHA256_DIGEST_SIZE;
#else
    nrf_crypto_hash_context_t context;
    size_t digest_size = SHA256_DIGEST_SIZE;

    if (!nrf_crypto_is_initialized() && nrf_crypto_init() != NRF_SUCCESS) {
        return false;
    }
    return nrf_crypto_hash_calculate(&context, &g_nrf_crypto_hash_sha256_info,
                                     data, size, digest, &digest_size) == NRF_SUCCESS &&
           digest_size == SHA256_DIGEST_SIZE;
#endif
}

static nfc_amiibo_uid_refresh_status_t validate_retail_keys(
    const uint8_t data_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
    const uint8_t tag_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE]) {
    uint8_t digest[SHA256_DIGEST_SIZE];

    if (data_retail_key == NULL || tag_retail_key == NULL) {
        return NFC_AMIIBO_UID_REFRESH_INVALID_ARGUMENT;
    }
    if (!retail_key_structure_is_valid(data_retail_key) ||
        !retail_key_structure_is_valid(tag_retail_key)) {
        return NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS;
    }
    if (!sha256_digest(data_retail_key, NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE,
                       digest)) {
        return NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR;
    }
    if (memcmp(digest, m_data_retail_key_sha256, sizeof(digest)) != 0) {
        return NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS;
    }
    if (!sha256_digest(tag_retail_key, NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE,
                       digest)) {
        return NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR;
    }
    if (memcmp(digest, m_tag_retail_key_sha256, sizeof(digest)) != 0) {
        return NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS;
    }
    return NFC_AMIIBO_UID_REFRESH_OK;
}

bool nfc_amiibo_uid_refresh_parse_request(
    uint16_t length,
    const uint8_t *data,
    bool *persist) {
    if (length != 1 || data == NULL || persist == NULL ||
        (data[0] & (uint8_t)~NFC_AMIIBO_UID_REFRESH_FLAG_PERSIST) != 0) {
        return false;
    }
    *persist = (data[0] & NFC_AMIIBO_UID_REFRESH_FLAG_PERSIST) != 0;
    return true;
}

nfc_amiibo_uid_refresh_status_t nfc_amiibo_uid_refresh_set_retail_keys(
    const uint8_t data_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
    const uint8_t tag_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE]) {
    if (data_retail_key == NULL || tag_retail_key == NULL) {
        return NFC_AMIIBO_UID_REFRESH_INVALID_ARGUMENT;
    }
    if (data_retail_key[RETAIL_KEY_MAGIC_SIZE] > 16 ||
        tag_retail_key[RETAIL_KEY_MAGIC_SIZE] > 16) {
        return NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS;
    }

    memcpy(m_data_retail_key, data_retail_key, sizeof(m_data_retail_key));
    memcpy(m_tag_retail_key, tag_retail_key, sizeof(m_tag_retail_key));
    m_retail_keys_ready = true;
    return NFC_AMIIBO_UID_REFRESH_OK;
}

void nfc_amiibo_uid_refresh_clear_retail_keys(void) {
    memset(m_data_retail_key, 0, sizeof(m_data_retail_key));
    memset(m_tag_retail_key, 0, sizeof(m_tag_retail_key));
    m_retail_keys_ready = false;
}

bool nfc_amiibo_uid_refresh_keys_ready(void) {
    return m_retail_keys_ready;
}

nfc_amiibo_uid_refresh_status_t nfc_amiibo_uid_refresh_upload_retail_keys(
    uint16_t length,
    const uint8_t *data) {
    nfc_amiibo_uid_refresh_status_t status;

    if (length == 0) {
        nfc_amiibo_uid_refresh_clear_retail_keys();
        return NFC_AMIIBO_UID_REFRESH_OK;
    }
    if (length != 2 * NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE || data == NULL) {
        return NFC_AMIIBO_UID_REFRESH_INVALID_ARGUMENT;
    }

    status = validate_retail_keys(
        data, data + NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE);
    if (status != NFC_AMIIBO_UID_REFRESH_OK) {
        return status;
    }
    return nfc_amiibo_uid_refresh_set_retail_keys(
        data, data + NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE);
}

nfc_amiibo_uid_refresh_status_t nfc_amiibo_uid_refresh_apply(
    const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
    const uint8_t new_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE],
    const uint8_t *signature,
    uint8_t refreshed_dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE]) {
    if (!m_retail_keys_ready) {
        return NFC_AMIIBO_UID_REFRESH_RETAIL_KEYS_MISSING;
    }
    return nfc_amiibo_uid_refresh(dump, new_uid, m_data_retail_key,
                                  m_tag_retail_key, signature, refreshed_dump);
}

static bool secure_equal(const uint8_t *a, const uint8_t *b, size_t size) {
    uint8_t difference = 0;
    for (size_t i = 0; i < size; i++) {
        difference |= a[i] ^ b[i];
    }
    return difference == 0;
}

#if defined(AMIIBO_UID_REFRESH_HOST_BUILD)
static bool hmac_sha256_parts(const uint8_t *key, size_t key_size,
                              const hmac_part_t *parts, size_t part_count,
                              uint8_t out[HMAC_SIZE]) {
    HMAC_CTX *ctx = HMAC_CTX_new();
    unsigned int digest_size = 0;
    bool success = false;

    if (ctx == NULL) return false;
    if (HMAC_Init_ex(ctx, key, (int)key_size, EVP_sha256(), NULL) != 1) goto done;

    for (size_t i = 0; i < part_count; i++) {
        if (parts[i].size != 0 && HMAC_Update(ctx, parts[i].data, parts[i].size) != 1) {
            goto done;
        }
    }
    if (HMAC_Final(ctx, out, &digest_size) != 1 || digest_size != HMAC_SIZE) goto done;
    success = true;

done:
    HMAC_CTX_free(ctx);
    return success;
}

static bool aes_ctr_crypt(uint8_t key[16], uint8_t iv[16],
                          uint8_t *input, uint8_t *output, size_t size,
                          bool encrypt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int part_size = 0;
    int final_size = 0;
    bool success = false;

    if (ctx == NULL) return false;
    if (encrypt) {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1) goto done;
        if (EVP_EncryptUpdate(ctx, output, &part_size, input, (int)size) != 1) goto done;
        if (EVP_EncryptFinal_ex(ctx, output + part_size, &final_size) != 1) goto done;
    } else {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1) goto done;
        if (EVP_DecryptUpdate(ctx, output, &part_size, input, (int)size) != 1) goto done;
        if (EVP_DecryptFinal_ex(ctx, output + part_size, &final_size) != 1) goto done;
    }
    if ((size_t)part_size != size || final_size != 0) goto done;
    success = true;

done:
    EVP_CIPHER_CTX_free(ctx);
    return success;
}
#else
static bool hmac_sha256_parts(const uint8_t *key, size_t key_size,
                              const hmac_part_t *parts, size_t part_count,
                              uint8_t out[HMAC_SIZE]) {
    nrf_crypto_hmac_context_t context;
    size_t digest_size = HMAC_SIZE;

    if (nrf_crypto_hmac_init(&context, &g_nrf_crypto_hmac_sha256_info, key, key_size) != NRF_SUCCESS) {
        return false;
    }
    for (size_t i = 0; i < part_count; i++) {
        if (parts[i].size != 0 &&
            nrf_crypto_hmac_update(&context, parts[i].data, parts[i].size) != NRF_SUCCESS) {
            return false;
        }
    }
    return nrf_crypto_hmac_finalize(&context, out, &digest_size) == NRF_SUCCESS &&
           digest_size == HMAC_SIZE;
}

static bool aes_ctr_crypt(uint8_t key[16], uint8_t iv[16],
                          uint8_t *input, uint8_t *output, size_t size,
                          bool encrypt) {
    nrf_crypto_aes_context_t context;
    size_t output_size = size;
    nrf_crypto_operation_t operation = encrypt ? NRF_CRYPTO_ENCRYPT : NRF_CRYPTO_DECRYPT;

    return nrf_crypto_aes_crypt(&context, &g_nrf_crypto_aes_ctr_128_info, operation,
                                key, iv, input, size, output, &output_size) == NRF_SUCCESS &&
           output_size == size;
}
#endif

static bool derive_seed(uint8_t seed[SEED_SIZE],
                        const uint8_t retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
                        const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE]) {
    uint8_t base[64];
    uint8_t magic_size = retail_key[RETAIL_KEY_MAGIC_SIZE];
    size_t position = 0;

    if (magic_size > 16) return false;

    memcpy(base, &dump[0x11], 2);
    memset(&base[2], 0, 14);
    memcpy(&base[16], &dump[DUMP_UID_CL1_OFFSET], 8);
    memcpy(&base[24], &dump[DUMP_UID_CL1_OFFSET], 8);
    for (size_t i = 0; i < 32; i++) {
        base[32 + i] = dump[0x60 + i] ^ retail_key[RETAIL_KEY_XOR_OFFSET + i];
    }

    memcpy(seed, &retail_key[RETAIL_KEY_TYPE_OFFSET], RETAIL_KEY_TYPE_SIZE);
    position = RETAIL_KEY_TYPE_SIZE;
    memcpy(&seed[position], base, 16 - magic_size);
    position += 16 - magic_size;
    memcpy(&seed[position], &retail_key[RETAIL_KEY_MAGIC_OFFSET], magic_size);
    position += magic_size;
    memcpy(&seed[position], &base[16], 16);
    position += 16;
    memcpy(&seed[position], &base[32], 32);
    position += 32;

    return position == SEED_SIZE;
}

static bool derive_hmac_key(const uint8_t retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
                            const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
                            uint16_t counter, uint8_t key[DERIVED_KEY_SIZE]) {
    uint8_t seed[SEED_SIZE];
    uint8_t material[SEED_SIZE + 2];
    uint8_t digest[HMAC_SIZE];
    hmac_part_t part = {material, sizeof(material)};

    if (!derive_seed(seed, retail_key, dump)) return false;
    material[0] = (uint8_t)(counter >> 8);
    material[1] = (uint8_t)counter;
    memcpy(&material[2], seed, sizeof(seed));
    if (!hmac_sha256_parts(&retail_key[RETAIL_KEY_MASTER_OFFSET], DERIVED_KEY_SIZE,
                           &part, 1, digest)) {
        return false;
    }
    memcpy(key, digest, DERIVED_KEY_SIZE);
    return true;
}

static bool derive_data_keys(const uint8_t retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
                             const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
                             uint8_t hmac_key[DERIVED_KEY_SIZE],
                             uint8_t aes_key[16], uint8_t aes_iv[16]) {
    uint8_t seed[SEED_SIZE];
    uint8_t material[SEED_SIZE + 2];
    uint8_t digest[HMAC_SIZE];
    hmac_part_t part = {material, sizeof(material)};

    if (!derive_seed(seed, retail_key, dump)) return false;
    memcpy(&material[2], seed, sizeof(seed));

    material[0] = 0x00;
    material[1] = 0x01;
    if (!hmac_sha256_parts(&retail_key[RETAIL_KEY_MASTER_OFFSET], DERIVED_KEY_SIZE,
                           &part, 1, digest)) {
        return false;
    }
    memcpy(hmac_key, digest, DERIVED_KEY_SIZE);

    material[0] = 0x00;
    material[1] = 0x00;
    if (!hmac_sha256_parts(&retail_key[RETAIL_KEY_MASTER_OFFSET], DERIVED_KEY_SIZE,
                           &part, 1, digest)) {
        return false;
    }
    memcpy(aes_key, digest, 16);
    memcpy(aes_iv, &digest[16], 16);
    return true;
}

static bool compute_tag_hmac(const uint8_t key[DERIVED_KEY_SIZE],
                             const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
                             uint8_t out[HMAC_SIZE]) {
    hmac_part_t parts[] = {
        {&dump[DUMP_UID_CL1_OFFSET], 8},
        {&dump[DUMP_TAG_CONFIG_OFFSET], DUMP_TAG_CONFIG_SIZE},
    };
    return hmac_sha256_parts(key, DERIVED_KEY_SIZE, parts, sizeof(parts) / sizeof(parts[0]), out);
}

static bool compute_data_hmac(const uint8_t key[DERIVED_KEY_SIZE],
                              const uint8_t plaintext[CRYPT_BUFFER_SIZE],
                              const uint8_t tag_hmac[HMAC_SIZE],
                              const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
                              uint8_t out[HMAC_SIZE]) {
    hmac_part_t parts[] = {
        {&dump[0x11], 3},
        {plaintext, CRYPT_BUFFER_SIZE},
        {tag_hmac, HMAC_SIZE},
        {&dump[DUMP_UID_CL1_OFFSET], 8},
        {&dump[DUMP_TAG_CONFIG_OFFSET], DUMP_TAG_CONFIG_SIZE},
    };
    return hmac_sha256_parts(key, DERIVED_KEY_SIZE, parts, sizeof(parts) / sizeof(parts[0]), out);
}

bool nfc_amiibo_uid_refresh_signature_is_blank(
    const uint8_t signature[NFC_AMIIBO_UID_REFRESH_SIGNATURE_SIZE]) {
    if (signature == NULL) return false;
    for (size_t i = 0; i < NFC_AMIIBO_UID_REFRESH_SIGNATURE_SIZE; i++) {
        if (signature[i] != 0) return false;
    }
    return true;
}

nfc_amiibo_uid_refresh_status_t nfc_amiibo_uid_refresh_validate(
    const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
    const uint8_t data_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
    const uint8_t tag_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
    const uint8_t *signature,
    uint8_t current_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE],
    uint8_t plaintext_out[NFC_AMIIBO_UID_REFRESH_PLAINTEXT_SIZE]) {
    uint8_t work[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE];
    uint8_t crypt_buffer[CRYPT_BUFFER_SIZE];
    uint8_t plaintext_local[CRYPT_BUFFER_SIZE];
    uint8_t *plaintext;
    uint8_t tag_hmac_key[DERIVED_KEY_SIZE];
    uint8_t data_hmac_key[DERIVED_KEY_SIZE];
    uint8_t aes_key[16];
    uint8_t aes_iv[16];
    uint8_t calculated_hmac[HMAC_SIZE];

    if (dump == NULL || data_retail_key == NULL || tag_retail_key == NULL ||
        current_uid == NULL) {
        return NFC_AMIIBO_UID_REFRESH_INVALID_ARGUMENT;
    }
    if (signature != NULL && !nfc_amiibo_uid_refresh_signature_is_blank(signature)) {
        return NFC_AMIIBO_UID_REFRESH_SIGNATURE_PRESENT;
    }
    if (data_retail_key[RETAIL_KEY_MAGIC_SIZE] > 16 ||
        tag_retail_key[RETAIL_KEY_MAGIC_SIZE] > 16) {
        return NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS;
    }

#if !defined(AMIIBO_UID_REFRESH_HOST_BUILD)
    if (!nrf_crypto_is_initialized() && nrf_crypto_init() != NRF_SUCCESS) {
        return NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR;
    }
#endif

    plaintext = (plaintext_out != NULL) ? plaintext_out : plaintext_local;

    memcpy(work, dump, sizeof(work));
    memcpy(&crypt_buffer[0], &work[DUMP_CRYPT1_OFFSET], DUMP_CRYPT1_SIZE);
    memcpy(&crypt_buffer[DUMP_CRYPT1_SIZE], &work[DUMP_CRYPT2_OFFSET], DUMP_CRYPT2_SIZE);

    if (!derive_hmac_key(tag_retail_key, work, 0x0001, tag_hmac_key) ||
        !compute_tag_hmac(tag_hmac_key, work, calculated_hmac)) {
        return NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR;
    }
    if (!secure_equal(calculated_hmac, &work[DUMP_TAG_HMAC_OFFSET], HMAC_SIZE)) {
        return NFC_AMIIBO_UID_REFRESH_TAG_HMAC_MISMATCH;
    }

    if (!derive_data_keys(data_retail_key, work, data_hmac_key, aes_key, aes_iv) ||
        !aes_ctr_crypt(aes_key, aes_iv, crypt_buffer, plaintext, CRYPT_BUFFER_SIZE, false)) {
        return NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR;
    }
    if (!compute_data_hmac(data_hmac_key, plaintext, &work[DUMP_TAG_HMAC_OFFSET], work,
                            calculated_hmac)) {
        return NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR;
    }
    if (!secure_equal(calculated_hmac, &work[DUMP_DATA_HMAC_OFFSET], HMAC_SIZE)) {
        return NFC_AMIIBO_UID_REFRESH_DATA_HMAC_MISMATCH;
    }

    current_uid[0] = dump[DUMP_UID_CL1_OFFSET];
    current_uid[1] = dump[DUMP_UID_CL1_OFFSET + 1];
    current_uid[2] = dump[DUMP_UID_CL1_OFFSET + 2];
    current_uid[3] = dump[DUMP_UID_CL2_OFFSET];
    current_uid[4] = dump[DUMP_UID_CL2_OFFSET + 1];
    current_uid[5] = dump[DUMP_UID_CL2_OFFSET + 2];
    current_uid[6] = dump[DUMP_UID_CL2_OFFSET + 3];
    return NFC_AMIIBO_UID_REFRESH_OK;
}

nfc_amiibo_uid_refresh_status_t nfc_amiibo_uid_refresh_validate_apply(
    const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
    const uint8_t *signature,
    uint8_t current_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE],
    uint8_t plaintext_out[NFC_AMIIBO_UID_REFRESH_PLAINTEXT_SIZE]) {
    if (!m_retail_keys_ready) {
        return NFC_AMIIBO_UID_REFRESH_RETAIL_KEYS_MISSING;
    }
    return nfc_amiibo_uid_refresh_validate(dump, m_data_retail_key, m_tag_retail_key,
                                           signature, current_uid, plaintext_out);
}

void nfc_amiibo_uid_refresh_set_uid(
    uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
    const uint8_t uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE]) {
    dump[DUMP_UID_CL1_OFFSET] = uid[0];
    dump[DUMP_UID_CL1_OFFSET + 1] = uid[1];
    dump[DUMP_UID_CL1_OFFSET + 2] = uid[2];
    dump[DUMP_UID_BCC1_OFFSET] = CASCADE_TAG ^ uid[0] ^ uid[1] ^ uid[2];
    dump[DUMP_UID_CL2_OFFSET] = uid[3];
    dump[DUMP_UID_CL2_OFFSET + 1] = uid[4];
    dump[DUMP_UID_CL2_OFFSET + 2] = uid[5];
    dump[DUMP_UID_CL2_OFFSET + 3] = uid[6];
    dump[DUMP_UID_BCC2_OFFSET] = uid[3] ^ uid[4] ^ uid[5] ^ uid[6];
}

void nfc_amiibo_uid_refresh_set_password(
    uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
    const uint8_t uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE]) {
    dump[DUMP_PWD_OFFSET] = 0xAA ^ uid[1] ^ uid[3];
    dump[DUMP_PWD_OFFSET + 1] = 0x55 ^ uid[2] ^ uid[4];
    dump[DUMP_PWD_OFFSET + 2] = 0xAA ^ uid[3] ^ uid[5];
    dump[DUMP_PWD_OFFSET + 3] = 0x55 ^ uid[4] ^ uid[6];
    dump[DUMP_PACK_OFFSET] = 0x80;
    dump[DUMP_PACK_OFFSET + 1] = 0x80;
}

nfc_amiibo_uid_refresh_status_t nfc_amiibo_uid_refresh(
    const uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE],
    const uint8_t new_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE],
    const uint8_t data_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
    const uint8_t tag_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE],
    const uint8_t *signature,
    uint8_t refreshed_dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE]) {
    uint8_t work[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE];
    uint8_t crypt_buffer[CRYPT_BUFFER_SIZE];
    uint8_t plaintext[CRYPT_BUFFER_SIZE];
    uint8_t tag_hmac_key[DERIVED_KEY_SIZE];
    uint8_t data_hmac_key[DERIVED_KEY_SIZE];
    uint8_t aes_key[16];
    uint8_t aes_iv[16];
    uint8_t calculated_hmac[HMAC_SIZE];
    uint8_t current_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE];
    nfc_amiibo_uid_refresh_status_t status;

    if (dump == NULL || new_uid == NULL || data_retail_key == NULL ||
        tag_retail_key == NULL || refreshed_dump == NULL) {
        return NFC_AMIIBO_UID_REFRESH_INVALID_ARGUMENT;
    }
    if (new_uid[0] != 0x04) return NFC_AMIIBO_UID_REFRESH_INVALID_UID;

    status = nfc_amiibo_uid_refresh_validate(dump, data_retail_key, tag_retail_key,
                                             signature, current_uid, plaintext);
    if (status != NFC_AMIIBO_UID_REFRESH_OK) {
        return status;
    }

    memcpy(work, dump, sizeof(work));
    memcpy(&crypt_buffer[0], &work[DUMP_CRYPT1_OFFSET], DUMP_CRYPT1_SIZE);
    memcpy(&crypt_buffer[DUMP_CRYPT1_SIZE], &work[DUMP_CRYPT2_OFFSET], DUMP_CRYPT2_SIZE);

    nfc_amiibo_uid_refresh_set_uid(work, new_uid);
    nfc_amiibo_uid_refresh_set_password(work, new_uid);

    if (!derive_hmac_key(tag_retail_key, work, 0x0001, tag_hmac_key) ||
        !compute_tag_hmac(tag_hmac_key, work, calculated_hmac)) {
        return NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR;
    }
    memcpy(&work[DUMP_TAG_HMAC_OFFSET], calculated_hmac, HMAC_SIZE);

    if (!derive_data_keys(data_retail_key, work, data_hmac_key, aes_key, aes_iv) ||
        !compute_data_hmac(data_hmac_key, plaintext, &work[DUMP_TAG_HMAC_OFFSET], work,
                           calculated_hmac)) {
        return NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR;
    }
    memcpy(&work[DUMP_DATA_HMAC_OFFSET], calculated_hmac, HMAC_SIZE);

    if (!aes_ctr_crypt(aes_key, aes_iv, plaintext, crypt_buffer, sizeof(plaintext), true)) {
        return NFC_AMIIBO_UID_REFRESH_CRYPTO_ERROR;
    }
    memcpy(&work[DUMP_CRYPT1_OFFSET], &crypt_buffer[0], DUMP_CRYPT1_SIZE);
    memcpy(&work[DUMP_CRYPT2_OFFSET], &crypt_buffer[DUMP_CRYPT1_SIZE], DUMP_CRYPT2_SIZE);

    memmove(refreshed_dump, work, sizeof(work));
    return NFC_AMIIBO_UID_REFRESH_OK;
}
