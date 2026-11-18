#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nfc_amiibo_uid_refresh.h"

extern const uint8_t amiibo_test_old_dump[540];
extern const uint8_t amiibo_test_expected_dump[540];
extern const uint8_t amiibo_test_data_retail_key[80];
extern const uint8_t amiibo_test_tag_retail_key[80];

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return false; \
    } \
} while (0)

static const uint8_t new_uid[7] = {0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42};

static const uint8_t old_uid[7] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

static bool test_request_parsing(void) {
    bool persist = true;
    uint8_t flags = 0;

    CHECK(nfc_amiibo_uid_refresh_parse_request(1, &flags, &persist));
    CHECK(!persist);

    flags = NFC_AMIIBO_UID_REFRESH_FLAG_PERSIST;
    CHECK(nfc_amiibo_uid_refresh_parse_request(1, &flags, &persist));
    CHECK(persist);

    flags = 0x02;
    CHECK(!nfc_amiibo_uid_refresh_parse_request(1, &flags, &persist));
    CHECK(!nfc_amiibo_uid_refresh_parse_request(0, &flags, &persist));
    CHECK(!nfc_amiibo_uid_refresh_parse_request(2, &flags, &persist));
    CHECK(!nfc_amiibo_uid_refresh_parse_request(1, NULL, &persist));
    CHECK(!nfc_amiibo_uid_refresh_parse_request(1, &flags, NULL));
    return true;
}

static bool test_retail_keys_api(void) {
    uint8_t output[540];
    uint8_t invalid_retail_key[80];

    nfc_amiibo_uid_refresh_clear_retail_keys();
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_RETAIL_KEYS_MISSING);

    CHECK(nfc_amiibo_uid_refresh_set_retail_keys(
              amiibo_test_data_retail_key, amiibo_test_tag_retail_key) ==
          NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(memcmp(output, amiibo_test_expected_dump, sizeof(output)) == 0);

    memcpy(invalid_retail_key, amiibo_test_data_retail_key, sizeof(invalid_retail_key));
    invalid_retail_key[31] = 17;
    CHECK(nfc_amiibo_uid_refresh_set_retail_keys(
              invalid_retail_key, amiibo_test_tag_retail_key) ==
          NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS);
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_OK);

    nfc_amiibo_uid_refresh_clear_retail_keys();
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_RETAIL_KEYS_MISSING);
    return true;
}

static bool test_upload_retail_keys(void) {
    uint8_t payload[2 * 80];
    uint8_t invalid[2 * 80];
    uint8_t swapped[2 * 80];
    uint8_t output[540];

    memcpy(payload, amiibo_test_data_retail_key, 80);
    memcpy(payload + 80, amiibo_test_tag_retail_key, 80);

    nfc_amiibo_uid_refresh_clear_retail_keys();
    CHECK(nfc_amiibo_uid_refresh_upload_retail_keys(159, payload) ==
          NFC_AMIIBO_UID_REFRESH_INVALID_ARGUMENT);
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_RETAIL_KEYS_MISSING);

    CHECK(nfc_amiibo_uid_refresh_upload_retail_keys(sizeof(payload), payload) ==
          NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(memcmp(output, amiibo_test_expected_dump, sizeof(output)) == 0);

    CHECK(nfc_amiibo_uid_refresh_upload_retail_keys(159, payload) ==
          NFC_AMIIBO_UID_REFRESH_INVALID_ARGUMENT);
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(memcmp(output, amiibo_test_expected_dump, sizeof(output)) == 0);

    memcpy(invalid, payload, sizeof(invalid));
    invalid[0] ^= 0x01;
    CHECK(nfc_amiibo_uid_refresh_upload_retail_keys(sizeof(invalid), invalid) ==
          NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS);
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(memcmp(output, amiibo_test_expected_dump, sizeof(output)) == 0);

    memcpy(invalid, payload, sizeof(invalid));
    invalid[31] = 17;
    CHECK(nfc_amiibo_uid_refresh_upload_retail_keys(sizeof(invalid), invalid) ==
          NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS);
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_OK);

    memcpy(swapped, payload, sizeof(swapped));
    memcpy(swapped, amiibo_test_tag_retail_key, 80);
    memcpy(swapped + 80, amiibo_test_data_retail_key, 80);
    CHECK(nfc_amiibo_uid_refresh_upload_retail_keys(sizeof(swapped), swapped) ==
          NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS);
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_OK);

    CHECK(nfc_amiibo_uid_refresh_upload_retail_keys(0, NULL) ==
          NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(nfc_amiibo_uid_refresh_apply(amiibo_test_old_dump, new_uid, NULL, output) ==
          NFC_AMIIBO_UID_REFRESH_RETAIL_KEYS_MISSING);
    return true;
}

static bool test_refresh_vector(void) {
    uint8_t output[540];

    CHECK(nfc_amiibo_uid_refresh(amiibo_test_old_dump, new_uid,
                                  amiibo_test_data_retail_key, amiibo_test_tag_retail_key,
                                  NULL, output) == NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(memcmp(output, amiibo_test_expected_dump, sizeof(output)) == 0);
    CHECK(output[0] == 0x04 && output[1] == 0xDE && output[2] == 0xAD);
    CHECK(output[3] == (0x88 ^ 0x04 ^ 0xDE ^ 0xAD));
    CHECK(output[4] == 0xBE && output[5] == 0xEF && output[6] == 0x00 && output[7] == 0x42);
    CHECK(output[8] == (0xBE ^ 0xEF ^ 0x00 ^ 0x42));
    CHECK(memcmp(&output[0x214], "\xca\x17\x14\xf8", 4) == 0);
    CHECK(memcmp(&output[0x218], "\x80\x80", 2) == 0);
    CHECK(memcmp(&output[0x208], &amiibo_test_old_dump[0x208], 12) == 0);
    CHECK(memcmp(&output[0x21A], &amiibo_test_old_dump[0x21A], 2) == 0);
    return true;
}

static bool check_failure_is_atomic(nfc_amiibo_uid_refresh_status_t expected_status,
                                    const uint8_t *dump,
                                    const uint8_t *data_retail_key,
                                    const uint8_t *tag_retail_key,
                                    const uint8_t *signature) {
    uint8_t output[540];
    uint8_t untouched[540];

    memset(output, 0xA5, sizeof(output));
    memset(untouched, 0xA5, sizeof(untouched));
    CHECK(nfc_amiibo_uid_refresh(dump, new_uid, data_retail_key, tag_retail_key,
                                  signature, output) == expected_status);
    CHECK(memcmp(output, untouched, sizeof(output)) == 0);
    return true;
}

static bool test_rejections(void) {
    uint8_t tampered[540];
    uint8_t invalid_retail_key[80];
    uint8_t invalid_uid[7] = {0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42};
    uint8_t signature[32] = {0};
    uint8_t output[540];

    memcpy(tampered, amiibo_test_old_dump, sizeof(tampered));
    tampered[0x34] ^= 0x01;
    CHECK(check_failure_is_atomic(NFC_AMIIBO_UID_REFRESH_TAG_HMAC_MISMATCH,
                                  tampered, amiibo_test_data_retail_key,
                                  amiibo_test_tag_retail_key, NULL));

    memcpy(tampered, amiibo_test_old_dump, sizeof(tampered));
    tampered[0x14] ^= 0x01;
    CHECK(check_failure_is_atomic(NFC_AMIIBO_UID_REFRESH_DATA_HMAC_MISMATCH,
                                  tampered, amiibo_test_data_retail_key,
                                  amiibo_test_tag_retail_key, NULL));

    signature[17] = 0x01;
    CHECK(check_failure_is_atomic(NFC_AMIIBO_UID_REFRESH_SIGNATURE_PRESENT,
                                  amiibo_test_old_dump, amiibo_test_data_retail_key,
                                  amiibo_test_tag_retail_key, signature));

    memcpy(invalid_retail_key, amiibo_test_data_retail_key, sizeof(invalid_retail_key));
    invalid_retail_key[31] = 17;
    CHECK(check_failure_is_atomic(NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS,
                                  amiibo_test_old_dump, invalid_retail_key,
                                  amiibo_test_tag_retail_key, NULL));

    memset(output, 0xA5, sizeof(output));
    CHECK(nfc_amiibo_uid_refresh(amiibo_test_old_dump, invalid_uid,
                                  amiibo_test_data_retail_key, amiibo_test_tag_retail_key,
                                  NULL, output) == NFC_AMIIBO_UID_REFRESH_INVALID_UID);

    memset(signature, 0, sizeof(signature));
    CHECK(nfc_amiibo_uid_refresh(amiibo_test_old_dump, new_uid,
                                  amiibo_test_data_retail_key, amiibo_test_tag_retail_key,
                                  signature, output) == NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(memcmp(output, amiibo_test_expected_dump, sizeof(output)) == 0);
    return true;
}

static bool test_validate_uid_extraction(void) {
    uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE];
    uint8_t snapshot[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE];
    uint8_t current_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE];
    uint8_t plaintext[NFC_AMIIBO_UID_REFRESH_PLAINTEXT_SIZE];
    uint8_t untouched[NFC_AMIIBO_UID_REFRESH_PLAINTEXT_SIZE];

    memcpy(dump, amiibo_test_old_dump, sizeof(dump));
    memcpy(snapshot, dump, sizeof(snapshot));
    memset(plaintext, 0xA5, sizeof(plaintext));
    memcpy(untouched, plaintext, sizeof(untouched));

    CHECK(nfc_amiibo_uid_refresh_validate(dump, amiibo_test_data_retail_key,
                                          amiibo_test_tag_retail_key, NULL,
                                          current_uid, plaintext) ==
          NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(memcmp(current_uid, old_uid, sizeof(old_uid)) == 0);
    CHECK(memcmp(plaintext, untouched, sizeof(plaintext)) != 0);
    CHECK(memcmp(dump, snapshot, sizeof(dump)) == 0);

    /* plaintext_out is optional; validation still succeeds without it. */
    memset(current_uid, 0, sizeof(current_uid));
    CHECK(nfc_amiibo_uid_refresh_validate(dump, amiibo_test_data_retail_key,
                                          amiibo_test_tag_retail_key, NULL,
                                          current_uid, NULL) ==
          NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(memcmp(current_uid, old_uid, sizeof(old_uid)) == 0);
    CHECK(memcmp(dump, snapshot, sizeof(dump)) == 0);
    return true;
}

static bool test_validate_rejections(void) {
    uint8_t dump[NFC_AMIIBO_UID_REFRESH_DUMP_SIZE];
    uint8_t current_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE];
    uint8_t signature[NFC_AMIIBO_UID_REFRESH_SIGNATURE_SIZE] = {0};
    uint8_t invalid_retail_key[NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE];

    memcpy(dump, amiibo_test_old_dump, sizeof(dump));
    dump[0x34] ^= 0x01;
    CHECK(nfc_amiibo_uid_refresh_validate(dump, amiibo_test_data_retail_key,
                                          amiibo_test_tag_retail_key, NULL,
                                          current_uid, NULL) ==
          NFC_AMIIBO_UID_REFRESH_TAG_HMAC_MISMATCH);

    memcpy(dump, amiibo_test_old_dump, sizeof(dump));
    dump[0x14] ^= 0x01;
    CHECK(nfc_amiibo_uid_refresh_validate(dump, amiibo_test_data_retail_key,
                                          amiibo_test_tag_retail_key, NULL,
                                          current_uid, NULL) ==
          NFC_AMIIBO_UID_REFRESH_DATA_HMAC_MISMATCH);

    memcpy(dump, amiibo_test_old_dump, sizeof(dump));
    dump[0xA0] ^= 0x80;
    CHECK(nfc_amiibo_uid_refresh_validate(dump, amiibo_test_data_retail_key,
                                          amiibo_test_tag_retail_key, NULL,
                                          current_uid, NULL) ==
          NFC_AMIIBO_UID_REFRESH_DATA_HMAC_MISMATCH);

    signature[17] = 0x01;
    CHECK(nfc_amiibo_uid_refresh_validate(amiibo_test_old_dump,
                                          amiibo_test_data_retail_key,
                                          amiibo_test_tag_retail_key, signature,
                                          current_uid, NULL) ==
          NFC_AMIIBO_UID_REFRESH_SIGNATURE_PRESENT);

    memcpy(invalid_retail_key, amiibo_test_data_retail_key,
           sizeof(invalid_retail_key));
    invalid_retail_key[31] = 17;
    CHECK(nfc_amiibo_uid_refresh_validate(amiibo_test_old_dump, invalid_retail_key,
                                          amiibo_test_tag_retail_key, NULL,
                                          current_uid, NULL) ==
          NFC_AMIIBO_UID_REFRESH_INVALID_RETAIL_KEYS);

    CHECK(nfc_amiibo_uid_refresh_validate(NULL, amiibo_test_data_retail_key,
                                          amiibo_test_tag_retail_key, NULL,
                                          current_uid, NULL) ==
          NFC_AMIIBO_UID_REFRESH_INVALID_ARGUMENT);
    CHECK(nfc_amiibo_uid_refresh_validate(amiibo_test_old_dump, NULL,
                                          amiibo_test_tag_retail_key, NULL,
                                          current_uid, NULL) ==
          NFC_AMIIBO_UID_REFRESH_INVALID_ARGUMENT);
    CHECK(nfc_amiibo_uid_refresh_validate(amiibo_test_old_dump,
                                          amiibo_test_data_retail_key, NULL, NULL,
                                          current_uid, NULL) ==
          NFC_AMIIBO_UID_REFRESH_INVALID_ARGUMENT);
    CHECK(nfc_amiibo_uid_refresh_validate(amiibo_test_old_dump,
                                          amiibo_test_data_retail_key,
                                          amiibo_test_tag_retail_key, NULL,
                                          NULL, NULL) ==
          NFC_AMIIBO_UID_REFRESH_INVALID_ARGUMENT);
    return true;
}

static bool test_validate_persisted_keys(void) {
    uint8_t current_uid[NFC_AMIIBO_UID_REFRESH_UID_SIZE];
    uint8_t plaintext[NFC_AMIIBO_UID_REFRESH_PLAINTEXT_SIZE];

    nfc_amiibo_uid_refresh_clear_retail_keys();
    CHECK(nfc_amiibo_uid_refresh_validate_apply(amiibo_test_old_dump, NULL,
                                                current_uid, NULL) ==
          NFC_AMIIBO_UID_REFRESH_RETAIL_KEYS_MISSING);

    CHECK(nfc_amiibo_uid_refresh_set_retail_keys(
              amiibo_test_data_retail_key, amiibo_test_tag_retail_key) ==
          NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(nfc_amiibo_uid_refresh_validate_apply(amiibo_test_old_dump, NULL,
                                                current_uid, plaintext) ==
          NFC_AMIIBO_UID_REFRESH_OK);
    CHECK(memcmp(current_uid, old_uid, sizeof(old_uid)) == 0);
    nfc_amiibo_uid_refresh_clear_retail_keys();
    return true;
}

static bool test_persisted_detection_config(void) {
    typedef struct {
        struct {
            bool detection_enable;
        } config;
    } fixture_t;
    fixture_t live = { .config = { .detection_enable = true } };
    fixture_t persisted = live;

    NFC_AMIIBO_UID_REFRESH_PREPARE_PERSISTED_CONFIG(&persisted);

    CHECK(!persisted.config.detection_enable);
    CHECK(live.config.detection_enable);
    return true;
}

static bool test_helpers(void) {
    uint8_t dump[540];
    uint8_t signature[32] = {0};

    memcpy(dump, amiibo_test_old_dump, sizeof(dump));
    nfc_amiibo_uid_refresh_set_uid(dump, new_uid);
    CHECK(dump[0] == 0x04 && dump[1] == 0xDE && dump[2] == 0xAD);
    CHECK(dump[3] == (0x88 ^ 0x04 ^ 0xDE ^ 0xAD));
    CHECK(dump[4] == 0xBE && dump[5] == 0xEF && dump[6] == 0x00 && dump[7] == 0x42);
    CHECK(dump[8] == (0xBE ^ 0xEF ^ 0x00 ^ 0x42));

    nfc_amiibo_uid_refresh_set_password(dump, new_uid);
    CHECK(memcmp(&dump[0x214], "\xca\x17\x14\xf8", 4) == 0);
    CHECK(memcmp(&dump[0x218], "\x80\x80", 2) == 0);

    CHECK(nfc_amiibo_uid_refresh_signature_is_blank(signature));
    signature[31] = 0x01;
    CHECK(!nfc_amiibo_uid_refresh_signature_is_blank(signature));
    return true;
}

int main(void) {
    if (!test_request_parsing() ||
        !test_retail_keys_api() ||
        !test_upload_retail_keys() ||
        !test_refresh_vector() ||
        !test_rejections() ||
        !test_validate_uid_extraction() ||
        !test_validate_rejections() ||
        !test_validate_persisted_keys() ||
        !test_persisted_detection_config() ||
        !test_helpers()) {
        return 1;
    }
    puts("nfc_amiibo_uid_refresh: all tests passed");
    return 0;
}
