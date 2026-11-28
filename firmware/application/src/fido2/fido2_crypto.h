#ifndef FIDO2_CRYPTO_H__
#define FIDO2_CRYPTO_H__

#include <stddef.h>
#include <stdint.h>

#include "sdk_errors.h"

ret_code_t f2_crypto_init(void);
ret_code_t f2_crypto_keygen(uint8_t priv[32], uint8_t pub[64]);
ret_code_t f2_crypto_sign(const uint8_t priv[32], const uint8_t hash32[32],
                          uint8_t der[72], size_t *der_len);
ret_code_t f2_crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
ret_code_t f2_crypto_random(uint8_t *out, size_t len);

#endif
