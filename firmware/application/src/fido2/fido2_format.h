/* Byte-level encoders for CTAP2 authenticator data, signatures and transports. */
#ifndef FIDO2_FORMAT_H
#define FIDO2_FORMAT_H

#include <stddef.h>
#include <stdint.h>

size_t fmt_cose_key(uint8_t out[77], const uint8_t pub[64]);

size_t fmt_auth_data(uint8_t *out, size_t cap, const uint8_t rp_hash[32],
                     uint8_t flags, uint32_t sign_count,
                     const uint8_t *cred_id, size_t cred_id_len,
                     const uint8_t *cose, size_t cose_len);
                     /* AT section only when cred_id != NULL */

size_t fmt_raw_sig_to_der(const uint8_t raw[64], uint8_t der[72]);

size_t fmt_u2f_reg_base(uint8_t *out, size_t cap, const uint8_t app[32],
                        const uint8_t chal[32], const uint8_t *kh, size_t kh_len,
                        const uint8_t pub[65]);

size_t fmt_u2f_auth_base(uint8_t out[69], const uint8_t app[32],
                         uint8_t up_byte, uint32_t counter_be,
                         const uint8_t chal[32]);

size_t fmt_ctaphid_init(uint8_t out[64], uint32_t cid, uint8_t cmd,
                        const uint8_t *data, size_t len);
size_t fmt_ctaphid_cont(uint8_t out[64], uint32_t cid, uint8_t seq,
                        const uint8_t *data, size_t len);

size_t fmt_ble_init(uint8_t *out, size_t cap, uint8_t cmd,
                    const uint8_t *data, size_t len);
size_t fmt_ble_cont(uint8_t *out, size_t cap, uint8_t seq,
                    const uint8_t *data, size_t len);

#endif /* FIDO2_FORMAT_H */
