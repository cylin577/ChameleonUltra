#ifndef FIDO2_CREDS_H__
#define FIDO2_CREDS_H__

#include <stddef.h>
#include <stdint.h>

#include "fido2/fido2_types.h"

typedef struct __attribute__((packed)) {
    uint8_t  cred_id[64];
    uint8_t  priv[32];
    uint8_t  pub[64];
    uint8_t  rp_hash[32];
    uint8_t  user_id[64];
    uint16_t user_id_len;
    uint8_t  cred_protect;
    uint8_t  reserved;
    uint32_t sign_count;
    uint16_t cred_id_len;
    uint16_t reserved2;
} fido2_cred_rec_t;

_Static_assert(sizeof(fido2_cred_rec_t) % 4 == 0, "FDS records must be word aligned");

fido2_status_t f2_creds_find_by_rp_user(const uint8_t *rp, const uint8_t *uid,
                                        size_t uid_len, fido2_cred_rec_t *out);
fido2_status_t f2_creds_find_by_id(const uint8_t *id, size_t id_len,
                                   fido2_cred_rec_t *out);
fido2_status_t f2_creds_add(const fido2_cred_rec_t *rec);
fido2_status_t f2_creds_bump_sign_count(const uint8_t *id, size_t id_len,
                                        uint32_t *new_count);
fido2_status_t f2_creds_next(uint16_t *cursor, fido2_cred_rec_t *out);
void           f2_creds_reset(void);
size_t         f2_creds_list(uint8_t *out, size_t cap); /* debug dump */

#endif
