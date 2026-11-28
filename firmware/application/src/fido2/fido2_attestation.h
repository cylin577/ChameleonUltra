/* Static batch attestation material for CTAP1 (U2F) REGISTER. Plain C11. */
#ifndef FIDO2_ATTESTATION_H__
#define FIDO2_ATTESTATION_H__

#include <stddef.h>
#include <stdint.h>

/* 32-byte big-endian P-256 private scalar matching the embedded certificate. */
const uint8_t *f2_attestation_key(void);

/* DER-encoded self-signed X.509 certificate. */
const uint8_t *f2_attestation_cert(void);
size_t         f2_attestation_cert_len(void);

#endif /* FIDO2_ATTESTATION_H__ */
