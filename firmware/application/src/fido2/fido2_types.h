/* Shared FIDO2/CTAP2 constants. Plain C11, no SDK headers. */
#ifndef FIDO2_TYPES_H
#define FIDO2_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FIDO2_AAGUID_LEN        16
#define FIDO2_CRED_ID_MAX       64
#define FIDO2_USER_ID_MAX       64
#define FIDO2_MAX_CREDENTIALS   16
#define FIDO2_CTAP_TIMEOUT_MS   30000
/* "CHAMELEONFIDO2V1" */
#define FIDO2_AAGUID_BYTES  {0x43,0x48,0x41,0x4D,0x45,0x4C,0x45,0x4F,0x4E,0x46,0x49,0x44,0x4F,0x32,0x56,0x31}

typedef enum { FIDO2_TRANSPORT_USB=0, FIDO2_TRANSPORT_NFC=1,
               FIDO2_TRANSPORT_BLE=2, FIDO2_TRANSPORT_DBG=3 } fido2_transport_t;

typedef enum { FIDO2_ST_OK=0x00, FIDO2_ST_INVALID_PARAM=0x02,
               FIDO2_ST_EXCLUDED=0x19, FIDO2_ST_UNSUPPORTED_ALG=0x26,
               FIDO2_ST_NO_CREDENTIALS=0x2E, FIDO2_ST_PIN_NOT_SET=0x35,
               FIDO2_ST_UP_REQUIRED=0x3B, FIDO2_ST_UV_INVALID=0x3F,
               FIDO2_ST_OTHER=0x7F } fido2_status_t;

typedef enum { FIDO2_GATE_NONE=0, FIDO2_GATE_UP, FIDO2_GATE_UV } fido2_gate_t;

/* CTAPHID/BLE KEEPALIVE status sent to a cancelled request's transport. */
#define FIDO2_ST_KEEPALIVE_CANCEL 0x2Du

#define FIDO2_FLAG_UP 0x01u
#define FIDO2_FLAG_UV 0x04u
#define FIDO2_FLAG_AT 0x40u
#define FIDO2_FLAG_ED 0x80u

#endif /* FIDO2_TYPES_H */
