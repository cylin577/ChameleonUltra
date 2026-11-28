/* CTAP2 / CTAP1 (U2F) core state machine. */
#ifndef FIDO2_CORE_H__
#define FIDO2_CORE_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fido2/fido2_types.h"

/* Returned by f2_core_dispatch() when the request needs a user gesture.
   resp_len is set to 0: the transport must hold the transaction, and call
   f2_core_dispatch() again with the same request once the gate is granted.
   f2_core_tick() emits the CTAPHID/BLE KEEPALIVE status while waiting. */
#define F2_CORE_PENDING 0xFFu

typedef struct {
    fido2_transport_t transport;
    bool uv_requested;
} fido2_request_t;

void   f2_core_init(void);

/* req = CTAP command byte + CBOR (CTAP2) or raw APDU (U2F, req[0] == 0x00).
   resp = CTAP status byte + CBOR for CTAP2; raw bytes + 2-byte SW for U2F.
   Returns F2_CORE_PENDING (no response yet), a CTAP status byte (CTAP2),
   or FIDO2_ST_OK for a completed U2F exchange. */
uint8_t f2_core_dispatch(const uint8_t *req, size_t req_len,
                         const fido2_request_t *ctx,
                         uint8_t *resp, size_t resp_max, size_t *resp_len);

void   f2_core_tick(uint32_t now_ms);   /* gate timeout + keepalive, called every ~5ms */
void   f2_core_cancel(void);             /* silent disarm/reset: no status emitted */
/* CTAP CANCEL: send 0x2D on the gated request's transport, then clear the gate. */
void   f2_core_cancel_request(void);
bool   f2_core_gate_pending(void);
fido2_status_t f2_core_grant(fido2_gate_t gate);  /* button or debug grant */
size_t f2_core_status(char *out, size_t cap);     /* "gate=...,uv=...,creds=N\n" */

#endif /* FIDO2_CORE_H__ */
