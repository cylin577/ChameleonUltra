/*
 * fido2_core.h — transport-independent FIDO2 / CTAP2 core.
 *
 * The core owns the credential crypto (stateless key wrapping, ECDSA, CBOR)
 * and a single-slot request state machine. Transports (NFC / USB CTAPHID /
 * BLE FIDO GATT) only frame bytes and hand a CTAP2 command to the core; the
 * main-loop tick runs the (slow) ECDSA outside any critical section and the
 * owner picks the finished response back up.
 */
#ifndef FIDO2_CORE_H
#define FIDO2_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Max CTAP2 request/response the core accepts. CTAPHID messages are capped
 * here as well (the spec allows 7609, real CTAP commands stay well below
 * 1 KiB and RAM is scarce on this part). */
#define FIDO2_MAX_REQUEST     1024
#define FIDO2_MAX_RESPONSE    1024

/* A physical user-presence gesture authorizes one nearby CTAP operation. */
#define FIDO2_UP_GRANT_MS     5000u

/* Bound how long a request may wait for that gesture before it is cancelled. */
#define FIDO2_UP_WAIT_TIMEOUT_MS 25000u

/* Credential handle: nonce(32) | mac(32) */
#define FIDO2_CRED_ID_LEN     64

/* Enabled transports (also drives the CTAP2 GetInfo "transports" list). */
#define FIDO2_TRANSPORT_NFC   0x01
#define FIDO2_TRANSPORT_USB   0x02
#define FIDO2_TRANSPORT_BLE   0x04

/* CTAP2 status codes */
#define FIDO2_OK                          0x00
#define FIDO2_ERR_INVALID_CMD             0x01
#define FIDO2_ERR_INVALID_LENGTH          0x03
#define FIDO2_ERR_INVALID_CBOR            0x12
#define FIDO2_ERR_MISSING_PARAMETER       0x14
#define FIDO2_ERR_OPERATION_DENIED        0x27
#define FIDO2_ERR_UNSUPPORTED_ALGORITHM   0x26
#define FIDO2_ERR_UNSUPPORTED_OPTION      0x2B
#define FIDO2_ERR_KEEPALIVE_CANCEL        0x2D
#define FIDO2_ERR_NO_CREDENTIALS          0x2E

/* CTAP2 command bytes */
#define FIDO2_CMD_MAKE_CREDENTIAL  0x01
#define FIDO2_CMD_GET_ASSERTION    0x02
#define FIDO2_CMD_GET_INFO         0x04

/* Which transport owns a queued request (and therefore its response). */
typedef enum {
    FIDO2_OWNER_NFC = 0,
    FIDO2_OWNER_USB,
    FIDO2_OWNER_BLE,
    FIDO2_OWNER_HOST,     /* CLI / host command path */
} fido2_owner_t;

/* Platform hooks: persistence of the master key + sign counter, and entropy.
 * The firmware wires these to FDS + nrf_drv_rng; host tests wire them to
 * plain memory. */
typedef struct {
    bool (*load_master_key)(uint8_t mk[32]);
    bool (*store_master_key)(const uint8_t mk[32]);
    bool (*load_counter)(uint32_t *ctr);
    void (*store_counter)(uint32_t ctr);
    bool (*random_bytes)(uint8_t *dst, size_t len);
    uint32_t (*now_ms)(void);
} fido2_core_io_t;

/* Register the platform hooks. Must be called before fido2_core_arm(). */
void     fido2_core_init(const fido2_core_io_t *io);

/* Load (or create) the master key + counter and enable the given transports. */
bool     fido2_core_arm(uint8_t transport_mask);
void     fido2_core_disarm(void);
uint8_t  fido2_core_transport_mask(void);

/* Queue a CTAP2 command (command byte + CBOR payload). Returns false when the
 * slot is busy, the mode is not armed or the request is too long. */
bool     fido2_submit(fido2_owner_t owner, const uint8_t *cmd, size_t len);

/* Main-loop pump: runs the queued request (crypto included). */
void     fido2_tick(void);

/* User-presence gate. MakeCredential/GetAssertion requests stay queued until
 * this is called, then execute with the UP flag set. The grant is consumed by
 * the next queued request. */
bool     fido2_grant_user_presence(void);
bool     fido2_up_granted(void);

/* Cancel the queued request for `owner`. The owner receives status
 * CTAP2_ERR_KEEPALIVE_CANCEL. */
bool     fido2_cancel(fido2_owner_t owner);

/* True while the owner is waiting for a user-presence gesture. Transports
 * use this to emit CTAPHID/BLE KEEPALIVE(UP_NEEDED). */
bool     fido2_waiting_for_presence(fido2_owner_t owner);

/* True when a finished response is waiting for `owner`. */
bool     fido2_response_ready(fido2_owner_t owner);

/* Pick up the finished response. The response starts with the CTAP status
 * byte. Returns false when nothing is ready or the buffer is too small. */
bool     fido2_take_response(fido2_owner_t owner, uint8_t *out, size_t out_max, size_t *out_len);

/* True while a request is queued or being processed. */
bool     fido2_busy(void);

/* Bump + persist the global sign counter and return the new value. The CTAP1
 * (U2F) path uses it too, so both transports share one monotonic counter. */
uint32_t fido2_core_next_counter(void);

/* ---- helpers shared with the CTAP1 (U2F) path in mode_u2f.c ---- */
void     fido2_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
uint16_t fido2_sign_der(const uint8_t priv[32], const uint8_t digest[32], uint8_t *out, size_t out_max);
void     fido2_derive_priv(const uint8_t rp_id_hash[32], const uint8_t nonce[32], uint8_t priv[32]);
void     fido2_derive_mac(const uint8_t rp_id_hash[32], const uint8_t nonce[32], uint8_t mac[32]);

#ifdef __cplusplus
}
#endif

#endif /* FIDO2_CORE_H */
