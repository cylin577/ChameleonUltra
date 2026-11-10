/*
 * fido2_ble.h — BLE FIDO GATT transport (FIDO 2.1) for the FIDO2 standalone mode.
 *
 * Service 0xFFFD:
 *   F1D0FFF1-... Control Point             Write / Write Without Response
 *   F1D0FFF2-... Status                    Notify (+ CCCD)
 *   F1D0FFF3-... Control Point Length      Read (2 bytes)
 *   F1D0FFF4-... Service Revision Bitfield Read / Write
 *   2A28        Service Revision           Read
 */
#ifndef FIDO2_BLE_H
#define FIDO2_BLE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Device data commands (the high bit marks a command byte). */
#define FIDO_BLE_CMD_PING       0x81
#define FIDO_BLE_CMD_KEEPALIVE  0x82
#define FIDO_BLE_CMD_MSG        0x83
#define FIDO_BLE_CMD_CANCEL     0xbe
#define FIDO_BLE_CMD_ERROR      0xbf

/* Error codes (same values as the CTAPHID ones). */
#define FIDO_BLE_ERR_INVALID_CMD 0x01
#define FIDO_BLE_ERR_INVALID_PAR 0x02
#define FIDO_BLE_ERR_INVALID_LEN 0x03
#define FIDO_BLE_ERR_INVALID_SEQ 0x04
#define FIDO_BLE_ERR_BUSY        0x06
#define FIDO_BLE_ERR_OTHER       0x7F

/* KEEPALIVE status byte. */
#define FIDO_BLE_KEEPALIVE_PROCESSING 0x01
#define FIDO_BLE_KEEPALIVE_UPNEEDED   0x02

/* FIDO characteristic UUID base, in Nordic's little-endian byte order. */
#define FIDO_BLE_BASE_UUID_BYTES { \
    0xBB, 0x23, 0xD6, 0x7E, 0xBA, 0xC9, 0x2F, 0xB4, \
    0xEE, 0xEC, 0xAA, 0xDE, 0x00, 0x00, 0xD0, 0xF1 \
}

/* UTF-8 Service Revision value ("1.0"), without a trailing NUL. */
#define FIDO_BLE_SERVICE_REVISION_BYTES { 0x31, 0x2E, 0x30 }

/* Max control point message (also the advertised control point length). */
#define FIDO_BLE_MAX_MESSAGE   512
#define FIDO_BLE_MIN_MTU       23

/* Register the FIDO GATT service (call once, at BLE service init). */
uint32_t ble_fido_svc_init(void);

/* Reset the transport state (called when the u2f mode is armed). */
void fido2_ble_reset(void);

/* Main-loop pump: sends the finished CTAP2 answer. */
void fido2_ble_poll(void);

#ifdef __cplusplus
}
#endif

#endif /* FIDO2_BLE_H */
