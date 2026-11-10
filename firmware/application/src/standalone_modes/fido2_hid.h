/*
 * fido2_hid.h — USB CTAPHID transport for the FIDO2 standalone mode.
 *
 * CTAPHID framing (FIDO CTAP 2.1, §12):
 *   init packet   : CID(4) | CMD(1, high bit set) | BCNTH(1) | BCNTL(1) | DATA(57)
 *   continuation  : CID(4) | SEQ(1)  | DATA(59)
 * All packets are 64 bytes.
 */
#ifndef FIDO2_HID_H
#define FIDO2_HID_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FIDO2_HID_PKT_SIZE      64
#define FIDO2_HID_INIT_DATA     57
#define FIDO2_HID_CONT_DATA     59

/* CTAPHID commands. The high bit is always set on the wire. */
#define FIDO2_HID_CMD_PING      0x81
#define FIDO2_HID_CMD_CBOR      0x90   /* CTAP2 command: status byte + CBOR */
#define FIDO2_HID_CMD_INIT      0x86
#define FIDO2_HID_CMD_CANCEL    0x91
#define FIDO2_HID_CMD_ERROR     0xBF
#define FIDO2_HID_CMD_KEEPALIVE 0xBB

/* CTAPHID error codes */
#define FIDO2_HID_ERR_INVALID_CMD 0x01
#define FIDO2_HID_ERR_INVALID_PAR 0x02
#define FIDO2_HID_ERR_INVALID_LEN 0x03
#define FIDO2_HID_ERR_INVALID_SEQ 0x04
#define FIDO2_HID_ERR_BUSY        0x06
#define FIDO2_HID_ERR_INVALID_CHANNEL 0x0B
#define FIDO2_HID_ERR_OTHER       0x7F

/* KEEPALIVE status byte. */
#define FIDO2_HID_KEEPALIVE_PROCESSING 0x01
#define FIDO2_HID_KEEPALIVE_UPNEEDED   0x02

/* Broadcast channel id: only CTAPHID_INIT may use it. */
#define FIDO2_HID_CID_BROADCAST  0xFFFFFFFFu

/* Protocol version / capabilities reported in the INIT answer. */
#define FIDO2_HID_PROTOVER       0x02
#define FIDO2_HID_CAP_CBOR       0x04
#define FIDO2_HID_CAP_NMSG       0x08
#define FIDO2_HID_CAPS           (FIDO2_HID_CAP_CBOR | FIDO2_HID_CAP_NMSG)

/* Sender: hands a finished 64-byte IN packet to the USB stack. Returning
 * false means the packet could not be queued (USB not up) — it is retried. */
typedef bool (*fido2_hid_send_fn)(const uint8_t *pkt, size_t len);

/* Reset the protocol state (channel id, pending transfers). */
void fido2_hid_init(void);

/* Register the USB sink. */
void fido2_hid_set_sender(fido2_hid_send_fn fn);

/* Main-loop pump: picks up a finished CTAP2 answer and pushes IN packets. */
void fido2_hid_poll(void);

/* Called by the USB stack with a received 64-byte OUT report. */
void fido2_hid_on_out_report(const uint8_t *pkt, size_t len);

/* Called by the USB stack when an IN report has been transferred. */
void fido2_hid_on_in_report_done(void);

#ifdef __cplusplus
}
#endif

#endif /* FIDO2_HID_H */
