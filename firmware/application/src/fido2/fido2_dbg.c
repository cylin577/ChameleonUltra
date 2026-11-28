/*
 * fido2_dbg.c
 *
 * Host-facing debug commands for the FIDO2 standalone authenticator.
 * Bound to DATA_CMD_FIDO2_* (7020-7025) in app_cmd.c.
 *
 * Lets the host grant UP/UV, inject CTAP2/U2F requests, dump/reset credentials
 * and read live status without physically touching the device.
 * Wire formats are little-endian (matches existing CU commands).
 */

#include "fido2/fido2_dbg.h"

#if CONFIG_STANDALONE_FIDO2

#include "app_standalone.h"
#include "app_status.h"
#include "data_cmd.h"
#include "dataframe.h"
#include "fido2/fido2_core.h"
#include "fido2/fido2_creds.h"
#include "fido2/fido2_types.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define FIDO2_DBG_MODE_ID STANDALONE_MODE_FIDO2

#define FIDO2_DBG_RESP_MAX 2048

/* Shared by the CTAP, creds-list and U2F handlers. They run one at a time in
 * the main loop, and data_frame_make() copies the payload before returning. */
static uint8_t s_resp[FIDO2_DBG_RESP_MAX];

/* Same armed test as the framework's own mode_is_armed(): selected mode must
 * be FIDO2 and the subsystem must be out of DISARMED. No new gate. */
static bool f2_dbg_armed(void) {
    return app_standalone_get_state() != STANDALONE_STATE_DISARMED &&
           app_standalone_get_mode() == FIDO2_DBG_MODE_ID;
}

static data_frame_tx_t *f2_dbg_not_armed(uint16_t cmd) {
    return data_frame_make(cmd, STATUS_DEVICE_MODE_ERROR, 0, NULL);
}

/* 7020 FIDO2_GRANT
 * Request:  { u8 gate }   1 = UP, 2 = UV
 * Response: empty
 */
data_frame_tx_t *cmd_handler_fido2_grant(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data) {
    (void)status;
    if (!f2_dbg_armed()) return f2_dbg_not_armed(cmd);
    if (length != 1 || data == NULL ||
            (data[0] != FIDO2_GATE_UP && data[0] != FIDO2_GATE_UV)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    (void)f2_core_grant((fido2_gate_t)data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

/* 7021 FIDO2_CTAP
 * Request:  { u8 transport, u8 uv, u8[] payload }
 * Response: { u8 ctap_status, u8[] payload }
 */
data_frame_tx_t *cmd_handler_fido2_ctap(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data) {
    (void)status;
    if (!f2_dbg_armed()) return f2_dbg_not_armed(cmd);
    if (length < 2 || data == NULL || data[0] > FIDO2_TRANSPORT_DBG) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    fido2_request_t req = {0};
    req.transport = (fido2_transport_t)data[0];
    req.uv_requested = (data[1] != 0);

    /* f2_core_dispatch() already emits { ctap_status, CBOR... } into resp. */
    size_t out_len = 0;
    (void)f2_core_dispatch(data + 2, length - 2, &req,
                           s_resp, sizeof(s_resp), &out_len);
    if (out_len > FIDO2_DBG_RESP_MAX) out_len = FIDO2_DBG_RESP_MAX;
    return data_frame_make(cmd, STATUS_SUCCESS, out_len, s_resp);
}

/* 7022 FIDO2_CREDS_LIST
 * Request:  empty
 * Response: f2_creds_list() text (NUL-terminated, length excludes the NUL)
 */
data_frame_tx_t *cmd_handler_fido2_creds_list(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data) {
    (void)status;
    (void)length;
    (void)data;
    if (!f2_dbg_armed()) return f2_dbg_not_armed(cmd);
    size_t n = f2_creds_list(s_resp, sizeof(s_resp));
    return data_frame_make(cmd, STATUS_SUCCESS, n, s_resp);
}

/* 7023 FIDO2_CREDS_RESET
 * Request:  empty
 * Response: empty. Allowed while DISARMED so the host can clean up between
 * test runs without having to arm the mode first.
 */
data_frame_tx_t *cmd_handler_fido2_creds_reset(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data) {
    (void)status;
    (void)length;
    (void)data;
    f2_core_cancel();
    f2_creds_reset();
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

/* 7024 FIDO2_STATUS
 * Request:  empty
 * Response: f2_core_status() text
 */
data_frame_tx_t *cmd_handler_fido2_status(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data) {
    (void)status;
    (void)length;
    (void)data;
    if (!f2_dbg_armed()) return f2_dbg_not_armed(cmd);
    /* f2_core_status() emits ~24 bytes ("gate=UV,uv=1,creds=1000\n"). */
    static char buf[256];
    size_t n = f2_core_status(buf, sizeof(buf));
    if (n > sizeof(buf)) n = sizeof(buf);
    return data_frame_make(cmd, STATUS_SUCCESS, n, (uint8_t *)buf);
}

/* 7025 FIDO2_U2F_APDU
 * Request:  raw APDU bytes
 * Response: raw U2F response including SW1|SW2
 */
data_frame_tx_t *cmd_handler_fido2_u2f_apdu(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data) {
    (void)status;
    if (!f2_dbg_armed()) return f2_dbg_not_armed(cmd);
    if (length == 0 || data == NULL) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    /* f2_core_dispatch() recognizes req[0] == 0x00 as a raw U2F APDU and
     * returns the raw response with SW1|SW2 already appended. */
    fido2_request_t req = {0};
    req.transport = FIDO2_TRANSPORT_DBG;
    req.uv_requested = false;

    size_t out_len = 0;
    (void)f2_core_dispatch(data, length, &req, s_resp, sizeof(s_resp), &out_len);
    if (out_len > FIDO2_DBG_RESP_MAX) out_len = FIDO2_DBG_RESP_MAX;
    /* Pending gate: no response yet; grant UP/UV with 7020 and resend. */
    return data_frame_make(cmd, STATUS_SUCCESS, out_len, s_resp);
}

#endif /* CONFIG_STANDALONE_FIDO2 */
