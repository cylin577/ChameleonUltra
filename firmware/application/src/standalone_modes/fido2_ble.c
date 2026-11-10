/*
 * fido2_ble.c — BLE FIDO GATT transport (FIDO 2.1 §12.3) for the FIDO2
 * standalone mode.
 *
 * Service 0xFFFD with:
 *   F1D0FFF1-... Control Point          Write / Write Without Response
 *   F1D0FFF2-... Status                 Notify (+ CCCD)
 *   F1D0FFF3-... Control Point Length   Read, 2 bytes (512)
 *   F1D0FFF4-... Service Revision Bitfield  Read / Write, 0x01
 *   2A28        Service Revision        Read, 0x01
 *
 * Device data framing:
 *   init fragment : CMD(1) | HLEN(1) | LLEN(1) | DATA...
 *   continuation  : SEQ(1)  | DATA...        (SEQ 0x00..0x7F, bit 7 clear)
 * The high bit of the first byte tells the two apart (0x80+ = command).
 *
 * Commands: PING 0x81, KEEPALIVE 0x82, MSG 0x83, CANCEL 0xbe, ERROR 0xbf.
 */
#include <stdint.h>
#include <string.h>

#include "fido2_ble.h"
#include "fido2_core.h"

#include "ble_srv_common.h"
#include "nrf_sdh.h"
#include "nrf_sdh_ble.h"
#include "nrf_ble_gatt.h"
#include "nrf_error.h"

#define NRF_LOG_MODULE_NAME fido2_ble
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

/* ---- UUIDs ---- */
#define FIDO_BLE_UUID_SERVICE           0xFFFD
#define FIDO_BLE_UUID_CONTROL_POINT     0xFFF1
#define FIDO_BLE_UUID_STATUS            0xFFF2
#define FIDO_BLE_UUID_CP_LENGTH         0xFFF3
#define FIDO_BLE_UUID_REV_BITFIELD      0xFFF4
#define FIDO_BLE_UUID_SERVICE_REVISION  0x2A28

/* Control point length (max message the peer may send). */
#define FIDO_BLE_CP_LENGTH              FIDO_BLE_MAX_MESSAGE
#define FIDO_BLE_MAX_FRAME_DATA         244

/* Service revision bitfield value. */
#define FIDO_BLE_REV_BITFIELD           0x01

/* FIDO vendor base: F1D00000-DEAA-ECEE-B42F-C9BA7ED623BB — the four
 * characteristics are the 16-bit numbers FFF1..FFF4 above. */
#define FIDO_BLE_BASE_UUID FIDO_BLE_BASE_UUID_BYTES

/* ---- module state ---- */
static uint16_t m_svc_handle;
static uint8_t  m_uuid_type;             /* vendor-specific UUID type */

static ble_gatts_char_handles_t m_ctrl_point_handles;
static ble_gatts_char_handles_t m_status_handles;
static ble_gatts_char_handles_t m_cp_length_handles;
static ble_gatts_char_handles_t m_rev_bitfield_handles;
static ble_gatts_char_handles_t m_service_rev_handles;

/* Request assembly and response payload use separate buffers. */
static uint8_t  m_req_buf[FIDO_BLE_MAX_MESSAGE];
static uint8_t  m_resp_buf[FIDO_BLE_MAX_MESSAGE];
static uint8_t  m_cmd;
static uint16_t m_expect;               /* announced payload length */
static uint16_t m_got;                   /* bytes received so far */
static uint8_t  m_seq;                   /* next expected continuation seq */
static bool     m_assembling;

/* response */
static bool     m_resp_ready;            /* payload queued */
static bool     m_resp_active;           /* fragments being sent */
static bool     m_resp_last;             /* the last fragment was queued */
static uint16_t m_resp_len;
static uint16_t m_resp_off;
static uint8_t  m_resp_cmd;
static uint8_t  m_resp_seq;

/* deferred error answer */
static bool     m_defer_err;
static uint8_t  m_defer_err_code;

static uint16_t m_conn_handle = BLE_CONN_HANDLE_INVALID;
static bool     m_notify_enabled = false;
static uint16_t m_mtu = FIDO_BLE_MIN_MTU;
static bool     m_up_keepalive_sent = false;

/* ===================================================================== */
/*  helpers                                                               */
/* ===================================================================== */
static bool fido_armed(void)
{
    return (fido2_core_transport_mask() & FIDO2_TRANSPORT_BLE) != 0;
}

static uint16_t fido_chunk_max(void)
{
    uint16_t n = (m_mtu > 3) ? (uint16_t)(m_mtu - 3) : 20;
    return n > FIDO_BLE_MAX_FRAME_DATA ? FIDO_BLE_MAX_FRAME_DATA : n;
}

/* Send one device-data frame (no fragmentation) on the Status characteristic. */
static bool ble_fido_send_frame(uint8_t cmd, const uint8_t *payload, uint16_t len)
{
    if (!m_notify_enabled || m_conn_handle == BLE_CONN_HANDLE_INVALID) return false;
    if (len > FIDO_BLE_MAX_FRAME_DATA) len = FIDO_BLE_MAX_FRAME_DATA;

    uint8_t  frame[3 + FIDO_BLE_MAX_FRAME_DATA];
    uint16_t flen = (uint16_t)(3 + len);
    frame[0] = cmd;
    frame[1] = (uint8_t)(len >> 8);
    frame[2] = (uint8_t)(len & 0xFF);
    if (len) memcpy(frame + 3, payload, len);

    ble_gatts_hvx_params_t hvx = {
        .handle = m_status_handles.value_handle,
        .p_data = frame,
        .p_len  = &flen,
        .type   = BLE_GATT_HVX_NOTIFICATION,
    };
    return sd_ble_gatts_hvx(m_conn_handle, &hvx) == NRF_SUCCESS;
}

/* Queue the CTAP2 answer (status byte + CBOR). */
static void ble_fido_start_response(uint8_t cmd, const uint8_t *payload, uint16_t len)
{
    if (len > sizeof(m_resp_buf)) len = sizeof(m_resp_buf);
    memcpy(m_resp_buf, payload, len);
    m_resp_cmd = cmd;
    m_resp_len = len;
    m_resp_off = 0;
    m_resp_seq = 0;
    m_resp_ready = true;
    m_resp_active = false;
    m_resp_last = false;
}

/* Send the next fragment of the pending answer. Returns false when the
 * fragment could not be handed to the stack (retry on the next poll). */
static bool ble_fido_send_next(void)
{
    if (!m_resp_ready && !m_resp_active) return true;

    uint16_t chunk_max = fido_chunk_max();
    uint8_t  frame[3 + FIDO_BLE_MAX_FRAME_DATA];
    uint16_t flen;
    uint16_t n;

    if (!m_resp_active) {
        /* init fragment: CMD | HLEN | LLEN | DATA */
        n = m_resp_len;
        if (n > chunk_max - 3) n = (uint16_t)(chunk_max - 3);
        frame[0] = m_resp_cmd;
        frame[1] = (uint8_t)(m_resp_len >> 8);
        frame[2] = (uint8_t)(m_resp_len & 0xFF);
        if (n) memcpy(frame + 3, m_resp_buf, n);
        flen = (uint16_t)(3 + n);
        m_resp_seq = 0;
    } else {
        n = (uint16_t)(m_resp_len - m_resp_off);
        if (n > chunk_max - 1) n = (uint16_t)(chunk_max - 1);
        frame[0] = (uint8_t)(m_resp_seq & 0x7F);
        if (n) memcpy(frame + 1, m_resp_buf + m_resp_off, n);
        flen = (uint16_t)(1 + n);
    }

    if (!m_notify_enabled || m_conn_handle == BLE_CONN_HANDLE_INVALID) {
        /* No subscriber: drop the answer instead of blocking the transport. */
        m_resp_ready = false;
        m_resp_active = false;
        m_resp_last = false;
        return true;
    }

    ble_gatts_hvx_params_t hvx = {
        .handle = m_status_handles.value_handle,
        .p_data = frame,
        .p_len  = &flen,
        .type   = BLE_GATT_HVX_NOTIFICATION,
    };
    if (sd_ble_gatts_hvx(m_conn_handle, &hvx) != NRF_SUCCESS) {
        return false;                   /* retry later */
    }

    if (!m_resp_active) {
        m_resp_off = n;
        m_resp_active = true;
    } else {
        m_resp_off = (uint16_t)(m_resp_off + n);
        m_resp_seq = (uint8_t)((m_resp_seq + 1) & 0x7F);
    }
    m_resp_last = (m_resp_off >= m_resp_len);
    return true;
}

/* Answer with a one-byte error payload (ERROR command). */
static void ble_fido_error(uint8_t err)
{
    if (m_resp_ready || m_resp_active) {
        m_defer_err = true;
        m_defer_err_code = err;
        return;
    }
    uint8_t e = err;
    ble_fido_start_response(FIDO_BLE_CMD_ERROR, &e, 1);
    ble_fido_send_next();
}

static void ble_fido_flush_deferred(void)
{
    if (m_defer_err && !m_resp_ready && !m_resp_active) {
        m_defer_err = false;
        uint8_t e = m_defer_err_code;
        ble_fido_start_response(FIDO_BLE_CMD_ERROR, &e, 1);
        ble_fido_send_next();
    }
}

/* ===================================================================== */
/*  command handling                                                      */
/* ===================================================================== */
static void ble_fido_handle_command(uint8_t cmd, const uint8_t *payload, uint16_t len)
{
    switch (cmd) {
        case FIDO_BLE_CMD_PING:
            ble_fido_start_response(FIDO_BLE_CMD_PING, payload, len);
            ble_fido_send_next();
            break;

        case FIDO_BLE_CMD_MSG: {
            /* payload = CTAP command byte + CBOR */
            if (!len) { ble_fido_error(FIDO_BLE_ERR_INVALID_LEN); return; }
            if (!fido2_submit(FIDO2_OWNER_BLE, payload, len)) {
                ble_fido_error(FIDO_BLE_ERR_BUSY);
                return;
            }
            m_up_keepalive_sent = false;
            /* one KEEPALIVE(PROCESSING) per accepted request */
            uint8_t ka = FIDO_BLE_KEEPALIVE_PROCESSING;
            ble_fido_send_frame(FIDO_BLE_CMD_KEEPALIVE, &ka, 1);
            break;
        }

        case FIDO_BLE_CMD_CANCEL:
            /* The eventual CTAP answer carries CTAP2_ERR_KEEPALIVE_CANCEL. */
            fido2_cancel(FIDO2_OWNER_BLE);
            break;

        default:
            ble_fido_error(FIDO_BLE_ERR_INVALID_CMD);
            break;
    }
}

/* Handle one received control-point fragment. */
static void ble_fido_rx(const uint8_t *data, uint16_t len)
{
    if (!len) return;
    if (!fido_armed()) {
        ble_fido_error(FIDO_BLE_ERR_OTHER);
        return;
    }
    if (m_resp_ready || m_resp_active) {
        /* An answer is still on its way — the core is busy anyway. */
        ble_fido_error(FIDO_BLE_ERR_BUSY);
        return;
    }

    uint8_t first = data[0];
    if (first & 0x80) {
        /* init fragment: CMD | HLEN | LLEN | DATA */
        if (len < 3) { ble_fido_error(FIDO_BLE_ERR_INVALID_LEN); return; }
        uint8_t  cmd   = first;          /* command byte, high bit always set */
        uint16_t total = (uint16_t)((data[1] << 8) | data[2]);
        if (total > sizeof(m_req_buf)) { ble_fido_error(FIDO_BLE_ERR_INVALID_LEN); return; }
        m_cmd = cmd;
        m_expect = total;
        uint16_t n = (uint16_t)(len - 3);
        if (n > total) n = total;
        if (n) memcpy(m_req_buf, data + 3, n);
        m_got = n;
        m_seq = 0;
        if (m_got >= m_expect) {
            m_assembling = false;
            ble_fido_handle_command(m_cmd, m_req_buf, m_expect);
        } else {
            m_assembling = true;
        }
    } else {
        /* continuation: SEQ | DATA */
        if (!m_assembling) { ble_fido_error(FIDO_BLE_ERR_INVALID_SEQ); return; }
        if (first != m_seq) {
            ble_fido_error(FIDO_BLE_ERR_INVALID_SEQ);
            m_assembling = false;
            return;
        }
        uint16_t space = (uint16_t)(m_expect - m_got);
        uint16_t n = (uint16_t)(len - 1);
        if (n > space) n = space;
        if (n) memcpy(m_req_buf + m_got, data + 1, n);
        m_got = (uint16_t)(m_got + n);
        m_seq = (uint8_t)((m_seq + 1) & 0x7F);
        if (m_got >= m_expect) {
            m_assembling = false;
            ble_fido_handle_command(m_cmd, m_req_buf, m_expect);
        }
    }
}

/* ===================================================================== */
/*  BLE events                                                            */
/* ===================================================================== */
static void ble_fido_on_ble_evt(ble_evt_t const *p_ble_evt, void *p_context)
{
    (void)p_context;

    switch (p_ble_evt->header.evt_id) {
        case BLE_GAP_EVT_CONNECTED:
            m_conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
            break;

        case BLE_GAP_EVT_DISCONNECTED:
            m_notify_enabled = false;
            m_conn_handle = BLE_CONN_HANDLE_INVALID;
            break;

        case BLE_GATTS_EVT_EXCHANGE_MTU_REQUEST: {
            /* The GATT module answers with the server MTU; the effective MTU
             * is the smaller of both sides. */
            uint16_t client_mtu =
                p_ble_evt->evt.gatts_evt.params.exchange_mtu_request.client_rx_mtu;
            m_mtu = (client_mtu < NRF_SDH_BLE_GATT_MAX_MTU_SIZE)
                        ? client_mtu
                        : (uint16_t)NRF_SDH_BLE_GATT_MAX_MTU_SIZE;
            if (m_mtu < FIDO_BLE_MIN_MTU) m_mtu = FIDO_BLE_MIN_MTU;
            break;
        }

        case BLE_GATTS_EVT_WRITE: {
            ble_gatts_evt_write_t const *p_write = &p_ble_evt->evt.gatts_evt.params.write;

            /* Subscription to the Status notifications happens through the
             * CCCD of that characteristic. */
            if (p_write->handle == m_status_handles.cccd_handle && p_write->len == 2) {
                m_notify_enabled = ble_srv_is_notification_enabled(p_write->data);
                break;
            }

            if (p_write->handle != m_ctrl_point_handles.value_handle) break;
            m_conn_handle = p_ble_evt->evt.gatts_evt.conn_handle;
            ble_fido_rx(p_write->data, p_write->len);
            break;
        }

        default:
            break;
    }
}

NRF_SDH_BLE_OBSERVER(m_fido_ble_observer, 3, ble_fido_on_ble_evt, NULL);

/* ===================================================================== */
/*  service setup                                                         */
/* ===================================================================== */
uint32_t ble_fido_svc_init(void)
{
    uint32_t err;
    ble_uuid_t uuid;
    ble_uuid128_t base_uuid = { .uuid128 = FIDO_BLE_BASE_UUID_BYTES };
    ble_add_char_params_t add_char_params;

    /* One vendor-specific UUID type covers FFF1..FFF4. */
    err = sd_ble_uuid_vs_add(&base_uuid, &m_uuid_type);
    if (err != NRF_SUCCESS) return err;

    /* primary service 0xFFFD */
    uuid.type = BLE_UUID_TYPE_BLE;
    uuid.uuid = FIDO_BLE_UUID_SERVICE;
    err = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY, &uuid, &m_svc_handle);
    if (err != NRF_SUCCESS) return err;

    /* Control Point: Write + Write Without Response */
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid              = FIDO_BLE_UUID_CONTROL_POINT;
    add_char_params.uuid_type         = m_uuid_type;
    add_char_params.max_len           = FIDO_BLE_CP_LENGTH;
    add_char_params.is_var_len        = true;
    add_char_params.char_props.write         = 1;
    add_char_params.char_props.write_wo_resp = 1;
    add_char_params.read_access       = SEC_OPEN;
    add_char_params.write_access      = SEC_OPEN;
    err = characteristic_add(m_svc_handle, &add_char_params, &m_ctrl_point_handles);
    if (err != NRF_SUCCESS) return err;

    /* Status: Notify */
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid              = FIDO_BLE_UUID_STATUS;
    add_char_params.uuid_type         = m_uuid_type;
    add_char_params.max_len           = FIDO_BLE_CP_LENGTH;
    add_char_params.is_var_len        = true;
    add_char_params.char_props.notify = 1;
    add_char_params.read_access       = SEC_OPEN;
    add_char_params.write_access      = SEC_OPEN;
    add_char_params.cccd_write_access = SEC_OPEN;
    err = characteristic_add(m_svc_handle, &add_char_params, &m_status_handles);
    if (err != NRF_SUCCESS) return err;

    /* Control Point Length: Read, 2 bytes = 512 */
    static uint8_t cp_len_value[2] = {
        (uint8_t)(FIDO_BLE_CP_LENGTH >> 8), (uint8_t)(FIDO_BLE_CP_LENGTH & 0xFF)
    };
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid         = FIDO_BLE_UUID_CP_LENGTH;
    add_char_params.uuid_type    = m_uuid_type;
    add_char_params.max_len      = sizeof(cp_len_value);
    add_char_params.init_len     = sizeof(cp_len_value);
    add_char_params.p_init_value = cp_len_value;
    add_char_params.char_props.read  = 1;
    add_char_params.read_access  = SEC_OPEN;
    add_char_params.write_access = SEC_OPEN;
    err = characteristic_add(m_svc_handle, &add_char_params, &m_cp_length_handles);
    if (err != NRF_SUCCESS) return err;

    /* Service Revision Bitfield: Read / Write, 0x01 */
    static uint8_t rev_bitfield_value = FIDO_BLE_REV_BITFIELD;
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid         = FIDO_BLE_UUID_REV_BITFIELD;
    add_char_params.uuid_type    = m_uuid_type;
    add_char_params.max_len      = 1;
    add_char_params.init_len     = 1;
    add_char_params.p_init_value = &rev_bitfield_value;
    add_char_params.char_props.read  = 1;
    add_char_params.char_props.write = 1;
    add_char_params.read_access  = SEC_OPEN;
    add_char_params.write_access = SEC_OPEN;
    err = characteristic_add(m_svc_handle, &add_char_params, &m_rev_bitfield_handles);
    if (err != NRF_SUCCESS) return err;

    /* Service Revision (0x2A28): Read, UTF-8 "1.0" */
    static uint8_t service_rev_value[] = FIDO_BLE_SERVICE_REVISION_BYTES;
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid         = FIDO_BLE_UUID_SERVICE_REVISION;
    add_char_params.uuid_type    = BLE_UUID_TYPE_BLE;
    add_char_params.max_len      = sizeof(service_rev_value);
    add_char_params.init_len     = sizeof(service_rev_value);
    add_char_params.p_init_value = service_rev_value;
    add_char_params.char_props.read = 1;
    add_char_params.read_access  = SEC_OPEN;
    add_char_params.write_access = SEC_OPEN;
    err = characteristic_add(m_svc_handle, &add_char_params, &m_service_rev_handles);
    if (err != NRF_SUCCESS) return err;

    NRF_LOG_INFO("fido2 ble service ready");
    return NRF_SUCCESS;
}

void fido2_ble_reset(void)
{
    m_assembling = false;
    m_resp_ready = false;
    m_resp_active = false;
    m_resp_last = false;
    m_defer_err = false;
    m_up_keepalive_sent = false;
    m_got = 0;
    m_expect = 0;
}

void fido2_ble_poll(void)
{
    if (!fido_armed()) return;

    /* Tell the client that a physical user-presence gesture is required. */
    if (!m_resp_ready && !m_resp_active && !m_assembling &&
        !m_up_keepalive_sent && fido2_waiting_for_presence(FIDO2_OWNER_BLE)) {
        uint8_t ka = FIDO_BLE_KEEPALIVE_UPNEEDED;
        if (ble_fido_send_frame(FIDO_BLE_CMD_KEEPALIVE, &ka, 1)) {
            m_up_keepalive_sent = true;
        }
    }

    /* A finished CTAP2 answer? */
    if (!m_resp_ready && !m_resp_active && !m_assembling &&
        fido2_response_ready(FIDO2_OWNER_BLE)) {
        size_t len = 0;
        if (fido2_take_response(FIDO2_OWNER_BLE, m_resp_buf, sizeof(m_resp_buf), &len)) {
            m_resp_cmd = FIDO_BLE_CMD_MSG;
            m_resp_len = (uint16_t)len;
            m_resp_off = 0;
            m_resp_seq = 0;
            m_resp_ready = true;
            m_resp_active = false;
            m_resp_last = false;
            m_up_keepalive_sent = false;    /* the next request needs a fresh KEEPALIVE */
        }
    }

    if (m_resp_ready || m_resp_active) {
        if (ble_fido_send_next() && m_resp_last) {
            /* the last fragment went out — the transport is free again */
            m_resp_ready = false;
            m_resp_active = false;
            m_resp_last = false;
        }
    }

    if (!m_resp_ready && !m_resp_active) {
        ble_fido_flush_deferred();
    }
}
