/* CTAP over BLE GATT. Non-fatal by design: sd_ble_gatts_* failures must not
 * call APP_ERROR_CHECK, because BLE/NUS/CLI share the same SoftDevice config
 * and an NRF_ERROR_NO_MEM here must never reset the device. */
#include "fido2_ble.h"

#include "fido2_core.h"
#include "fido2_format.h"
#include "fido2_transport.h"
#include "fido2_types.h"

#include <stddef.h>
#include <string.h>

#include "nrf.h"
#include "nordic_common.h"
#include "nrf_sdh_ble.h"
#include "ble_gap.h"
#include "ble_gatts.h"
#include "sdk_config.h"

#define NRF_LOG_MODULE_NAME f2_ble
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

#define F2_BLE_SVC_UUID       0xFFFDu
#define F2_BLE_CTRL_UUID      0xFFF1u
#define F2_BLE_STATUS_UUID    0xFFF2u
#define F2_BLE_LEN_UUID       0xFFF3u
#define F2_BLE_REV_UUID       0xFFF4u

/* 256-max values keep the FIDO GATT service inside the shared ATT table.
 * Longer CTAP messages use the framing below and are split into MTU-3 chunks. */
#define F2_BLE_CHAR_MAX_LEN   256u
#define F2_BLE_REASM_MAX      1024u
#define F2_BLE_FRAG_MAX       244u
#define F2_BLE_FRAME_MAX      (3u + F2_BLE_FRAG_MAX)
#define F2_BLE_TX_QUEUE_SIZE  4u
#define F2_BLE_POLL_BUDGET    4u

/* CTAP BLE opcodes */
#define F2_CMD_PING           0x81u
#define F2_CMD_KEEPALIVE      0x82u
#define F2_CMD_MSG            0x83u
#define F2_CMD_CANCEL         0xBEu
#define F2_CMD_ERROR          0xBFu
#define F2_CMD_U2F_APDU       0x00u

#define F2_ERR_INVALID_CMD    0x01u
#define F2_ERR_INVALID_LEN    0x03u

#define F2_SRC_RESPONSE       0u
#define F2_SRC_INLINE         1u

/* F1D0FFFD-DEAA-ECEE-B42F-C9BA7ED623BB, little endian (bytes 12/13 ignored) */
static const ble_uuid128_t m_base_uuid = { .uuid128 = {
    0xBB, 0x23, 0xD6, 0x7E, 0xBA, 0xC9, 0x2F, 0xB4,
    0xEE, 0xEC, 0xAA, 0xDE, 0x00, 0x00, 0xD0, 0xF1
}};

static bool      m_ble_ok;
static bool      m_armed;
static uint8_t   m_uuid_type;
static uint16_t  m_conn_handle = BLE_CONN_HANDLE_INVALID;
static uint16_t  m_svc_handle;
static uint16_t  m_ctrl_handle;
static uint16_t  m_status_handle;
static uint16_t  m_cccd_handle;
static uint16_t  m_att_mtu = BLE_GATT_ATT_MTU_DEFAULT;
static bool      m_notify_enabled;

static uint8_t   m_cp_len_value[2] = {0x01u, 0x00u};  /* 256 */
static uint8_t   m_rev_value = 0x20u;                  /* FIDO2 revision */

/* Request reassembly. Written only from the BLE observer, read only by
 * f2_ble_poll() through the m_dispatch_pending handoff. */
static uint8_t              m_req[F2_BLE_REASM_MAX];
static uint16_t             m_req_len;
static uint16_t             m_req_off;
static uint8_t              m_req_cmd;
static uint8_t              m_next_seq;
static bool                 m_reasm_active;
static volatile bool        m_dispatch_pending;
static bool                 m_core_pending;   /* core returned F2_CORE_PENDING */
static bool                 m_redispatch;     /* core emitted PROCESSING after grant */

/* Outbound notification queue. Jobs point either at m_dispatch_resp or at
 * their own inline byte (keepalive / error status), so no allocation is
 * needed and the BLE handler never blocks on a send. */
typedef struct {
    uint8_t         cmd;
    uint8_t         seq;
    uint8_t         src;
    uint16_t        len;
    uint16_t        off;
    const uint8_t  *data;
    uint8_t         inline_byte;
} f2_tx_job_t;

static f2_tx_job_t       m_txq[F2_BLE_TX_QUEUE_SIZE];
static volatile uint8_t  m_tx_head;
static volatile uint8_t  m_tx_tail;
static uint8_t           m_dispatch_resp[F2_BLE_REASM_MAX];
static bool              m_resp_queued;

static void f2_ble_evt_handler(ble_evt_t const *p_evt, void *p_ctx);
static void f2_ble_keepalive(uint8_t status);
static void f2_ble_core_send(const uint8_t *data, size_t len);

NRF_SDH_BLE_OBSERVER(m_f2_ble_observer, 3, f2_ble_evt_handler, NULL);


static void reset_reassembly(void)
{
    m_reasm_active = false;
    m_req_len = 0u;
    m_req_off = 0u;
    m_req_cmd = 0u;
    m_next_seq = 0u;
}

static void reset_all(void)
{
    reset_reassembly();
    m_dispatch_pending = false;
    m_core_pending = false;
    m_redispatch = false;
    m_tx_head = 0u;
    m_tx_tail = 0u;
    m_resp_queued = false;
    m_notify_enabled = false;
}

static void tx_push(uint8_t cmd, const uint8_t *data, uint16_t len,
                    uint8_t inline_byte, uint8_t src)
{
    uint8_t next = (uint8_t)((m_tx_tail + 1u) % F2_BLE_TX_QUEUE_SIZE);

    if (next == m_tx_head) {
        NRF_LOG_WARNING("f2_ble: notification queue full");
        return;
    }
    f2_tx_job_t *job = &m_txq[m_tx_tail];
    job->cmd = cmd;
    job->seq = 0u;
    job->src = src;
    job->len = len;
    job->off = 0u;
    job->inline_byte = inline_byte;
    job->data = (data != NULL) ? data : &job->inline_byte;
    m_tx_tail = next;
}

static void send_error(uint8_t code)
{
    tx_push(F2_CMD_ERROR, NULL, 1u, code, F2_SRC_INLINE);
}

/* CTAP statuses (including 0x2D CANCEL) are normal MSG replies, not
 * transport-level ERROR frames. */
static void send_status(uint8_t status)
{
    tx_push(F2_CMD_MSG, NULL, 1u, status, F2_SRC_INLINE);
}

/* Observer-side: only copies bytes and raises a flag; dispatch happens later. */
static void on_ctrl_write(const uint8_t *data, uint16_t len)
{
    if (data == NULL || len == 0u) return;

    /* CANCEL is the one command allowed to preempt a pending gate: a 30 s
     * UP/UV wait must stay abortable. Complete frame = init 0xBE, len 0x0000. */
    bool cancel_frame = (data[0] == F2_CMD_CANCEL) && (len >= 3u) &&
                        (data[1] == 0u) && (data[2] == 0u);

    if (!cancel_frame && (m_dispatch_pending || m_core_pending)) {
        NRF_LOG_WARNING("f2_ble: request dropped, transaction pending");
        return;
    }

    if ((data[0] & 0x80u) != 0u) {                       /* init frame */
        reset_reassembly();
        if (len < 3u) {
            send_error(F2_ERR_INVALID_LEN);
            return;
        }
        uint16_t total = (uint16_t)(((uint16_t)data[1] << 8) | data[2]);
        if (total > F2_BLE_REASM_MAX) {
            NRF_LOG_WARNING("f2_ble: request too long (%u)", (unsigned)total);
            send_error(F2_ERR_INVALID_LEN);
            return;
        }
        m_req_cmd = data[0];
        m_req_len = total;
        uint16_t chunk = (uint16_t)(len - 3u);
        if (chunk > total) chunk = total;
        if (chunk != 0u) memcpy(m_req, data + 3u, chunk);
        m_req_off = chunk;
        m_next_seq = 0u;
        m_reasm_active = (m_req_off < total);
        if (!m_reasm_active) m_dispatch_pending = true;
        return;
    }

    /* Continuation frame */
    if (!m_reasm_active) return;
    uint8_t seq = (uint8_t)(data[0] & 0x7Fu);
    if (seq != m_next_seq) {
        NRF_LOG_WARNING("f2_ble: bad seq %u, expected %u", (unsigned)seq,
                        (unsigned)m_next_seq);
        reset_reassembly();
        return;
    }
    uint16_t chunk = (uint16_t)(len - 1u);
    uint16_t remain = (uint16_t)(m_req_len - m_req_off);
    if (chunk > remain) chunk = remain;
    if (chunk != 0u) memcpy(m_req + m_req_off, data + 1u, chunk);
    m_req_off = (uint16_t)(m_req_off + chunk);
    m_next_seq = (uint8_t)((m_next_seq + 1u) & 0x7Fu);
    if (m_req_off >= m_req_len) {
        m_reasm_active = false;
        m_dispatch_pending = true;
    }
}

/* Poll-side: core dispatch and CBOR encoding stay out of the BLE callback. */
static void do_dispatch(void)
{
    uint8_t cmd = m_req_cmd;
    uint16_t len = m_req_len;

    if (cmd == F2_CMD_PING) {                     /* always answer PING */
        if (m_resp_queued) {
            NRF_LOG_WARNING("f2_ble: response buffer still queued");
            return;
        }
        memcpy(m_dispatch_resp, m_req, len);
        tx_push(F2_CMD_PING, m_dispatch_resp, len, 0u, F2_SRC_RESPONSE);
        m_resp_queued = true;
        return;
    }
    if (cmd == F2_CMD_CANCEL) {
        f2_core_cancel_request();
        m_core_pending = false;
        m_redispatch = false;
        return;
    }
    if (cmd == F2_CMD_KEEPALIVE) return;
    if (!m_armed) {
        NRF_LOG_DEBUG("f2_ble: CTAP ignored while disarmed");
        return;
    }
    if (cmd != F2_CMD_MSG && cmd != F2_CMD_U2F_APDU) {
        send_error(F2_ERR_INVALID_CMD);
        return;
    }
    if (m_resp_queued) {
        NRF_LOG_WARNING("f2_ble: response buffer still queued");
        return;
    }

    fido2_request_t ctx = {
        .transport = FIDO2_TRANSPORT_BLE,
        .uv_requested = false,
    };
    size_t resp_len = 0u;
    uint8_t status = f2_core_dispatch(m_req, len, &ctx,
                                      m_dispatch_resp, sizeof(m_dispatch_resp),
                                      &resp_len);
    if (status == F2_CORE_PENDING) {
        /* Gate wait: keep the exact request until the core signals the grant. */
        m_core_pending = true;
        return;
    }
    m_core_pending = false;
    m_redispatch = false;
    if (status == FIDO2_ST_OK && resp_len != 0u &&
        resp_len <= sizeof(m_dispatch_resp)) {
        tx_push(F2_CMD_MSG, m_dispatch_resp, (uint16_t)resp_len,
                0u, F2_SRC_RESPONSE);
        m_resp_queued = true;
    } else {
        send_status(status);
    }
}

static uint32_t tx_send_one(void)
{
    if (m_tx_head == m_tx_tail) return NRF_SUCCESS;
    if (m_conn_handle == BLE_CONN_HANDLE_INVALID || !m_notify_enabled) {
        return NRF_ERROR_INVALID_STATE;
    }

    f2_tx_job_t *job = &m_txq[m_tx_head];
    uint16_t chunk = (m_att_mtu > 3u) ? (uint16_t)(m_att_mtu - 3u)
                                      : (uint16_t)(BLE_GATT_ATT_MTU_DEFAULT - 3u);
    if (chunk > F2_BLE_FRAG_MAX) chunk = F2_BLE_FRAG_MAX;
    uint16_t remain = (uint16_t)(job->len - job->off);
    if (chunk > remain) chunk = remain;

    uint8_t frame[F2_BLE_FRAME_MAX];
    size_t n;
    if (job->off == 0u) {
        n = fmt_ble_init(frame, sizeof(frame), job->cmd, job->data, chunk);
    } else {
        n = fmt_ble_cont(frame, sizeof(frame), job->seq, job->data, chunk);
    }
    if (n == 0u) return NRF_ERROR_INVALID_LENGTH;

    uint16_t hvx_len = (uint16_t)n;
    ble_gatts_hvx_params_t hvx_params = {0};
    hvx_params.handle = m_status_handle;
    hvx_params.type = BLE_GATT_HVX_NOTIFICATION;
    hvx_params.p_data = frame;
    hvx_params.p_len = &hvx_len;

    uint32_t rc = sd_ble_gatts_hvx(m_conn_handle, &hvx_params);
    if (rc == NRF_SUCCESS) {
        if (job->off != 0u) job->seq = (uint8_t)((job->seq + 1u) & 0x7Fu);
        job->off = (uint16_t)(job->off + chunk);
        if (job->off >= job->len) {
            if (job->src == F2_SRC_RESPONSE) m_resp_queued = false;
            m_tx_head = (uint8_t)((m_tx_head + 1u) % F2_BLE_TX_QUEUE_SIZE);
        }
    }
    return rc;
}

static void f2_ble_evt_handler(ble_evt_t const *p_evt, void *p_ctx)
{
    UNUSED_PARAMETER(p_ctx);
    if (!m_ble_ok || p_evt == NULL) return;

    switch (p_evt->header.evt_id) {
        case BLE_GAP_EVT_CONNECTED:
            m_conn_handle = p_evt->evt.gap_evt.conn_handle;
            reset_all();
            break;

        case BLE_GAP_EVT_DISCONNECTED:
            if (m_conn_handle == p_evt->evt.gap_evt.conn_handle) reset_all();
            m_conn_handle = BLE_CONN_HANDLE_INVALID;
            break;

        case BLE_GATTS_EVT_WRITE: {
            ble_gatts_evt_write_t const *write = &p_evt->evt.gatts_evt.params.write;
            if (write->handle == m_cccd_handle && write->len >= 2u) {
                m_notify_enabled = (write->data[0] & 0x01u) != 0u;
            } else if (write->handle == m_ctrl_handle &&
                       (write->op == BLE_GATTS_OP_WRITE_REQ ||
                        write->op == BLE_GATTS_OP_WRITE_CMD)) {
                on_ctrl_write(write->data, write->len);
            }
            break;
        }

        case BLE_GATTS_EVT_EXCHANGE_MTU_REQUEST:
            /* nrf_ble_gatt (ble_main.c) owns the MTU reply; just learn the
             * effective value so fragments fit the negotiated link. */
            m_att_mtu = p_evt->evt.gatts_evt.params.exchange_mtu_request.client_rx_mtu;
            if (m_att_mtu < BLE_GATT_ATT_MTU_DEFAULT) m_att_mtu = BLE_GATT_ATT_MTU_DEFAULT;
            if (m_att_mtu > NRF_SDH_BLE_GATT_MAX_MTU_SIZE) m_att_mtu = NRF_SDH_BLE_GATT_MAX_MTU_SIZE;
            break;

        default:
            break;
    }
}

static void f2_ble_keepalive(uint8_t status)
{
    uint8_t ble_status;

    if (!m_ble_ok) return;
    /* Core uses 0x02=processing / 0x03=UP needed; BLE uses 0x01 / 0x02. */
    if (status == 0x02u) {
        ble_status = 0x01u;
        if (m_core_pending) m_redispatch = true;   /* gate granted */
    } else if (status == 0x03u) {
        ble_status = 0x02u;
    } else {
        ble_status = (status <= 2u) ? status : 2u; /* already BLE-encoded */
    }
    tx_push(F2_CMD_KEEPALIVE, NULL, 1u, ble_status, F2_SRC_INLINE);
}

/* The core uses this for a gate timeout: it passes a bare CTAP status byte. */
static void f2_ble_core_send(const uint8_t *data, size_t len)
{
    uint8_t status = (data != NULL && len != 0u) ? data[0]
                                                 : (uint8_t)FIDO2_ST_OTHER;
    m_core_pending = false;
    m_redispatch = false;
    if (m_ble_ok) send_status(status);
}

static const fido2_transport_api_t m_transport_api = {
    .id        = FIDO2_TRANSPORT_BLE,
    .send      = f2_ble_core_send,
    .keepalive = f2_ble_keepalive,
};

static bool add_char(uint16_t uuid, ble_gatts_char_md_t *p_md,
                     ble_gatts_attr_t *p_attr, ble_gatts_char_handles_t *p_handles)
{
    ble_uuid_t char_uuid = { .uuid = uuid, .type = m_uuid_type };
    uint32_t err;

    p_attr->p_uuid = &char_uuid;
    err = sd_ble_gatts_characteristic_add(m_svc_handle, p_md, p_attr, p_handles);
    if (err != NRF_SUCCESS) {
        NRF_LOG_WARNING("f2_ble: add characteristic 0x%04x failed: 0x%x",
                        (unsigned)uuid, (unsigned)err);
        return false;
    }
    return true;
}

bool f2_ble_init(void)
{
    uint32_t err;
    ble_uuid_t svc_uuid;
    ble_gatts_char_handles_t handles;

    if (m_ble_ok) return true;

    err = sd_ble_uuid_vs_add(&m_base_uuid, &m_uuid_type);
    if (err != NRF_SUCCESS) {
        NRF_LOG_WARNING("f2_ble: vs_add failed: 0x%x", (unsigned)err);
        return false;
    }

    svc_uuid.uuid = F2_BLE_SVC_UUID;
    svc_uuid.type = m_uuid_type;
    err = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY, &svc_uuid, &m_svc_handle);
    if (err != NRF_SUCCESS) {
        NRF_LOG_WARNING("f2_ble: service_add failed: 0x%x", (unsigned)err);
        return false;
    }

    /* FFF1 control point: write and write-without-response, variable 256 B */
    {
        ble_gatts_char_md_t md = {0};
        ble_gatts_attr_md_t attr_md = {0};
        ble_gatts_attr_t attr = {0};

        md.char_props.write = 1;
        md.char_props.write_wo_resp = 1;
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
        attr_md.vloc = BLE_GATTS_VLOC_STACK;
        attr.p_attr_md = &attr_md;
        attr.init_len = 0u;
        attr.max_len = F2_BLE_CHAR_MAX_LEN;
        attr.p_value = NULL;
        if (!add_char(F2_BLE_CTRL_UUID, &md, &attr, &handles)) return false;
        m_ctrl_handle = handles.value_handle;
    }

    /* FFF2 status: notify with CCCD, 256 B */
    {
        ble_gatts_char_md_t md = {0};
        ble_gatts_attr_md_t attr_md = {0};
        ble_gatts_attr_md_t cccd_md = {0};
        ble_gatts_attr_t attr = {0};

        md.char_props.notify = 1;
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.write_perm);
        cccd_md.vloc = BLE_GATTS_VLOC_STACK;
        md.p_cccd_md = &cccd_md;
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
        attr_md.vloc = BLE_GATTS_VLOC_STACK;
        attr.p_attr_md = &attr_md;
        attr.init_len = 0u;
        attr.max_len = F2_BLE_CHAR_MAX_LEN;
        attr.p_value = NULL;
        if (!add_char(F2_BLE_STATUS_UUID, &md, &attr, &handles)) return false;
        m_status_handle = handles.value_handle;
        m_cccd_handle = handles.cccd_handle;
    }

    /* FFF3 control point length: BE16 0x0100 (256) */
    {
        ble_gatts_char_md_t md = {0};
        ble_gatts_attr_md_t attr_md = {0};
        ble_gatts_attr_t attr = {0};

        md.char_props.read = 1;
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
        attr_md.vloc = BLE_GATTS_VLOC_STACK;
        attr.p_attr_md = &attr_md;
        attr.init_len = 2u;
        attr.max_len = 2u;
        attr.p_value = m_cp_len_value;
        if (!add_char(F2_BLE_LEN_UUID, &md, &attr, &handles)) return false;
    }

    /* FFF4 revision bitfield: 0x20 = FIDO2 */
    {
        ble_gatts_char_md_t md = {0};
        ble_gatts_attr_md_t attr_md = {0};
        ble_gatts_attr_t attr = {0};

        md.char_props.read = 1;
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
        attr_md.vloc = BLE_GATTS_VLOC_STACK;
        attr.p_attr_md = &attr_md;
        attr.init_len = 1u;
        attr.max_len = 1u;
        attr.p_value = &m_rev_value;
        if (!add_char(F2_BLE_REV_UUID, &md, &attr, &handles)) return false;
    }

    reset_all();
    m_ble_ok = true;
    f2_transport_register(&m_transport_api);
    NRF_LOG_INFO("f2_ble: GATT service ready");
    return true;
}

void f2_ble_set_armed(bool armed)
{
    m_armed = armed;
    if (!armed) {
        /* Clear only transaction state. reset_all() would also clear
         * m_notify_enabled and stall every notification until re-subscribe. */
        reset_reassembly();
        m_dispatch_pending = false;
        m_core_pending = false;
        m_redispatch = false;
        m_tx_head = 0u;
        m_tx_tail = 0u;
        m_resp_queued = false;
    }
}

void f2_ble_poll(void)
{
    uint8_t budget;

    if (!m_ble_ok) return;

    if (m_core_pending && m_redispatch) {
        m_redispatch = false;
        m_dispatch_pending = true;   /* re-send the held request to the core */
    }

    if (m_dispatch_pending) {
        /* Keep the flag up during dispatch: a write arriving from the BLE
         * interrupt must not overwrite the request being decoded. */
        do_dispatch();
        m_dispatch_pending = false;
    }

    for (budget = F2_BLE_POLL_BUDGET; budget != 0u && m_tx_head != m_tx_tail; budget--) {
        uint32_t rc = tx_send_one();
        if (rc == NRF_SUCCESS) continue;
        if (rc == NRF_ERROR_RESOURCES || rc == NRF_ERROR_BUSY ||
            rc == NRF_ERROR_INVALID_STATE) {
            break;                              /* retry on a later poll */
        }
        NRF_LOG_WARNING("f2_ble: notification failed: 0x%x", (unsigned)rc);
        if (m_txq[m_tx_head].src == F2_SRC_RESPONSE) m_resp_queued = false;
        m_tx_head = (uint8_t)((m_tx_head + 1u) % F2_BLE_TX_QUEUE_SIZE);
    }
}

bool f2_ble_available(void)
{
    return m_ble_ok;
}
