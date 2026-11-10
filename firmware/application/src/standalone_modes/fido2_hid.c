/*
 * fido2_hid.c — USB CTAPHID transport for the FIDO2 standalone mode.
 *
 * CTAPHID framing (FIDO CTAP 2.1 §12): 64-byte packets.
 *   init packet  : CID(4) | CMD(1) | BCNTH(1) | BCNTL(1) | DATA(57)
 *   continuation : CID(4) | SEQ(1)  | DATA(59)
 * The first byte of an answer is the CTAP status byte for CBOR.
 *
 * The protocol state machine lives here; the USB stack only hands over
 * finished 64-byte OUT reports and takes finished IN reports. All sending
 * happens from the main-loop poll, never from the USB interrupt.
 */
#include <stdint.h>
#include <string.h>

#include "fido2_hid.h"
#include "fido2_core.h"

#ifndef APP_FW_VER_MAJOR
#define APP_FW_VER_MAJOR 1
#endif
#ifndef APP_FW_VER_MINOR
#define APP_FW_VER_MINOR 0
#endif

/* ---- module state ---- */
static uint32_t m_cid;                  /* allocated channel id (0 = none) */
static uint32_t m_next_cid = 1;

/* Request assembly and response payload use separate buffers so a new OUT
 * report cannot overwrite a response that is still being sent. */
static uint8_t  m_req_buf[1024];
static uint8_t  m_resp_buf[1024];
static uint8_t  m_cmd;
static uint16_t m_expect;               /* announced payload length */
static uint16_t m_got;                   /* bytes received so far */
static uint8_t  m_seq;                   /* next expected continuation seq */
static volatile bool m_assembling;

/* answer */
static volatile bool m_resp_ready;       /* a packet has to be built */
static volatile bool m_resp_active;      /* the answer is being sent */
static volatile bool m_resp_last;        /* the packet just built was the last */
static uint16_t m_resp_len;
static uint16_t m_resp_off;
static uint8_t  m_resp_cmd;
static uint8_t  m_resp_seq;
static bool     m_resp_first;
static uint32_t m_resp_cid;
static bool     m_up_keepalive_sent;

/* IN endpoint ping-pong */
static uint8_t  m_in[2][FIDO2_HID_PKT_SIZE];
static uint8_t  m_in_idx;
static volatile bool m_in_busy;         /* a packet is in flight */

/* deferred "busy" answer */
static volatile bool m_defer_busy;
static uint32_t m_defer_cid;

static fido2_hid_send_fn m_sender;

/* ===================================================================== */
static bool hid_armed(void)
{
    return (fido2_core_transport_mask() & FIDO2_TRANSPORT_USB) != 0;
}

void fido2_hid_init(void)
{
    m_cid = 0;
    m_next_cid = 1;
    m_assembling = false;
    m_resp_ready = false;
    m_resp_active = false;
    m_resp_last = false;
    m_in_busy = false;
    m_defer_busy = false;
    m_expect = 0;
    m_got = 0;
    m_resp_len = 0;
    m_resp_off = 0;
    m_up_keepalive_sent = false;
}

void fido2_hid_set_sender(fido2_hid_send_fn fn)
{
    m_sender = fn;
}

/* Build the next answer packet into the free IN buffer. */
static void hid_build_packet(void)
{
    uint8_t *pkt = m_in[m_in_idx ^ 1];
    memset(pkt, 0, FIDO2_HID_PKT_SIZE);

    pkt[0] = (uint8_t)(m_resp_cid >> 24);
    pkt[1] = (uint8_t)(m_resp_cid >> 16);
    pkt[2] = (uint8_t)(m_resp_cid >> 8);
    pkt[3] = (uint8_t)(m_resp_cid);

    uint16_t remaining = (uint16_t)(m_resp_len - m_resp_off);
    if (m_resp_first) {
        uint16_t n = (remaining > FIDO2_HID_INIT_DATA) ? FIDO2_HID_INIT_DATA : remaining;
        pkt[4] = m_resp_cmd;
        pkt[5] = (uint8_t)(m_resp_len >> 8);
        pkt[6] = (uint8_t)(m_resp_len & 0xFF);
        if (n) memcpy(pkt + 7, m_resp_buf, n);
        m_resp_off = n;
        m_resp_first = false;
    } else {
        uint16_t n = (remaining > FIDO2_HID_CONT_DATA) ? FIDO2_HID_CONT_DATA : remaining;
        pkt[4] = m_resp_seq;
        if (n) memcpy(pkt + 5, m_resp_buf + m_resp_off, n);
        m_resp_off = (uint16_t)(m_resp_off + n);
        m_resp_seq = (uint8_t)((m_resp_seq + 1) & 0x7F);
    }
    m_resp_last = (m_resp_off >= m_resp_len);
}

/* Hand the next packet to the USB stack (if it is up). */
static void hid_try_send(void)
{
    if (!m_resp_ready || m_in_busy || !m_sender) return;

    hid_build_packet();
    m_in_idx ^= 1;
    if (!m_sender(m_in[m_in_idx], FIDO2_HID_PKT_SIZE)) {
        m_in_idx ^= 1;                    /* keep the buffer, retry later */
        return;
    }
    m_in_busy = true;
    m_resp_ready = false;
    m_resp_active = true;
}

/* Queue an answer (payload copied into m_resp_buf). */
static void hid_queue_response(uint32_t cid, uint8_t cmd, const uint8_t *payload, uint16_t len)
{
    if (m_resp_ready || m_resp_active) {
        /* One answer at a time — the peer gets a busy error instead. */
        m_defer_busy = true;
        m_defer_cid = cid;
        return;
    }
    if (len > sizeof(m_resp_buf)) len = sizeof(m_resp_buf);
    if (len && payload) memcpy(m_resp_buf, payload, len);
    m_resp_cmd = cmd;
    m_resp_len = len;
    m_resp_off = 0;
    m_resp_seq = 0;
    m_resp_first = true;
    m_resp_cid = cid;
    m_resp_ready = true;
}

static void hid_queue_error(uint32_t cid, uint8_t err)
{
    uint8_t e = err;
    if (m_resp_ready || m_resp_active) {
        m_defer_busy = true;
        m_defer_cid = cid;
        return;
    }
    hid_queue_response(cid, FIDO2_HID_CMD_ERROR, &e, 1);
}

void fido2_hid_on_in_report_done(void)
{
    m_in_busy = false;
    if (m_resp_active && m_resp_last) {
        /* the answer is complete */
        m_resp_active = false;
        m_resp_last = false;
        if (m_defer_busy) {
            m_defer_busy = false;
            uint8_t e = FIDO2_HID_ERR_BUSY;
            hid_queue_response(m_defer_cid, FIDO2_HID_CMD_ERROR, &e, 1);
        }
    } else if (m_resp_active) {
        m_resp_ready = true;              /* more packets to send */
    }
}

/* ===================================================================== */
/*  command handling                                                      */
/* ===================================================================== */
static void hid_handle_init(uint32_t request_cid, const uint8_t *nonce, uint16_t len)
{
    if (len != 8) {
        hid_queue_error(request_cid, FIDO2_HID_ERR_INVALID_LEN);
        return;
    }

    uint32_t response_cid;
    uint32_t channel_cid;
    if (request_cid == FIDO2_HID_CID_BROADCAST) {
        m_cid = m_next_cid++;
        if (m_cid == 0 || m_cid == FIDO2_HID_CID_BROADCAST) m_cid = 1;
        channel_cid = m_cid;
        response_cid = FIDO2_HID_CID_BROADCAST;
    } else {
        channel_cid = request_cid;
        response_cid = request_cid;
    }

    /* CTAPHID INIT payload: nonce(8) | cid(4) | protocol(1) |
     * major(1) | minor(1) | build(1) | capabilities(1). */
    uint8_t ans[17];
    memcpy(ans, nonce, 8);
    ans[8]  = (uint8_t)(channel_cid >> 24);
    ans[9]  = (uint8_t)(channel_cid >> 16);
    ans[10] = (uint8_t)(channel_cid >> 8);
    ans[11] = (uint8_t)(channel_cid);
    ans[12] = (uint8_t)FIDO2_HID_PROTOVER;
    ans[13] = (uint8_t)APP_FW_VER_MAJOR;
    ans[14] = (uint8_t)APP_FW_VER_MINOR;
    ans[15] = 0x00;                      /* build number */
    ans[16] = (uint8_t)FIDO2_HID_CAPS;
    hid_queue_response(response_cid, FIDO2_HID_CMD_INIT, ans, sizeof(ans));
}

static void hid_handle_command(uint8_t cmd, const uint8_t *payload, uint16_t len)
{
    switch (cmd) {
        case FIDO2_HID_CMD_PING:
            hid_queue_response(m_cid, FIDO2_HID_CMD_PING, payload, len);
            break;

        case FIDO2_HID_CMD_CBOR:
            /* payload = CTAP command byte + CBOR */
            if (!len) { hid_queue_error(m_cid, FIDO2_HID_ERR_INVALID_LEN); return; }
            if (!fido2_submit(FIDO2_OWNER_USB, payload, len)) {
                hid_queue_error(m_cid, FIDO2_HID_ERR_BUSY);
                return;
            }
            m_up_keepalive_sent = false;
            break;

        case FIDO2_HID_CMD_INIT:
            hid_handle_init(m_cid, payload, len);
            break;

        case FIDO2_HID_CMD_CANCEL:
            /* The eventual CTAP answer carries CTAP2_ERR_KEEPALIVE_CANCEL. */
            fido2_cancel(FIDO2_OWNER_USB);
            break;

        default:
            hid_queue_error(m_cid, FIDO2_HID_ERR_INVALID_CMD);
            break;
    }
}

/* ===================================================================== */
/*  packet handling                                                       */
/* ===================================================================== */
void fido2_hid_on_out_report(const uint8_t *pkt, size_t len)
{
    if (!pkt || len < FIDO2_HID_PKT_SIZE) return;
    if (!hid_armed()) return;

    uint32_t cid = ((uint32_t)pkt[0] << 24) | ((uint32_t)pkt[1] << 16) |
                   ((uint32_t)pkt[2] << 8) | (uint32_t)pkt[3];

    if (m_assembling) {
        /* continuation packet */
        if (cid != m_cid) {
            m_assembling = false;
            hid_queue_error(cid, FIDO2_HID_ERR_INVALID_CHANNEL);
            return;
        }
        uint8_t seq = pkt[4];
        if (seq != m_seq) {
            m_assembling = false;
            hid_queue_error(cid, FIDO2_HID_ERR_INVALID_SEQ);
            return;
        }
        uint16_t space = (uint16_t)(m_expect - m_got);
        uint16_t n = FIDO2_HID_CONT_DATA;
        if (n > space) n = space;
        memcpy(m_req_buf + m_got, pkt + 5, n);
        m_got = (uint16_t)(m_got + n);
        m_seq = (uint8_t)((m_seq + 1) & 0x7F);
        if (m_got >= m_expect) {
            m_assembling = false;
            hid_handle_command(m_cmd, m_req_buf, m_expect);
        }
        return;
    }

    /* init packet */
    uint8_t cmd = pkt[4];
    uint16_t bcnt = (uint16_t)((pkt[5] << 8) | pkt[6]);

    if (cid == FIDO2_HID_CID_BROADCAST) {
        if (cmd != FIDO2_HID_CMD_INIT) {
            hid_queue_error(cid, FIDO2_HID_ERR_INVALID_CHANNEL);
            return;
        }
    } else if (cid != m_cid || m_cid == 0) {
        hid_queue_error(cid, FIDO2_HID_ERR_INVALID_CHANNEL);
        return;
    }

    switch (cmd) {
        case FIDO2_HID_CMD_PING:
        case FIDO2_HID_CMD_CBOR:
        case FIDO2_HID_CMD_INIT:
        case FIDO2_HID_CMD_CANCEL:
            break;
        default:
            hid_queue_error(cid, FIDO2_HID_ERR_INVALID_CMD);
            return;
    }

    if (bcnt > sizeof(m_req_buf)) {
        hid_queue_error(cid, FIDO2_HID_ERR_INVALID_LEN);
        return;
    }

    m_cmd = cmd;
    m_expect = bcnt;
    m_got = 0;
    m_seq = 0;

    uint16_t n = FIDO2_HID_INIT_DATA;
    if (n > bcnt) n = bcnt;
    memcpy(m_req_buf, pkt + 7, n);
    m_got = n;

    if (m_got >= m_expect) {
        m_assembling = false;
        if (cmd == FIDO2_HID_CMD_INIT) {
            hid_handle_init(cid, m_req_buf, m_expect);
        } else {
            hid_handle_command(cmd, m_req_buf, m_expect);
        }
    } else {
        m_assembling = true;
    }
}

/* ===================================================================== */
void fido2_hid_poll(void)
{
    if (!hid_armed()) return;

    /* Tell the client that a physical user-presence gesture is required. */
    if (!m_resp_ready && !m_resp_active && !m_assembling &&
        !m_up_keepalive_sent && fido2_waiting_for_presence(FIDO2_OWNER_USB)) {
        uint8_t status = FIDO2_HID_KEEPALIVE_UPNEEDED;
        hid_queue_response(m_cid, FIDO2_HID_CMD_KEEPALIVE, &status, 1);
        m_up_keepalive_sent = true;
    }

    /* A finished CTAP2 answer? */
    if (!m_resp_ready && !m_resp_active && !m_assembling &&
        fido2_response_ready(FIDO2_OWNER_USB)) {
        size_t len = 0;
        if (fido2_take_response(FIDO2_OWNER_USB, m_resp_buf, sizeof(m_resp_buf), &len)) {
            m_up_keepalive_sent = false;    /* the next request needs a fresh KEEPALIVE */
            m_resp_cmd = FIDO2_HID_CMD_CBOR;
            m_resp_len = (uint16_t)len;
            m_resp_off = 0;
            m_resp_seq = 0;
            m_resp_first = true;
            m_resp_cid = m_cid;
            m_resp_ready = true;
        }
    }

    hid_try_send();
}
