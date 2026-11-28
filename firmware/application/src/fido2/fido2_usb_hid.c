/* CTAPHID transport on the Nordic generic HID class.
 *
 * The HID class shares USBD with the CLI CDC class. CDC keeps interfaces 0/1;
 * this instance uses interface 2 and EPIN3/EPOUT3.
 */
#include "fido2/fido2_usb_hid.h"

#include <string.h>

#include "app_util_platform.h"
#include "app_usbd.h"
#include "app_usbd_hid.h"
#include "app_usbd_hid_generic.h"
#include "nrf_drv_rng.h"

#include "fido2/fido2_core.h"
#include "fido2/fido2_format.h"
#include "fido2/fido2_transport.h"
#include "fido2/fido2_types.h"

#define NRF_LOG_MODULE_NAME fido2_usb_hid
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
NRF_LOG_MODULE_REGISTER();

#define F2_HID_REPORT_SIZE 64u
#define F2_HID_MAX_MSG     1024u
/* A 1 KB CTAP response needs ~18 frames; 4 would drop continuation frames. */
#define F2_HID_TX_RING_LEN 20u

#define CTAPHID_PING       0x01u
#define CTAPHID_U2F        0x03u
#define CTAPHID_INIT       0x06u
#define CTAPHID_WINK       0x08u
#define CTAPHID_KEEPALIVE  0x3Bu
#define CTAPHID_CBOR       0x10u
#define CTAPHID_CANCEL     0x11u
#define CTAPHID_ERROR      0x3Fu
#define CTAPHID_BCID       0xFFFFFFFFu

#define ERR_INVALID_CMD    0x01u
#define ERR_INVALID_LEN    0x03u
#define ERR_INVALID_SEQ    0x04u
#define ERR_CHANNEL_BUSY   0x06u
#define ERR_INVALID_CHANNEL 0x0Bu

/* Usage Page 0xF1D0 / Usage 0x01, two 64-byte reports, no Report ID. */
APP_USBD_HID_GENERIC_SUBCLASS_REPORT_DESC(fido_report_desc,
    {
        0x06, 0xD0, 0xF1,       /* Usage Page (FIDO Alliance) */
        0x09, 0x01,             /* Usage (U2F authenticator)  */
        0xA1, 0x01,             /* Collection (Application)   */
        0x09, 0x20,             /*   Usage (Input Report Data)  */
        0x15, 0x00,             /*   Logical Minimum (0)        */
        0x26, 0xFF, 0x00,       /*   Logical Maximum (255)      */
        0x75, 0x08,             /*   Report Size (8)            */
        0x95, 0x40,             /*   Report Count (64)          */
        0x81, 0x02,             /*   Input (Data,Var,Abs)       */
        0x09, 0x21,             /*   Usage (Output Report Data) */
        0x15, 0x00,
        0x26, 0xFF, 0x00,
        0x75, 0x08,
        0x95, 0x40,
        0x91, 0x02,             /*   Output (Data,Var,Abs)      */
        0xC0                    /* End Collection              */
    });

static const app_usbd_hid_subclass_desc_t * fido_reports[] = {&fido_report_desc};

static void fido_hid_user_ev_handler(app_usbd_class_inst_t const * p_inst,
                                     app_usbd_hid_user_event_t event);

/* The SDK adds one byte to report_out_maxsize for a Report ID. With no Report
 * ID in our descriptor, 63 gives the 64-byte OUT buffer CTAPHID needs. */
APP_USBD_HID_GENERIC_GLOBAL_DEF(m_fido_hid,
                                2,
                                fido_hid_user_ev_handler,
                                (NRF_DRV_USBD_EPIN3, NRF_DRV_USBD_EPOUT3),
                                fido_reports,
                                4,
                                63,
                                0,
                                APP_USBD_HID_SUBCLASS_NONE,
                                APP_USBD_HID_PROTO_GENERIC);

static bool s_available;
static bool s_armed;
static uint32_t s_cid;              /* 0 until the host allocates a channel */
static uint32_t s_cid_counter;      /* fallback when the RNG pool is empty */

typedef struct {
    uint32_t cid;
    uint8_t  cmd;
    size_t   len;
    size_t   expected;
    uint8_t  next_seq;
    bool     active;
    volatile bool pending;
} f2_hid_rx_t;

/* s_rx_buf holds the raw CTAPHID payload, so it goes straight to core. */
static uint8_t s_rx_buf[1u + F2_HID_MAX_MSG];
static uint8_t s_resp_buf[1u + F2_HID_MAX_MSG];
static f2_hid_rx_t s_rx;

/* A gated transaction lives in s_rx_buf until the core returns a real status. */
static volatile bool s_hold_active;
static uint32_t s_hold_cid;
static uint8_t  s_hold_cmd;
static size_t   s_hold_len;

/* Static ring: the SDK queues pointers, so slots stay put until IN done. */
static uint8_t s_tx[F2_HID_TX_RING_LEN][F2_HID_REPORT_SIZE];
static volatile uint8_t s_tx_head;
static volatile uint8_t s_tx_tail;
static volatile uint8_t s_tx_count;
static volatile bool s_tx_busy;

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static size_t min_size(size_t a, size_t b)
{
    return a < b ? a : b;
}

static void rx_reset(void)
{
    s_rx.active = false;
    s_rx.pending = false;
    s_rx.len = 0u;
    s_rx.expected = 0u;
}

static void queue_raw(const uint8_t frame[F2_HID_REPORT_SIZE])
{
    CRITICAL_REGION_ENTER();
    if (s_tx_count < F2_HID_TX_RING_LEN) {
        memcpy(s_tx[s_tx_head], frame, F2_HID_REPORT_SIZE);
        s_tx_head = (uint8_t)((s_tx_head + 1u) % F2_HID_TX_RING_LEN);
        s_tx_count++;
    }
    CRITICAL_REGION_EXIT();
}

static void queue_response(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len)
{
    uint8_t frame[F2_HID_REPORT_SIZE];
    size_t off = 0u;
    uint8_t seq = 0u;

    do {
        size_t chunk = min_size(len - off, off == 0u ? 57u : 59u);
        size_t made = off == 0u
            ? fmt_ctaphid_init(frame, cid, cmd, data + off, chunk)
            : fmt_ctaphid_cont(frame, cid, seq++, data + off, chunk);
        if (made == 0u) return;
        if (off == 0u) {
            frame[5] = (uint8_t)(len >> 8);
            frame[6] = (uint8_t)len;
        }
        queue_raw(frame);
        off += chunk;
    } while (off < len);
}

static void queue_error(uint32_t cid, uint8_t code)
{
    queue_response(cid, CTAPHID_ERROR, &code, 1u);
}

/* Core: 0x02 PROCESSING / 0x03 UP needed; CTAPHID: 0x01 / 0x02. */
static void f2_usb_keepalive(uint8_t status)
{
    uint8_t ka;

    if (!s_hold_active) return;
    if (status == 0x02u) {
        ka = 0x01u;
    } else if (status == 0x03u) {
        ka = 0x02u;
    } else {
        ka = (status <= 2u) ? status : 2u;   /* already CTAPHID-encoded */
    }
    queue_response(s_hold_cid, CTAPHID_KEEPALIVE, &ka, 1u);
}

/* Core gate timeout pushes a bare CTAP status byte; frame it like a reply. */
static void f2_usb_core_send(const uint8_t *data, size_t len)
{
    uint8_t st;

    if (!s_hold_active) return;
    st = (data != NULL && len != 0u) ? data[0] : (uint8_t)FIDO2_ST_OTHER;
    queue_response(s_hold_cid, CTAPHID_CBOR, &st, 1u);
    s_hold_active = false;
    rx_reset();
}

static const fido2_transport_api_t m_fido2_usb_transport = {
    .id        = FIDO2_TRANSPORT_USB,
    .send      = f2_usb_core_send,
    .keepalive = f2_usb_keepalive,
};

static void handle_init(const uint8_t *nonce, size_t nonce_len)
{
    uint8_t payload[17];
    uint8_t cid_bytes[4];
    uint8_t available = 0u;
    uint32_t cid;

    if (nonce_len < 8u) {
        return;
    }
    nrf_drv_rng_bytes_available(&available);
    if (available >= 4u && nrf_drv_rng_rand(cid_bytes, 4u) == NRF_SUCCESS) {
        cid = get_be32(cid_bytes);
    } else {
        cid = (++s_cid_counter * 0x9E3779B9u) ^ get_be32(nonce);
    }
    if (cid == 0u || cid == CTAPHID_BCID) {
        cid = (++s_cid_counter * 0x9E3779B9u) | 1u;
    }
    s_cid = cid;
    /* A fresh channel invalidates any transaction still waiting on a gate. */
    s_hold_active = false;
    f2_core_cancel();
    rx_reset();

    memcpy(payload, nonce, 8u);
    put_be32(payload + 8u, cid);
    payload[12] = 0x02u;            /* CTAPHID protocol version */
    payload[13] = 0u;               /* device major */
    payload[14] = 0u;               /* device minor */
    payload[15] = 0u;               /* device build */
    payload[16] = 0x04u;            /* CAPABILITY_CBOR */
    queue_response(CTAPHID_BCID, CTAPHID_INIT, payload, sizeof(payload));
}

/* Called from the USBD event handler: copy only, no core dispatch or FDS. */
static void on_hid_frame(const uint8_t *frame, size_t size)
{
    uint32_t cid;
    uint8_t header;
    size_t bcnt;
    const uint8_t *data;
    size_t data_len;

    if (size < 7u) {
        return;
    }
    cid = get_be32(frame);
    header = frame[4];
    bcnt = ((size_t)frame[5] << 8) | frame[6];

    if ((header & 0x80u) != 0u) {
        uint8_t cmd = header & 0x7Fu;

        data = frame + 7u;
        data_len = size - 7u;
        if (cid == CTAPHID_BCID && cmd == CTAPHID_INIT) {
            handle_init(data, data_len);
            return;
        }
        if (cid != s_cid || s_cid == 0u) {
            queue_error(cid, ERR_INVALID_CHANNEL);
            return;
        }
        {
            /* Only a cancel may replace a transaction waiting on a gate. */
            bool cancel = (cmd == CTAPHID_CANCEL) ||
                          (cmd == CTAPHID_CBOR && bcnt != 0u &&
                           data_len != 0u && frame[7] == 0x11u);
            if (s_hold_active && !cancel) {
                queue_error(cid, ERR_CHANNEL_BUSY);
                return;
            }
            if (s_rx.active) {
                if (s_hold_active && cancel) {
                    s_rx.pending = false;   /* cancel overrides the held request */
                } else {
                    queue_error(cid, ERR_CHANNEL_BUSY);
                    return;
                }
            }
        }
        if (bcnt > F2_HID_MAX_MSG) {
            queue_error(cid, ERR_INVALID_LEN);
            return;
        }
        {
            /* BCNT is the total message length. The init frame carries at
             * most 57 bytes; the remainder arrives in continuation frames. */
            size_t init_len = min_size(min_size(data_len, 57u), bcnt);
            if (init_len != 0u) {
                memcpy(s_rx_buf, data, init_len);
            }
            s_rx.cid = cid;
            s_rx.cmd = cmd;
            s_rx.expected = bcnt;
            s_rx.len = init_len;
            s_rx.next_seq = 0u;
            s_rx.active = true;
            s_rx.pending = false;
        }
    } else {
        uint8_t seq = header & 0x7Fu;
        size_t chunk;

        if (s_hold_active) {
            queue_error(cid, ERR_CHANNEL_BUSY);
            return;
        }
        if (!s_rx.active || cid != s_rx.cid) {
            queue_error(cid, ERR_INVALID_CHANNEL);
            return;
        }
        if (s_rx.pending) {
            queue_error(cid, ERR_CHANNEL_BUSY);
            return;
        }
        if (seq != s_rx.next_seq) {
            queue_error(cid, ERR_INVALID_SEQ);
            rx_reset();
            return;
        }
        data = frame + 5u;
        data_len = size - 5u;
        /* A final continuation frame is padded to 59 bytes; copy only what
         * BCNT still needs so padding bytes never reach the CBOR parser. */
        chunk = min_size(data_len,
                         min_size(F2_HID_MAX_MSG - s_rx.len,
                                  s_rx.expected - s_rx.len));
        if (chunk != 0u) {
            memcpy(s_rx_buf + s_rx.len, data, chunk);
            s_rx.len += chunk;
        }
        s_rx.next_seq++;
    }

    if (s_rx.active && s_rx.len >= s_rx.expected) {
        s_rx.pending = true;
    }
}

/* Dispatch from s_rx_buf. F2_CORE_PENDING keeps the request for the next tick. */
static void dispatch_request(uint32_t cid, uint8_t cmd, size_t len)
{
    size_t resp_len = 0u;
    uint8_t status;
    fido2_request_t ctx = {
        .transport = FIDO2_TRANSPORT_USB,
        .uv_requested = false       /* core parses the CBOR uv option */
    };

    status = f2_core_dispatch(s_rx_buf, len, &ctx,
                              s_resp_buf, sizeof(s_resp_buf), &resp_len);
    if (status == F2_CORE_PENDING) {
        s_hold_active = true;
        s_hold_cid = cid;
        s_hold_cmd = cmd;
        s_hold_len = len;
        return;                     /* no response, no rx_reset: gate is waiting */
    }
    s_hold_active = false;
    if (resp_len == 0u) {
        uint8_t st = FIDO2_ST_OTHER;
        queue_response(cid, cmd, &st, 1u);
    } else {
        queue_response(cid, cmd, s_resp_buf, resp_len);
    }
    rx_reset();
}

/* Main-loop half: dispatch and queue IN reports, never called from USBD IRQ. */
static void process_pending(void)
{
    uint32_t cid;
    uint8_t cmd;
    size_t len;

    if (!s_rx.pending) {
        return;
    }
    CRITICAL_REGION_ENTER();
    s_rx.pending = false;
    cid = s_rx.cid;
    cmd = s_rx.cmd;
    len = s_rx.len;
    CRITICAL_REGION_EXIT();

    if (cmd == CTAPHID_CANCEL ||
        (cmd == CTAPHID_CBOR && len != 0u && s_rx_buf[0] == 0x11u)) {
        f2_core_cancel_request();
        s_hold_active = false;      /* CANCEL gets no reply */
        rx_reset();
    } else if (cmd == CTAPHID_PING) {
        queue_response(cid, cmd, s_rx_buf, len);
        rx_reset();
    } else if (s_armed && (cmd == CTAPHID_CBOR || cmd == CTAPHID_U2F)) {
        dispatch_request(cid, cmd, len);
    } else if (s_armed) {
        queue_error(cid, ERR_INVALID_CMD);   /* WINK, unexpected INIT, unknown */
        rx_reset();
    } else {
        rx_reset();                  /* disarmed CTAP commands are dropped */
    }
}

static void fido_hid_user_ev_handler(app_usbd_class_inst_t const * p_inst,
                                     app_usbd_hid_user_event_t event)
{
    UNUSED_VARIABLE(p_inst);

    switch (event) {
        case APP_USBD_HID_USER_EVT_OUT_REPORT_READY: {
            size_t size = 0u;
            const void *p = app_usbd_hid_generic_out_report_get(&m_fido_hid, &size);
            if (p != NULL) {
                on_hid_frame((const uint8_t *)p, min_size(size, F2_HID_REPORT_SIZE));
            }
            break;
        }

        case APP_USBD_HID_USER_EVT_IN_REPORT_DONE:
            CRITICAL_REGION_ENTER();
            if (s_tx_busy && s_tx_count != 0u) {
                s_tx_tail = (uint8_t)((s_tx_tail + 1u) % F2_HID_TX_RING_LEN);
                s_tx_count--;
            }
            s_tx_busy = false;
            CRITICAL_REGION_EXIT();
            break;

        default:
            break;
    }
}

void f2_usb_hid_init(void)
{
    ret_code_t ret;

    if (s_available) {
        return;
    }
    ret = app_usbd_class_append(app_usbd_hid_generic_class_inst_get(&m_fido_hid));
    if (ret != NRF_SUCCESS) {
        NRF_LOG_ERROR("FIDO2 HID class append failed: %u", (unsigned int)ret);
        s_available = false;
        return;
    }
    s_available = true;
    /* Static api object: registering again with the same pointer is harmless. */
    f2_transport_register(&m_fido2_usb_transport);
}

void f2_usb_hid_set_armed(bool armed)
{
    s_armed = armed;
    if (armed) {
        /* BLE registers at boot after us; re-register when FIDO2 mode starts. */
        f2_transport_register(&m_fido2_usb_transport);
    } else {
        s_hold_active = false;
        f2_core_cancel();
        rx_reset();
    }
}

void f2_usb_hid_poll(void)
{
    uint8_t submit = 0u;
    bool have_frame = false;
    ret_code_t ret;

    process_pending();
    if (s_hold_active) {
        dispatch_request(s_hold_cid, s_hold_cmd, s_hold_len);
    }
    if (!s_available) {
        return;
    }

    CRITICAL_REGION_ENTER();
    if (!s_tx_busy && s_tx_count != 0u) {
        submit = s_tx_tail;
        s_tx_busy = true;
        have_frame = true;
    }
    CRITICAL_REGION_EXIT();

    if (have_frame) {
        ret = app_usbd_hid_generic_in_report_set(&m_fido_hid,
                                                 s_tx[submit],
                                                 F2_HID_REPORT_SIZE);
        if (ret != NRF_SUCCESS) {
            /* Keep the slot queued and retry on the next pump. */
            CRITICAL_REGION_ENTER();
            s_tx_busy = false;
            CRITICAL_REGION_EXIT();
        }
    }
}

bool f2_usb_hid_available(void)
{
    return s_available;
}
