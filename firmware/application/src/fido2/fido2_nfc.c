/*
 * fido2_nfc.c
 *
 * NFC transport for the FIDO2 authenticator: ISO14443-4 T=CL frames carrying
 * ISO7816-4 APDUs. SELECT addresses the FIDO AID; CLA 80 INS 10 carries a
 * CTAP2 command; CLA 00 INS 01/02/03 carries U2F. The CTAP payload is handed
 * to f2_core_dispatch() from the mode tick, never from the NFCT ISR.
 */
#include "fido2/fido2_nfc.h"
#include "fido2/fido2_core.h"
#include "fido2/fido2_transport.h"
#include "fido2/fido2_types.h"

#include "nfc_14a.h"
#include "nfc_14a_4.h"
#include "tag_emulation.h"

#include "nrf.h"   /* __DMB */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define F2_NFC_REQ_MAX  1024u
#define F2_NFC_RESP_MAX 768u    /* full CTAP/U2F response, incl. 554-byte DER cert */
#define F2_NFC_FDT_MAX  0xFFFFFUL

/* AID A0000006472F0001 (FIDO Alliance, U2F/NFC) */
static const uint8_t s_aid[] = {
    0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
};
/* U2F_V2 version answer. CTAP2 readers accept this too. */
static const uint8_t s_version_resp[] = {
    0x55, 0x32, 0x46, 0x5F, 0x56, 0x32, 0x90, 0x00
};

/* Our own T=CL state: nfc_tag_14a_4_* helpers operate on the state pointer we
 * pass them, so this transport does not touch the slot's 14A-4 session. */
static nfc_tag_14a_4_tcl_state_t s_tcl;

static uint8_t  s_req[F2_NFC_REQ_MAX];   /* CTAP chaining + core-pending request */
static size_t   s_req_len;
static bool     s_req_chaining;
static bool     s_core_pending;           /* core asked for a user gesture */
static bool     s_core_pending_ctap2;
static volatile bool s_status_pending;    /* core pushed a CTAP status byte */
static uint8_t  s_status_byte;

/* NFC has no keepalive channel: the NFCT ISR holds the reader with S(WTX). */
static void f2_nfc_keepalive(uint8_t status)
{
    (void)status;
}

/* Core timeout / CANCEL pushes a bare CTAP status; stage it as the response
 * APDU so f2_nfc_poll() emits it with SW 9000. */
static void f2_nfc_core_send(const uint8_t *data, size_t len)
{
    s_core_pending = false;
    s_status_byte = (data != NULL && len != 0u) ? data[0] : (uint8_t)FIDO2_ST_OTHER;
    s_status_pending = true;
}

static const fido2_transport_api_t m_fido2_nfc_transport = {
    .id        = FIDO2_TRANSPORT_NFC,
    .send      = f2_nfc_core_send,
    .keepalive = f2_nfc_keepalive,
};

/* Full response APDU. The 260-byte s_tcl.m_resp_buf stays the T=CL chunk
 * buffer; stage_chunk() feeds it from here. U2F REGISTER carries a 554-byte
 * DER certificate, so this must be larger than one APDU. */
static uint8_t  s_resp_full[F2_NFC_RESP_MAX] __attribute__((aligned(4)));
static uint16_t s_resp_full_len;
static uint16_t s_resp_sent;                     /* bytes already handed out */
static bool     s_getresp_pending;

static volatile bool s_apdu_pending;             /* ISR -> tick handoff */
static volatile bool s_installed;
static volatile bool s_field_presence;           /* field entry, gate not granted yet */

static nfc_tag_14a_handler_t s_handler;

/* ------------------------------------------------------------------------- */
/* APDU parsing                                                              */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint8_t        cla, ins, p1, p2;
    const uint8_t *data;
    uint16_t       len;
} f2_apdu_t;

static bool parse_apdu(const uint8_t *a, uint16_t n, f2_apdu_t *out) {
    if (n < 4) return false;
    out->cla = a[0];
    out->ins = a[1];
    out->p1  = a[2];
    out->p2  = a[3];
    out->data = NULL;
    out->len  = 0;

    if (n == 5) return true;              /* case 2: Le only (VERSION etc.) */
    if (n < 5) return true;               /* case 1: no data, no Le */

    if (a[4] == 0) {
        /* Extended Lc: 00 LL LL. Le-only extended APDUs have LL LL = 00 00. */
        if (n < 7) return true;
        uint16_t ext = ((uint16_t)a[5] << 8) | a[6];
        if ((uint32_t)n < 7u + (uint32_t)ext) return false;
        out->data = &a[7];
        out->len  = ext;
        return true;
    }

    if (n < (uint16_t)(5u + a[4])) return false;
    out->data = &a[5];
    out->len  = a[4];
    return true;
}

/* ------------------------------------------------------------------------- */
/* Response staging                                                          */
/* ------------------------------------------------------------------------- */

static void respond_sw(uint8_t sw1, uint8_t sw2) {
    s_resp_full[0] = sw1;
    s_resp_full[1] = sw2;
    s_resp_full_len = 2;
}

static void stage_full(const uint8_t *d, uint16_t n) {
    if (n > sizeof(s_resp_full)) n = sizeof(s_resp_full);
    memcpy(s_resp_full, d, n);
    s_resp_full_len = n;
}

/* Largest I-block payload we allow, derived from the reader's FSD as
 * advertised in RATS. nfc_tag_14a_get_reader_fsd() is 0 before RATS. */
static uint16_t resp_frag(void) {
    uint16_t fsd = nfc_tag_14a_get_reader_fsd();
    if (fsd < 8 || fsd > NFC_14A_4_MAX_APDU) fsd = 32;
    uint16_t frag = fsd - 2;   /* FSD minus the frame's two CRC bytes */
    if (frag < 4) frag = 4;
    if (frag > NFC_14A_4_MAX_APDU) frag = NFC_14A_4_MAX_APDU;
    return frag;
}

/* Copy one APDU-level chunk into the T=CL response buffer and send it.
 * s_resp_full is a complete response APDU (it already ends in SW 9000 on
 * success). For a long response the last two bytes of each intermediate
 * chunk are replaced by SW 61XX; those two payload bytes are re-sent in the
 * next chunk, hence s_resp_sent advances by n-2. The T=CL chaining fields
 * are staged too, so a chunk larger than one I-block is split by
 * nfc_tag_14a_4_base_respond() automatically. */
static void stage_chunk(uint16_t off) {
    if (s_resp_full_len == 0 || off >= s_resp_full_len) {
        respond_sw(0x6F, 0x00);
        off = 0;
    }

    uint16_t frag = resp_frag();
    uint16_t cap  = frag;   /* SW is already part of s_resp_full */
    if (cap > NFC_14A_4_MAX_APDU) cap = NFC_14A_4_MAX_APDU;

    uint16_t remain = (uint16_t)(s_resp_full_len - off);
    uint16_t n = (remain < cap) ? remain : cap;
    if (n < 2) n = (remain < 2) ? remain : 2;
    if (n > sizeof(s_tcl.m_resp_buf)) n = (uint16_t)sizeof(s_tcl.m_resp_buf);

    memcpy(s_tcl.m_resp_buf, &s_resp_full[off], n);
    bool more = ((uint32_t)off + n < s_resp_full_len);
    if (more) {
        /* SW 61 <bytes still unread after this chunk, including the two
         * bytes overwritten by the SW itself>. SW2 is one byte, so clamp:
         * the reader keeps issuing GET RESPONSE until it sees 9000. */
        uint16_t left = (uint16_t)(s_resp_full_len - off - n + 2u);
        if (left > 255u) left = 255u;
        s_tcl.m_resp_buf[n - 2] = 0x61;
        s_tcl.m_resp_buf[n - 1] = (uint8_t)left;
    }
    s_tcl.m_resp_len = n;

    s_tcl.m_tx_off      = 0;
    s_tcl.m_tx_frag     = frag;
    s_tcl.m_tx_chaining = true;   /* base_respond clears it after the last block */
    s_tcl.m_response_ready = true;

    s_resp_sent       = (uint16_t)(off + (more ? n - 2u : n));
    s_getresp_pending = more;

    nfc_tag_14a_set_frame_delay_max(F2_NFC_FDT_MAX);
    nfc_tag_14a_4_base_respond(&s_tcl);
}

/* ------------------------------------------------------------------------- */
/* Core dispatch                                                             */
/* ------------------------------------------------------------------------- */

static void dispatch_core(const uint8_t *req, size_t req_len, bool ctap2) {
    /* Keep a retryable copy: the core may return F2_CORE_PENDING until a user
     * gesture arrives, then we must re-send the very same request. */
    if (req != s_req) {
        if (req_len > sizeof(s_req)) {
            respond_sw(0x6A, 0x80);
            return;
        }
        memcpy(s_req, req, req_len);
    }
    s_req_len = req_len;

    fido2_request_t ctx;
    ctx.transport    = FIDO2_TRANSPORT_NFC;   /* NFC tap satisfies the UP gate */
    ctx.uv_requested = false;                /* never auto-grant UV */

    size_t out_len = 0;
    uint8_t st = f2_core_dispatch(s_req, req_len, &ctx,
                                  ctap2 ? &s_resp_full[1] : s_resp_full,
                                  ctap2 ? sizeof(s_resp_full) - 3 : sizeof(s_resp_full),
                                  &out_len);

    if (st == F2_CORE_PENDING) {
        s_core_pending = true;
        s_core_pending_ctap2 = ctap2;
        return;   /* s_req/s_req_len stay intact for the retry */
    }
    s_core_pending = false;

    if (ctap2) {
        if (out_len > sizeof(s_resp_full) - 3) out_len = sizeof(s_resp_full) - 3;
        s_resp_full[0] = st;                 /* CTAP status byte */
        uint16_t n = (uint16_t)out_len + 1;
        s_resp_full[n++] = 0x90;
        s_resp_full[n++] = 0x00;
        s_resp_full_len = n;
        return;
    }

    /* U2F: the core returns the complete response including SW 9000. */
    if (out_len < 2 || out_len > sizeof(s_resp_full)) {
        if (req_len >= 2 && req[1] == 0x03) {
            stage_full(s_version_resp, sizeof(s_version_resp));
        } else {
            respond_sw(0x6A, 0x80);
        }
        return;
    }
    s_resp_full_len = (uint16_t)out_len;
}

static void handle_ctap2(const f2_apdu_t *ap, bool chained) {
    /* P1 bit 7 = "client supports GETRESPONSE"; the other bits are RFU. */
    if ((ap->p1 & 0x7Fu) != 0x00u || ap->p2 != 0x00u) {
        s_req_len = 0;
        s_req_chaining = false;
        respond_sw(0x6A, 0x80);
        return;
    }

    if (ap->len != 0u && ap->data[0] == 0x11u) {   /* CTAP CANCEL */
        s_req_len = 0;
        s_req_chaining = false;
        s_core_pending = false;
        f2_core_cancel_request();
        respond_sw(0x90, 0x00);
        return;
    }

    if (chained) {
        if ((size_t)ap->len > F2_NFC_REQ_MAX - s_req_len) {
            s_req_len = 0;
            s_req_chaining = false;
            respond_sw(0x6A, 0x80);
            return;
        }
        if (ap->len) memcpy(&s_req[s_req_len], ap->data, ap->len);
        s_req_len += ap->len;
        s_req_chaining = true;
        respond_sw(0x90, 0x00);   /* acknowledge the fragment */
        return;
    }

    size_t total = s_req_len + (size_t)ap->len;
    if (total == 0 || total > F2_NFC_REQ_MAX) {
        s_req_len = 0;
        s_req_chaining = false;
        respond_sw(0x6A, 0x80);
        return;
    }
    if (s_req_chaining && s_req_len) {
        memcpy(&s_req[s_req_len], ap->data, ap->len);
    } else {
        memcpy(s_req, ap->data, ap->len);
    }
    s_req_len = total;
    s_req_chaining = false;

    dispatch_core(s_req, s_req_len, true);
    if (!s_core_pending) s_req_len = 0;
}

/* ------------------------------------------------------------------------- */
/* NFCT callbacks (ISR context)                                              */
/* ------------------------------------------------------------------------- */

static void f2_nfc_cb_reset(void) {
    nfc_tag_14a_4_reset_state(&s_tcl);
    s_tcl.m_resp_len = 0;
    s_req_len = 0;
    s_req_chaining = false;
    s_core_pending = false;
    s_getresp_pending = false;
    s_resp_full_len = 0;
    s_resp_sent = 0;
    s_apdu_pending = false;
    s_status_pending = false;
}

static void f2_nfc_cb_field(bool present) {
    if (present) {
        s_field_presence = true;   /* one tap -> one UP grant in poll() */
    } else {
        s_field_presence = false;
        s_req_len = 0;
        s_req_chaining = false;
        s_core_pending = false;
        s_getresp_pending = false;
        s_status_pending = false;
        s_resp_full_len = 0;
    }
}

static void f2_nfc_cb_state(uint8_t *data, uint16_t szBits) {
    if (!s_installed) return;
    if ((szBits & 7u) != 0u || szBits < 24u) return;

    /* cb_state receives BITS; the 14A-4 engine works in BYTES. */
    uint16_t szBytes = szBits / 8u;

    /* DESELECT ends the T=CL session. Let base_handler echo it (and reset its
     * own state), then reset ours too. */
    if ((data[0] & 0xF7u) == 0xC2u) {
        (void)nfc_tag_14a_4_base_handler(&s_tcl, data, szBytes);
        f2_nfc_cb_reset();
        return;
    }

    if (!nfc_tag_14a_4_base_handler(&s_tcl, data, szBytes)) return;

    /* base_handler leaves the trailing 2 CRC bytes in m_apdu_len. */
    if (s_tcl.m_apdu_len >= 2) {
        s_tcl.m_apdu_len -= 2;
    } else {
        s_tcl.m_apdu_len = 0;
    }
    s_tcl.m_resp_len = 0;
    s_tcl.m_response_ready = false;

    __DMB();
    s_apdu_pending = true;
    __DMB();

    /* No response staged yet: emit S(WTX) so the reader waits for the tick. */
    nfc_tag_14a_4_base_respond(&s_tcl);
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

void f2_nfc_init(void) {
    s_req_len = 0;
    s_req_chaining = false;
    s_core_pending = false;
    s_resp_full_len = 0;
    s_resp_sent = 0;
    s_getresp_pending = false;
    s_field_presence = false;
    s_apdu_pending = false;
    s_status_pending = false;
    s_installed = false;
    nfc_tag_14a_4_reset_state(&s_tcl);
    f2_transport_register(&m_fido2_nfc_transport);

    s_handler.cb_reset    = f2_nfc_cb_reset;
    s_handler.cb_field    = f2_nfc_cb_field;
    s_handler.cb_state    = f2_nfc_cb_state;
    s_handler.get_coll_res = nfc_tag_14a_4_get_coll_res;
}

void f2_nfc_set_armed(bool armed) {
    if (armed) {
        s_req_len = 0;
        s_req_chaining = false;
        s_core_pending = false;
        s_resp_full_len = 0;
        s_resp_sent = 0;
        s_getresp_pending = false;
        s_apdu_pending = false;
        s_status_pending = false;
        nfc_tag_14a_4_reset_state(&s_tcl);
        __DMB();
        s_installed = true;
        __DMB();
        nfc_tag_14a_set_handler(&s_handler);
    } else {
        __DMB();
        s_installed = false;
        __DMB();
        s_apdu_pending = false;
        s_getresp_pending = false;
        s_status_pending = false;
        s_req_len = 0;
        s_req_chaining = false;
        s_core_pending = false;

        /* Hand the field back to the slot's normal 14A-4 handler. No FDS
         * writes: data_loadcb only rebinds to the existing slot buffer. */
        nfc_tag_14a_4_reset_handler();
        tag_data_buffer_t *buf = get_buffer_by_tag_type(TAG_TYPE_HF14A_4);
        if (buf != NULL) {
            nfc_tag_14a_4_data_loadcb(TAG_TYPE_HF14A_4, buf);
        }
    }
}

bool f2_nfc_available(void) {
    return s_installed;
}

void f2_nfc_poll(void) {
    if (!s_installed) return;

    /* Field entry is user presence. Grant the core's UP gate once per tap;
     * the first UP-requiring command consumes it there. UV is never granted. */
    if (s_field_presence) {
        s_field_presence = false;
        (void)f2_core_grant(FIDO2_GATE_UP);
    }

    /* A core timeout/CANCEL status replaces any held request. */
    if (s_status_pending) {
        s_status_pending = false;
        s_req_len = 0;
        s_req_chaining = false;
        s_resp_full[0] = s_status_byte;
        s_resp_full[1] = 0x90;
        s_resp_full[2] = 0x00;
        s_resp_full_len = 3;
        stage_chunk(0);
        return;
    }

    /* A request the core deferred on a gate is retried verbatim on later
     * ticks. The reader is held off with S(WTX) until a response exists. */
    if (s_core_pending) {
        dispatch_core(s_req, s_req_len, s_core_pending_ctap2);
        if (s_core_pending) return;
        s_req_len = 0;
        stage_chunk(0);
        return;
    }

    if (!s_apdu_pending) return;
    __DMB();
    s_apdu_pending = false;
    __DMB();

    /* Snapshot the APDU before the slow dispatch; an ISR may overwrite the
     * shared T=CL buffer while the core is signing. */
    uint8_t apdu[NFC_14A_4_MAX_APDU];
    uint16_t len = s_tcl.m_apdu_len;
    if (len > sizeof(apdu)) len = sizeof(apdu);
    memcpy(apdu, s_tcl.m_apdu_buf, len);

    f2_apdu_t a;
    uint16_t off = 0;
    if (len == 0 || !parse_apdu(apdu, len, &a)) {
        respond_sw(0x6A, 0x80);
    } else if (a.cla == 0x00 && a.ins == 0xA4) {
        /* SELECT by AID (P1=04) */
        if (a.p1 != 0x04 || a.data == NULL ||
                a.len != sizeof(s_aid) || memcmp(a.data, s_aid, sizeof(s_aid)) != 0) {
            respond_sw(0x6A, 0x80);
        } else {
            stage_full(s_version_resp, sizeof(s_version_resp));
        }
    } else if (a.cla == 0x80 && a.ins == 0x10) {
        handle_ctap2(&a, false);
    } else if (a.cla == 0x90 && a.ins == 0x10) {
        handle_ctap2(&a, true);   /* CLA chaining bit: collect fragments */
    } else if ((a.cla == 0x80 || a.cla == 0x00) && a.ins == 0x11) {
        if (a.p1 != 0x00u || a.p2 != 0x00u) {
            respond_sw(0x6A, 0x80);
        } else if (s_getresp_pending) {
            off = s_resp_sent;
        } else {
            respond_sw(0x6D, 0x00);
        }
    } else if (a.cla == 0x00 && (a.ins == 0x01 || a.ins == 0x02 || a.ins == 0x03)) {
        dispatch_core(apdu, len, false);   /* raw U2F APDU, core appends SW */
    } else {
        respond_sw(0x6D, 0x00);            /* unknown INS */
    }

    if (s_status_pending) return;   /* core pushed a status; emit it next tick */
    stage_chunk(off);
}
