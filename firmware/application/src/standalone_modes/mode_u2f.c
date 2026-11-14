/*
 * mode_u2f.c — FIDO2 (CTAP2) + U2F (CTAP1) authenticator, standalone mode.
 *
 * One authenticator, three transports:
 *   - NFC : ISO-14443-4 T=CL. NFCCTAP_MSG (INS 0x10) carries a CTAP2 command;
 *           U2F APDUs (INS 0x01/0x02) stay handled as the CTAP1 fallback.
 *   - USB : CTAPHID — 64-byte HID reports on usage page 0xF1D0.
 *   - BLE : FIDO GATT service 0xFFFD.
 *
 * All three hand their bytes to the same transport-independent core
 * (fido2_core.c), which owns the crypto (stateless key wrapping, ECDSA, CBOR)
 * and a single request slot; the CTAP1 path shares the core's master key and
 * sign counter. The tested T=CL engine (nfc_14a_4) does all ISO-DEP framing;
 * responses are processed in on_tick so S(WTX) keeps the reader waiting while
 * ECDSA runs, and 61xx chaining returns oversized results.
 *
 * NOTE: CTAP2 here is non-UV (up-only, non-resident) — no clientPIN. Works for
 * UV-discouraged / second-factor WebAuthn; passkeys (UV-required) need PIN.
 *
 * Stateless key wrapping — no per-credential flash:
 *   priv = HMAC-SHA256(mk, 0x01 | rpIdHash32 | nonce32)   (P-256 scalar)
 *   kh   = nonce32 | HMAC-SHA256(mk, 0x02 | rpIdHash32 | nonce32)32
 * Only a 32-byte master key and a 4-byte global counter live in FDS. A key
 * handle is bound to its rpId by the MAC, so it cannot be used on another
 * origin. Keys live in internal flash, not a secure element — research use.
 *
 * Crypto: SHA-256/HMAC/ECDSA live in fido2_core.c; micro-ecc (uECC) for P-256.
 */

#include <stdint.h>
#include <string.h>
#include "app_standalone.h"
#include "app_timer.h"
#include "standalone_led.h"
#include "nrf_gpio.h"
#include "nfc_14a.h"
#include "rfid/nfctag/hf/nfc_14a_4.h"
#include "utils/fds_util.h"
#include "nrf_drv_rng.h"
#include "uECC.h"
#include "fido2_core.h"
#include "u2f.h"
#include "nrf_crypto.h"
#include "fido2_hid.h"
#include "fido2_ble.h"

#define NRF_LOG_MODULE_NAME u2f
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

/* ---- persistence ---- */
#define U2F_FDS_FILE          0x1020
#define U2F_FDS_KEY_MK        0x0001   /* 32-byte master key            */
#define U2F_FDS_KEY_CTR       0x0002   /* 4-byte global counter         */
#define U2F_FDS_KEY_ATT_PRIV  0x0003   /* 32-byte attestation priv key  */
#define U2F_FDS_KEY_ATT_CERT  0x0004   /* attestation cert (DER)        */
#define U2F_ATT_CERT_MAX      512      /* max provisioned cert size     */

/* ---- status words ---- */
#define SW_NO_ERROR               0x9000
#define SW_CONDITIONS_NOT_SAT     0x6985   /* also: test-of-presence / check-only "mine" */
#define SW_WRONG_DATA             0x6A80
#define SW_WRONG_LENGTH           0x6700
#define SW_FILE_NOT_FOUND         0x6A82
#define SW_INS_NOT_SUPPORTED      0x6D00

/* ---- U2F / ISO7816 instructions ---- */
#define U2F_INS_REGISTER     0x01
#define U2F_INS_AUTHENTICATE 0x02
#define U2F_INS_VERSION      0x03
#define ISO_INS_SELECT       0xA4
#define ISO_INS_GET_RESPONSE 0xC0

#define U2F_AUTH_CHECK_ONLY  0x07
#define U2F_AUTH_ENFORCE     0x03
#define U2F_AUTH_NO_ENFORCE  0x08

static const uint8_t U2F_AID[]   = {0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01};
static const uint8_t U2F_V2[]    = {'U','2','F','_','V','2'};
#define KH_LEN 64   /* nonce(32) | mac(32) */

/* ---- CTAP2 / FIDO2 (NFCCTAP) ---- */
#define NFCCTAP_MSG          0x10   /* CLA 0x80: carries a CTAP2 command         */
#define NFCCTAP_GETRESPONSE  0x11   /* CLA 0x80: fetch more of a chained response */
/* CTAP status bytes (first byte of a CTAP response) */
#define CTAP2_OK                     0x00
#define CTAP1_ERR_INVALID_LENGTH     0x03
#define CTAP2_ERR_OPERATION_DENIED   0x27

static const uint8_t FIDO2_V[] = {'F','I','D','O','_','2','_','0'};

/* =====================================================================
 *  Attestation material is provisioned at RUNTIME, no code edit needed:
 *    firmware/tools/gen_u2f_attestation.sh      # make a P-256 key + cert
 *    hw u2f set-attestation -k att.key -c att.crt
 *  which stores them in FDS (keys 3/4) and overrides the fallback below.
 *  The fallback is an empty placeholder: REGISTER only yields a usable
 *  credential once a real key/cert have been provisioned.
 * ===================================================================== */
static const uint8_t U2F_ATT_PRIV_DEFAULT[32] = { 0 };

/* Vendored makerdiary U2F globals (attestation material + AES key). */
extern uint8_t aes_key[];
extern uint8_t attestation_cert[];
extern uint8_t attestation_private_key[];
extern uint16_t attestation_cert_size;
extern uint8_t attestation_private_key_size;

/* ---- session ---- */
static nfc_tag_14a_4_tcl_state_t m_tcl;
static uint8_t  m_uid[7];
static uint8_t  m_att_priv[32] __attribute__((aligned(4)));   /* from FDS or default */
static uint32_t m_clock_ticks;
static uint32_t m_clock_ms;

/* Large response + ISO7816 GET RESPONSE chaining. 768 B covers the worst
 * case of the CTAP1 REGISTER response (66 + 1 + 64 + 512 cert + 72 sig + SW). */
static uint8_t  m_big[768];
static uint16_t m_big_len;
static uint16_t m_big_off;
/* CTAP2 response from the core (status byte + CBOR). */
static uint8_t  m_ctap_resp[FIDO2_MAX_RESPONSE];
/* CTAP2 (NFCCTAP) responses must go out in one ISO-DEP frame: this phone does
 * not continue an NFCCTAP response via 61 XX / GET RESPONSE (it re-SELECTs). The
 * U2F path keeps small-frame 61 XX chaining, which real U2F readers do follow. */
static bool     m_ctap2_resp;
/* A CTAP2 command was handed to the core; the answer is emitted later. */
static bool     m_ctap2_pending;

/* fixed anti-collision identity: ISO-14443-4 (SAK bit 0x20) + a minimal ATS */
static nfc_tag_14a_uid_size s_uid_size = NFC_TAG_14A_UID_DOUBLE_SIZE;
static uint8_t  s_atqa[2]  = {0x44, 0x00};
static uint8_t  s_sak[1]   = {0x20};
static nfc_tag_14a_coll_res_reference_t s_coll;
/* ATS: TL,T0(TA/TB/TC,FSCI=8),TA=80,TB=90(high FWI for slow ECDSA),TC=00, then
 * ISO7816-4 historical bytes: 80 (category) | 73 C0 21 C0 (card-capabilities TLV,
 * full ISO7816-4 — identical to a YubiKey 5) | 5A "Phreakbyte" (issuer-data TLV).
 * Without historical bytes iOS classifies the tag as storage/DESFire and probes
 * GetVersion; these route it to the ISO7816/FIDO path, same as a real key. */
static nfc_14a_ats_t s_ats = {
    .length = 21,
    .data = {0x15, 0x78, 0x80, 0x84, 0x00,      /* TA1=80 (106k), TB1=84 (SFGI4/FWI8, as YubiKey), TC1=00 */
             0x80, 0x73, 0xC0, 0x21, 0xC0,
             0x5A, 'P','h','r','e','a','k','b','y','t','e'}
};

static nfc_tag_14a_coll_res_reference_t *u2f_get_coll_res(void) {
    s_coll.size = &s_uid_size;
    s_coll.uid  = m_uid;
    s_coll.atqa = s_atqa;
    s_coll.sak  = s_sak;
    s_coll.ats  = &s_ats;
    return &s_coll;
}

/* ===================================================================== */
/*  Platform hooks for the FIDO2 core: FDS persistence + hardware RNG     */
/* ===================================================================== */
static int u2f_rng(uint8_t *dest, unsigned size){
    return nrf_drv_rng_rand(dest, (uint8_t)size) == NRF_SUCCESS ? 1 : 0;
}

static bool io_load_master_key(uint8_t mk[32]) {
    uint16_t len = sizeof(uint8_t) * 32;
    if (!fds_read_sync(U2F_FDS_FILE, U2F_FDS_KEY_MK, &len, mk)) return false;
    return len == 32;
}

static bool io_store_master_key(const uint8_t mk[32]) {
    /* FDS wants word-aligned source data; the core hands us a stack buffer. */
    static uint32_t buf[32 / 4];
    memcpy(buf, mk, 32);
    return fds_write_sync(U2F_FDS_FILE, U2F_FDS_KEY_MK, 32, buf);
}

static bool io_load_counter(uint32_t *ctr) {
    uint16_t len = sizeof(uint32_t);
    if (!fds_read_sync(U2F_FDS_FILE, U2F_FDS_KEY_CTR, &len, (uint8_t *)ctr)) return false;
    return len == sizeof(uint32_t);
}

static void io_store_counter(uint32_t ctr) {
    fds_write_sync(U2F_FDS_FILE, U2F_FDS_KEY_CTR, sizeof(uint32_t), &ctr);
}

static bool io_random(uint8_t *dst, size_t len) {
    while (len) {
        uint8_t chunk = (len > 32) ? 32 : (uint8_t)len;
        if (nrf_drv_rng_rand(dst, chunk) != NRF_SUCCESS) return false;
        dst += chunk;
        len -= chunk;
    }
    return true;
}

static uint32_t io_now_ms(void) {
    uint32_t ticks = app_timer_cnt_get();
    uint32_t elapsed = app_timer_cnt_diff_compute(ticks, m_clock_ticks);
    m_clock_ticks = ticks;
    m_clock_ms += (uint32_t)(((uint64_t)elapsed * 1000U) / APP_TIMER_TICKS(1000));
    return m_clock_ms;
}

static const fido2_core_io_t m_core_io = {
    .load_master_key  = io_load_master_key,
    .store_master_key = io_store_master_key,
    .load_counter     = io_load_counter,
    .store_counter    = io_store_counter,
    .random_bytes     = io_random,
    .now_ms           = io_now_ms,
};

/* Provision the attestation key (32 bytes) + cert (DER) into FDS at runtime,
 * so users set them over the CLI instead of editing source. Takes effect on
 * the next arm; the key is also applied live if the mode is armed. */
bool u2f_set_attestation(const uint8_t *priv, const uint8_t *cert, uint16_t cert_len) {
    if (!priv || !cert || cert_len < 2 || cert_len > U2F_ATT_CERT_MAX) return false;
    /* FDS requires word-aligned source data; the inbound command buffer sits at
     * an odd offset after the frame preamble, so stage into aligned buffers. */
    static uint32_t priv_buf[32 / 4];
    static uint32_t cert_buf[(U2F_ATT_CERT_MAX + 3) / 4];
    memcpy(priv_buf, priv, 32);
    memcpy(cert_buf, cert, cert_len);
    bool ok = fds_write_sync(U2F_FDS_FILE, U2F_FDS_KEY_ATT_PRIV, 32, priv_buf);
    ok = fds_write_sync(U2F_FDS_FILE, U2F_FDS_KEY_ATT_CERT, cert_len, cert_buf) && ok;
    if (ok) memcpy(m_att_priv, priv, 32);
    return ok;
}

/* ---- APDU helpers ---- */
static uint16_t put_sw(uint8_t *resp, uint16_t off, uint16_t sw){
    resp[off++]=(uint8_t)(sw>>8); resp[off++]=(uint8_t)sw; return off;
}

/* Parse an ISO7816 command: short or extended Lc/Le. Fills *data,*lc. */
static bool apdu_parse(const uint8_t *a, uint16_t n, const uint8_t **data, uint16_t *lc){
    if (n < 4) return false;
    *data=NULL; *lc=0;
    if (n == 4) return true;                     /* no body */
    if (a[4] != 0) {                             /* short */
        *lc=a[4]; *data=a+5; return (5+*lc) <= n;
    }
    if (n < 7) return true;                      /* extended, no body (Le only) */
    *lc=(a[5]<<8)|a[6]; *data=a+7; return (7+*lc) <= n;
}

/* Build REGISTER response into m_big. (makerdiary reference backend) */
static uint16_t do_register(const uint8_t *body, uint16_t lc, uint8_t *out){
    if (lc != 64) return put_sw(out, 0, SW_WRONG_LENGTH);
    U2F_REGISTER_REQ req;
    memcpy(req.chal, body, 32);
    memcpy(req.appId, body + 32, 32);
    U2F_REGISTER_RESP resp;
    uint16_t resp_len = 0;
    uint16_t sw = u2f_register(&req, &resp, U2F_AUTH_ENFORCE, &resp_len);
    if (sw != U2F_SW_NO_ERROR) return put_sw(out, 0, sw);
    memcpy(out, &resp, resp_len);
    return put_sw(out, resp_len, SW_NO_ERROR);
}

/* Build AUTHENTICATE response. (makerdiary reference backend) */
static uint16_t do_authenticate(uint8_t p1, const uint8_t *body, uint16_t lc, uint8_t *out){
    if (lc < 65) return put_sw(out, 0, SW_WRONG_LENGTH);
    if (p1 == U2F_AUTH_CHECK_ONLY) return put_sw(out, 0, SW_CONDITIONS_NOT_SAT);
    const uint8_t *kh = body + 65;
    uint8_t khl = body[64];
    if (khl != KH_LEN || lc < (uint16_t)(65 + khl)) return put_sw(out, 0, SW_WRONG_DATA);

    U2F_AUTHENTICATE_REQ req;
    memcpy(req.chal, body, 32);
    memcpy(req.appId, body + 32, 32);
    req.keyHandleLen = khl;
    memcpy(req.keyHandle, kh, khl);

    int flags = (p1 == U2F_AUTH_ENFORCE) ? U2F_AUTH_ENFORCE : 0;
    U2F_AUTHENTICATE_RESP resp;
    uint16_t resp_len = 0;
    uint16_t sw = u2f_authenticate(&req, &resp, flags, &resp_len);
    if (sw != U2F_SW_NO_ERROR) return put_sw(out, 0, sw);
    /* makerdiary-style counter persistence: store. */
    {
        uint32_t c = u2f_impl_get_counter();
        fds_write_sync(U2F_FDS_FILE, U2F_FDS_KEY_CTR, sizeof(c), &c);
    }
    memcpy(out, &resp, resp_len);
    return put_sw(out, resp_len, SW_NO_ERROR);
}

/* APDU dispatch → writes to m_big, returns total length (incl SW). */
static uint16_t u2f_process(const uint8_t *a, uint16_t n){
    m_ctap2_resp = false;
    m_ctap2_pending = false;
    if (n < 4) { m_big_len = put_sw(m_big,0,SW_WRONG_LENGTH); return m_big_len; }
    uint8_t cla=a[0], ins=a[1], p1=a[2];
    const uint8_t *body; uint16_t lc;
    if (!apdu_parse(a,n,&body,&lc)) { m_big_len = put_sw(m_big,0,SW_WRONG_LENGTH); return m_big_len; }

    /* ISO SELECT by name (CLA 00, INS A4, P1 04) — answer FIDO_2_0 so the
     * platform drives CTAP2; a U2F-only reader that insists on U2F_V2 won't
     * engage, which is the accepted trade for phone support. */
    if (cla == 0x00 && ins == ISO_INS_SELECT) {
        if (p1 == 0x04 && body && lc >= sizeof(U2F_AID) &&
                memcmp(body, U2F_AID, sizeof(U2F_AID)) == 0) {
            memcpy(m_big, FIDO2_V, sizeof(FIDO2_V));
            m_big_len = put_sw(m_big, sizeof(FIDO2_V), SW_NO_ERROR);
        } else {
            m_big_len = put_sw(m_big, 0, SW_FILE_NOT_FOUND);
        }
        return m_big_len;
    }

    /* CTAP2: NFCCTAP_MSG (CLA 80, INS 10) carries cmd byte + CBOR. The command
     * is handed to the shared core; the answer is emitted by on_tick once the
     * core is done (the reader waits on S(WTX) meanwhile). */
    if (cla == 0x80 && ins == NFCCTAP_MSG) {
        m_ctap2_resp = true;                 /* layer-4 chained response */
        if (!body || lc < 1) {
            m_big[0] = CTAP1_ERR_INVALID_LENGTH;
            m_big_len = put_sw(m_big, 1, SW_NO_ERROR);
            return m_big_len;
        }
        if (!fido2_submit(FIDO2_OWNER_NFC, body, lc)) {
            /* core busy (another transport) or mode not armed */
            m_big[0] = CTAP2_ERR_OPERATION_DENIED;
            m_big_len = put_sw(m_big, 1, SW_NO_ERROR);
            return m_big_len;
        }
        m_ctap2_pending = true;
        return 0;
    }

    /* U2F / CTAP1 fallback (CLA 00). */
    if (cla == 0x00) {
        switch (ins) {
        case U2F_INS_VERSION:
            memcpy(m_big, U2F_V2, sizeof(U2F_V2));
            m_big_len = put_sw(m_big, sizeof(U2F_V2), SW_NO_ERROR);
            return m_big_len;
        case U2F_INS_REGISTER:
            return (m_big_len = do_register(body, lc, m_big));
        case U2F_INS_AUTHENTICATE:
            return (m_big_len = do_authenticate(p1, body, lc, m_big));
        }
    }

    m_big_len = put_sw(m_big, 0, SW_INS_NOT_SUPPORTED);
    return m_big_len;
}

/* Emit the next response chunk (ISO7816 chaining). If more remains, the chunk
 * ends with 61 XX and the reader follows up with GET RESPONSE (00 C0 ..). */
static void emit_chunk(void){
    uint16_t remain = m_big_len - m_big_off;
    m_tcl.m_tx_chaining = false;          /* U2F path never layer-4 chains */
    /* U2F/CTAP1 path: 58-byte ISO7816 GET-RESPONSE chunks (fits a 64-byte-FIFO
     * reader). CTAP2 responses use layer-4 chaining instead (see emit_ctap). */
    uint16_t max = 58;
    if (remain <= max) {
        memcpy(m_tcl.m_resp_buf, m_big + m_big_off, remain);
        m_tcl.m_resp_len = remain;
        m_big_off = m_big_len;                        /* done */
    } else {
        /* send `max` payload bytes (no SW yet) then 61 XX */
        memcpy(m_tcl.m_resp_buf, m_big + m_big_off, max);
        m_big_off += max;
        uint16_t left = m_big_len - m_big_off - 2;    /* bytes still owed (excl final SW) */
        uint8_t xx = left > 0xFF ? 0x00 : (uint8_t)left;
        m_tcl.m_resp_buf[max]   = 0x61;
        m_tcl.m_resp_buf[max+1] = xx;
        m_tcl.m_resp_len = max + 2;
    }
    m_tcl.m_response_ready = true;
}

/* Hand the whole CTAP2 response to the engine for ISO-DEP layer-4 chaining:
 * it goes out in <=58-byte I-block fragments, each ACKed by the reader. This
 * works for a 64-byte-FIFO reader (a second CU) and for a phone alike, unlike a
 * single large frame or ISO7816 61 XX (which this phone won't continue). */
static void emit_ctap(void){
    uint16_t len = m_big_len;
    if (len > NFC_14A_4_MAX_APDU) len = NFC_14A_4_MAX_APDU;   /* CTAP resp fits (<=~211) */
    memcpy(m_tcl.m_resp_buf, m_big, len);
    m_tcl.m_resp_len = len;

    /* Fragment to the reader's advertised frame size (RATS FSDI) minus PCB+CRC.
     * A phone (FSD 256) takes the whole response in one frame — no chaining. A
     * 64-byte-FIFO reader (a second CU) advertises a small FSD and gets it in
     * chained I-block fragments it can actually receive. */
    uint16_t fsd = nfc_tag_14a_get_reader_fsd();
    uint16_t frag = (fsd > 3) ? (fsd - 3) : 58;              /* 1 PCB + 2 CRC */
    if (frag > NFC_14A_4_MAX_APDU) frag = NFC_14A_4_MAX_APDU;
    m_tcl.m_tx_off      = 0;
    m_tcl.m_tx_frag     = frag;
    m_tcl.m_tx_chaining = (len > frag);
    m_tcl.m_response_ready = true;
}

/* ===================================================================== */
/*  ISO-DEP handler (ISR) — delegate framing to the 14a_4 engine          */
/* ===================================================================== */
static void u2f_cb_state(uint8_t *data, uint16_t szBits){
    /* nfc_14a delivers the frame length in BITS; the 14a_4 engine works in
     * bytes. ISO-DEP frames are byte-aligned, so divide. */
    uint16_t szBytes = szBits / 8;
    if (!nfc_tag_14a_4_base_handler(&m_tcl, data, szBytes)) return;

    /* Complete APDU assembled. Hold the reader with S(WTX) and build the answer
     * in on_tick — far too slow for the ISR once ECDSA is involved. */
    nfc_tag_14a_4_base_respond(&m_tcl);
}

static void u2f_cb_reset(void){
    nfc_tag_14a_4_reset_state(&m_tcl);
    m_big_len = 0; m_big_off = 0;
}

static nfc_tag_14a_handler_t s_handler = {
    .get_coll_res = u2f_get_coll_res,
    .cb_state     = u2f_cb_state,
    .cb_reset     = u2f_cb_reset,
};

/* ===================================================================== */
/*  Lifecycle                                                             */
/* ===================================================================== */
static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len){
    (void)cfg; (void)cfg_len;

    uECC_set_rng(u2f_rng);

    /* attestation key: provisioned (FDS) overrides the compiled fallback */
    uint16_t apl = sizeof(m_att_priv);
    if (!fds_read_sync(U2F_FDS_FILE, U2F_FDS_KEY_ATT_PRIV, &apl, m_att_priv) || apl != sizeof(m_att_priv))
        memcpy(m_att_priv, U2F_ATT_PRIV_DEFAULT, sizeof(m_att_priv));

    /* makerdiary-style counter persistence: load. */
    {
        uint32_t c = 0; uint16_t cl = sizeof(c);
        if (fds_read_sync(U2F_FDS_FILE, U2F_FDS_KEY_CTR, &cl, (uint8_t *)&c) && cl == sizeof(c))
            u2f_impl_set_counter(c);
    }

    /* Initialize Cryptocell-backed crypto (makerdiary reference backend). */
    (void)nrf_crypto_init();

    /* Populate vendored makerdiary globals from runtime-provisioned material. */
    memcpy(attestation_private_key, m_att_priv, sizeof(m_att_priv));
    attestation_private_key_size = sizeof(m_att_priv);
    /* aes_key: derive a per-device key from the attestation key (first 16 bytes). */
    memcpy(aes_key, m_att_priv, 16);
    /* attestation cert */
    uint16_t cert_apl = 512;
    if (!fds_read_sync(U2F_FDS_FILE, U2F_FDS_KEY_ATT_CERT, &cert_apl, attestation_cert) || cert_apl < 2) {
        attestation_cert[0] = 0x30; attestation_cert[1] = 0x00; cert_apl = 2;
    }
    attestation_cert_size = cert_apl;

    /* Arm the shared core: it loads (or creates) the master key + counter and
     * enables the three FIDO transports. */
    m_clock_ticks = app_timer_cnt_get();
    m_clock_ms = 0;
    fido2_core_init(&m_core_io);
    /* Only offer the transports that are really there: NFC always works, USB
     * needs the HID class and BLE needs the FIDO GATT service. A transport
     * that failed to register is left out instead of being advertised. */
    uint8_t transports = FIDO2_TRANSPORT_NFC;
    if (fido2_hid_available()) transports |= FIDO2_TRANSPORT_USB;
    if (ble_fido_svc_available()) transports |= FIDO2_TRANSPORT_BLE;
    if (!fido2_core_arm(transports)) {
        NRF_LOG_ERROR("u2f: core arm failed");
        return STANDALONE_RC_INVALID_STATE;
    }
    fido2_hid_init();
    fido2_ble_reset();

    if (!u2f_rng(m_uid, sizeof(m_uid))) return STANDALONE_RC_INVALID_STATE;
    m_uid[0] = 0x08;   /* RID-style first byte; avoids 0x88 cascade marker clash */

    nfc_tag_14a_4_reset_state(&m_tcl);
    m_big_len = 0; m_big_off = 0;
    m_ctap2_pending = false;

    nfc_tag_14a_set_handler(&s_handler);
    nfc_tag_14a_set_relay_hold(true);    /* keep FRAMEDELAYMAX wide for slow ECDSA */
    nfc_tag_14a_sense_switch(false);
    nfc_tag_14a_sense_switch(true);

    standalone_led_set_mode_color(STANDALONE_MODE_U2F, RGB_BLUE);
    standalone_led_solid();
    NRF_LOG_INFO("u2f: armed transports=%u", fido2_core_transport_mask());
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void){
    fido2_core_disarm();
    fido2_hid_init();
    fido2_ble_reset();
    nfc_tag_14a_set_relay_hold(false);
    nfc_tag_14a_set_frame_delay_max(0x00001000UL);
    nfc_tag_14a_set_state(NFC_TAG_STATE_14A_IDLE);
    return STANDALONE_RC_OK;
}

/* NFC half of the tick: hand the finished CTAP2 answer to the ISO-DEP layer,
 * or process a pending APDU. */
static void nfc_poll(void){
    /* A CTAP2 answer finished in the core? */
    if (fido2_response_ready(FIDO2_OWNER_NFC)) {
        size_t rlen = 0;
        if (fido2_take_response(FIDO2_OWNER_NFC, m_ctap_resp, sizeof(m_ctap_resp), &rlen)) {
            if (rlen > sizeof(m_big) - 2) rlen = sizeof(m_big) - 2;
            memcpy(m_big, m_ctap_resp, rlen);
            m_big_len = put_sw(m_big, (uint16_t)rlen, SW_NO_ERROR);
            m_big_off = m_big_len;        /* the whole answer goes out at once */
            m_ctap2_pending = false;
            m_ctap2_resp = true;
            emit_ctap();
        }
        return;
    }

    if (!m_tcl.m_apdu_pending) return;
    m_tcl.m_apdu_pending = false;

    /* The NFCT RX leaves the 2-byte ISO14443 CRC on the frame (hardware CRC
     * strip is off and the 14a_4 layer doesn't remove it), so drop it before
     * parsing — otherwise a body-less APDU's absent Lc reads the CRC as an
     * extended length and fails. */
    uint16_t alen = m_tcl.m_apdu_len >= 2 ? m_tcl.m_apdu_len - 2 : 0;
    uint8_t cla = alen >= 1 ? m_tcl.m_apdu_buf[0] : 0;
    uint8_t ins = alen >= 2 ? m_tcl.m_apdu_buf[1] : 0;
    /* Chained-response continuation: ISO GET RESPONSE (00 C0) for U2F, or
     * NFCCTAP_GETRESPONSE (80 11) for CTAP2 — both signalled by our 61 XX. */
    bool getresp = (cla == 0x00 && ins == ISO_INS_GET_RESPONSE) ||
                   (cla == 0x80 && ins == NFCCTAP_GETRESPONSE);
    if (getresp && m_big_off < m_big_len) {
        emit_chunk();
        return;
    }
    u2f_process(m_tcl.m_apdu_buf, alen);
    if (m_ctap2_pending) return;           /* core is still working on it */
    if (m_ctap2_resp) {
        emit_ctap();                  /* CTAP2: layer-4 chained response */
    } else {
        m_big_off = 0;
        emit_chunk();                 /* U2F: 61 XX GET-RESPONSE chunks */
    }
}

static standalone_rc_t on_tick(uint32_t now_ms){
    (void)now_ms;
    /* Capture state before tick to detect transitions. */
    bool was_pending = fido2_has_pending_request();
    fido2_tick();          /* run the queued CTAP2 command (crypto included) */
    bool response_ready = fido2_response_ready_any();   /* check BEFORE hid_poll resets state */
    fido2_hid_poll();      /* USB CTAPHID: emit the next response packet    */
    fido2_ble_poll();      /* BLE FIDO GATT: emit the next response fragment */
    nfc_poll();            /* NFC: CTAP2 answer / APDU processing           */

    /* LED color reflects CTAP2 state. We track a simple state machine:
     *   blue   = armed, idle
     *   purple = UP granted (5 s window)
     *   yellow = processing
     *   green  = success (1 s)
     *   red    = error (1 s) */
    static uint8_t m_led_state = 0;   /* 0=idle,1=up,2=proc,3=done,4=err */
    static uint16_t m_led_timer = 0;  /* ticks remaining for done state */
    static uint8_t m_breath_phase = 0;

    if (m_led_state == 3) {
        /* Green breathing wave. */
        uint32_t *leds = hw_get_led_array();
        set_slot_light_color(RGB_GREEN);
        if (m_breath_phase < 8) {
            for (uint8_t i = 0; i < RGB_LIST_NUM; i++) {
                if (i <= m_breath_phase) nrf_gpio_pin_clear(leds[i]);
                else                      nrf_gpio_pin_set(leds[i]);
            }
        } else {
            uint8_t off = m_breath_phase - 8;
            for (uint8_t i = 0; i < RGB_LIST_NUM; i++) {
                if (i <= off) nrf_gpio_pin_set(leds[i]);
                else           nrf_gpio_pin_clear(leds[i]);
            }
        }
        if (++m_breath_phase >= 16) m_breath_phase = 0;
    }

    if (m_led_timer > 0) {
        m_led_timer--;
        if (m_led_timer == 0) {
            standalone_led_set_mode_color(STANDALONE_MODE_U2F, RGB_BLUE);
            standalone_led_solid();
            m_led_state = 0;
            m_breath_phase = 0;
        }
    }

    /* Detect state transitions. */
    if (was_pending && response_ready) {
        /* Completed this tick. */
        if (fido2_last_response_status() == 0x00) {
            m_led_state = 3;          /* green breathing */
            m_led_timer = 200;         /* 1 s at 5 ms/tick */
            m_breath_phase = 0;
        } else {
            standalone_led_set_mode_color(STANDALONE_MODE_U2F, RGB_RED);
            standalone_led_solid();
            m_led_state = 4;          /* red solid */
            m_led_timer = 200;         /* 1 s at 5 ms/tick */
        }
    } else if (was_pending) {
        /* Still processing. */
        if (m_led_state != 2) {
            standalone_led_set_mode_color(STANDALONE_MODE_U2F, RGB_YELLOW);
            standalone_led_solid();
            m_led_state = 2;
        }
    } else if (fido2_up_granted()) {
        if (m_led_state != 1) {
            standalone_led_set_mode_color(STANDALONE_MODE_U2F, RGB_MAGENTA);
            standalone_led_solid();
            m_led_state = 1;
        }
    } else {
        /* Nothing pending, UP expired. */
        if (m_led_state != 0 && m_led_timer == 0) {
            standalone_led_set_mode_color(STANDALONE_MODE_U2F, RGB_BLUE);
            standalone_led_solid();
            m_led_state = 0;
        }
    }

    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    if (evt == STANDALONE_BTN_BOTH_SHORT) {
        fido2_grant_user_presence();   /* LED turns purple via on_tick */
    } else if (evt == STANDALONE_BTN_BOTH_LONG) {
        /* Allow disarm via long press when no STANDALONE_TOGGLE binding exists. */
        fido2_core_disarm();
        standalone_led_set_mode_color(STANDALONE_MODE_U2F, RGB_BLUE);
        standalone_led_clear();
    }
    return STANDALONE_RC_OK;
}

const standalone_mode_iface_t mode_u2f_iface = {
    .id               = STANDALONE_MODE_U2F,
    .name             = "u2f",
    .writes_tag       = false,
    .writes_slot      = false,
    .wants_tick       = true,
    .requires_physical_user_presence = true,
    .tick_interval_ms = 5,          /* answer APDUs promptly within the WTX window */
    .on_enter         = on_enter,
    .on_exit          = on_exit,
    .on_button        = on_button,
    .on_tick          = on_tick,
    .get_result_size  = NULL,
    .read_result      = NULL,
    .clear_result     = NULL,
    .ensure_loaded    = NULL,
};
