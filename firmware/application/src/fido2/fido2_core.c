/* CTAP2 / CTAP1 state machine. Deliberately free of SDK headers so the core
   can be exercised by the host tests with stub crypto/credentials backends. */
#include "fido2/fido2_core.h"

#include <stdio.h>
#include <string.h>

#include "fido2/fido2_attestation.h"
#include "fido2/fido2_cbor.h"
#include "fido2/fido2_creds.h"
#include "fido2/fido2_format.h"
#include "fido2/fido2_transport.h"

/* Keep the core free of SDK headers when built by host tests. Host stubs
   provide nrf_log.h without the SDK's module-registration macro. */
#if defined(__has_include)
#  if __has_include("nrf_log.h")
#    define NRF_LOG_MODULE_NAME f2_core
#    include "nrf_log.h"
#    if defined(NRF_LOG_MODULE_REGISTER) && defined(NRF_LOG_ERROR)
#      define F2_CORE_LOG_ENABLED 1
      NRF_LOG_MODULE_REGISTER();
#    endif
#  endif
#endif
#ifdef F2_CORE_LOG_ENABLED
#define F2_CORE_LOG_ERROR(...) NRF_LOG_ERROR(__VA_ARGS__)
#else
#define F2_CORE_LOG_ERROR(...) ((void)0)
#endif

/* fido2_crypto.h's ret_code_t is uint32_t; restate the ABI locally. */
uint32_t f2_crypto_keygen(uint8_t priv[32], uint8_t pub[64]);
uint32_t f2_crypto_sign(const uint8_t priv[32], const uint8_t hash32[32],
                        uint8_t der[72], size_t *der_len);
uint32_t f2_crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
uint32_t f2_crypto_random(uint8_t *out, size_t len);

#define F2_KA_PROCESSING 0x02u
#define F2_KA_UP_NEEDED  0x03u
#define F2_KA_PERIOD_MS  300u
#define F2_SIGN_CAP      256u    /* authData (<=196) + clientDataHash (32) */
#define F2_RESET_WINDOW_MS 10000u
#define F2_ST_NOT_ALLOWED 0x30u

typedef enum {
    F2_GATE_STATE_IDLE = 0,
    F2_GATE_STATE_WAIT,
    F2_GATE_STATE_GRANTED
} f2_gate_state_t;

typedef struct {
    uint8_t id[FIDO2_CRED_ID_MAX];
    uint8_t id_len;
    uint8_t rp_hash[32];
} f2_assert_entry_t;

static uint8_t          m_sign_buf[F2_SIGN_CAP];
static uint8_t          m_cose[77];
static uint8_t          m_der[72];
static uint8_t          m_pub65[65];
static uint8_t          m_rp_hash[32];
static uint8_t          m_assert_hash[32];
static fido2_cred_rec_t m_rec;
static fido2_cbor_w_t   m_writer;

static f2_assert_entry_t m_asserts[FIDO2_MAX_CREDENTIALS];
static uint8_t m_assert_count;
static uint8_t m_assert_cursor;
static bool    m_assert_uv;
static bool    m_assert_up_suppressed;

static f2_gate_state_t m_gate_state;
static fido2_gate_t    m_gate;
static uint32_t        m_now_ms;
static uint32_t        m_gate_start;
static uint32_t        m_gate_ka;
static bool            m_granted_uv;
static bool            m_pregrant;
static fido2_gate_t    m_pregrant_gate;
static bool            m_timeout_armed;
static uint8_t         m_timeout_status;
static fido2_transport_t m_active_transport = FIDO2_TRANSPORT_USB;
static fido2_transport_t m_gate_transport   = FIDO2_TRANSPORT_USB;
static uint32_t        m_boot_ms;
static bool            m_boot_ts_set;

/* ---- gate --------------------------------------------------------------- */

static void gate_clear(void)
{
    m_gate_state = F2_GATE_STATE_IDLE;
    m_gate = FIDO2_GATE_NONE;
    m_granted_uv = false;
}

/* Returns FIDO2_ST_OK when authorized, F2_CORE_PENDING when waiting, or a
   CTAP error byte (e.g. a pending timeout) without arming a new gate. */
static uint8_t gate_begin(fido2_gate_t want)
{
    const fido2_transport_api_t *api;

    if (m_gate_state == F2_GATE_STATE_WAIT) {
        /* Transports may re-dispatch the held request on every tick; keep the
           original timeout and UP_NEEDED keepalive schedule intact. */
        return F2_CORE_PENDING;
    }
    if (m_gate_state != F2_GATE_STATE_IDLE) {
        if (m_gate_state == F2_GATE_STATE_GRANTED &&
            (m_granted_uv || m_gate == want)) {
            gate_clear();
            api = f2_transport_get(m_gate_transport);
            if (api != NULL && api->keepalive != NULL) {
                api->keepalive(F2_KA_PROCESSING);
            }
            return FIDO2_ST_OK;
        }
        gate_clear();
    }
    if (m_pregrant) {
        bool satisfied = (m_pregrant_gate == FIDO2_GATE_UV) ||
                         (m_pregrant_gate == want);
        m_pregrant = false;
        if (satisfied) {
            m_gate_transport = m_active_transport;
            api = f2_transport_get(m_gate_transport);
            if (api != NULL && api->keepalive != NULL) {
                api->keepalive(F2_KA_PROCESSING);
            }
            return FIDO2_ST_OK;
        }
    }
    if (m_timeout_armed) {
        uint8_t st = m_timeout_status;
        m_timeout_armed = false;
        return st;
    }

    m_gate_transport = m_active_transport;  /* new gate: origin is this transport */
    m_gate = want;
    m_gate_state = F2_GATE_STATE_WAIT;
    m_gate_start = m_now_ms;
    m_gate_ka = m_now_ms;
    return F2_CORE_PENDING;
}

/* U2F has no keepalive handshake: a button press must already be latched. */
static bool consume_up_now(void)
{
    if (m_pregrant) {
        m_pregrant = false;
        return true;
    }
    if (m_gate_state == F2_GATE_STATE_GRANTED &&
        (m_granted_uv || m_gate == FIDO2_GATE_UP)) {
        gate_clear();
        return true;
    }
    return false;
}

fido2_status_t f2_core_grant(fido2_gate_t gate)
{
    if (gate != FIDO2_GATE_UP && gate != FIDO2_GATE_UV) {
        return FIDO2_ST_INVALID_PARAM;
    }
    if (m_gate_state != F2_GATE_STATE_IDLE) {
        if (m_gate == FIDO2_GATE_UV && gate != FIDO2_GATE_UV) {
            return FIDO2_ST_UV_INVALID;
        }
        const fido2_transport_api_t *api = f2_transport_get(m_gate_transport);

        m_granted_uv = (gate == FIDO2_GATE_UV);
        m_gate_state = F2_GATE_STATE_GRANTED;
        m_timeout_armed = false;
        if (api != NULL && api->keepalive != NULL) {
            api->keepalive(F2_KA_PROCESSING);
        }
        return FIDO2_ST_OK;
    }
    m_pregrant = true;
    m_pregrant_gate = gate;
    return FIDO2_ST_OK;
}

/* Silent disarm/reset: no status is emitted to any transport. */
void f2_core_cancel(void)
{
    gate_clear();
    m_pregrant = false;
    m_timeout_armed = false;
}

/* CTAP CANCEL: report 0x2D on the gated request's own transport, then disarm.
   The CANCEL command itself gets no response. */
void f2_core_cancel_request(void)
{
    if (m_gate_state != F2_GATE_STATE_IDLE) {
        const fido2_transport_api_t *api = f2_transport_get(m_gate_transport);
        if (api != NULL && api->send != NULL) {
            const uint8_t st = (uint8_t)FIDO2_ST_KEEPALIVE_CANCEL;
            api->send(&st, 1u);
        }
    }
    f2_core_cancel();
}

bool f2_core_gate_pending(void)
{
    return m_gate_state != F2_GATE_STATE_IDLE;
}

void f2_core_tick(uint32_t now_ms)
{
    const fido2_transport_api_t *api;
    uint32_t elapsed;

    if (!m_boot_ts_set) {
        m_boot_ms = now_ms;
        m_boot_ts_set = true;
    }
    m_now_ms = now_ms;
    if (m_gate_state != F2_GATE_STATE_WAIT) {
        return;
    }
    api = f2_transport_get(m_gate_transport);

    elapsed = now_ms - m_gate_start;   /* uint32 wrap-safe */
    if (elapsed >= FIDO2_CTAP_TIMEOUT_MS) {
        uint8_t st = (m_gate == FIDO2_GATE_UV) ? (uint8_t)FIDO2_ST_UV_INVALID
                                               : (uint8_t)FIDO2_ST_UP_REQUIRED;
        gate_clear();
        m_timeout_armed = true;
        m_timeout_status = st;
        if (api != NULL && api->send != NULL) {
            api->send(&st, 1u);
        }
        return;
    }
    if ((uint32_t)(now_ms - m_gate_ka) >= F2_KA_PERIOD_MS) {
        m_gate_ka = now_ms;
        if (api != NULL && api->keepalive != NULL) {
            api->keepalive(m_gate == FIDO2_GATE_UV ? F2_KA_PROCESSING : F2_KA_UP_NEEDED);
        }
    }
}

void f2_core_init(void)
{
    gate_clear();
    m_pregrant = false;
    m_timeout_armed = false;
    m_active_transport = FIDO2_TRANSPORT_USB;
    m_gate_transport = FIDO2_TRANSPORT_USB;
    m_assert_count = 0u;
    m_assert_cursor = 0u;
    m_assert_uv = false;
    m_assert_up_suppressed = false;
    memset(m_asserts, 0, sizeof(m_asserts));
    memset(m_assert_hash, 0, sizeof(m_assert_hash));
}

size_t f2_core_status(char *out, size_t cap)
{
    const char *gate = "NONE";
    unsigned uv = 0u;
    uint16_t cursor = 0u;
    unsigned count = 0u;
    int n;

    if (out == NULL || cap == 0u) {
        return 0u;
    }
    if (m_gate_state != F2_GATE_STATE_IDLE) {
        gate = (m_gate == FIDO2_GATE_UV) ? "UV" : "UP";
    }
    if ((m_gate_state != F2_GATE_STATE_IDLE &&
         (m_gate == FIDO2_GATE_UV || m_granted_uv)) ||
        (m_pregrant && m_pregrant_gate == FIDO2_GATE_UV)) {
        uv = 1u;
    }
    while (count < 1000u &&
           f2_creds_next(&cursor, &m_rec) == FIDO2_ST_OK) {
        count++;
    }
    n = snprintf(out, cap, "gate=%s,uv=%u,creds=%u\n", gate, uv, count);
    if (n < 0) {
        out[0] = '\0';
        return 0u;
    }
    return ((size_t)n >= cap) ? cap - 1u : (size_t)n;
}

/* ---- small CBOR helpers ------------------------------------------------- */

static bool text_is(const uint8_t *p, size_t len, const char *s)
{
    size_t n = strlen(s);
    return len == n && memcmp(p, s, n) == 0;
}

/* Skip one CBOR value of any supported type (including arrays/maps). */
static bool skip_value(fido2_cbor_r_t *r, unsigned depth)
{
    uint8_t first;
    unsigned major, ai;
    uint64_t v = 0u;
    size_t extra = 0u;

    if (depth > 8u || r->failed || r->pos >= r->len) {
        r->failed = true;
        return false;
    }
    first = r->buf[r->pos];
    major = (unsigned)(first >> 5);
    ai = (unsigned)(first & 0x1Fu);
    if (ai < 24u) {
        v = ai;
    } else if (ai <= 27u) {
        extra = 1u << (ai - 24u);
        if (extra > r->len - r->pos - 1u) {
            r->failed = true;
            return false;
        }
        for (size_t i = 0u; i < extra; i++) {
            v = (v << 8) | r->buf[r->pos + 1u + i];
        }
    } else {
        r->failed = true;
        return false;
    }
    r->pos += 1u + extra;

    if (major <= 1u || major == 7u) {
        return true;
    }
    if (major == 2u || major == 3u) {
        if (v > (uint64_t)(r->len - r->pos)) {
            r->failed = true;
            return false;
        }
        r->pos += (size_t)v;
        return true;
    }
    if (major == 4u) {
        if (v > (uint64_t)(r->len - r->pos)) {
            r->failed = true;
            return false;
        }
        for (uint64_t i = 0u; i < v; i++) {
            if (!skip_value(r, depth + 1u)) {
                return false;
            }
        }
        return true;
    }
    if (major == 5u) {
        if (v > (uint64_t)((r->len - r->pos) / 2u)) {
            r->failed = true;
            return false;
        }
        for (uint64_t i = 0u; i < v; i++) {
            if (!skip_value(r, depth + 1u) || !skip_value(r, depth + 1u)) {
                return false;
            }
        }
        return true;
    }
    r->failed = true;
    return false;
}

/* ---- response helpers --------------------------------------------------- */

static uint8_t ctap_error(uint8_t st, uint8_t *resp, size_t resp_max,
                          size_t *resp_len)
{
    if (resp_len != NULL) {
        *resp_len = 0u;
    }
    if (resp != NULL && resp_max != 0u) {
        resp[0] = st;
        if (resp_len != NULL) {
            *resp_len = 1u;
        }
    }
    return st;
}

static uint8_t emit(uint8_t st, size_t cbor_len, uint8_t *resp,
                    size_t resp_max, size_t *resp_len)
{
    if (resp_len != NULL) {
        *resp_len = 0u;
    }
    if (resp == NULL || resp_max == 0u) {
        return st;
    }
    resp[0] = st;
    if (st != FIDO2_ST_OK || cbor_len == 0u || cbor_len > resp_max - 1u) {
        if (st == FIDO2_ST_OK) {
            resp[0] = (uint8_t)FIDO2_ST_OTHER;
            st = FIDO2_ST_OTHER;
        }
        if (resp_len != NULL) {
            *resp_len = 1u;
        }
        return st;
    }
    if (resp_len != NULL) {
        *resp_len = 1u + cbor_len;
    }
    return st;
}

static uint8_t gate_result(uint8_t gs, uint8_t *resp, size_t resp_max,
                           size_t *resp_len)
{
    if (gs == F2_CORE_PENDING) {
        if (resp_len != NULL) {
            *resp_len = 0u;
        }
        return gs;
    }
    return ctap_error(gs, resp, resp_max, resp_len);
}

static uint8_t emit_empty(uint8_t *resp, size_t resp_max, size_t *resp_len)
{
    if (resp_len != NULL) {
        *resp_len = 0u;
    }
    if (resp == NULL || resp_max == 0u) {
        return FIDO2_ST_OK;
    }
    resp[0] = FIDO2_ST_OK;
    if (resp_len != NULL) {
        *resp_len = 1u;
    }
    return FIDO2_ST_OK;
}

/* ---- CTAP2 commands ----------------------------------------------------- */

static uint8_t cmd_get_info(uint8_t *resp, size_t resp_max, size_t *resp_len)
{
    static const uint8_t aaguid[FIDO2_AAGUID_LEN] = FIDO2_AAGUID_BYTES;

    if (resp == NULL || resp_max < 2u) {
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }
    cw_init(&m_writer, resp + 1u, resp_max - 1u);
    cw_map(&m_writer, 8u);

    cw_uint(&m_writer, 1u);
    cw_array(&m_writer, 2u);
    cw_text(&m_writer, "U2F_V2", 6u);
    cw_text(&m_writer, "FIDO_2_0", 8u);

    cw_uint(&m_writer, 3u);
    cw_bytes(&m_writer, aaguid, sizeof(aaguid));

    cw_uint(&m_writer, 4u);
    cw_map(&m_writer, 4u);
    cw_text(&m_writer, "rk", 2u);        cw_bool(&m_writer, true);
    cw_text(&m_writer, "up", 2u);        cw_bool(&m_writer, true);
    cw_text(&m_writer, "uv", 2u);        cw_bool(&m_writer, true);
    cw_text(&m_writer, "clientPin", 9u); cw_bool(&m_writer, false);

    cw_uint(&m_writer, 5u);
    cw_uint(&m_writer, 1024u);

    cw_uint(&m_writer, 7u);
    cw_uint(&m_writer, FIDO2_MAX_CREDENTIALS);

    cw_uint(&m_writer, 8u);
    cw_uint(&m_writer, FIDO2_CRED_ID_MAX);

    cw_uint(&m_writer, 9u);
    cw_array(&m_writer, 3u);
    cw_text(&m_writer, "usb", 3u);
    cw_text(&m_writer, "nfc", 3u);
    cw_text(&m_writer, "ble", 3u);

    cw_uint(&m_writer, 0x0Au);
    cw_array(&m_writer, 1u);
    cw_map(&m_writer, 2u);
    /* Canonical order: "alg" (0x63) sorts before "type" (0x64). */
    cw_text(&m_writer, "alg", 3u);  cw_int(&m_writer, -7);
    cw_text(&m_writer, "type", 4u); cw_text(&m_writer, "public-key", 10u);

    return emit(FIDO2_ST_OK, cw_finish(&m_writer), resp, resp_max, resp_len);
}

static bool want_uv(const fido2_request_t *ctx, bool options_uv)
{
    return options_uv || (ctx != NULL && ctx->uv_requested);
}

static uint8_t cmd_make_credential(const uint8_t *req, size_t req_len,
                                   const fido2_request_t *ctx,
                                   uint8_t *resp, size_t resp_max, size_t *resp_len)
{
    fido2_cbor_r_t r;
    const uint8_t *client_hash = NULL, *rp_id = NULL, *user_id = NULL;
    size_t client_hash_len = 0u, rp_id_len = 0u, user_id_len = 0u;
    bool have_ch = false, have_rp = false, have_user = false;
    bool have_params = false, alg_ok = false, options_uv = false;
    uint8_t gs, flags;
    bool uv;
    size_t n, cose_len, auth_len, der_len;
    uint8_t hash[32];
    uint32_t rc;
    fido2_status_t cs;
    uint8_t st;

    m_assert_count = 0u;
    m_assert_cursor = 0u;

    cr_init(&r, req + 1u, req_len - 1u);
    if (!cr_map(&r, &n)) {
        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
    }
    for (size_t i = 0u; i < n; i++) {
        uint64_t key;
        if (!cr_uint(&r, &key)) {
            return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
        }
        switch ((unsigned)key) {
        case 1u:
            if (!cr_bytes(&r, &client_hash, &client_hash_len) ||
                client_hash_len != 32u) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            have_ch = true;
            break;
        case 2u: {
            size_t m;
            if (!cr_map(&r, &m)) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            for (size_t j = 0u; j < m; j++) {
                const uint8_t *k;
                size_t klen;
                if (!cr_text(&r, &k, &klen)) {
                    return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                }
                if (text_is(k, klen, "id")) {
                    if (!cr_text(&r, &rp_id, &rp_id_len) || rp_id_len == 0u) {
                        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                    }
                } else if (!skip_value(&r, 0u)) {
                    return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                }
            }
            have_rp = (rp_id != NULL);
            break;
        }
        case 3u: {
            size_t m;
            if (!cr_map(&r, &m)) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            for (size_t j = 0u; j < m; j++) {
                const uint8_t *k;
                size_t klen;
                if (!cr_text(&r, &k, &klen)) {
                    return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                }
                if (text_is(k, klen, "id")) {
                    if (!cr_bytes(&r, &user_id, &user_id_len) ||
                        user_id_len == 0u || user_id_len > FIDO2_USER_ID_MAX) {
                        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                    }
                } else if (!skip_value(&r, 0u)) {
                    return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                }
            }
            have_user = (user_id != NULL);
            break;
        }
        case 4u: {
            size_t cnt;
            if (!cr_array(&r, &cnt)) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            for (size_t j = 0u; j < cnt; j++) {
                size_t m;
                const uint8_t *type = NULL;
                size_t type_len = 0u;
                int64_t alg = 0;
                bool have_alg = false;
                if (!cr_map(&r, &m)) {
                    return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                }
                for (size_t k = 0u; k < m; k++) {
                    const uint8_t *fk;
                    size_t fklen;
                    if (!cr_text(&r, &fk, &fklen)) {
                        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                    }
                    if (text_is(fk, fklen, "type")) {
                        if (!cr_text(&r, &type, &type_len)) {
                            return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                        }
                    } else if (text_is(fk, fklen, "alg")) {
                        if (!cr_int(&r, &alg)) {
                            return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                        }
                        have_alg = true;
                    } else if (!skip_value(&r, 0u)) {
                        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                    }
                }
                if (have_alg && type != NULL &&
                    text_is(type, type_len, "public-key") && alg == -7) {
                    alg_ok = true;
                }
            }
            have_params = true;
            break;
        }
        case 5u: {
            size_t cnt;
            if (!cr_array(&r, &cnt)) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            for (size_t j = 0u; j < cnt; j++) {
                size_t m;
                const uint8_t *id = NULL;
                size_t id_len = 0u;
                if (!cr_map(&r, &m)) {
                    return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                }
                for (size_t k = 0u; k < m; k++) {
                    const uint8_t *fk;
                    size_t fklen;
                    if (!cr_text(&r, &fk, &fklen)) {
                        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                    }
                    if (text_is(fk, fklen, "id")) {
                        if (!cr_bytes(&r, &id, &id_len)) {
                            return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                        }
                    } else if (!skip_value(&r, 0u)) {
                        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                    }
                }
                if (id == NULL || id_len == 0u || id_len > FIDO2_CRED_ID_MAX) {
                    return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                }
                if (f2_creds_find_by_id(id, id_len, &m_rec) == FIDO2_ST_OK) {
                    return ctap_error(FIDO2_ST_EXCLUDED, resp, resp_max, resp_len);
                }
            }
            break;
        }
        case 7u: {
            size_t m;
            if (!cr_map(&r, &m)) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            for (size_t j = 0u; j < m; j++) {
                const uint8_t *k;
                size_t klen;
                bool value;
                if (!cr_text(&r, &k, &klen) || !cr_bool(&r, &value)) {
                    return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                }
                if (value && text_is(k, klen, "uv")) {
                    options_uv = true;
                }
            }
            break;
        }
        default:
            if (!skip_value(&r, 0u)) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            break;
        }
    }
    if (r.failed || r.pos != r.len ||
        !have_ch || !have_rp || !have_user || !have_params) {
        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
    }
    if (!alg_ok) {
        return ctap_error(FIDO2_ST_UNSUPPORTED_ALG, resp, resp_max, resp_len);
    }

    uv = want_uv(ctx, options_uv);
    gs = gate_begin(uv ? FIDO2_GATE_UV : FIDO2_GATE_UP);
    if (gs != FIDO2_ST_OK) {
        return gate_result(gs, resp, resp_max, resp_len);
    }
    flags = FIDO2_FLAG_UP | (uv ? FIDO2_FLAG_UV : 0u) | FIDO2_FLAG_AT;

    memset(&m_rec, 0, sizeof(m_rec));
    rc = f2_crypto_keygen(m_rec.priv, m_rec.pub);
    if (rc != 0u) {
        F2_CORE_LOG_ERROR("fido2: makeCredential failed at keygen rc=0x%x", (unsigned)rc);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }
    rc = f2_crypto_random(m_rec.cred_id, 32u);
    if (rc != 0u) {
        F2_CORE_LOG_ERROR("fido2: makeCredential failed at random rc=0x%x", (unsigned)rc);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }
    rc = f2_crypto_sha256(rp_id, rp_id_len, m_rec.rp_hash);
    if (rc != 0u) {
        F2_CORE_LOG_ERROR("fido2: makeCredential failed at rp_hash rc=0x%x", (unsigned)rc);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }
    m_rec.cred_id_len = 32u;
    memcpy(m_rec.user_id, user_id, user_id_len);
    m_rec.user_id_len = (uint16_t)user_id_len;
    m_rec.cred_protect = 1u;
    cs = f2_creds_add(&m_rec);
    if (cs != FIDO2_ST_OK) {
        F2_CORE_LOG_ERROR("fido2: makeCredential failed at creds_add rc=0x%x", (unsigned)cs);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }

    cose_len = fmt_cose_key(m_cose, m_rec.pub);
    if (cose_len == 0u) {
        F2_CORE_LOG_ERROR("fido2: makeCredential failed at cose");
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }
    auth_len = fmt_auth_data(m_sign_buf, sizeof(m_sign_buf), m_rec.rp_hash,
                             flags, 0u, m_rec.cred_id, m_rec.cred_id_len,
                             m_cose, cose_len);
    if (auth_len == 0u || auth_len + 32u > sizeof(m_sign_buf)) {
        F2_CORE_LOG_ERROR("fido2: makeCredential failed at authdata len=%u", (unsigned)auth_len);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }
    memcpy(m_sign_buf + auth_len, client_hash, 32u);
    rc = f2_crypto_sha256(m_sign_buf, auth_len + 32u, hash);
    if (rc != 0u) {
        F2_CORE_LOG_ERROR("fido2: makeCredential failed at digest rc=0x%x", (unsigned)rc);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }
    der_len = sizeof(m_der);
    rc = f2_crypto_sign(m_rec.priv, hash, m_der, &der_len);
    if (rc != 0u) {
        F2_CORE_LOG_ERROR("fido2: makeCredential failed at sign rc=0x%x", (unsigned)rc);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }

    if (resp == NULL || resp_max < 2u) {
        F2_CORE_LOG_ERROR("fido2: makeCredential failed at response cap=%u", (unsigned)resp_max);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }
    cw_init(&m_writer, resp + 1u, resp_max - 1u);
    cw_map(&m_writer, 3u);
    cw_uint(&m_writer, 1u);
    cw_text(&m_writer, "packed", 6u);
    cw_uint(&m_writer, 2u);
    cw_bytes(&m_writer, m_sign_buf, auth_len);
    cw_uint(&m_writer, 3u);
    cw_map(&m_writer, 2u);
    cw_text(&m_writer, "alg", 3u);
    cw_int(&m_writer, -7);
    cw_text(&m_writer, "sig", 3u);
    cw_bytes(&m_writer, m_der, der_len);
    st = emit(FIDO2_ST_OK, cw_finish(&m_writer), resp, resp_max, resp_len);
    if (st != FIDO2_ST_OK) {
        F2_CORE_LOG_ERROR("fido2: makeCredential failed at emit cap=%u", (unsigned)resp_max);
    }
    return st;
}

static void assert_cache_add(const uint8_t *id, size_t id_len,
                             const uint8_t *rp_hash)
{
    if (m_assert_count >= FIDO2_MAX_CREDENTIALS || id_len > FIDO2_CRED_ID_MAX) {
        return;
    }
    memcpy(m_asserts[m_assert_count].id, id, id_len);
    m_asserts[m_assert_count].id_len = (uint8_t)id_len;
    memcpy(m_asserts[m_assert_count].rp_hash, rp_hash, 32u);
    m_assert_count++;
}

static uint8_t build_assertion(const uint8_t *id, size_t id_len,
                               const uint8_t *rp_hash, const uint8_t *client_hash,
                               bool uv, uint8_t n_creds,
                               uint8_t *resp, size_t resp_max, size_t *resp_len)
{
    uint32_t count = 0u;
    uint8_t flags;
    uint8_t hash[32];
    size_t cose_len, auth_len, der_len;
    uint32_t rc;
    uint8_t st;

    if (f2_creds_find_by_id(id, id_len, &m_rec) != FIDO2_ST_OK ||
        f2_creds_bump_sign_count(id, id_len, &count) != FIDO2_ST_OK) {
        return ctap_error(FIDO2_ST_NO_CREDENTIALS, resp, resp_max, resp_len);
    }
    flags = (m_assert_up_suppressed ? 0u : FIDO2_FLAG_UP) |
            (uv ? FIDO2_FLAG_UV : 0u);
    cose_len = fmt_cose_key(m_cose, m_rec.pub);
    if (cose_len == 0u) {
        F2_CORE_LOG_ERROR("fido2: assertion failed at cose");
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }
    auth_len = fmt_auth_data(m_sign_buf, sizeof(m_sign_buf), rp_hash, flags,
                             count, NULL, 0u, NULL, 0u);
    if (auth_len == 0u || auth_len + 32u > sizeof(m_sign_buf)) {
        F2_CORE_LOG_ERROR("fido2: assertion failed at authdata len=%u", (unsigned)auth_len);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }
    memcpy(m_sign_buf + auth_len, client_hash, 32u);
    rc = f2_crypto_sha256(m_sign_buf, auth_len + 32u, hash);
    if (rc != 0u) {
        F2_CORE_LOG_ERROR("fido2: assertion failed at digest rc=0x%x", (unsigned)rc);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }
    der_len = sizeof(m_der);
    rc = f2_crypto_sign(m_rec.priv, hash, m_der, &der_len);
    if (rc != 0u) {
        F2_CORE_LOG_ERROR("fido2: assertion failed at sign rc=0x%x", (unsigned)rc);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }

    if (resp == NULL || resp_max < 2u) {
        F2_CORE_LOG_ERROR("fido2: assertion failed at response cap=%u", (unsigned)resp_max);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }
    cw_init(&m_writer, resp + 1u, resp_max - 1u);
    cw_map(&m_writer, (n_creds > 1u) ? 5u : 4u);
    cw_uint(&m_writer, 1u);
    cw_map(&m_writer, 2u);
    /* Canonical CTAP2 order: "id" (0x62) sorts before "type" (0x64). */
    cw_text(&m_writer, "id", 2u);
    cw_bytes(&m_writer, id, id_len);
    cw_text(&m_writer, "type", 4u);
    cw_text(&m_writer, "public-key", 10u);
    cw_uint(&m_writer, 2u);
    cw_bytes(&m_writer, m_sign_buf, auth_len);
    cw_uint(&m_writer, 3u);
    cw_bytes(&m_writer, m_der, der_len);
    cw_uint(&m_writer, 4u);
    cw_map(&m_writer, 2u);
    cw_text(&m_writer, "id", 2u);
    cw_bytes(&m_writer, m_rec.user_id, m_rec.user_id_len);
    cw_text(&m_writer, "name", 4u);
    cw_text(&m_writer, "", 0u);
    if (n_creds > 1u) {
        cw_uint(&m_writer, 5u);
        cw_uint(&m_writer, n_creds);
    }
    st = emit(FIDO2_ST_OK, cw_finish(&m_writer), resp, resp_max, resp_len);
    if (st != FIDO2_ST_OK) {
        F2_CORE_LOG_ERROR("fido2: assertion failed at emit cap=%u", (unsigned)resp_max);
    }
    return st;
}

static uint8_t cmd_get_assertion(const uint8_t *req, size_t req_len,
                                 const fido2_request_t *ctx,
                                 uint8_t *resp, size_t resp_max, size_t *resp_len)
{
    fido2_cbor_r_t r;
    const uint8_t *rp_id = NULL, *client_hash = NULL;
    size_t rp_id_len = 0u, client_hash_len = 0u;
    bool have_rp = false, have_ch = false, have_allow = false;
    bool options_uv = false, up_suppressed = false;
    uint8_t gs, st;
    uint32_t rc;
    bool uv;

    cr_init(&r, req + 1u, req_len - 1u);
    size_t n;
    if (!cr_map(&r, &n)) {
        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
    }
    for (size_t i = 0u; i < n; i++) {
        uint64_t key;
        if (!cr_uint(&r, &key)) {
            return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
        }
        switch ((unsigned)key) {
        case 1u:
            if (!cr_text(&r, &rp_id, &rp_id_len) || rp_id_len == 0u) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            have_rp = true;
            break;
        case 2u:
            if (!cr_bytes(&r, &client_hash, &client_hash_len) ||
                client_hash_len != 32u) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            have_ch = true;
            break;
        case 3u: {
            size_t cnt;
            if (!cr_array(&r, &cnt)) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            have_allow = true;
            for (size_t j = 0u; j < cnt; j++) {
                size_t m;
                const uint8_t *id = NULL;
                size_t id_len = 0u;
                if (!cr_map(&r, &m)) {
                    return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                }
                for (size_t k = 0u; k < m; k++) {
                    const uint8_t *fk;
                    size_t fklen;
                    if (!cr_text(&r, &fk, &fklen)) {
                        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                    }
                    if (text_is(fk, fklen, "id")) {
                        if (!cr_bytes(&r, &id, &id_len)) {
                            return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                        }
                    } else if (!skip_value(&r, 0u)) {
                        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                    }
                }
                if (id == NULL || id_len == 0u || id_len > FIDO2_CRED_ID_MAX) {
                    return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                }
            }
            break;
        }
        case 5u: {
            size_t m;
            if (!cr_map(&r, &m)) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            for (size_t j = 0u; j < m; j++) {
                const uint8_t *k;
                size_t klen;
                bool value;
                if (!cr_text(&r, &k, &klen) || !cr_bool(&r, &value)) {
                    return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                }
                if (value && text_is(k, klen, "uv")) {
                    options_uv = true;
                } else if (!value && text_is(k, klen, "up")) {
                    up_suppressed = true;
                }
            }
            break;
        }
        default:
            if (!skip_value(&r, 0u)) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            break;
        }
    }
    if (r.failed || r.pos != r.len || !have_rp || !have_ch) {
        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
    }
    rc = f2_crypto_sha256(rp_id, rp_id_len, m_rp_hash);
    if (rc != 0u) {
        F2_CORE_LOG_ERROR("fido2: getAssertion failed at rp_hash rc=0x%x", (unsigned)rc);
        return ctap_error(FIDO2_ST_OTHER, resp, resp_max, resp_len);
    }

    /* rpHash is needed to filter the allowList, so walk it after hashing rpId. */
    m_assert_count = 0u;
    if (have_allow) {
        fido2_cbor_r_t a;
        size_t an;
        cr_init(&a, req + 1u, req_len - 1u);
        if (!cr_map(&a, &an)) {
            return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
        }
        for (size_t i = 0u; i < an; i++) {
            uint64_t key;
            if (!cr_uint(&a, &key)) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
            if (key == 3u) {
                size_t cnt;
                if (!cr_array(&a, &cnt)) {
                    return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                }
                for (size_t j = 0u; j < cnt; j++) {
                    size_t m;
                    const uint8_t *id = NULL;
                    size_t id_len = 0u;
                    if (!cr_map(&a, &m)) {
                        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                    }
                    for (size_t k = 0u; k < m; k++) {
                        const uint8_t *fk;
                        size_t fklen;
                        if (!cr_text(&a, &fk, &fklen)) {
                            return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                        }
                        if (text_is(fk, fklen, "id")) {
                            if (!cr_bytes(&a, &id, &id_len)) {
                                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                            }
                        } else if (!skip_value(&a, 0u)) {
                            return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                        }
                    }
                    if (id == NULL || id_len == 0u || id_len > FIDO2_CRED_ID_MAX) {
                        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
                    }
                    if (f2_creds_find_by_id(id, id_len, &m_rec) == FIDO2_ST_OK &&
                        memcmp(m_rec.rp_hash, m_rp_hash, 32u) == 0) {
                        assert_cache_add(id, id_len, m_rp_hash);
                    }
                }
            } else if (!skip_value(&a, 0u)) {
                return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
            }
        }
    } else {
        uint16_t cursor = 0u;
        while (m_assert_count < FIDO2_MAX_CREDENTIALS &&
               f2_creds_next(&cursor, &m_rec) == FIDO2_ST_OK) {
            if (memcmp(m_rec.rp_hash, m_rp_hash, 32u) == 0) {
                assert_cache_add(m_rec.cred_id, m_rec.cred_id_len, m_rp_hash);
            }
        }
    }
    if (m_assert_count == 0u) {
        return ctap_error(FIDO2_ST_NO_CREDENTIALS, resp, resp_max, resp_len);
    }

    uv = want_uv(ctx, options_uv);
    if (uv || !up_suppressed) {
        gs = gate_begin(uv ? FIDO2_GATE_UV : FIDO2_GATE_UP);
        if (gs != FIDO2_ST_OK) {
            return gate_result(gs, resp, resp_max, resp_len);
        }
    }
    m_assert_up_suppressed = up_suppressed;
    memcpy(m_assert_hash, client_hash, 32u);
    m_assert_uv = uv;
    m_assert_cursor = 1u;
    st = build_assertion(m_asserts[0].id, m_asserts[0].id_len,
                         m_rp_hash, client_hash, uv, m_assert_count,
                         resp, resp_max, resp_len);
    if (st == FIDO2_ST_OTHER) {
        F2_CORE_LOG_ERROR("fido2: getAssertion failed at build_assertion st=0x%x", (unsigned)st);
    }
    return st;
}

static uint8_t cmd_get_next_assertion(uint8_t *resp, size_t resp_max,
                                      size_t *resp_len)
{
    uint8_t idx;

    if (m_assert_cursor >= m_assert_count) {
        return ctap_error(FIDO2_ST_NO_CREDENTIALS, resp, resp_max, resp_len);
    }
    idx = m_assert_cursor++;
    return build_assertion(m_asserts[idx].id, m_asserts[idx].id_len,
                           m_asserts[idx].rp_hash, m_assert_hash, m_assert_uv,
                           m_assert_count, resp, resp_max, resp_len);
}

static uint8_t cmd_reset(uint8_t *resp, size_t resp_max, size_t *resp_len)
{
    uint8_t gs;

    /* CTAP2.0: factoryReset is only available in the 10 s power-up window. */
    if (m_boot_ts_set &&
        (uint32_t)(m_now_ms - m_boot_ms) > F2_RESET_WINDOW_MS) {
        return ctap_error(F2_ST_NOT_ALLOWED, resp, resp_max, resp_len);
    }
    gs = gate_begin(FIDO2_GATE_UV);
    if (gs != FIDO2_ST_OK) {
        return gate_result(gs, resp, resp_max, resp_len);
    }
    f2_creds_reset();
    m_assert_count = 0u;
    m_assert_cursor = 0u;
    return emit_empty(resp, resp_max, resp_len);
}

static uint8_t cmd_selection(uint8_t *resp, size_t resp_max, size_t *resp_len)
{
    uint8_t gs = gate_begin(FIDO2_GATE_UP);
    if (gs != FIDO2_ST_OK) {
        return gate_result(gs, resp, resp_max, resp_len);
    }
    return emit_empty(resp, resp_max, resp_len);
}

/* ---- CTAP1 / U2F raw APDUs ---------------------------------------------- */

typedef struct {
    uint8_t ins;
    uint8_t p1;
    const uint8_t *data;
    size_t data_len;
} f2_apdu_t;

static bool parse_apdu(const uint8_t *req, size_t len, f2_apdu_t *a)
{
    size_t off, lc;

    if (len < 5u) {
        return false;
    }
    a->ins = req[1];
    a->p1 = req[2];
    if (req[4] == 0u) {
        if (len == 5u) {        /* short APDU with no data field */
            lc = 0u;
            off = 5u;
        } else if (len >= 7u) { /* extended-length APDU */
            lc = ((size_t)req[5] << 8) | req[6];
            off = 7u;
        } else {
            return false;
        }
    } else {
        lc = req[4];
        off = 5u;
    }
    if (lc > len - off) {
        return false;
    }
    a->data = req + off;
    a->data_len = lc;
    return true;
}

static uint8_t u2f_emit(const uint8_t *data, size_t n, uint8_t sw1, uint8_t sw2,
                        uint8_t *resp, size_t resp_max, size_t *resp_len)
{
    if (resp_len != NULL) {
        *resp_len = 0u;
    }
    if (resp == NULL || resp_max < 2u) {
        return FIDO2_ST_OTHER;
    }
    if (n > resp_max - 2u) {
        resp[0] = 0x6Au;
        resp[1] = 0x80u;
        if (resp_len != NULL) {
            *resp_len = 2u;
        }
        return FIDO2_ST_OTHER;
    }
    if (n != 0u) {
        memcpy(resp, data, n);
    }
    resp[n] = sw1;
    resp[n + 1u] = sw2;
    if (resp_len != NULL) {
        *resp_len = n + 2u;
    }
    return FIDO2_ST_OK;
}

static uint8_t u2f_error(uint8_t sw1, uint8_t sw2,
                         uint8_t *resp, size_t resp_max, size_t *resp_len)
{
    return u2f_emit(NULL, 0u, sw1, sw2, resp, resp_max, resp_len);
}

static uint8_t cmd_u2f(const uint8_t *req, size_t req_len,
                       uint8_t *resp, size_t resp_max, size_t *resp_len)
{
    f2_apdu_t a;
    uint8_t hash[32];
    size_t der_len, base;

    if (!parse_apdu(req, req_len, &a) || a.p1 > 0x08u) {
        return u2f_error(0x6Au, 0x80u, resp, resp_max, resp_len);
    }

    switch (a.ins) {
    case 0x01u: { /* REGISTER */
        const uint8_t *chal, *app;
        size_t cert_len, reg_len;
        if (a.data_len != 64u) {
            return u2f_error(0x6Au, 0x80u, resp, resp_max, resp_len);
        }
        chal = a.data;
        app = a.data + 32u;
        /* U2F has no keepalive handshake: require an already-latched touch. */
        if (!consume_up_now()) {
            return u2f_error(0x69u, 0x85u, resp, resp_max, resp_len);
        }
        memset(&m_rec, 0, sizeof(m_rec));
        if (f2_crypto_keygen(m_rec.priv, m_rec.pub) != 0u ||
            f2_crypto_random(m_rec.cred_id, 32u) != 0u ||
            f2_crypto_sha256(app, 32u, m_rec.rp_hash) != 0u) {
            return u2f_error(0x6Fu, 0x00u, resp, resp_max, resp_len);
        }
        m_rec.cred_id_len = 32u;
        m_rec.cred_protect = 1u;
        if (f2_creds_add(&m_rec) != FIDO2_ST_OK) {
            return u2f_error(0x6Fu, 0x00u, resp, resp_max, resp_len);
        }
        m_pub65[0] = 0x04u;
        memcpy(m_pub65 + 1u, m_rec.pub, 64u);
        base = fmt_u2f_reg_base(m_sign_buf, sizeof(m_sign_buf), app, chal,
                                m_rec.cred_id, m_rec.cred_id_len, m_pub65);
        if (base == 0u || f2_crypto_sha256(m_sign_buf, base, hash) != 0u) {
            return u2f_error(0x6Fu, 0x00u, resp, resp_max, resp_len);
        }
        der_len = sizeof(m_der);
        /* Batch self-signed attestation, not a per-device certified key. */
        if (f2_crypto_sign(f2_attestation_key(), hash, m_der, &der_len) != 0u) {
            return u2f_error(0x6Fu, 0x00u, resp, resp_max, resp_len);
        }
        cert_len = f2_attestation_cert_len();
        if (resp == NULL || resp_max < 2u + 1u + 65u + 1u +
                            m_rec.cred_id_len + cert_len + der_len) {
            return u2f_error(0x6Au, 0x80u, resp, resp_max, resp_len);
        }
        resp[0] = 0x05u;
        memcpy(resp + 1u, m_pub65, 65u);
        resp[66u] = (uint8_t)m_rec.cred_id_len;
        memcpy(resp + 67u, m_rec.cred_id, m_rec.cred_id_len);
        reg_len = 67u + m_rec.cred_id_len;
        memcpy(resp + reg_len, f2_attestation_cert(), cert_len);
        reg_len += cert_len;
        memcpy(resp + reg_len, m_der, der_len);
        reg_len += der_len;
        resp[reg_len] = 0x90u;
        resp[reg_len + 1u] = 0x00u;
        if (resp_len != NULL) {
            *resp_len = reg_len + 2u;
        }
        return FIDO2_ST_OK;
    }
    case 0x02u: { /* AUTHENTICATE */
        const uint8_t *chal, *app, *kh;
        size_t kh_len;
        uint32_t count = 0u;
        if (a.data_len < 65u) {
            return u2f_error(0x6Au, 0x80u, resp, resp_max, resp_len);
        }
        chal = a.data;
        app = a.data + 32u;
        kh_len = a.data[64u];
        kh = a.data + 65u;
        if (kh_len == 0u || a.data_len != 65u + kh_len) {
            return u2f_error(0x6Au, 0x80u, resp, resp_max, resp_len);
        }
        if (f2_creds_find_by_id(kh, kh_len, &m_rec) != FIDO2_ST_OK) {
            return u2f_error(0x69u, 0x84u, resp, resp_max, resp_len);
        }
        /* Bind the key handle to this application parameter (all P1 modes). */
        if (f2_crypto_sha256(app, 32u, hash) != 0u ||
            memcmp(m_rec.rp_hash, hash, 32u) != 0) {
            return u2f_error(0x69u, 0x84u, resp, resp_max, resp_len);
        }
        if (a.p1 == 0x07u) { /* check-only */
            return u2f_error(0x69u, 0x85u, resp, resp_max, resp_len);
        }
        if (a.p1 == 0x03u && !consume_up_now()) {
            return u2f_error(0x69u, 0x85u, resp, resp_max, resp_len);
        }
        if (f2_creds_bump_sign_count(kh, kh_len, &count) != FIDO2_ST_OK) {
            return u2f_error(0x6Fu, 0x00u, resp, resp_max, resp_len);
        }
        /* dont-enforce-UP signs with the UP byte clear in the signature base. */
        base = fmt_u2f_auth_base(m_sign_buf, app,
                                 (a.p1 == 0x08u) ? 0x00u : 0x01u, count, chal);
        if (base == 0u || f2_crypto_sha256(m_sign_buf, base, hash) != 0u) {
            return u2f_error(0x6Fu, 0x00u, resp, resp_max, resp_len);
        }
        der_len = sizeof(m_der);
        if (f2_crypto_sign(m_rec.priv, hash, m_der, &der_len) != 0u) {
            return u2f_error(0x6Fu, 0x00u, resp, resp_max, resp_len);
        }
        if (resp == NULL || resp_max < 2u + 1u + 4u + der_len) {
            return u2f_error(0x6Au, 0x80u, resp, resp_max, resp_len);
        }
        resp[0] = 0x01u;
        resp[1] = (uint8_t)(count >> 24);
        resp[2] = (uint8_t)(count >> 16);
        resp[3] = (uint8_t)(count >> 8);
        resp[4] = (uint8_t)count;
        memcpy(resp + 5u, m_der, der_len);
        resp[5u + der_len] = 0x90u;
        resp[6u + der_len] = 0x00u;
        if (resp_len != NULL) {
            *resp_len = 7u + der_len;
        }
        return FIDO2_ST_OK;
    }
    case 0x03u: /* VERSION */
        return u2f_emit((const uint8_t *)"U2F_V2", 6u, 0x90u, 0x00u,
                        resp, resp_max, resp_len);
    default:
        return u2f_error(0x6Du, 0x00u, resp, resp_max, resp_len);
    }
}

/* ---- dispatch ----------------------------------------------------------- */

uint8_t f2_core_dispatch(const uint8_t *req, size_t req_len,
                         const fido2_request_t *ctx,
                         uint8_t *resp, size_t resp_max, size_t *resp_len)
{
    m_active_transport = (ctx != NULL) ? ctx->transport : FIDO2_TRANSPORT_USB;
    if (resp_len != NULL) {
        *resp_len = 0u;
    }
    if (req == NULL || req_len == 0u) {
        return ctap_error(FIDO2_ST_INVALID_PARAM, resp, resp_max, resp_len);
    }
    if (req[0] == 0x00u) { /* U2F raw APDU */
        return cmd_u2f(req, req_len, resp, resp_max, resp_len);
    }

    switch (req[0]) {
    case 0x01u:
        return cmd_make_credential(req, req_len, ctx, resp, resp_max, resp_len);
    case 0x02u:
        return cmd_get_assertion(req, req_len, ctx, resp, resp_max, resp_len);
    case 0x04u:
        return cmd_get_info(resp, resp_max, resp_len);
    case 0x07u:
        return cmd_reset(resp, resp_max, resp_len);
    case 0x08u:
        return cmd_get_next_assertion(resp, resp_max, resp_len);
    case 0x0Bu:
        return cmd_selection(resp, resp_max, resp_len);
    case 0x11u:
        f2_core_cancel_request();
        return F2_CORE_PENDING;   /* CANCEL itself gets no response */
    default:
        return ctap_error(0x01u, resp, resp_max, resp_len);
    }
}
