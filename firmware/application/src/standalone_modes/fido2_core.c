/*
 * fido2_core.c — transport-independent FIDO2 / CTAP2 core.
 *
 * Stateless key wrapping (no per-credential flash):
 *   priv = HMAC-SHA256(mk, 0x01 | rpIdHash32 | nonce32)   (P-256 scalar)
 *   kh   = nonce32 | HMAC-SHA256(mk, 0x02 | rpIdHash32 | nonce32)32
 * A credential handle is bound to its rpId by the MAC, so it cannot be used
 * on another origin. Only a 32-byte master key and a 4-byte global counter
 * live in FDS.
 *
 * Crypto: self-contained SHA-256/HMAC below; micro-ecc (uECC) for P-256.
 */
#include <stdint.h>
#include <string.h>

#include "fido2_core.h"
#include "uECC.h"

#if defined(FIDO2_HOST_BUILD)
#define FIDO2_CRIT_ENTER() do { } while (0)
#define FIDO2_CRIT_EXIT()  do { } while (0)
#else
#include "app_util_platform.h"
#define FIDO2_CRIT_ENTER() CRITICAL_REGION_ENTER()
#define FIDO2_CRIT_EXIT()  CRITICAL_REGION_EXIT()
#endif

/* ===================================================================== */
/*  SHA-256 + HMAC-SHA256 (self-contained, FIPS 180-4 / RFC 2104)         */
/* ===================================================================== */
typedef struct { uint32_t s[8]; uint64_t n; uint8_t b[64]; uint8_t bl; } sha256_t;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

static void sha256_blk(sha256_t *c, const uint8_t *p) {
    uint32_t w[64], a,b,cc,d,e,f,g,h,t1,t2;
    for (int i=0;i<16;i++) w[i]=((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];
    for (int i=16;i<64;i++){
        uint32_t s0=ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    a=c->s[0];b=c->s[1];cc=c->s[2];d=c->s[3];e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7];
    for (int i=0;i<64;i++){
        uint32_t S1=ROR(e,6)^ROR(e,11)^ROR(e,25), ch=(e&f)^((~e)&g);
        t1=h+S1+ch+K256[i]+w[i];
        uint32_t S0=ROR(a,2)^ROR(a,13)^ROR(a,22), mj=(a&b)^(a&cc)^(b&cc);
        t2=S0+mj;
        h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
    }
    c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
static void sha256_init(sha256_t *c){
    c->s[0]=0x6a09e667;c->s[1]=0xbb67ae85;c->s[2]=0x3c6ef372;c->s[3]=0xa54ff53a;
    c->s[4]=0x510e527f;c->s[5]=0x9b05688c;c->s[6]=0x1f83d9ab;c->s[7]=0x5be0cd19;
    c->n=0;c->bl=0;
}
static void sha256_upd(sha256_t *c, const uint8_t *p, size_t n){
    c->n+=n;
    while(n){
        uint8_t k=64-c->bl; if(k>n)k=n;
        memcpy(c->b+c->bl,p,k); c->bl+=k; p+=k; n-=k;
        if(c->bl==64){ sha256_blk(c,c->b); c->bl=0; }
    }
}
static void sha256_fin(sha256_t *c, uint8_t out[32]){
    uint64_t bits=c->n*8; uint8_t pad=0x80;
    sha256_upd(c,&pad,1);
    uint8_t z=0; while(c->bl!=56) sha256_upd(c,&z,1);
    uint8_t L[8]; for(int i=0;i<8;i++) L[i]=(uint8_t)(bits>>(56-8*i));
    sha256_upd(c,L,8);
    for(int i=0;i<8;i++){ out[i*4]=c->s[i]>>24;out[i*4+1]=c->s[i]>>16;out[i*4+2]=c->s[i]>>8;out[i*4+3]=c->s[i]; }
}
static void hmac_sha256(const uint8_t *key, size_t kl, const uint8_t *msg, size_t ml, uint8_t out[32]){
    uint8_t k[64]={0}, ip[64], op[64], ih[32]; sha256_t c;
    if(kl>64){ sha256_init(&c); sha256_upd(&c,key,kl); sha256_fin(&c,k); } else memcpy(k,key,kl);
    for(int i=0;i<64;i++){ ip[i]=k[i]^0x36; op[i]=k[i]^0x5c; }
    sha256_init(&c); sha256_upd(&c,ip,64); sha256_upd(&c,msg,ml); sha256_fin(&c,ih);
    sha256_init(&c); sha256_upd(&c,op,64); sha256_upd(&c,ih,32); sha256_fin(&c,out);
}

void fido2_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_t c;
    sha256_init(&c);
    sha256_upd(&c, data, len);
    sha256_fin(&c, out);
}

/* DER-encode an ECDSA (r,s) pair (each 32 bytes) into out. Returns length. */
static uint16_t der_sig(const uint8_t *rs, uint8_t *out){
    const uint8_t *r=rs, *s=rs+32;
    uint8_t rb[33], sb[33]; int rl=32, sl=32;
    memcpy(rb, r, 32); memcpy(sb, s, 32);
    /* strip leading zeros, then prepend one if high bit set (positive INTEGER) */
    int ro=0; while(ro<31 && rb[ro]==0) ro++; rl=32-ro;
    uint8_t rbuf[33]; int rn=0; if(rb[ro]&0x80) rbuf[rn++]=0x00; memcpy(rbuf+rn, rb+ro, rl); rn+=rl;
    int so=0; while(so<31 && sb[so]==0) so++; sl=32-so;
    uint8_t sbuf[33]; int sn=0; if(sb[so]&0x80) sbuf[sn++]=0x00; memcpy(sbuf+sn, sb+so, sl); sn+=sl;
    uint16_t i=0;
    out[i++]=0x30; out[i++]=(uint8_t)(2+rn+2+sn);
    out[i++]=0x02; out[i++]=(uint8_t)rn; memcpy(out+i, rbuf, rn); i+=rn;
    out[i++]=0x02; out[i++]=(uint8_t)sn; memcpy(out+i, sbuf, sn); i+=sn;
    return i;
}

uint16_t fido2_sign_der(const uint8_t priv[32], const uint8_t digest[32], uint8_t *out, size_t out_max) {
    uint8_t rs[64], der[72];
    if (!uECC_sign(priv, digest, 32, rs, uECC_secp256r1())) return 0;
    uint16_t n = der_sig(rs, der);
    if (n == 0 || n > out_max) return 0;
    memcpy(out, der, n);
    return n;
}

/* ===================================================================== */
/*  minimal definite-length CBOR reader (the subset CTAP input uses)      */
/* ===================================================================== */
typedef struct { const uint8_t *p, *end; } cbor_t;

/* Read a data item head: major type + argument. Advances past any argument. */
static bool cbor_head(cbor_t *c, uint8_t *major, uint64_t *val){
    if (c->p >= c->end) return false;
    uint8_t ib = *c->p++, ai = ib & 0x1F;
    *major = ib >> 5;
    if (ai < 24) { *val = ai; return true; }
    uint8_t nb = (ai == 24) ? 1 : (ai == 25) ? 2 : (ai == 26) ? 4 : (ai == 27) ? 8 : 0xFF;
    if (nb == 0xFF || (size_t)(c->end - c->p) < nb) return false;
    uint64_t v = 0;
    for (uint8_t i = 0; i < nb; i++) v = (v << 8) | *c->p++;
    *val = v;
    return true;
}

/* Read a byte or text string: point ptr/len at its body, advance past it. */
static bool cbor_str(cbor_t *c, const uint8_t **ptr, uint64_t *len){
    uint8_t m; uint64_t v;
    /* Compare against the remaining length, not c->p + v: v comes straight off
     * the wire (up to 2^64-1 via an 8-byte length argument) and c->p/c->end are
     * 32-bit pointers, so c->p + v can wrap and pass a bogus huge v. end - p is
     * always a small, valid difference and can't wrap. */
    if (!cbor_head(c, &m, &v) || (m != 2 && m != 3) || v > (uint64_t)(c->end - c->p)) return false;
    *ptr = c->p; *len = v; c->p += v;
    return true;
}

/* Read a byte string item. */
static bool cbor_bytes(cbor_t *c, const uint8_t **ptr, uint64_t *len){
    uint8_t m; uint64_t v;
    if (!cbor_head(c, &m, &v) || m != 2 || v > (uint64_t)(c->end - c->p)) return false;
    *ptr = c->p; *len = v; c->p += v;
    return true;
}

/* Read an array header and remember where its items start. */
static bool cbor_array(cbor_t *c, const uint8_t **items, uint64_t *count){
    uint8_t m; uint64_t v;
    if (!cbor_head(c, &m, &v) || m != 4 || v > (uint64_t)(c->end - c->p)) return false;
    *items = c->p; *count = v;
    return true;
}

/* Skip one item (recursively for arrays/maps). */
static bool cbor_skip(cbor_t *c){
    uint8_t m; uint64_t v;
    if (!cbor_head(c, &m, &v)) return false;
    switch (m) {
    case 0: case 1: case 7: return true;                 /* uint / negint / simple */
    case 2: case 3: if (v > (uint64_t)(c->end - c->p)) return false; c->p += v; return true;
    case 4:
        /* Each array item needs at least one byte. This also prevents v from
         * wrapping when the old implementation multiplied it by two. */
        if (v > (uint64_t)(c->end - c->p)) return false;
        for (uint64_t i = 0; i < v; i++) if (!cbor_skip(c)) return false;
        return true;
    case 5:
        /* Each map entry needs at least two bytes (key and value). */
        if (v > (uint64_t)(c->end - c->p) / 2) return false;
        for (uint64_t i = 0; i < v; i++) {
            if (!cbor_skip(c) || !cbor_skip(c)) return false;
        }
        return true;
    default: return false;
    }
}

/* Is this map-key the text string "id"? */
static bool key_is(const uint8_t *ks, uint64_t kl, const char *s){
    size_t n = strlen(s);
    return kl == n && memcmp(ks, s, n) == 0;
}

/* Read a signed integer item. */
static bool cbor_int(cbor_t *c, int32_t *out){
    uint8_t m; uint64_t v;
    if (!cbor_head(c, &m, &v)) return false;
    if (m == 0) {
        if (v > INT32_MAX) return false;
        *out = (int32_t)v;
        return true;
    }
    if (m == 1) {
        if (v > INT32_MAX) return false;
        *out = (int32_t)(-1 - (int64_t)v);
        return true;
    }
    return false;
}

/* ===================================================================== */
/*  minimal CBOR writer (definite length, unsigned heads)                 */
/* ===================================================================== */
typedef struct { uint8_t *buf; size_t cap; size_t len; bool ovf; } cbw_t;

static void cbw_byte(cbw_t *w, uint8_t b){
    if (w->len >= w->cap) { w->ovf = true; return; }
    w->buf[w->len++] = b;
}
static void cbw_head(cbw_t *w, uint8_t major, uint64_t val){
    uint8_t m = (uint8_t)(major << 5);
    if (val < 24) {
        cbw_byte(w, (uint8_t)(m | val));
    } else if (val < 256) {
        cbw_byte(w, (uint8_t)(m | 24)); cbw_byte(w, (uint8_t)val);
    } else if (val < 65536) {
        cbw_byte(w, (uint8_t)(m | 25));
        cbw_byte(w, (uint8_t)(val >> 8)); cbw_byte(w, (uint8_t)val);
    } else if (val <= UINT32_MAX) {
        cbw_byte(w, (uint8_t)(m | 26));
        cbw_byte(w, (uint8_t)(val >> 24)); cbw_byte(w, (uint8_t)(val >> 16));
        cbw_byte(w, (uint8_t)(val >> 8)); cbw_byte(w, (uint8_t)val);
    } else {
        cbw_byte(w, (uint8_t)(m | 27));
        for (int i = 7; i >= 0; i--) cbw_byte(w, (uint8_t)(val >> (i * 8)));
    }
}
static void cbw_bytes(cbw_t *w, const uint8_t *d, size_t n){
    cbw_head(w, 2, (uint64_t)n);
    for (size_t i = 0; i < n; i++) cbw_byte(w, d[i]);
}
static void cbw_text(cbw_t *w, const char *s){
    size_t n = strlen(s);
    cbw_head(w, 3, (uint64_t)n);
    for (size_t i = 0; i < n; i++) cbw_byte(w, (uint8_t)s[i]);
}

/* COSE_Key for a P-256 public key: {1:2,3:-7,-1:1,-2:x,-3:y}. */
static uint16_t cose_p256(uint8_t *o, const uint8_t *pub){
    uint16_t i = 0;
    o[i++] = 0xA5;
    o[i++] = 0x01; o[i++] = 0x02;                         /* kty: EC2  */
    o[i++] = 0x03; o[i++] = 0x26;                         /* alg: ES256 (-7) */
    o[i++] = 0x20; o[i++] = 0x01;                         /* crv: P-256 */
    o[i++] = 0x21; o[i++] = 0x58; o[i++] = 0x20; memcpy(o + i, pub, 32);      i += 32;  /* x */
    o[i++] = 0x22; o[i++] = 0x58; o[i++] = 0x20; memcpy(o + i, pub + 32, 32); i += 32;  /* y */
    return i;
}

static void sc4_of(uint32_t v, uint8_t *o){
    o[0]=(uint8_t)(v>>24); o[1]=(uint8_t)(v>>16); o[2]=(uint8_t)(v>>8); o[3]=(uint8_t)v;
}

/* ===================================================================== */
/*  module state                                                          */
/* ===================================================================== */
typedef enum {
    FIDO2_ST_IDLE = 0,
    FIDO2_ST_PENDING,      /* request queued, not started          */
    FIDO2_ST_WAITING_UP,   /* MakeCredential/GetAssertion awaiting a gesture */
    FIDO2_ST_PROCESSING,   /* crypto running (no critical section) */
    FIDO2_ST_DONE,         /* response ready for the owner         */
} fido2_state_t;

static const fido2_core_io_t *s_io;
static uint8_t  s_mk[32];
static uint32_t s_ctr;
static uint8_t  s_mask;
static bool     s_armed;
static bool     s_up_granted;
static uint32_t s_up_grant_deadline;
static uint32_t s_up_wait_started_ms;
static bool     s_cancel_requested;

static volatile uint8_t s_state = FIDO2_ST_IDLE;
static fido2_owner_t s_owner = FIDO2_OWNER_NFC;
static uint8_t  s_req[FIDO2_MAX_REQUEST];
static size_t   s_req_len;
static uint8_t  s_resp[FIDO2_MAX_RESPONSE];
static size_t   s_resp_len;

static int core_rng(uint8_t *dest, unsigned size) {
    if (!s_io || !s_io->random_bytes) return 0;
    return s_io->random_bytes(dest, size) ? 1 : 0;
}

static bool rng_bytes(uint8_t *dst, size_t len) {
    return s_io && s_io->random_bytes && s_io->random_bytes(dst, len);
}

/* ===================================================================== */
/*  key wrapping                                                          */
/* ===================================================================== */
void fido2_derive_priv(const uint8_t rp_id_hash[32], const uint8_t nonce[32], uint8_t priv[32]){
    uint8_t in[1+32+32]; in[0]=0x01; memcpy(in+1,rp_id_hash,32); memcpy(in+33,nonce,32);
    hmac_sha256(s_mk, sizeof(s_mk), in, sizeof(in), priv);
}
void fido2_derive_mac(const uint8_t rp_id_hash[32], const uint8_t nonce[32], uint8_t mac[32]){
    uint8_t in[1+32+32]; in[0]=0x02; memcpy(in+1,rp_id_hash,32); memcpy(in+33,nonce,32);
    hmac_sha256(s_mk, sizeof(s_mk), in, sizeof(in), mac);
}

/* Sign counter: bump + persist. */
static uint32_t ctr_next(void) {
    s_ctr++;
    if (s_io && s_io->store_counter) s_io->store_counter(s_ctr);
    return s_ctr;
}

/* ===================================================================== */
/*  CTAP2 commands                                                        */
/* ===================================================================== */
static size_t ctap_status(uint8_t *out, uint8_t status) {
    out[0] = status;
    return 1;
}

/* authenticatorGetInfo — data-driven so the transports list follows the
 * armed transport mask:
 *   {1:["FIDO_2_0","U2F_V2"], 3:h'<16 zero bytes aaguid>',
 *    4:{"rk":false,"up":true,"clientPin":false,"makeCredUvNotRqd":true},
 *    9:["usb","nfc","ble"]}
 * "none" attestation => the AAGUID is all zeros. */
static size_t ctap_get_info(uint8_t *out, size_t out_max) {
    if (out_max < 2) return ctap_status(out, FIDO2_ERR_INVALID_LENGTH);
    static const uint8_t aaguid[16] = {0};
    cbw_t w = { out + 1, out_max - 1, 0, false };

    cbw_head(&w, 5, 4);                       /* map with 4 entries */

    cbw_head(&w, 0, 1);                       /* 1: versions */
    cbw_head(&w, 4, 2);
    cbw_text(&w, "FIDO_2_0");
    cbw_text(&w, "U2F_V2");

    cbw_head(&w, 0, 3);                       /* 3: aaguid */
    cbw_bytes(&w, aaguid, sizeof aaguid);

    cbw_head(&w, 0, 4);                       /* 4: options */
    cbw_head(&w, 5, 4);
    cbw_text(&w, "rk");            cbw_byte(&w, 0xF4);   /* false */
    cbw_text(&w, "up");            cbw_byte(&w, 0xF5);   /* true  */
    cbw_text(&w, "clientPin");     cbw_byte(&w, 0xF4);   /* false */
    cbw_text(&w, "makeCredUvNotRqd"); cbw_byte(&w, 0xF5);

    uint8_t n = 0;
    if (s_mask & FIDO2_TRANSPORT_USB) n++;
    if (s_mask & FIDO2_TRANSPORT_NFC) n++;
    if (s_mask & FIDO2_TRANSPORT_BLE) n++;
    cbw_head(&w, 0, 9);                       /* 9: transports */
    cbw_head(&w, 4, n);
    if (s_mask & FIDO2_TRANSPORT_USB) cbw_text(&w, "usb");
    if (s_mask & FIDO2_TRANSPORT_NFC) cbw_text(&w, "nfc");
    if (s_mask & FIDO2_TRANSPORT_BLE) cbw_text(&w, "ble");

    if (w.ovf) return ctap_status(out, FIDO2_ERR_INVALID_LENGTH);
    out[0] = FIDO2_OK;
    return 1 + w.len;
}

typedef struct {
    const uint8_t *cdh;
    const uint8_t *rpid;
    uint64_t cdh_len;
    uint64_t rpid_len;
    bool rk;
    bool have_es256;
} make_credential_params_t;

/* Parse and validate authenticatorMakeCredential parameters without changing
 * persistent state. The same validation runs before and after the UP gate. */
static uint8_t parse_make_credential(const uint8_t *d, size_t len,
                                     make_credential_params_t *p) {
    cbor_t c = { d, d + len };
    uint8_t m; uint64_t np;
    memset(p, 0, sizeof *p);
    if (!cbor_head(&c, &m, &np) || m != 5) return FIDO2_ERR_INVALID_CBOR;

    for (uint64_t i = 0; i < np; i++) {
        uint8_t km; uint64_t key;
        if (!cbor_head(&c, &km, &key) || km != 0) return FIDO2_ERR_INVALID_CBOR;
        if (key == 1) {                                  /* clientDataHash */
            if (!cbor_bytes(&c, &p->cdh, &p->cdh_len)) return FIDO2_ERR_INVALID_CBOR;
        } else if (key == 2) {                           /* rp: find "id" */
            uint8_t rm; uint64_t rn;
            if (!cbor_head(&c, &rm, &rn) || rm != 5) return FIDO2_ERR_INVALID_CBOR;
            for (uint64_t j = 0; j < rn; j++) {
                const uint8_t *ks; uint64_t kl;
                if (!cbor_str(&c, &ks, &kl)) return FIDO2_ERR_INVALID_CBOR;
                if (key_is(ks, kl, "id")) {
                    if (!cbor_str(&c, &p->rpid, &p->rpid_len)) return FIDO2_ERR_INVALID_CBOR;
                } else if (!cbor_skip(&c)) return FIDO2_ERR_INVALID_CBOR;
            }
        } else if (key == 4) {                           /* pubKeyCredParams */
            uint8_t am; uint64_t an;
            if (!cbor_head(&c, &am, &an) || am != 4) return FIDO2_ERR_INVALID_CBOR;
            for (uint64_t j = 0; j < an; j++) {
                uint8_t em; uint64_t en;
                if (!cbor_head(&c, &em, &en) || em != 5) return FIDO2_ERR_INVALID_CBOR;
                for (uint64_t k = 0; k < en; k++) {
                    const uint8_t *ks; uint64_t kl;
                    if (!cbor_str(&c, &ks, &kl)) return FIDO2_ERR_INVALID_CBOR;
                    if (key_is(ks, kl, "alg")) {
                        int32_t alg;
                        if (!cbor_int(&c, &alg)) return FIDO2_ERR_INVALID_CBOR;
                        if (alg == -7) p->have_es256 = true;
                    } else if (!cbor_skip(&c)) return FIDO2_ERR_INVALID_CBOR;
                }
            }
        } else if (key == 6) {                           /* extensions (not supported) */
            if (!cbor_skip(&c)) return FIDO2_ERR_INVALID_CBOR;
        } else if (key == 7) {                           /* options: "rk" is unsupported */
            uint8_t om; uint64_t on;
            if (!cbor_head(&c, &om, &on) || om != 5) return FIDO2_ERR_INVALID_CBOR;
            for (uint64_t j = 0; j < on; j++) {
                const uint8_t *ks; uint64_t kl;
                if (!cbor_str(&c, &ks, &kl)) return FIDO2_ERR_INVALID_CBOR;
                if (key_is(ks, kl, "rk")) {
                    uint8_t vm; uint64_t vv;
                    if (!cbor_head(&c, &vm, &vv) || vm != 7) return FIDO2_ERR_INVALID_CBOR;
                    p->rk = (vv != 0);
                } else if (!cbor_skip(&c)) return FIDO2_ERR_INVALID_CBOR;
            }
        } else if (!cbor_skip(&c)) return FIDO2_ERR_INVALID_CBOR;
    }
    if (!p->cdh || p->cdh_len != 32 || !p->rpid) return FIDO2_ERR_MISSING_PARAMETER;
    if (!p->have_es256) return FIDO2_ERR_UNSUPPORTED_ALGORITHM;
    if (p->rk) return FIDO2_ERR_UNSUPPORTED_OPTION;
    return FIDO2_OK;
}

/* authenticatorMakeCredential — non-UV, non-resident, "none" attestation.
 * Needs clientDataHash (key 1), rp.id (key 2) and ES256 (key 4). */
static size_t ctap_make_credential(const uint8_t *d, size_t len, uint8_t *out, size_t out_max) {
    make_credential_params_t p;
    uint8_t parse_status = parse_make_credential(d, len, &p);
    if (parse_status != FIDO2_OK) return ctap_status(out, parse_status);

    uint8_t rpIdHash[32];
    fido2_sha256(p.rpid, p.rpid_len, rpIdHash);

    uint8_t nonce[32], priv[32], pub[64], mac[32];
    uECC_Curve C = uECC_secp256r1();
    for (int t = 0; ; t++) {
        if (t > 8) return ctap_status(out, FIDO2_ERR_OPERATION_DENIED);
        if (!rng_bytes(nonce, 32)) return ctap_status(out, FIDO2_ERR_OPERATION_DENIED);
        fido2_derive_priv(rpIdHash, nonce, priv);
        if (uECC_compute_public_key(priv, pub, C)) break;
    }
    fido2_derive_mac(rpIdHash, nonce, mac);
    uint8_t credId[FIDO2_CRED_ID_LEN]; memcpy(credId, nonce, 32); memcpy(credId + 32, mac, 32);

    uint8_t sc4[4]; sc4_of(ctr_next(), sc4);

    /* authData = rpIdHash | flags(UP|AT) | signCount | attestedCredentialData */
    uint8_t ad[256]; uint16_t ap = 0;
    memcpy(ad + ap, rpIdHash, 32); ap += 32;
    ad[ap++] = 0x41;                                     /* UP(0x01) | AT(0x40) */
    memcpy(ad + ap, sc4, 4); ap += 4;
    memset(ad + ap, 0, 16); ap += 16;                   /* aaguid: 16 zero bytes */
    ad[ap++] = 0x00; ad[ap++] = FIDO2_CRED_ID_LEN;
    memcpy(ad + ap, credId, FIDO2_CRED_ID_LEN); ap += FIDO2_CRED_ID_LEN;
    ap += cose_p256(ad + ap, pub);

    /* response map {1:"none", 2:authData, 3:{}} */
    if (out_max < 2) return ctap_status(out, FIDO2_ERR_INVALID_LENGTH);
    cbw_t w = { out + 1, out_max - 1, 0, false };
    cbw_head(&w, 5, 3);
    cbw_head(&w, 0, 1); cbw_text(&w, "none");
    cbw_head(&w, 0, 2); cbw_bytes(&w, ad, ap);
    cbw_head(&w, 0, 3); cbw_head(&w, 5, 0);            /* attStmt: {} */
    if (w.ovf) return ctap_status(out, FIDO2_ERR_INVALID_LENGTH);
    out[0] = FIDO2_OK;
    return 1 + w.len;
}

/* authenticatorGetAssertion — verifies an allow-list credential is ours,
 * then signs authData | clientDataHash. rpId(1), clientDataHash(2),
 * allowList(3). */
typedef struct {
    const uint8_t *rpid;
    const uint8_t *cdh;
    uint64_t rpid_len;
    uint64_t cdh_len;
    uint8_t cred[FIDO2_CRED_ID_LEN];
} get_assertion_params_t;

static uint8_t parse_get_assertion(const uint8_t *d, size_t len,
                                   get_assertion_params_t *p) {
    cbor_t c = { d, d + len };
    uint8_t m; uint64_t np;
    const uint8_t *allow_items = NULL;
    uint64_t allow_count = 0;
    memset(p, 0, sizeof *p);

    if (!cbor_head(&c, &m, &np) || m != 5) return FIDO2_ERR_INVALID_CBOR;
    for (uint64_t i = 0; i < np; i++) {
        uint8_t km; uint64_t key;
        if (!cbor_head(&c, &km, &key) || km != 0) return FIDO2_ERR_INVALID_CBOR;
        if (key == 1) {                                  /* rpId */
            if (!cbor_str(&c, &p->rpid, &p->rpid_len)) return FIDO2_ERR_INVALID_CBOR;
        } else if (key == 2) {                           /* clientDataHash */
            if (!cbor_bytes(&c, &p->cdh, &p->cdh_len)) return FIDO2_ERR_INVALID_CBOR;
        } else if (key == 3) {                           /* allowList */
            if (!cbor_array(&c, &allow_items, &allow_count)) return FIDO2_ERR_INVALID_CBOR;
            for (uint64_t i = 0; i < allow_count; i++) {
                if (!cbor_skip(&c)) return FIDO2_ERR_INVALID_CBOR;
            }
        } else if (!cbor_skip(&c)) return FIDO2_ERR_INVALID_CBOR;
    }
    if (!p->rpid || !p->cdh || p->cdh_len != 32) return FIDO2_ERR_MISSING_PARAMETER;
    if (!allow_items) return FIDO2_ERR_NO_CREDENTIALS;

    uint8_t rp_id_hash[32];
    fido2_sha256(p->rpid, p->rpid_len, rp_id_hash);

    /* Every descriptor is checked; a foreign or malformed-length entry must
     * not hide a later credential that belongs to this authenticator. */
    cbor_t a = { allow_items, d + len };
    for (uint64_t i = 0; i < allow_count; i++) {
        uint8_t em; uint64_t en;
        if (!cbor_head(&a, &em, &en) || em != 5) return FIDO2_ERR_INVALID_CBOR;
        for (uint64_t j = 0; j < en; j++) {
            const uint8_t *ks; uint64_t kl;
            if (!cbor_str(&a, &ks, &kl)) return FIDO2_ERR_INVALID_CBOR;
            if (key_is(ks, kl, "id")) {
                const uint8_t *id; uint64_t id_len;
                if (!cbor_bytes(&a, &id, &id_len)) return FIDO2_ERR_INVALID_CBOR;
                if (id_len != FIDO2_CRED_ID_LEN) continue;
                uint8_t want[32];
                fido2_derive_mac(rp_id_hash, id, want);
                if (memcmp(want, id + 32, 32) == 0) {
                    memcpy(p->cred, id, FIDO2_CRED_ID_LEN);
                    return FIDO2_OK;
                }
            } else if (!cbor_skip(&a)) return FIDO2_ERR_INVALID_CBOR;
        }
    }
    return FIDO2_ERR_NO_CREDENTIALS;
}

static size_t ctap_get_assertion(const uint8_t *d, size_t len, uint8_t *out, size_t out_max) {
    get_assertion_params_t p;
    uint8_t parse_status = parse_get_assertion(d, len, &p);
    if (parse_status != FIDO2_OK) return ctap_status(out, parse_status);

    uint8_t rp_id_hash[32];
    fido2_sha256(p.rpid, p.rpid_len, rp_id_hash);
    const uint8_t *nonce = p.cred, *mac = p.cred + 32;
    uint8_t want[32]; fido2_derive_mac(rp_id_hash, nonce, want);
    if (memcmp(want, mac, 32) != 0) return ctap_status(out, FIDO2_ERR_NO_CREDENTIALS);
    uint8_t priv[32]; fido2_derive_priv(rp_id_hash, nonce, priv);

    uint8_t sc4[4]; sc4_of(ctr_next(), sc4);

    uint8_t ad[37];                                      /* rpIdHash | flags(UP) | signCount */
    memcpy(ad, rp_id_hash, 32); ad[32] = 0x01; memcpy(ad + 33, sc4, 4);
    uint8_t h[32];
    {
        sha256_t sc;
        sha256_init(&sc); sha256_upd(&sc, ad, 37); sha256_upd(&sc, p.cdh, 32); sha256_fin(&sc, h);
    }
    uint8_t sig[72];
    uint16_t sl = fido2_sign_der(priv, h, sig, sizeof sig);
    if (!sl) return ctap_status(out, FIDO2_ERR_OPERATION_DENIED);

    /* response {1:{id,type}, 2:authData, 3:signature} */
    if (out_max < 2) return ctap_status(out, FIDO2_ERR_INVALID_LENGTH);
    cbw_t w = { out + 1, out_max - 1, 0, false };
    cbw_head(&w, 5, 3);
    cbw_head(&w, 0, 1); cbw_head(&w, 5, 2);
    cbw_text(&w, "id"); cbw_bytes(&w, p.cred, FIDO2_CRED_ID_LEN);
    cbw_text(&w, "type"); cbw_text(&w, "public-key");
    cbw_head(&w, 0, 2); cbw_bytes(&w, ad, 37);
    cbw_head(&w, 0, 3); cbw_bytes(&w, sig, sl);
    if (w.ovf) return ctap_status(out, FIDO2_ERR_INVALID_LENGTH);
    out[0] = FIDO2_OK;
    return 1 + w.len;
}

/* CTAP2 command dispatch. `cmd` = command byte + CBOR. The response starts
 * with the CTAP status byte. */
static size_t ctap_dispatch(const uint8_t *cmd, size_t len, uint8_t *out, size_t out_max) {
    if (!cmd || len < 1) return ctap_status(out, FIDO2_ERR_INVALID_LENGTH);
    switch (cmd[0]) {
    case FIDO2_CMD_GET_INFO:
        return ctap_get_info(out, out_max);
    case FIDO2_CMD_MAKE_CREDENTIAL:
        return ctap_make_credential(cmd + 1, len - 1, out, out_max);
    case FIDO2_CMD_GET_ASSERTION:
        return ctap_get_assertion(cmd + 1, len - 1, out, out_max);
    default:
        return ctap_status(out, FIDO2_ERR_INVALID_CMD);
    }
}

/* ===================================================================== */
/*  public API                                                            */
/* ===================================================================== */
void fido2_core_init(const fido2_core_io_t *io) {
    s_io = io;
    s_armed = false;
    s_mask = 0;
    s_state = FIDO2_ST_IDLE;
    s_req_len = 0;
    s_resp_len = 0;
    memset(s_mk, 0, sizeof s_mk);
    s_ctr = 0;
    s_up_granted = false;
    s_up_grant_deadline = 0;
    s_up_wait_started_ms = 0;
    s_cancel_requested = false;
}

bool fido2_core_arm(uint8_t transport_mask) {
    if (!s_io || !s_io->load_master_key || !s_io->store_master_key ||
        !s_io->load_counter || !s_io->random_bytes || !s_io->now_ms) return false;

    uint8_t mk[32];
    if (!s_io->load_master_key(mk)) {
        if (!s_io->random_bytes(mk, sizeof mk)) return false;
        if (!s_io->store_master_key(mk)) {
            memset(mk, 0, sizeof mk);
            return false;
        }
    }
    memcpy(s_mk, mk, sizeof s_mk);

    uint32_t ctr = 0;
    if (!s_io->load_counter(&ctr)) ctr = 0;
    s_ctr = ctr;

    uECC_set_rng(core_rng);

    s_mask = transport_mask;
    s_armed = true;
    s_up_granted = false;
    s_up_wait_started_ms = 0;
    s_cancel_requested = false;
    return true;
}

void fido2_core_disarm(void) {
    s_armed = false;
    s_mask = 0;
    memset(s_mk, 0, sizeof s_mk);
    FIDO2_CRIT_ENTER();
    s_state = FIDO2_ST_IDLE;
    s_up_granted = false;
    s_up_wait_started_ms = 0;
    s_cancel_requested = false;
    FIDO2_CRIT_EXIT();
}

uint8_t fido2_core_transport_mask(void) { return s_mask; }

bool fido2_submit(fido2_owner_t owner, const uint8_t *cmd, size_t len) {
    if (!s_armed || !cmd || len == 0 || len > FIDO2_MAX_REQUEST) return false;
    bool ok = false;
    FIDO2_CRIT_ENTER();
    if (s_state == FIDO2_ST_IDLE) {
        memcpy(s_req, cmd, len);
        s_req_len = len;
        s_owner = owner;
        s_cancel_requested = false;
        s_state = FIDO2_ST_PENDING;
        ok = true;
    }
    FIDO2_CRIT_EXIT();
    return ok;
}

static uint32_t core_now_ms(void) {
    return s_io && s_io->now_ms ? s_io->now_ms() : 0;
}

static bool up_grant_valid(void) {
    if (!s_up_granted) return false;
    return (int32_t)(core_now_ms() - s_up_grant_deadline) < 0;
}

static bool command_requires_up(const uint8_t *cmd, size_t len) {
    return len > 0 && (cmd[0] == FIDO2_CMD_MAKE_CREDENTIAL ||
                       cmd[0] == FIDO2_CMD_GET_ASSERTION);
}

static uint8_t validate_ctap_request(const uint8_t *cmd, size_t len) {
    if (!cmd || len < 1) return FIDO2_ERR_INVALID_LENGTH;
    switch (cmd[0]) {
    case FIDO2_CMD_GET_INFO:
        return FIDO2_OK;
    case FIDO2_CMD_MAKE_CREDENTIAL: {
        make_credential_params_t p;
        return parse_make_credential(cmd + 1, len - 1, &p);
    }
    case FIDO2_CMD_GET_ASSERTION: {
        get_assertion_params_t p;
        return parse_get_assertion(cmd + 1, len - 1, &p);
    }
    default:
        return FIDO2_ERR_INVALID_CMD;
    }
}

void fido2_tick(void) {
    bool pending = false;
    FIDO2_CRIT_ENTER();
    if (s_state == FIDO2_ST_PENDING) {
        pending = true;
    } else if (s_state == FIDO2_ST_WAITING_UP) {
        if (up_grant_valid()) {
            s_state = FIDO2_ST_PENDING;
            pending = true;
        } else if ((uint32_t)(core_now_ms() - s_up_wait_started_ms) >=
                   FIDO2_UP_WAIT_TIMEOUT_MS) {
            s_resp[0] = FIDO2_ERR_KEEPALIVE_CANCEL;
            s_resp_len = 1;
            s_up_granted = false;
            s_cancel_requested = false;
            s_state = FIDO2_ST_DONE;
        } else {
            s_up_granted = false;
        }
    }
    FIDO2_CRIT_EXIT();
    if (!pending) return;

    uint8_t status = validate_ctap_request(s_req, s_req_len);
    bool needs_up = command_requires_up(s_req, s_req_len);
    bool granted = up_grant_valid();
    bool process = false;
    bool stale = false;

    FIDO2_CRIT_ENTER();
    if (s_state != FIDO2_ST_PENDING) {
        stale = true;
    } else if (s_cancel_requested) {
        s_resp[0] = FIDO2_ERR_KEEPALIVE_CANCEL;
        s_resp_len = 1;
        s_cancel_requested = false;
        s_state = FIDO2_ST_DONE;
    } else if (status != FIDO2_OK) {
        s_resp[0] = status;
        s_resp_len = 1;
        s_state = FIDO2_ST_DONE;
    } else if (needs_up && !granted) {
        s_up_wait_started_ms = core_now_ms();
        s_state = FIDO2_ST_WAITING_UP;
    } else {
        if (needs_up) s_up_granted = false;
        s_state = FIDO2_ST_PROCESSING;
        process = true;
    }
    FIDO2_CRIT_EXIT();

    if (stale || !process) return;

    /* ECDSA runs here, outside any critical section. */
    s_resp_len = ctap_dispatch(s_req, s_req_len, s_resp, sizeof s_resp);

    FIDO2_CRIT_ENTER();
    if (s_cancel_requested) {
        s_resp[0] = FIDO2_ERR_KEEPALIVE_CANCEL;
        s_resp_len = 1;
        s_cancel_requested = false;
    }
    s_state = FIDO2_ST_DONE;
    FIDO2_CRIT_EXIT();
}

bool fido2_grant_user_presence(void) {
    if (!s_armed || !s_io || !s_io->now_ms) return false;
    FIDO2_CRIT_ENTER();
    s_up_granted = true;
    s_up_grant_deadline = core_now_ms() + FIDO2_UP_GRANT_MS;
    FIDO2_CRIT_EXIT();
    return true;
}

bool fido2_cancel(fido2_owner_t owner) {
    bool ok = false;
    FIDO2_CRIT_ENTER();
    if (s_owner == owner && (s_state == FIDO2_ST_PENDING ||
                             s_state == FIDO2_ST_WAITING_UP ||
                             s_state == FIDO2_ST_PROCESSING)) {
        s_cancel_requested = true;
        if (s_state != FIDO2_ST_PROCESSING) {
            s_resp[0] = FIDO2_ERR_KEEPALIVE_CANCEL;
            s_resp_len = 1;
            s_cancel_requested = false;
            s_state = FIDO2_ST_DONE;
        }
        ok = true;
    }
    FIDO2_CRIT_EXIT();
    return ok;
}

bool fido2_waiting_for_presence(fido2_owner_t owner) {
    return s_state == FIDO2_ST_WAITING_UP && s_owner == owner;
}

bool fido2_response_ready(fido2_owner_t owner) {
    return s_state == FIDO2_ST_DONE && s_owner == owner;
}

bool fido2_take_response(fido2_owner_t owner, uint8_t *out, size_t out_max, size_t *out_len) {
    bool ok = false;
    FIDO2_CRIT_ENTER();
    if (s_state == FIDO2_ST_DONE && s_owner == owner && s_resp_len <= out_max) {
        memcpy(out, s_resp, s_resp_len);
        if (out_len) *out_len = s_resp_len;
        s_state = FIDO2_ST_IDLE;
        ok = true;
    }
    FIDO2_CRIT_EXIT();
    return ok;
}

bool fido2_busy(void) {
    return s_state == FIDO2_ST_PENDING || s_state == FIDO2_ST_WAITING_UP ||
           s_state == FIDO2_ST_PROCESSING;
}

uint32_t fido2_core_next_counter(void) {
    if (!s_armed) return 0;
    return ctr_next();
}
