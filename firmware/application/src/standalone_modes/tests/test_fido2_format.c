/* Native tests for the CTAP2/U2F byte encoders. */
#include "../../fido2/fido2_format.h"
#include "../../fido2/fido2_types.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static void fill(uint8_t *p, size_t n, uint8_t seed)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(seed + i);
}

static void test_cose_key(void)
{
    uint8_t pub[64], cose[77];
    static const uint8_t prefix[10] = {
        0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20
    };

    fill(pub, sizeof pub, 1u);
    CHECK(fmt_cose_key(cose, pub) == 77u);
    CHECK(memcmp(cose, prefix, sizeof prefix) == 0);
    CHECK(memcmp(cose + 10u, pub, 32u) == 0);
    CHECK(cose[42] == 0x22u && cose[43] == 0x58u && cose[44] == 0x20u);
    CHECK(memcmp(cose + 45u, pub + 32u, 32u) == 0);
    CHECK(fmt_cose_key(NULL, pub) == 0u && fmt_cose_key(cose, NULL) == 0u);
}

static void test_auth_data(void)
{
    uint8_t rp[32], cred[8], cose[77], pub[64], out[160];
    size_t n;

    fill(rp, sizeof rp, 0u);
    fill(cred, sizeof cred, 0x80u);
    fill(pub, sizeof pub, 1u);
    CHECK(fmt_cose_key(cose, pub) == 77u);

    n = fmt_auth_data(out, sizeof out, rp, FIDO2_FLAG_UP, 0x01020304u,
                      NULL, 0u, NULL, 0u);
    CHECK(n == 37u);
    CHECK(memcmp(out, rp, 32u) == 0 && out[32] == FIDO2_FLAG_UP);
    CHECK(out[33] == 1u && out[34] == 2u && out[35] == 3u && out[36] == 4u);

    n = fmt_auth_data(out, sizeof out, rp, FIDO2_FLAG_UP | FIDO2_FLAG_AT,
                      0x01020304u, cred, sizeof cred, cose, sizeof cose);
    CHECK(n == 37u + 16u + 2u + sizeof cred + sizeof cose);
    CHECK(memcmp(out + 37u, "CHAMELEONFIDO2V1", 16u) == 0);
    CHECK(out[53] == 0u && out[54] == 8u);
    CHECK(memcmp(out + 55u, cred, sizeof cred) == 0);
    CHECK(memcmp(out + 63u, cose, sizeof cose) == 0);
    CHECK(fmt_auth_data(out, n - 1u, rp, 0u, 0u, cred, sizeof cred,
                        cose, sizeof cose) == 0u);
    CHECK(fmt_auth_data(out, sizeof out, rp, 0u, 0u, cred, sizeof cred,
                        cose, SIZE_MAX - 4u) == 0u);
    CHECK(fmt_auth_data(out, sizeof out, rp, 0u, 0u, cred, sizeof cred,
                        cose, SIZE_MAX - 20u) == 0u);
    CHECK(fmt_auth_data(NULL, sizeof out, rp, 0u, 0u, NULL, 0u, NULL, 0u) == 0u);
}

static void test_der(void)
{
    uint8_t raw[64], der[72];
    size_t n;

    memset(raw, 0, sizeof raw);
    raw[0] = 0x80u; raw[31] = 0x01u;
    raw[32] = 0x7Fu; raw[63] = 0x02u;
    n = fmt_raw_sig_to_der(raw, der);
    CHECK(n == 71u);
    CHECK(der[0] == 0x30u && der[1] == 69u);
    CHECK(der[2] == 0x02u && der[3] == 33u && der[4] == 0u);
    CHECK(der[5] == 0x80u && der[36] == 0x01u);
    CHECK(der[37] == 0x02u && der[38] == 32u);
    CHECK(der[39] == 0x7Fu && der[70] == 0x02u);

    raw[0] = 0x80u; raw[32] = 0x80u;
    n = fmt_raw_sig_to_der(raw, der);
    CHECK(n == 72u && der[1] == 70u && der[3] == 33u);
    CHECK(der[37] == 0x02u && der[38] == 33u && der[39] == 0u);

    memset(raw, 0, sizeof raw);
    raw[1] = 0x81u;                      /* leading zero stripped, MSB set */
    n = fmt_raw_sig_to_der(raw, der);
    CHECK(n == 39u && der[3] == 32u && der[4] == 0u && der[5] == 0x81u);
    CHECK(der[36] == 0x02u && der[37] == 1u && der[38] == 0u);

    CHECK(fmt_raw_sig_to_der(NULL, der) == 0u);
    CHECK(fmt_raw_sig_to_der(raw, NULL) == 0u);
}

static void test_u2f_bases(void)
{
    uint8_t app[32], chal[32], kh[5], pub[65], base[140];
    uint8_t auth[69];

    fill(app, sizeof app, 1u);
    fill(chal, sizeof chal, 33u);
    fill(kh, sizeof kh, 70u);
    fill(pub, sizeof pub, 90u);
    CHECK(fmt_u2f_reg_base(base, sizeof base, app, chal, kh, sizeof kh, pub) == 136u);
    CHECK(base[0] == 0u);
    CHECK(memcmp(base + 1u, app, 32u) == 0);
    CHECK(memcmp(base + 33u, chal, 32u) == 0);
    CHECK(base[65] == 5u);
    CHECK(memcmp(base + 66u, kh, sizeof kh) == 0);
    CHECK(memcmp(base + 71u, pub, sizeof pub) == 0);
    CHECK(fmt_u2f_reg_base(base, 135u, app, chal, kh, sizeof kh, pub) == 0u);
    CHECK(fmt_u2f_reg_base(base, sizeof base, app, chal, NULL, 1u, pub) == 0u);
    CHECK(fmt_u2f_reg_base(base, sizeof base, app, chal, NULL, 0u, pub) == 131u);

    CHECK(fmt_u2f_auth_base(auth, app, 0x01u, 0x01020304u, chal) == 69u);
    CHECK(memcmp(auth, app, 32u) == 0 && auth[32] == 1u);
    CHECK(auth[33] == 1u && auth[34] == 2u && auth[35] == 3u && auth[36] == 4u);
    CHECK(memcmp(auth + 37u, chal, 32u) == 0);
    CHECK(fmt_u2f_auth_base(NULL, app, 0u, 0u, chal) == 0u);
}

static void test_ctaphid(void)
{
    uint8_t frame[64], data[59];

    fill(data, sizeof data, 1u);
    CHECK(fmt_ctaphid_init(frame, 0x12345678u, 0x86u, data, 57u) == 64u);
    CHECK(frame[0] == 0x12u && frame[1] == 0x34u);
    CHECK(frame[2] == 0x56u && frame[3] == 0x78u);
    CHECK(frame[4] == 0x86u && frame[5] == 0u && frame[6] == 57u);
    CHECK(memcmp(frame + 7u, data, 57u) == 0);
    CHECK(fmt_ctaphid_init(frame, 0u, 0x06u, NULL, 0u) == 64u && frame[4] == 0x86u);
    CHECK(frame[7] == 0u && frame[63] == 0u);
    CHECK(fmt_ctaphid_init(frame, 0u, 0x86u, data, 58u) == 0u);

    CHECK(fmt_ctaphid_cont(frame, 0x01020304u, 0x8Bu, data, 59u) == 64u);
    CHECK(frame[0] == 1u && frame[1] == 2u && frame[2] == 3u && frame[3] == 4u);
    CHECK(frame[4] == 0x0Bu && memcmp(frame + 5u, data, 59u) == 0);
    CHECK(fmt_ctaphid_cont(frame, 0u, 0u, data, 60u) == 0u);
}

static void test_ble(void)
{
    uint8_t out[80], data[5];

    fill(data, sizeof data, 0x20u);
    CHECK(fmt_ble_init(out, sizeof out, 0x03u, data, sizeof data) == 8u);
    CHECK(out[0] == 0x83u && out[1] == 0u && out[2] == 5u);
    CHECK(memcmp(out + 3u, data, sizeof data) == 0);
    CHECK(fmt_ble_init(out, 7u, 0x03u, data, sizeof data) == 0u);

    CHECK(fmt_ble_cont(out, sizeof out, 0x85u, data, sizeof data) == 6u);
    CHECK(out[0] == 5u && memcmp(out + 1u, data, sizeof data) == 0);
    CHECK(fmt_ble_cont(out, 5u, 0u, data, sizeof data) == 0u);
}

int main(void)
{
    test_cose_key();
    test_auth_data();
    test_der();
    test_u2f_bases();
    test_ctaphid();
    test_ble();
    printf("%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
