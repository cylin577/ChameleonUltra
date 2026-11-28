/* Native tests for the CTAP2 CBOR reader/writer. */
#include "../../fido2/fido2_cbor.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static void test_uints(void)
{
    fido2_cbor_r_t r;
    uint64_t u;
    uint8_t a[] = {0x01};
    uint8_t b[] = {0x18, 0x2A};
    uint8_t c[] = {0x18, 0x18};
    uint8_t d[] = {0x19, 0x01, 0x00};
    uint8_t e[] = {0x1A, 0x00, 0x01, 0x00, 0x00};
    uint8_t f[] = {0x1B, 0, 0, 0, 1, 0, 0, 0, 0};

    cr_init(&r, a, sizeof a);
    CHECK(cr_uint(&r, &u) && u == 1u && r.pos == sizeof a);
    cr_init(&r, b, sizeof b);
    CHECK(cr_uint(&r, &u) && u == 42u && r.pos == sizeof b);
    cr_init(&r, c, sizeof c);
    CHECK(cr_uint(&r, &u) && u == 24u);
    cr_init(&r, d, sizeof d);
    CHECK(cr_uint(&r, &u) && u == 256u);
    cr_init(&r, e, sizeof e);
    CHECK(cr_uint(&r, &u) && u == 65536u);
    cr_init(&r, f, sizeof f);
    CHECK(cr_uint(&r, &u) && u == 4294967296ULL);
}

static void test_ints(void)
{
    fido2_cbor_r_t r;
    int64_t v;
    uint8_t minus_one[] = {0x20};
    uint8_t minus_48[] = {0x38, 0x2F};
    uint8_t zero[] = {0x00};
    uint8_t min[] = {0x3B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t too_big[] = {0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    cr_init(&r, minus_one, sizeof minus_one);
    CHECK(cr_int(&r, &v) && v == -1);
    cr_init(&r, minus_48, sizeof minus_48);
    CHECK(cr_int(&r, &v) && v == -48);
    cr_init(&r, zero, sizeof zero);
    CHECK(cr_int(&r, &v) && v == 0);
    cr_init(&r, min, sizeof min);
    CHECK(cr_int(&r, &v) && v == INT64_MIN);
    cr_init(&r, too_big, sizeof too_big);
    CHECK(!cr_int(&r, &v));
}

static void test_strings_and_headers(void)
{
    fido2_cbor_r_t r;
    const uint8_t *p;
    size_t n;
    bool b;
    uint8_t bytes[] = {0x42, 0x01, 0x02};
    uint8_t text[] = {0x63, 'a', 'b', 'c'};
    uint8_t arr[] = {0x82};
    uint8_t map[] = {0xA2};
    uint8_t yes[] = {0xF5};
    uint8_t no[] = {0xF4};

    cr_init(&r, bytes, sizeof bytes);
    CHECK(cr_bytes(&r, &p, &n) && n == 2u && p[0] == 1u && p[1] == 2u);
    CHECK(r.pos == sizeof bytes);
    cr_init(&r, text, sizeof text);
    CHECK(cr_text(&r, &p, &n) && n == 3u && memcmp(p, "abc", 3u) == 0);
    cr_init(&r, arr, sizeof arr);
    CHECK(cr_array(&r, &n) && n == 2u);
    cr_init(&r, map, sizeof map);
    CHECK(cr_map(&r, &n) && n == 2u);
    cr_init(&r, yes, sizeof yes);
    CHECK(cr_bool(&r, &b) && b);
    cr_init(&r, no, sizeof no);
    CHECK(cr_bool(&r, &b) && !b);
}

static void test_rejects(void)
{
    fido2_cbor_r_t r;
    uint64_t u;
    size_t n;
    const uint8_t *p;
    bool b;
    uint8_t indefinite[] = {0x9F};
    uint8_t tag[] = {0xC0, 0x00};
    uint8_t truncated[] = {0x18};
    uint8_t non_shortest[] = {0x18, 0x17};
    uint8_t reserved[] = {0x1C};
    uint8_t short_bytes[] = {0x43, 0x01};
    uint8_t wrong_major[] = {0x22};
    uint8_t null_value[] = {0xF6};
    uint8_t float32[] = {0xFA, 0, 0, 0, 0};

    cr_init(&r, indefinite, sizeof indefinite);
    CHECK(!cr_array(&r, &n) && r.failed);
    cr_init(&r, tag, sizeof tag);
    CHECK(!cr_uint(&r, &u) && r.failed);
    cr_init(&r, truncated, sizeof truncated);
    CHECK(!cr_uint(&r, &u) && r.failed);
    cr_init(&r, non_shortest, sizeof non_shortest);
    CHECK(!cr_uint(&r, &u) && r.failed);
    cr_init(&r, reserved, sizeof reserved);
    CHECK(!cr_uint(&r, &u) && r.failed);
    cr_init(&r, short_bytes, sizeof short_bytes);
    CHECK(!cr_bytes(&r, &p, &n) && r.failed);
    cr_init(&r, wrong_major, sizeof wrong_major);
    CHECK(!cr_uint(&r, &u) && r.failed);
    cr_init(&r, null_value, sizeof null_value);
    CHECK(!cr_bool(&r, &b) && r.failed);
    cr_init(&r, float32, sizeof float32);
    CHECK(!cr_uint(&r, &u) && r.failed);
}

static void test_encoder(void)
{
    fido2_cbor_w_t w;
    fido2_cbor_r_t r;
    uint8_t buf[64];
    uint8_t small[2];
    uint8_t payload[] = {9, 8, 7};
    uint64_t u;
    int64_t v;
    size_t n, count;
    const uint8_t *p;

    cw_init(&w, buf, sizeof buf);
    cw_array(&w, 3u);
    cw_uint(&w, 1u);
    cw_int(&w, -7);
    cw_text(&w, "hi", 2u);
    n = cw_finish(&w);
    CHECK(n == 6u && buf[0] == 0x83u && buf[1] == 0x01u && buf[2] == 0x26u);
    CHECK(buf[3] == 0x62u && buf[4] == 'h' && buf[5] == 'i');

    cr_init(&r, buf, n);
    CHECK(cr_array(&r, &count) && count == 3u);
    CHECK(cr_uint(&r, &u) && u == 1u);
    CHECK(cr_int(&r, &v) && v == -7);
    CHECK(cr_text(&r, &p, &count) && count == 2u && p[0] == 'h');

    cw_init(&w, buf, sizeof buf);
    cw_map(&w, 2u);
    cw_bool(&w, true);
    cw_bytes(&w, payload, sizeof payload);
    n = cw_finish(&w);
    CHECK(n == 6u && buf[0] == 0xA2u && buf[1] == 0xF5u);
    CHECK(buf[2] == 0x43u && memcmp(buf + 3u, payload, 3u) == 0);

    cw_init(&w, buf, sizeof buf);
    cw_uint(&w, 42u);
    CHECK(cw_finish(&w) == 2u && buf[0] == 0x18u && buf[1] == 0x2Au);
    cw_init(&w, buf, sizeof buf);
    cw_uint(&w, 0xFFFFFFFFULL);
    CHECK(cw_finish(&w) == 5u && buf[0] == 0x1Au);
    cw_init(&w, buf, sizeof buf);
    cw_uint(&w, 0x100000000ULL);
    CHECK(cw_finish(&w) == 9u && buf[0] == 0x1Bu);
    cw_init(&w, buf, sizeof buf);
    cw_int(&w, INT64_MIN);
    CHECK(cw_finish(&w) == 9u && buf[0] == 0x3Bu);

    cw_init(&w, small, sizeof small);
    cw_uint(&w, 300u);
    CHECK(w.failed && cw_finish(&w) == 0u);
    cw_init(&w, buf, sizeof buf);
    cw_bytes(&w, NULL, 1u);
    CHECK(w.failed && cw_finish(&w) == 0u);
}

int main(void)
{
    test_uints();
    test_ints();
    test_strings_and_headers();
    test_rejects();
    test_encoder();
    printf("%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
