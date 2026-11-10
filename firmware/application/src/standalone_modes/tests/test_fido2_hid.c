/*
 * Host tests for the USB CTAPHID transport.
 */
#include "../fido2_core.h"
#include "../fido2_hid.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static uint8_t g_mk[32];
static uint32_t g_ctr;
static uint32_t g_rng = 0xC0FFEE02u;
static uint32_t g_now_ms;

static bool io_load_mk(uint8_t mk[32]) { memcpy(mk, g_mk, sizeof g_mk); return true; }
static bool io_store_mk(const uint8_t mk[32]) { memcpy(g_mk, mk, sizeof g_mk); return true; }
static bool io_load_ctr(uint32_t *ctr) { *ctr = g_ctr; return true; }
static void io_store_ctr(uint32_t ctr) { g_ctr = ctr; }
static bool io_random(uint8_t *dst, size_t len) {
    for (size_t i = 0; i < len; i++) {
        g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5;
        dst[i] = (uint8_t)(g_rng >> 24);
    }
    return true;
}
static uint32_t io_now_ms(void) { return g_now_ms; }
static const fido2_core_io_t g_io = {
    .load_master_key  = io_load_mk,
    .store_master_key = io_store_mk,
    .load_counter     = io_load_ctr,
    .store_counter    = io_store_ctr,
    .random_bytes     = io_random,
    .now_ms           = io_now_ms,
};

static uint8_t g_sent[8][FIDO2_HID_PKT_SIZE];
static size_t g_sent_count;

static bool capture_packet(const uint8_t *pkt, size_t len) {
    if (g_sent_count >= sizeof(g_sent) / sizeof(g_sent[0]) || len != FIDO2_HID_PKT_SIZE) return false;
    memcpy(g_sent[g_sent_count++], pkt, len);
    return true;
}

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static size_t make_packet(uint8_t *pkt, uint32_t cid, uint8_t cmd,
                          const uint8_t *payload, uint16_t len) {
    memset(pkt, 0, FIDO2_HID_PKT_SIZE);
    put_u32(pkt, cid);
    pkt[4] = cmd;
    pkt[5] = (uint8_t)(len >> 8);
    pkt[6] = (uint8_t)len;
    uint16_t n = len > FIDO2_HID_INIT_DATA ? FIDO2_HID_INIT_DATA : len;
    if (n) memcpy(pkt + 7, payload, n);
    return len;
}

static void send_hid_payload(uint32_t cid, uint8_t cmd,
                             const uint8_t *payload, uint16_t len) {
    uint8_t packet[FIDO2_HID_PKT_SIZE];
    uint16_t n = len > FIDO2_HID_INIT_DATA ? FIDO2_HID_INIT_DATA : len;
    make_packet(packet, cid, cmd, payload, len);
    if (n < len) memcpy(packet + 7, payload, n);
    fido2_hid_on_out_report(packet, sizeof packet);
    if (n < len) {
        memset(packet, 0, sizeof packet);
        put_u32(packet, cid);
        packet[4] = 0;
        memcpy(packet + 5, payload + n, len - n);
        fido2_hid_on_out_report(packet, sizeof packet);
    }
}

static void reset_mode(void) {
    fido2_core_init(&g_io);
    CHECK(fido2_core_arm(FIDO2_TRANSPORT_USB));
    fido2_hid_init();
    fido2_hid_set_sender(capture_packet);
    g_sent_count = 0;
}

static void test_init_and_unknown_cid(void) {
    reset_mode();
    uint8_t nonce[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t packet[FIDO2_HID_PKT_SIZE];
    make_packet(packet, FIDO2_HID_CID_BROADCAST, FIDO2_HID_CMD_INIT, nonce, sizeof nonce);
    fido2_hid_on_out_report(packet, sizeof packet);
    fido2_hid_poll();

    CHECK(g_sent_count == 1);
    if (g_sent_count != 1) return;
    uint8_t *ans = g_sent[0];
    CHECK(get_u32(ans) == FIDO2_HID_CID_BROADCAST);
    uint32_t allocated_cid = get_u32(ans + 7 + 8);
    CHECK(allocated_cid != 0 && allocated_cid != FIDO2_HID_CID_BROADCAST);
    CHECK(ans[4] == FIDO2_HID_CMD_INIT);
    CHECK(((uint16_t)ans[5] << 8 | ans[6]) == 17);
    CHECK(memcmp(ans + 7, nonce, sizeof nonce) == 0);
    CHECK(ans[7 + 12] == FIDO2_HID_PROTOVER);
    CHECK(ans[7 + 12] == 0x02);
    CHECK(FIDO2_HID_CMD_PING == 0x81);
    CHECK(FIDO2_HID_CMD_CBOR == 0x90);
    CHECK(FIDO2_HID_CMD_INIT == 0x86);
    CHECK(FIDO2_HID_CMD_CANCEL == 0x91);
    CHECK(FIDO2_HID_CMD_ERROR == 0xBF);
    CHECK(FIDO2_HID_CMD_KEEPALIVE == 0xBB);
    CHECK(FIDO2_HID_CAPS == 0x0C);
    fido2_hid_on_in_report_done();

    /* INIT on the allocated CID synchronizes that channel without changing it. */
    uint8_t sync_nonce[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
    g_sent_count = 0;
    make_packet(packet, allocated_cid, FIDO2_HID_CMD_INIT, sync_nonce, sizeof sync_nonce);
    fido2_hid_on_out_report(packet, sizeof packet);
    fido2_hid_poll();
    CHECK(g_sent_count == 1);
    if (g_sent_count != 1) return;
    CHECK(get_u32(g_sent[0]) == allocated_cid);
    CHECK(get_u32(g_sent[0] + 7 + 8) == allocated_cid);
    CHECK(memcmp(g_sent[0] + 7, sync_nonce, sizeof sync_nonce) == 0);
    fido2_hid_on_in_report_done();

    /* An unknown channel gets ERR_INVALID_CHANNEL, not silence. */
    g_sent_count = 0;
    make_packet(packet, 0x12345678u, FIDO2_HID_CMD_PING, NULL, 0);
    fido2_hid_on_out_report(packet, sizeof packet);
    fido2_hid_poll();
    CHECK(g_sent_count == 1);
    if (g_sent_count != 1) return;
    CHECK(get_u32(g_sent[0]) == 0x12345678u);
    CHECK(g_sent[0][4] == FIDO2_HID_CMD_ERROR);
    CHECK(((uint16_t)g_sent[0][5] << 8 | g_sent[0][6]) == 1);
    CHECK(g_sent[0][7] == FIDO2_HID_ERR_INVALID_CHANNEL);
}

static void test_separate_request_response_buffers(void) {
    reset_mode();
    uint8_t nonce[8] = { 0 };
    uint8_t packet[FIDO2_HID_PKT_SIZE];
    make_packet(packet, FIDO2_HID_CID_BROADCAST, FIDO2_HID_CMD_INIT, nonce, sizeof nonce);
    fido2_hid_on_out_report(packet, sizeof packet);
    fido2_hid_poll();
    uint32_t cid = get_u32(g_sent[0] + 7 + 8);
    fido2_hid_on_in_report_done();
    g_sent_count = 0;

    uint8_t first[100], second[100];
    memset(first, 0xA5, sizeof first);
    memset(second, 0x5A, sizeof second);
    send_hid_payload(cid, FIDO2_HID_CMD_PING, first, sizeof first);
    fido2_hid_poll();
    CHECK(g_sent_count == 1);

    /* Queue another fragmented request while the first answer is still being
     * sent. It must not overwrite the first answer's pending continuation. */
    send_hid_payload(cid, FIDO2_HID_CMD_PING, second, sizeof second);
    fido2_hid_on_in_report_done();
    fido2_hid_poll();
    CHECK(g_sent_count == 2);
    if (g_sent_count != 2) return;
    for (size_t i = 0; i < sizeof(first) - FIDO2_HID_INIT_DATA; i++) {
        CHECK(g_sent[1][5 + i] == 0xA5);
    }
}

static size_t build_make_cred(uint8_t *buf, const uint8_t cdh[32]) {
    size_t i = 0;
    buf[i++] = 0xA3;
    buf[i++] = 0x01; buf[i++] = 0x58; buf[i++] = 0x20;
    memcpy(buf + i, cdh, 32); i += 32;
    buf[i++] = 0x02; buf[i++] = 0xA1;
    buf[i++] = 0x62; buf[i++] = 'i'; buf[i++] = 'd';
    buf[i++] = 0x6B; memcpy(buf + i, "example.com", 11); i += 11;
    buf[i++] = 0x04; buf[i++] = 0x81; buf[i++] = 0xA2;
    buf[i++] = 0x63; buf[i++] = 'a'; buf[i++] = 'l'; buf[i++] = 'g'; buf[i++] = 0x26;
    buf[i++] = 0x64; buf[i++] = 't'; buf[i++] = 'y'; buf[i++] = 'p'; buf[i++] = 'e';
    buf[i++] = 0x6A; memcpy(buf + i, "public-key", 10); i += 10;
    return i;
}

static void test_cancel(void) {
    reset_mode();
    uint8_t nonce[8] = { 0 };
    uint8_t packet[FIDO2_HID_PKT_SIZE];
    make_packet(packet, FIDO2_HID_CID_BROADCAST, FIDO2_HID_CMD_INIT, nonce, sizeof nonce);
    fido2_hid_on_out_report(packet, sizeof packet);
    fido2_hid_poll();
    uint32_t cid = get_u32(g_sent[0] + 7 + 8);
    fido2_hid_on_in_report_done();
    g_sent_count = 0;

    uint8_t cdh[32];
    memset(cdh, 0x11, sizeof cdh);
    uint8_t request[256];
    size_t body_len = build_make_cred(request, cdh);
    uint8_t msg[257];
    msg[0] = FIDO2_CMD_MAKE_CREDENTIAL;
    memcpy(msg + 1, request, body_len);
    send_hid_payload(cid, FIDO2_HID_CMD_CBOR, msg, (uint16_t)(body_len + 1));
    fido2_tick();
    fido2_hid_poll();
    CHECK(g_sent_count == 1);
    if (g_sent_count != 1) return;
    CHECK(g_sent[0][4] == FIDO2_HID_CMD_KEEPALIVE);
    CHECK(g_sent[0][7] == FIDO2_HID_KEEPALIVE_UPNEEDED);
    fido2_hid_on_in_report_done();

    make_packet(packet, cid, FIDO2_HID_CMD_CANCEL, NULL, 0);
    fido2_hid_on_out_report(packet, sizeof packet);
    fido2_hid_poll();
    CHECK(g_sent_count == 2);
    if (g_sent_count != 2) return;
    CHECK(g_sent[1][4] == FIDO2_HID_CMD_CBOR);
    CHECK(g_sent[1][7] == FIDO2_ERR_KEEPALIVE_CANCEL);
}

int main(void) {
    memset(g_mk, 0x5A, sizeof g_mk);
    test_init_and_unknown_cid();
    test_separate_request_response_buffers();
    test_cancel();
    printf("%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
