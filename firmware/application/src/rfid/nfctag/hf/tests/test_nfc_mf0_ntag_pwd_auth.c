/* Host tests for NTAG215 PWD_AUTH policy. Only an active, marked Amiibo slot
 * uses the pixl.js-style "accept any password, answer PACK 80 80" behavior; a
 * plain NTAG215 and every other tag keep strict PWD/PACK comparison. */
#include "../nfc_mf0_ntag_pwd_auth.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

#define NTAG215 NFC_MF0_NTAG_PWD_AUTH_TAG_TYPE_NTAG215
#define NTAG213 1100u
#define NTAG216 1102u

static char g_src[262144];

static bool load_source(const char *path, char *buf, size_t cap) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return false;
    size_t n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
    return true;
}

static bool source_contains(const char *path, const char *needle) {
    return load_source(path, g_src, sizeof(g_src)) && strstr(g_src, needle) != NULL;
}

/* Slice a function body out of a source file for fine-grained ordering checks. */
static bool function_contains(const char *path, const char *signature,
                              const char *needle, const char *before_needle) {
    if (!load_source(path, g_src, sizeof(g_src))) return false;
    char *start = strstr(g_src, signature);
    if (start == NULL) return false;
    char *end = strstr(start, "\n}\n");
    if (end == NULL) return false;
    char *hit = strstr(start, needle);
    if (hit == NULL || hit > end) return false;
    if (before_needle != NULL) {
        char *later = strstr(start, before_needle);
        if (later == NULL || later > end || later < hit) return false;
    }
    return true;
}

int main(void) {
    /* Marked NTAG215 Amiibo: a wrong password is accepted, PACK 80 80. */
    {
        const uint8_t stored_pwd[4] = {0x00, 0x00, 0x00, 0x00};
        const uint8_t stored_pack[2] = {0x12, 0x34};
        const uint8_t wrong_pwd[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        uint8_t pack[2] = {0, 0};
        CHECK(nfc_mf0_ntag_pwd_auth_decide(NTAG215, wrong_pwd, stored_pwd, stored_pack, true, pack));
        CHECK(pack[0] == 0x80 && pack[1] == 0x80);
    }

    /* Marked NTAG215: the correct password also gets the fixed PACK. */
    {
        const uint8_t stored_pwd[4] = {0xAA, 0xBB, 0xCC, 0xDD};
        const uint8_t stored_pack[2] = {0x12, 0x34};
        const uint8_t right_pwd[4] = {0xAA, 0xBB, 0xCC, 0xDD};
        uint8_t pack[2] = {0, 0};
        CHECK(nfc_mf0_ntag_pwd_auth_decide(NTAG215, right_pwd, stored_pwd, stored_pack, true, pack));
        CHECK(pack[0] == 0x80 && pack[1] == 0x80);
    }

    /* Stored PWD/PACK bytes are never mutated by the decision. */
    {
        uint8_t stored_pwd[4] = {0xAA, 0xBB, 0xCC, 0xDD};
        uint8_t stored_pack[2] = {0x56, 0x78};
        const uint8_t wrong_pwd[4] = {0x01, 0x02, 0x03, 0x04};
        uint8_t pack[2] = {0, 0};
        CHECK(nfc_mf0_ntag_pwd_auth_decide(NTAG215, wrong_pwd, stored_pwd, stored_pack, true, pack));
        CHECK(stored_pwd[0] == 0xAA && stored_pwd[1] == 0xBB &&
              stored_pwd[2] == 0xCC && stored_pwd[3] == 0xDD);
        CHECK(stored_pack[0] == 0x56 && stored_pack[1] == 0x78);
    }

    /* Plain (unmarked) NTAG215: strict comparison, configured PACK returned. */
    {
        const uint8_t stored_pwd[4] = {0xAA, 0xBB, 0xCC, 0xDD};
        const uint8_t stored_pack[2] = {0x12, 0x34};
        const uint8_t wrong_pwd[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        const uint8_t right_pwd[4] = {0xAA, 0xBB, 0xCC, 0xDD};
        uint8_t pack[2] = {0xEE, 0xEE};
        CHECK(!nfc_mf0_ntag_pwd_auth_decide(NTAG215, wrong_pwd, stored_pwd, stored_pack, false, pack));
        CHECK(nfc_mf0_ntag_pwd_auth_decide(NTAG215, right_pwd, stored_pwd, stored_pack, false, pack));
        CHECK(pack[0] == 0x12 && pack[1] == 0x34);
    }

    /* Other NTAG types keep strict PWD/PACK comparison regardless of marker. */
    {
        const uint8_t stored_pwd[4] = {0xAA, 0xBB, 0xCC, 0xDD};
        const uint8_t stored_pack[2] = {0x12, 0x34};
        const uint8_t wrong_pwd[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        const uint8_t right_pwd[4] = {0xAA, 0xBB, 0xCC, 0xDD};
        uint8_t pack[2] = {0xEE, 0xEE};
        CHECK(!nfc_mf0_ntag_pwd_auth_decide(NTAG213, wrong_pwd, stored_pwd, stored_pack, true, pack));
        CHECK(!nfc_mf0_ntag_pwd_auth_decide(NTAG216, wrong_pwd, stored_pwd, stored_pack, true, pack));
        CHECK(nfc_mf0_ntag_pwd_auth_decide(NTAG213, right_pwd, stored_pwd, stored_pack, true, pack));
        CHECK(pack[0] == 0x12 && pack[1] == 0x34);
    }

    /* Firmware wiring: detection logging still runs before the decision and
     * the decision is passed the active-Amiibo gate. */
    CHECK(function_contains("../nfc_mf0_ntag.c", "handle_pwd_auth_command",
                            "m_auth_log.count++", "nfc_mf0_ntag_pwd_auth_decide"));
    CHECK(function_contains("../nfc_mf0_ntag.c", "handle_pwd_auth_command",
                            "NTAG password:", "nfc_mf0_ntag_pwd_auth_decide"));
    CHECK(source_contains("../nfc_mf0_ntag.c",
                          "nfc_tag_mf0_ntag_is_amiibo_active(), pack"));
    CHECK(source_contains("../nfc_mf0_ntag_pwd_auth.h", "bool is_amiibo,"));

    /* Command 0x1B still reaches the activity hook and the handler. */
    CHECK(source_contains("../nfc_mf0_ntag.c", "nfc_amiibo_auto_refresh_on_command(command)"));
    CHECK(source_contains("../nfc_mf0_ntag.c", "case CMD_PWD_AUTH:"));
    CHECK(source_contains("../nfc_mf0_ntag.c", "handle_pwd_auth_command(p_data)"));
    CHECK(source_contains("../nfc_amiibo_auto_refresh.c", "cmd == CMD_PWD_AUTH"));

    /* The response comes from the helper output, and stored bytes are const. */
    CHECK(source_contains("../nfc_mf0_ntag.c", "nfc_tag_14a_tx_bytes(pack, 2, true)"));
    CHECK(source_contains("../nfc_mf0_ntag_pwd_auth.h", "const uint8_t stored_pwd[4]"));
    CHECK(source_contains("../nfc_mf0_ntag_pwd_auth.h", "const uint8_t stored_pack[2]"));

    printf("test_nfc_mf0_ntag_pwd_auth: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
