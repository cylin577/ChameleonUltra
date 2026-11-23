/* Host tests for the per-field-session NTAG counter policy (no NFC/SDK). Only
 * an active, marked NTAG215 Amiibo freezes the counter; a plain NTAG215 and
 * every other NTAG type keep the one-per-field-session increment. */
#include "../nfc_mf0_ntag_counter.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

#define NTAG215 NFC_MF0_NTAG_COUNTER_TAG_TYPE_NTAG215
#define NTAG213 1100u
#define NTAG216 1102u
#define CNT_EN  NFC_MF0_NTAG_COUNTER_ACCESS_NFC_CNT_EN

static bool source_contains(const char *path, const char *needle) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, needle) != NULL) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

int main(void) {
    /* Marked NTAG215 Amiibo: repeated field sessions / READs leave it alone. */
    {
        uint8_t ctr[3] = {0x00, 0x12, 0x34};
        bool first_read;
        for (int session = 0; session < 5; session++) {
            first_read = false; /* FIELD_DETECTED resets the session flag */
            for (int read = 0; read < 3; read++) {
                nfc_mf0_ntag_counter_on_read(NTAG215, CNT_EN, &first_read, ctr, true);
            }
            CHECK(ctr[0] == 0x00 && ctr[1] == 0x12 && ctr[2] == 0x34);
        }
        CHECK(first_read);
    }

    /* Plain (unmarked) NTAG215: the counter still increments once per session. */
    {
        uint8_t ctr[3] = {0x00, 0x00, 0x05};
        bool first_read = false;
        nfc_mf0_ntag_counter_on_read(NTAG215, CNT_EN, &first_read, ctr, false);
        nfc_mf0_ntag_counter_on_read(NTAG215, CNT_EN, &first_read, ctr, false);
        CHECK(ctr[0] == 0 && ctr[1] == 0 && ctr[2] == 6);
        CHECK(first_read);
    }

    /* Explicit counter APIs still own the stored value: a value written via
     * a counter command survives any number of subsequent marked-Amiibo reads. */
    {
        uint8_t ctr[3] = {0x00, 0x00, 0x01};
        bool first_read = false;
        nfc_mf0_ntag_counter_on_read(NTAG215, CNT_EN, &first_read, ctr, true);
        CHECK(ctr[0] == 0 && ctr[1] == 0 && ctr[2] == 1);

        ctr[0] = 0x00; ctr[1] = 0xAB; ctr[2] = 0xCD; /* explicit set */
        for (int session = 0; session < 4; session++) {
            first_read = false;
            nfc_mf0_ntag_counter_on_read(NTAG215, CNT_EN, &first_read, ctr, true);
        }
        CHECK(ctr[0] == 0x00 && ctr[1] == 0xAB && ctr[2] == 0xCD);
    }

    /* Other NTAG types keep the old increment, even if is_amiibo is set. */
    {
        uint8_t ctr[3] = {0x00, 0x00, 0x05};
        bool first_read = false;
        nfc_mf0_ntag_counter_on_read(NTAG213, CNT_EN, &first_read, ctr, false);
        nfc_mf0_ntag_counter_on_read(NTAG213, CNT_EN, &first_read, ctr, false);
        CHECK(ctr[0] == 0 && ctr[1] == 0 && ctr[2] == 6);
        CHECK(first_read);

        first_read = false;
        nfc_mf0_ntag_counter_on_read(NTAG216, CNT_EN, &first_read, ctr, true);
        CHECK(ctr[0] == 0 && ctr[1] == 0 && ctr[2] == 7);
    }

    /* Counter-enable config bit gates the increment for non-NTAG215 types. */
    {
        uint8_t ctr[3] = {0x00, 0x00, 0x09};
        bool first_read = false;
        nfc_mf0_ntag_counter_on_read(NTAG213, 0x00, &first_read, ctr, false);
        CHECK(ctr[0] == 0 && ctr[1] == 0 && ctr[2] == 9);
        CHECK(first_read);
    }

    /* 24-bit saturation is preserved for types that still increment. */
    {
        uint8_t ctr[3] = {0xFF, 0xFF, 0xFF};
        bool first_read = false;
        nfc_mf0_ntag_counter_on_read(NTAG213, CNT_EN, &first_read, ctr, false);
        CHECK(ctr[0] == 0xFF && ctr[1] == 0xFF && ctr[2] == 0xFF);
    }

    /* Firmware wiring: helper is called from the READ path with the active
     * Amiibo gate, and explicit counter commands are still present. */
    CHECK(source_contains("../nfc_mf0_ntag.c", "nfc_mf0_ntag_counter_on_read"));
    CHECK(source_contains("../nfc_mf0_ntag.c", "nfc_tag_mf0_ntag_is_amiibo_active());"));
    CHECK(source_contains("../nfc_mf0_ntag_counter.h", "bool is_amiibo"));
    CHECK(!source_contains("../nfc_mf0_ntag.c", "counter += 1"));
    CHECK(source_contains("../nfc_mf0_ntag.c", "nfc_tag_mf0_ntag_get_counter_data_by_index"));
    CHECK(source_contains("../../../../app_cmd.c", "cmd_processor_mf0_ntag_get_counter_data"));
    CHECK(source_contains("../../../../app_cmd.c", "cmd_processor_mf0_ntag_set_counter_data"));
    CHECK(source_contains("../../../../app_cmd.c", "cmd_processor_mf0_ntag_reset_auth_cnt"));

    printf("test_nfc_mf0_ntag_counter: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
