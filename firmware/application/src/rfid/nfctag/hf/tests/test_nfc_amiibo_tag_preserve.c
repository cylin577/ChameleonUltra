/* Host tests for the pure golden-snapshot helper (no NFC hardware/SDK). */
#include "../nfc_amiibo_tag_preserve.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

#define NTAG215 NFC_AMIIBO_TAG_PRESERVE_NTAG215_TYPE
#define BUF_SIZE 128

static void fill(uint8_t *buf, uint8_t seed) {
    for (size_t i = 0; i < BUF_SIZE; i++) buf[i] = (uint8_t)(seed + i);
}

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

static bool source_contains_call(const char *path) {
    return source_contains(path, "nfc_tag_mf0_ntag_update_golden_snapshot");
}

int main(void) {
    /* Target predicate: an active, marked NTAG215 only. The signature is
     * irrelevant, so an unsigned marked Amiibo still gets a golden snapshot. */
    CHECK(nfc_amiibo_tag_preserve_is_target(NTAG215, true));
    CHECK(!nfc_amiibo_tag_preserve_is_target(NTAG215, false)); /* plain NTAG215 */
    CHECK(!nfc_amiibo_tag_preserve_is_target(1100u, true));    /* NTAG213 */
    CHECK(!nfc_amiibo_tag_preserve_is_target(1102u, true));    /* NTAG216 */

    /* Capture -> mutate -> restore is byte-identical. */
    nfc_amiibo_tag_preserve_t ctx;
    uint8_t live[BUF_SIZE], expected[BUF_SIZE];
    memset(&ctx, 0, sizeof(ctx));
    fill(live, 1);
    memcpy(expected, live, sizeof(expected));
    nfc_amiibo_tag_preserve_capture(&ctx, live, sizeof(live));
    CHECK(nfc_amiibo_tag_preserve_is_valid(&ctx));
    CHECK(!nfc_amiibo_tag_preserve_is_dirty(&ctx));
    fill(live, 99); /* simulate scan/counter drift */
    CHECK(memcmp(live, expected, sizeof(live)) != 0);
    CHECK(nfc_amiibo_tag_preserve_is_dirty(&ctx) == false);
    nfc_amiibo_tag_preserve_take(&ctx, live);
    CHECK(memcmp(live, expected, sizeof(live)) == 0);

    /* Dirty bookkeeping only works on a valid snapshot. */
    nfc_amiibo_tag_preserve_mark_dirty(&ctx);
    CHECK(nfc_amiibo_tag_preserve_is_dirty(&ctx));
    nfc_amiibo_tag_preserve_mark_clean(&ctx);
    CHECK(!nfc_amiibo_tag_preserve_is_dirty(&ctx));

    /* Clean / invalid: take is a no-op and dirty cannot be set. */
    nfc_amiibo_tag_preserve_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    CHECK(!nfc_amiibo_tag_preserve_is_valid(&fresh));
    nfc_amiibo_tag_preserve_mark_dirty(&fresh);
    CHECK(!nfc_amiibo_tag_preserve_is_dirty(&fresh));
    fill(live, 7);
    uint8_t untouched[BUF_SIZE];
    memcpy(untouched, live, sizeof(untouched));
    nfc_amiibo_tag_preserve_take(&fresh, live);
    CHECK(memcmp(live, untouched, sizeof(live)) == 0);
    nfc_amiibo_tag_preserve_invalidate(&ctx);
    CHECK(!nfc_amiibo_tag_preserve_is_valid(&ctx));
    nfc_amiibo_tag_preserve_take(&ctx, live);
    CHECK(memcmp(live, untouched, sizeof(live)) == 0);

    /* Commit refreshes golden: take now yields the new state. */
    fill(live, 1);
    nfc_amiibo_tag_preserve_capture(&ctx, live, sizeof(live));
    fill(live, 40);
    memcpy(expected, live, sizeof(expected));
    nfc_amiibo_tag_preserve_commit(&ctx, live, sizeof(live));
    CHECK(nfc_amiibo_tag_preserve_is_valid(&ctx));
    CHECK(!nfc_amiibo_tag_preserve_is_dirty(&ctx));
    fill(live, 99);
    nfc_amiibo_tag_preserve_take(&ctx, live);
    CHECK(memcmp(live, expected, sizeof(live)) == 0);

    /* Oversized capture is rejected, not partially stored. */
    nfc_amiibo_tag_preserve_invalidate(&ctx);
    static uint8_t too_big[NFC_AMIIBO_TAG_PRESERVE_SIZE + 1];
    nfc_amiibo_tag_preserve_capture(&ctx, too_big, sizeof(too_big));
    CHECK(!nfc_amiibo_tag_preserve_is_valid(&ctx));

    /* Field-edge policy on a golden-bearing tag. */
    {
        nfc_amiibo_tag_preserve_t f;
        uint8_t golden[BUF_SIZE], committed[BUF_SIZE];
        memset(&f, 0, sizeof(f));
        fill(live, 1);
        memcpy(golden, live, sizeof(golden));
        nfc_amiibo_tag_preserve_capture(&f, live, sizeof(live));

        /* Clean scan: DETECTED must not revert live state. */
        fill(live, 2);
        CHECK(nfc_amiibo_tag_preserve_on_field(&f, true, live, sizeof(live)) ==
              NFC_AMIIBO_PRESERVE_FIELD_NONE);
        CHECK(live[0] == 2);
        CHECK(!nfc_amiibo_tag_preserve_is_dirty(&f));

        /* Commands drift the live tag; an interrupted session (no LOST
         * commit) restores golden on the next DETECTED. */
        nfc_amiibo_tag_preserve_mark_dirty(&f);
        fill(live, 99);
        CHECK(nfc_amiibo_tag_preserve_on_field(&f, true, live, sizeof(live)) ==
              NFC_AMIIBO_PRESERVE_FIELD_RESTORE);
        CHECK(memcmp(live, golden, sizeof(live)) == 0);
        CHECK(!nfc_amiibo_tag_preserve_is_dirty(&f));

        /* A mid-field save while dirty restores golden (never persists a
         * partial write). */
        nfc_amiibo_tag_preserve_mark_dirty(&f);
        fill(live, 55);
        nfc_amiibo_tag_preserve_take(&f, live);
        CHECK(memcmp(live, golden, sizeof(live)) == 0);

        /* Completed session: LOST while dirty commits live as the new golden. */
        nfc_amiibo_tag_preserve_mark_dirty(&f);
        fill(live, 40);
        memcpy(committed, live, sizeof(committed));
        CHECK(nfc_amiibo_tag_preserve_on_field(&f, false, live, sizeof(live)) ==
              NFC_AMIIBO_PRESERVE_FIELD_COMMIT);
        CHECK(!nfc_amiibo_tag_preserve_is_dirty(&f));
        CHECK(memcmp(golden, committed, sizeof(golden)) != 0);

        /* The following DETECTED must keep the committed writes/counter. */
        fill(live, 7);
        CHECK(nfc_amiibo_tag_preserve_on_field(&f, true, live, sizeof(live)) ==
              NFC_AMIIBO_PRESERVE_FIELD_NONE);
        CHECK(live[0] == 7);
        nfc_amiibo_tag_preserve_take(&f, live);
        CHECK(memcmp(live, committed, sizeof(live)) == 0);
    }

    /* Unsigned Guardian / unmarked NTAG215: no golden, so neither field edge
     * touches live data. */
    {
        nfc_amiibo_tag_preserve_t no_golden;
        memset(&no_golden, 0, sizeof(no_golden));
        CHECK(!nfc_amiibo_tag_preserve_is_valid(&no_golden));
        fill(live, 3);
        uint8_t before[BUF_SIZE];
        memcpy(before, live, sizeof(before));
        nfc_amiibo_tag_preserve_mark_dirty(&no_golden);
        CHECK(!nfc_amiibo_tag_preserve_is_dirty(&no_golden));
        CHECK(nfc_amiibo_tag_preserve_on_field(&no_golden, true, live, sizeof(live)) ==
              NFC_AMIIBO_PRESERVE_FIELD_NONE);
        CHECK(memcmp(live, before, sizeof(live)) == 0);
        CHECK(nfc_amiibo_tag_preserve_on_field(&no_golden, false, live, sizeof(live)) ==
              NFC_AMIIBO_PRESERVE_FIELD_NONE);
        CHECK(memcmp(live, before, sizeof(live)) == 0);
    }

    /* Non-target / call-site wiring: the firmware disables the snapshot for
     * non-targets and refreshes it after an intentional modification. */
    CHECK(source_contains_call("../nfc_amiibo_refresh_slot.c"));
    CHECK(source_contains_call("../../../../app_cmd.c"));
    CHECK(source_contains("../nfc_mf0_ntag.c", "nfc_tag_mf0_ntag_is_amiibo_active()"));
    /* The field handler must drive the new commit-on-LOST / restore-on-DETECTED
     * policy, and saves must still restore golden while dirty. */
    CHECK(source_contains("../nfc_mf0_ntag.c", "nfc_amiibo_tag_preserve_on_field"));
    CHECK(source_contains("../nfc_mf0_ntag.c", "nfc_amiibo_tag_preserve_is_dirty(&m_amiibo_golden)"));

    printf("test_nfc_amiibo_tag_preserve: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
