/* Host tests for the persistent per-slot Amiibo marker (no SDK/NFC). */
#include "../nfc_amiibo_slot_mark.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

#define NTAG215 NFC_AMIIBO_SLOT_MARK_NTAG215_TYPE
#define NTAG213 1100u
#define NTAG216 1102u
#define MAGIC   NFC_AMIIBO_SLOT_MARK_PAGE4_MAGIC

/* Mirror the config bitfield layout to prove the split keeps its size. */
typedef enum { MIRROR_MODE_NORMAL = 0, MIRROR_MODE_DENIED = 1 } mirror_mode_t;
typedef struct {
    uint8_t mode_uid_magic: 1;
    mirror_mode_t mode_block_write: 3;
    uint8_t detection_enable: 1;
    uint8_t reserved1: 3;
    uint8_t reserved2;
    uint8_t reserved3;
} old_cfg_t;
typedef struct {
    uint8_t mode_uid_magic: 1;
    mirror_mode_t mode_block_write: 3;
    uint8_t detection_enable: 1;
    uint8_t is_amiibo: 1;
    uint8_t amiibo_mark_locked: 1;
    uint8_t reserved1: 1;
    uint8_t reserved2;
    uint8_t reserved3;
} new_cfg_t;

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

/* True when `needle` appears on a line strictly after the first line
 * containing `anchor`. Used to assert the golden refresh follows the
 * active-slot marker write in amiibo_slot_mark_access(). */
static bool source_contains_after(const char *path, const char *anchor, const char *needle) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return false;
    char line[512];
    bool seen_anchor = false, found = false;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (!seen_anchor) {
            if (strstr(line, anchor) != NULL) seen_anchor = true;
        } else if (strstr(line, needle) != NULL) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

int main(void) {
    /* detect: NTAG215 + 0xA5 on page 4 only. */
    {
        uint8_t page4[4] = { MAGIC, 0x01, 0x02, 0x03 };
        CHECK(nfc_amiibo_slot_mark_detect(NTAG215, page4));
        page4[0] = 0x00;
        CHECK(!nfc_amiibo_slot_mark_detect(NTAG215, page4));
        page4[0] = MAGIC;
        CHECK(!nfc_amiibo_slot_mark_detect(NTAG213, page4));
        CHECK(!nfc_amiibo_slot_mark_detect(NTAG216, page4));
        CHECK(!nfc_amiibo_slot_mark_detect(NTAG215, NULL));
    }

    /* update: locked keeps the explicit value, unlocked follows detection. */
    {
        bool mark = false;
        nfc_amiibo_slot_mark_update(false, true, &mark);
        CHECK(mark);
        nfc_amiibo_slot_mark_update(false, false, &mark);
        CHECK(!mark);

        mark = true;
        nfc_amiibo_slot_mark_update(true, false, &mark);
        CHECK(mark);
        mark = false;
        nfc_amiibo_slot_mark_update(true, true, &mark);
        CHECK(!mark);
        nfc_amiibo_slot_mark_update(false, true, NULL); /* NULL is a no-op */
    }

    /* Active-slot getter gate: all four conditions must hold. */
    {
        CHECK(nfc_amiibo_slot_mark_is_active(true, true, true, true));
        CHECK(!nfc_amiibo_slot_mark_is_active(false, true, true, true));
        CHECK(!nfc_amiibo_slot_mark_is_active(true, false, true, true));
        CHECK(!nfc_amiibo_slot_mark_is_active(true, true, false, true));
        CHECK(!nfc_amiibo_slot_mark_is_active(true, true, true, false));
    }

    /* CMD 1074/1075 wire parsing. */
    {
        uint8_t slot = 0xFF;
        bool mark = false;
        uint8_t set[] = { 0x03, 0x01 };
        uint8_t clr[] = { 0x00, 0x00 };
        CHECK(nfc_amiibo_slot_mark_parse_set(2, set, &slot, &mark));
        CHECK(slot == 3 && mark);
        CHECK(nfc_amiibo_slot_mark_parse_set(2, clr, &slot, &mark));
        CHECK(slot == 0 && !mark);
        CHECK(!nfc_amiibo_slot_mark_parse_set(1, set, &slot, &mark));
        CHECK(!nfc_amiibo_slot_mark_parse_set(3, set, &slot, &mark));
        CHECK(!nfc_amiibo_slot_mark_parse_set(2, (uint8_t[]){8, 1}, &slot, &mark));
        CHECK(!nfc_amiibo_slot_mark_parse_set(2, (uint8_t[]){0, 2}, &slot, &mark));
        CHECK(!nfc_amiibo_slot_mark_parse_set(2, NULL, &slot, &mark));

        CHECK(nfc_amiibo_slot_mark_parse_get(1, set, &slot));
        CHECK(slot == 3);
        CHECK(!nfc_amiibo_slot_mark_parse_get(2, set, &slot));
        CHECK(!nfc_amiibo_slot_mark_parse_get(1, (uint8_t[]){8}, &slot));
        CHECK(!nfc_amiibo_slot_mark_parse_get(1, NULL, &slot));
    }

    /* Wire IDs: 1069-1073 unchanged, new commands adjacent. */
    CHECK(source_contains("../../../../data_cmd.h", "DATA_CMD_AMIIBO_UPLOAD_KEYS             (1069)"));
    CHECK(source_contains("../../../../data_cmd.h", "DATA_CMD_AMIIBO_REFRESH_UID             (1070)"));
    CHECK(source_contains("../../../../data_cmd.h", "DATA_CMD_AMIIBO_AUTO_REFRESH_SET        (1071)"));
    CHECK(source_contains("../../../../data_cmd.h", "DATA_CMD_AMIIBO_AUTO_REFRESH_GET        (1072)"));
    CHECK(source_contains("../../../../data_cmd.h", "DATA_CMD_AMIIBO_VERIFY_SLOT             (1073)"));
    CHECK(source_contains("../../../../data_cmd.h", "DATA_CMD_AMIIBO_SET_SLOT_MARK           (1074)"));
    CHECK(source_contains("../../../../data_cmd.h", "DATA_CMD_AMIIBO_GET_SLOT_MARK           (1075)"));

    /* Struct split keeps the config record three bytes (FDS layout unchanged). */
    CHECK(source_contains("../nfc_mf0_ntag.h", "uint8_t is_amiibo: 1;"));
    CHECK(source_contains("../nfc_mf0_ntag.h", "uint8_t amiibo_mark_locked: 1;"));
    CHECK(source_contains("../nfc_mf0_ntag.h", "uint8_t reserved1: 1;"));
    CHECK(sizeof(old_cfg_t) == sizeof(new_cfg_t));

    /* Firmware wiring: load, factory reset, and getter. */
    CHECK(source_contains("../nfc_mf0_ntag.c", "nfc_tag_mf0_ntag_update_amiibo_mark();"));
    CHECK(source_contains("../nfc_mf0_ntag.c", "config.amiibo_mark_locked = false;"));
    CHECK(source_contains("../nfc_mf0_ntag.c", "nfc_tag_mf0_ntag_is_amiibo_active(void)"));
    CHECK(source_contains("../nfc_mf0_ntag.c", "tag_emulation_get_specific_types_by_slot(tag_emulation_get_slot(), &types)"));

    /* Host page-write and signature-write refresh the cached marker; the
     * existing 1069-1073 handlers keep their length checks. */
    CHECK(source_contains("../../../../app_cmd.c", "cmd_processor_amiibo_set_slot_mark"));
    CHECK(source_contains("../../../../app_cmd.c", "cmd_processor_amiibo_get_slot_mark"));
    CHECK(source_contains("../../../../app_cmd.c", "DATA_CMD_AMIIBO_SET_SLOT_MARK"));
    CHECK(source_contains("../../../../app_cmd.c", "DATA_CMD_AMIIBO_GET_SLOT_MARK"));
    CHECK(source_contains("../../../../app_cmd.c", "nfc_amiibo_slot_mark_parse_set(length, data, &slot, &mark)"));
    CHECK(source_contains("../../../../app_cmd.c", "nfc_amiibo_slot_mark_parse_get(length, data, &slot)"));
    CHECK(source_contains("../../../../app_cmd.c", "nfc_tag_mf0_ntag_update_amiibo_mark();"));
    /* CMD 1074 force set/clear must refresh the golden snapshot after writing
     * the active slot's live config marker, so force-set captures a valid
     * golden and force-clear invalidates a stale one. */
    CHECK(source_contains_after("../../../../app_cmd.c",
                                "live->config.is_amiibo = mark;",
                                "nfc_tag_mf0_ntag_update_golden_snapshot();"));
    /* Host page writes: refresh the 0xA5 marker BEFORE capturing/invalidating
     * the golden snapshot, so writing/clearing page 4 drops a stale golden. */
    CHECK(source_contains_after("../../../../app_cmd.c",
                                "memcpy(&info->memory[page_index][0], &data[2], byte_length);",
                                "nfc_tag_mf0_ntag_update_amiibo_mark();"));
    CHECK(source_contains_after("../../../../app_cmd.c",
                                "nfc_tag_mf0_ntag_update_amiibo_mark();",
                                "nfc_tag_mf0_ntag_update_golden_snapshot();"));
    CHECK(source_contains("../../../../app_cmd.c", "length != 2 * NFC_AMIIBO_UID_REFRESH_RETAIL_KEY_SIZE"));
    CHECK(source_contains("../../../../app_cmd.c", "cmd_processor_amiibo_verify_slot"));

    /* CMD 1070/1071/1073 and the boot store restore are gated on an active
     * Amiibo slot, not merely on the NTAG215 type. A successful verify also
     * auto-marks an unlocked slot. */
    CHECK(source_contains("../nfc_amiibo_refresh_slot.c", "nfc_tag_mf0_ntag_is_amiibo_active()"));
    CHECK(source_contains("../nfc_amiibo_refresh_slot.c", "nfc_amiibo_slot_mark_update"));
    CHECK(source_contains("../../../../app_cmd.c", "if (!nfc_tag_mf0_ntag_is_amiibo_active())"));
    CHECK(source_contains("../../../../app_main.c", "nfc_tag_mf0_ntag_is_amiibo_active()"));
    CHECK(source_contains("../nfc_amiibo_auto_refresh_store.c", "active_slot_is_amiibo"));

    /* Build wiring: the new pure helper is part of the firmware sources. */
    CHECK(source_contains("../../../../../Makefile", "nfc_amiibo_slot_mark.c"));

    printf("test_nfc_amiibo_slot_mark: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
