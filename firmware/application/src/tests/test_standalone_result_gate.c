/*
 * Host unit test for the standalone result-buffer gate.
 *
 * The trace modes share ONE RAM result buffer, so the framework has to keep
 * that buffer exclusive: while a mode is armed it owns the buffer (it may
 * be appending to it live) and no other mode may load its record into it.
 * Before the fix, a GET_SIZES (which loaded every mode) or a GET_RESULT_FOR
 * for another mode overwrote the armed mode's live capture, which the armed
 * mode then appended to and persisted as its own.
 *
 * The real app_standalone.c is compiled against the SDK stubs in stubs/.
 *
 * Build + run:
 *   make -C firmware/application/src/tests
 */
#include "../app_standalone.h"
#include "../standalone_led.h"
#include "../utils/fds_util.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

/* -------------------------------------------------------------------------
 * FDS stub — a flat record store
 * ------------------------------------------------------------------------- */

#define FDS_MAX_RECS  8
#define FDS_MAX_DATA  2100

static struct {
    bool     used;
    uint16_t id;
    uint16_t key;
    uint16_t len;
    uint8_t  data[FDS_MAX_DATA];
} g_fds[FDS_MAX_RECS];

static void fds_reset(void) {
    memset(g_fds, 0, sizeof(g_fds));
}

static int fds_find(uint16_t id, uint16_t key) {
    for (int i = 0; i < FDS_MAX_RECS; i++) {
        if (g_fds[i].used && g_fds[i].id == id && g_fds[i].key == key) return i;
    }
    return -1;
}

bool fds_read_sync(uint16_t id, uint16_t key, uint16_t *length, uint8_t *buffer) {
    int i = fds_find(id, key);
    if (i < 0 || g_fds[i].len > *length) {
        *length = 0;
        return false;
    }
    memcpy(buffer, g_fds[i].data, g_fds[i].len);
    *length = g_fds[i].len;
    return true;
}

bool fds_write_sync(uint16_t id, uint16_t key, uint16_t length, void *buffer) {
    if (length > FDS_MAX_DATA) return false;
    int i = fds_find(id, key);
    if (i < 0) {
        for (i = 0; i < FDS_MAX_RECS; i++) {
            if (!g_fds[i].used) break;
        }
        if (i == FDS_MAX_RECS) return false;
        g_fds[i].used = true;
        g_fds[i].id   = id;
        g_fds[i].key  = key;
    }
    memcpy(g_fds[i].data, buffer, length);
    g_fds[i].len = length;
    return true;
}

int fds_delete_sync(uint16_t id, uint16_t key) {
    int i = fds_find(id, key);
    if (i < 0) return -1;
    g_fds[i].used = false;
    return 0;
}

bool fds_is_exists(uint16_t id, uint16_t key) { return fds_find(id, key) >= 0; }
void fds_util_init(void) { }
void fds_gc_sync(void) { }
bool fds_wipe(void) { fds_reset(); return true; }

const uint8_t *fds_peek(uint16_t id, uint16_t key, uint16_t *len_bytes,
                        fds_record_desc_t *desc) {
    int i = fds_find(id, key);
    if (i < 0) return NULL;
    *len_bytes = g_fds[i].len;
    desc->dummy = (uint32_t)i;
    return g_fds[i].data;
}

void fds_peek_close(fds_record_desc_t *desc) { (void)desc; }

/* -------------------------------------------------------------------------
 * LED stub
 * ------------------------------------------------------------------------- */

void standalone_led_init(void) { }
void standalone_feedback(standalone_feedback_t fb) { (void)fb; }
void standalone_feedback_for_mode(standalone_feedback_t fb, standalone_mode_t mode) {
    (void)fb; (void)mode;
}
void standalone_led_clear(void) { }
void standalone_led_solid(void) { }
void standalone_led_set_mode_color(standalone_mode_t mode, chameleon_rgb_type_t color) {
    (void)mode; (void)color;
}

/* -------------------------------------------------------------------------
 * Fake modes
 *
 * The fake ensure_loaded() pulls the mode's FDS record into ONE shared
 * buffer — exactly what the real trace modes do — and counts the loads so
 * the test can prove that a non-armed mode never loads while another mode
 * is armed.
 * ------------------------------------------------------------------------- */

#define FAKE_BUF_WORDS 64

static uint32_t g_fake_shared[FAKE_BUF_WORDS];
static int      g_ensure_calls[STANDALONE_MODE__COUNT];
static int      g_read_calls[STANDALONE_MODE__COUNT];
static int      g_clear_calls[STANDALONE_MODE__COUNT];
static size_t   g_fake_size[STANDALONE_MODE__COUNT];

#define FAKE_MODE(SYM, ID)                                                    \
    static void fake_ensure_##ID(void) {                                      \
        g_ensure_calls[ID]++;                                                 \
        size_t n = 0;                                                         \
        (void)app_standalone_load_result_buf(ID, g_fake_shared,               \
                                             sizeof(g_fake_shared), &n);     \
        if (n > 0) g_fake_size[ID] = n;  /* the record is the mode's RAM copy */ \
    }                                                                        \
    static size_t fake_get_size_##ID(void) { return g_fake_size[ID]; }        \
    static standalone_rc_t fake_read_##ID(uint8_t *out, size_t out_max,       \
                                          size_t *out_len) {                  \
        g_read_calls[ID]++;                                                   \
        fake_ensure_##ID();      /* the real modes lazy-load before reading */ \
        size_t take = g_fake_size[ID];                                        \
        if (take > out_max) take = out_max;                                   \
        if (take > 0) memcpy(out, g_fake_shared, take);                       \
        *out_len = take;                                                      \
        return take ? STANDALONE_RC_OK : STANDALONE_RC_NO_RESULT;             \
    }                                                                        \
    static void fake_clear_##ID(void) {                                       \
        g_clear_calls[ID]++;              /* clearing never loads */          \
        g_fake_size[ID] = 0;                                                 \
    }                                                                        \
    static standalone_rc_t fake_enter_##ID(const uint8_t *cfg, size_t len) {  \
        (void)cfg; (void)len;                                                 \
        return STANDALONE_RC_OK;                                              \
    }                                                                        \
    static standalone_rc_t fake_exit_##ID(void) { return STANDALONE_RC_OK; } \
    const standalone_mode_iface_t SYM = {                                     \
        .id              = ID,                                                \
        .name            = #ID,                                               \
        .wants_tick      = false,                                             \
        .on_enter        = fake_enter_##ID,                                   \
        .on_exit         = fake_exit_##ID,                                    \
        .get_result_size = fake_get_size_##ID,                                \
        .read_result     = fake_read_##ID,                                    \
        .clear_result    = fake_clear_##ID,                                   \
        .ensure_loaded   = fake_ensure_##ID,                                  \
    };

FAKE_MODE(mode_slot_cycle_iface,  STANDALONE_MODE_SLOT_CYCLE)
FAKE_MODE(mode_emultrace_iface,  STANDALONE_MODE_EMUL_TRACE)
FAKE_MODE(mode_nfc_canary_iface,  STANDALONE_MODE_NFC_CANARY)
FAKE_MODE(mode_gdb_gateway_iface, STANDALONE_MODE_GDB_GATEWAY)
FAKE_MODE(mode_u2f_iface,         STANDALONE_MODE_U2F)

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

static void reset_world(void) {
    fds_reset();
    memset(g_fake_shared, 0, sizeof(g_fake_shared));
    memset(g_ensure_calls, 0, sizeof(g_ensure_calls));
    memset(g_read_calls, 0, sizeof(g_read_calls));
    memset(g_clear_calls, 0, sizeof(g_clear_calls));
    memset(g_fake_size, 0, sizeof(g_fake_size));
    app_standalone_init();
}

/* Persist `len` bytes for a mode through the framework (writes the
 * [u32 len][data] record the trace modes use). */
static void store_result(standalone_mode_t mode, size_t len) {
    uint32_t words[FAKE_BUF_WORDS];
    memset(words, 0xA5, sizeof(words));
    (void)app_standalone_save_result_buf(mode, words, len);
}

static void arm(standalone_mode_t mode) {
    (void)app_standalone_set_mode(mode, 0);
    (void)app_standalone_on_button(STANDALONE_BTN_BOTH_LONG);
}

/* -------------------------------------------------------------------------
 * Tests
 * ------------------------------------------------------------------------- */

/* GET_SIZES walks every mode: it must report the persisted size without
 * pulling another mode's record into the shared buffer. */
static void test_get_sizes_never_loads_a_mode(void) {
    reset_world();
    store_result(STANDALONE_MODE_NFC_CANARY, 16);

    size_t sz = app_standalone_get_result_avail(STANDALONE_MODE_NFC_CANARY);
    CHECK(sz == 16);
    CHECK(g_ensure_calls[STANDALONE_MODE_NFC_CANARY] == 0);
}

/* The same while another mode is armed — the case that used to overwrite
 * the armed mode's live capture. */
static void test_get_sizes_never_loads_while_another_mode_is_armed(void) {
    reset_world();
    store_result(STANDALONE_MODE_NFC_CANARY, 16);
    arm(STANDALONE_MODE_EMUL_TRACE);
    CHECK(app_standalone_get_state() == STANDALONE_STATE_ARMED_IDLE);

    size_t sz = app_standalone_get_result_avail(STANDALONE_MODE_NFC_CANARY);
    CHECK(sz == 16);
    CHECK(g_ensure_calls[STANDALONE_MODE_NFC_CANARY] == 0);
}

/* The armed mode owns the buffer: it may load and reports its RAM size. */
static void test_get_sizes_loads_the_armed_mode(void) {
    reset_world();
    arm(STANDALONE_MODE_EMUL_TRACE);
    g_fake_size[STANDALONE_MODE_EMUL_TRACE] = 7;

    size_t sz = app_standalone_get_result_avail(STANDALONE_MODE_EMUL_TRACE);
    CHECK(sz == 7);
    CHECK(g_ensure_calls[STANDALONE_MODE_EMUL_TRACE] == 1);
}

/* Reading another mode's result while a mode is armed is refused instead
 * of loading that mode's record over the live capture. */
static void test_read_of_another_mode_is_refused_while_armed(void) {
    reset_world();
    store_result(STANDALONE_MODE_NFC_CANARY, 16);
    arm(STANDALONE_MODE_EMUL_TRACE);

    uint8_t buf[64];
    size_t  len = 123;
    standalone_rc_t rc = app_standalone_read_result_mode(STANDALONE_MODE_NFC_CANARY,
                                                         buf, sizeof(buf), &len);
    CHECK(rc == STANDALONE_RC_INVALID_STATE);
    CHECK(len == 0);
    CHECK(g_ensure_calls[STANDALONE_MODE_NFC_CANARY] == 0);
    CHECK(g_read_calls[STANDALONE_MODE_NFC_CANARY] == 0);
}

/* The armed mode itself still reads its own capture. */
static void test_read_of_the_armed_mode_is_allowed(void) {
    reset_world();
    arm(STANDALONE_MODE_EMUL_TRACE);
    g_fake_size[STANDALONE_MODE_EMUL_TRACE] = 4;

    uint8_t buf[64];
    size_t  len = 0;
    standalone_rc_t rc = app_standalone_read_result_mode(STANDALONE_MODE_EMUL_TRACE,
                                                         buf, sizeof(buf), &len);
    CHECK(rc == STANDALONE_RC_OK);
    CHECK(len == 4);
    CHECK(g_read_calls[STANDALONE_MODE_EMUL_TRACE] == 1);
}

/* With nothing armed a read loads the record and takes the buffer over:
 * the framework records the owner so a mode that lost the buffer reloads
 * its own record instead of serving somebody else's bytes. */
static void test_read_when_disarmed_claims_the_buffer(void) {
    reset_world();
    store_result(STANDALONE_MODE_EMUL_TRACE, 8);

    uint8_t buf[64];
    size_t  len = 0;
    standalone_rc_t rc = app_standalone_read_result_mode(STANDALONE_MODE_EMUL_TRACE,
                                                         buf, sizeof(buf), &len);
    CHECK(rc == STANDALONE_RC_OK);
    CHECK(g_ensure_calls[STANDALONE_MODE_EMUL_TRACE] == 1);
    CHECK(app_standalone_result_buf_owner() == STANDALONE_MODE_EMUL_TRACE);
}

/* Clearing a mode never loads its record into the shared buffer. */
static void test_clear_does_not_load(void) {
    reset_world();
    store_result(STANDALONE_MODE_NFC_CANARY, 16);
    arm(STANDALONE_MODE_EMUL_TRACE);

    (void)app_standalone_clear_result_mode(STANDALONE_MODE_NFC_CANARY);
    CHECK(g_ensure_calls[STANDALONE_MODE_NFC_CANARY] == 0);
    CHECK(g_clear_calls[STANDALONE_MODE_NFC_CANARY] == 1);
}

/* The persisted size comes from the record header in flash. */
static void test_stored_size_reads_the_record_header(void) {
    reset_world();
    store_result(STANDALONE_MODE_NFC_CANARY, 1234);
    CHECK(app_standalone_get_stored_size(STANDALONE_MODE_NFC_CANARY) == 1234);

    store_result(STANDALONE_MODE_EMUL_TRACE, 0);
    CHECK(app_standalone_get_stored_size(STANDALONE_MODE_EMUL_TRACE) == 0);
    CHECK(app_standalone_get_stored_size(STANDALONE_MODE_SLOT_CYCLE) == 0);
}

int main(void) {
    test_get_sizes_never_loads_a_mode();
    test_get_sizes_never_loads_while_another_mode_is_armed();
    test_get_sizes_loads_the_armed_mode();
    test_read_of_another_mode_is_refused_while_armed();
    test_read_of_the_armed_mode_is_allowed();
    test_read_when_disarmed_claims_the_buffer();
    test_clear_does_not_load();
    test_stored_size_reads_the_record_header();

    printf("%s: %d checks, %d failures\n", g_fail ? "FAILED" : "ok",
           g_checks, g_fail);
    return g_fail ? 1 : 0;
}
