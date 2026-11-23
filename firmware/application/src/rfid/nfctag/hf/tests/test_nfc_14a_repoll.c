/*
 * Host test for the 7-bit REQA/WUPA handling and ATQA timing in nfc_14a.c.
 *
 * The real 14A path needs the Nordic NFCT peripheral, so it cannot be linked
 * on the host. Instead this test (a) asserts the source keeps the dead handler
 * out and wires the NS2-only behavior to nfc_tag_mf0_ntag_is_amiibo_active(),
 * and (b) models the short-frame/timing branches for both an active Amiibo
 * slot and a plain tag. No SDK/hardware.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

#define SRC "../nfc_14a.c"

static char *read_source(void) {
    FILE *f = fopen(SRC, "rb");
    if (f == NULL) { printf("FAIL cannot open %s\n", SRC); g_fail++; return NULL; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = (char *)malloc((size_t)n + 1);
    if (buf == NULL) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

static bool contains(const char *hay, const char *needle) {
    return hay != NULL && strstr(hay, needle) != NULL;
}

static bool contains_in_order(const char *hay, const char *first, const char *second) {
    if (hay == NULL) return false;
    const char *p = strstr(hay, first);
    if (p == NULL) return false;
    return strstr(p + strlen(first), second) != NULL;
}

/* ---- Model of the 7-bit REQA/WUPA branch ---- */
typedef enum { ST_IDLE, ST_HALTED, ST_READY, ST_ACTIVE } tag_state_t;

typedef struct {
    tag_state_t state;
    int atqa_sent;
    int cb_reset_calls;
} tag_t;

/* Mirrors nfc_tag_14a_data_process(): szDataBits <= 8 branch. */
static void short_frame(tag_t *t, unsigned bits, bool is_reqa, bool is_wupa,
                        bool auto_coll, bool is_amiibo) {
    if (bits == 7 && ((is_reqa && t->state != ST_HALTED) || is_wupa)) {
        if (t->state != ST_IDLE && t->state != ST_HALTED) {
            t->state = ST_IDLE;
            /* Non-Amiibo keeps the original reset-and-early-return. */
            if (!is_amiibo) return;
        }
        if (auto_coll) {
            t->atqa_sent++;                 /* nfc_tag_14a_tx_bytes(atqa) */
            t->cb_reset_calls++;            /* m_tag_handler.cb_reset()   */
            t->state = ST_READY;
        } else {
            t->state = ST_IDLE;
        }
    }
}

/* ---- Model of the ATQA exact-delay window ---- */
typedef struct {
    uint32_t fdm;
    uint32_t saved_fdm;
    bool     atqa_exact;
    int      exact_tx;
    int      window_tx;
    int      restores;
} nfct_model_t;

#define AMBIENT_FDM 0x00001000UL   /* nfc_fdt_reset() default window */

static void model_tx_bytes(nfct_model_t *m, unsigned bytes, bool append_crc,
                           bool is_amiibo) {
    if (bytes == 2 && !append_crc && is_amiibo) {
        m->saved_fdm = m->fdm;
        m->fdm = 1172;
        m->atqa_exact = true;
        m->exact_tx++;
    } else {
        m->window_tx++;
    }
}

static void model_tx_frameend(nfct_model_t *m) {
    if (m->atqa_exact) {
        m->fdm = m->saved_fdm;
        m->atqa_exact = false;
        m->restores++;
    }
}

int main(void) {
    char *src = read_source();

    /* The >=16-bit REQA/WUPA resend is restored. */
    CHECK(contains(src, "Reader is re-sending REQA/WUPA while in READY state"));
    CHECK(contains(src, "case NFC_TAG_14A_CMD_REQA:"));
    CHECK(contains(src, "case NFC_TAG_14A_CMD_WUPA:"));
    CHECK(contains(src, "if (auto_coll_res != NULL) {"));
    CHECK(contains(src, "re-poll while already active/ready"));

    /* Both SDD settings exist: 00100 for Amiibo, 00001 otherwise. */
    CHECK(contains(src, "NRF_NFCT_SENSRES_BIT_FRAME_SDD_00100"));
    CHECK(contains(src, "NRF_NFCT_SENSRES_BIT_FRAME_SDD_00001"));
    CHECK(contains(src, "if (nfc_tag_mf0_ntag_is_amiibo_active()) {\n"
                        "        nrf_nfct_sensres_bit_frame_sdd_set(NRF_NFCT_SENSRES_BIT_FRAME_SDD_00100);"));

    /* Non-Amiibo keeps the original early-return; Amiibo falls through. */
    CHECK(contains(src, "if (!nfc_tag_mf0_ntag_is_amiibo_active()) return;"));

    /* Normal send-ATQA / cb_reset / READY semantics still exist. */
    CHECK(contains(src, "nfc_tag_14a_tx_bytes(auto_coll_res->atqa, 2, false)"));
    CHECK(contains(src, "m_tag_handler.cb_reset"));
    CHECK(contains(src, "m_tag_state_14a = NFC_TAG_STATE_14A_READY"));

    /* ATQA timing is gated on the active Amiibo slot; every other frame keeps
     * WINDOWGRID. The 1172/EXACTVAL window is restored once at TX_FRAMEEND. */
    CHECK(contains(src, "bytes == 2 && !appendCrc && nfc_tag_mf0_ntag_is_amiibo_active()"));
    CHECK(contains(src, "if (m_atqa_exact)"));
    CHECK(contains(src, "NRF_NFCT_FRAME_DELAY_MODE_EXACTVAL"));
    CHECK(contains(src, "nrf_nfct_frame_delay_max_set(1172)"));
    CHECK(contains(src, "m_saved_frame_delay_max = nrf_nfct_frame_delay_max_get()"));
    CHECK(contains(src, "nrf_nfct_frame_delay_max_set(m_saved_frame_delay_max)"));
    CHECK(contains(src, "NRF_NFCT_FRAME_DELAY_MODE_WINDOWGRID"));
    CHECK(contains(src, "nfc_mf0_ntag.h"));   /* the gate is declared */

    /* ATQA is armed and sent before cb_reset(), not after it. */
    CHECK(contains_in_order(src,
        "m_atqa_pending = true",
        "nfc_tag_14a_tx_bytes(auto_coll_res->atqa, 2, false)"));
    CHECK(contains_in_order(src,
        "nfc_tag_14a_tx_bytes(auto_coll_res->atqa, 2, false)",
        "m_tag_handler.cb_reset()"));
    free(src);

    /* Amiibo: repeated 7-bit REQA yields ATQA every time (the NS2 trace). */
    tag_t t = { ST_IDLE, 0, 0 };
    for (int i = 1; i <= 5; i++) {
        short_frame(&t, 7, true, false, true, true);
        CHECK(t.atqa_sent == i);
        CHECK(t.cb_reset_calls == i);
        CHECK(t.state == ST_READY);
    }

    /* Amiibo: re-poll from ACTIVE also answers instead of going silent. */
    tag_t a = { ST_ACTIVE, 0, 0 };
    short_frame(&a, 7, true, false, true, true);
    CHECK(a.atqa_sent == 1);
    CHECK(a.cb_reset_calls == 1);
    CHECK(a.state == ST_READY);

    /* Non-Amiibo: first REQA from IDLE answers; the next while READY hits the
     * early return and goes dark; the one after that (back in IDLE) answers. */
    tag_t p = { ST_IDLE, 0, 0 };
    short_frame(&p, 7, true, false, true, false);
    CHECK(p.atqa_sent == 1);
    CHECK(p.state == ST_READY);
    short_frame(&p, 7, true, false, true, false);   /* re-poll: early return */
    CHECK(p.atqa_sent == 1);
    CHECK(p.cb_reset_calls == 1);
    CHECK(p.state == ST_IDLE);
    short_frame(&p, 7, true, false, true, false);
    CHECK(p.atqa_sent == 2);
    CHECK(p.state == ST_READY);

    /* WUPA wakes HALTED; REQA in HALTED is ignored (unchanged semantics). */
    tag_t h = { ST_HALTED, 0, 0 };
    short_frame(&h, 7, true, false, true, true);
    CHECK(h.atqa_sent == 0);
    CHECK(h.state == ST_HALTED);
    short_frame(&h, 7, false, true, true, true);
    CHECK(h.atqa_sent == 1);
    CHECK(h.state == ST_READY);
    short_frame(&h, 7, false, true, true, true);
    CHECK(h.atqa_sent == 2);

    /* No anti-collision resource: no ATQA, state stays IDLE (unchanged). */
    tag_t n = { ST_READY, 0, 0 };
    short_frame(&n, 7, true, false, false, true);
    CHECK(n.atqa_sent == 0);
    CHECK(n.cb_reset_calls == 0);
    CHECK(n.state == ST_IDLE);

    /* Amiibo ATQA arms 1172/EXACTVAL and awaits TX end; restored once. */
    nfct_model_t nf = { (uint32_t)AMBIENT_FDM, 0, false, 0, 0, 0 };
    model_tx_bytes(&nf, 2, false, true);
    CHECK(nf.fdm == 1172);
    CHECK(nf.atqa_exact);
    CHECK(nf.fdm == 1172);
    CHECK(nf.restores == 0);
    model_tx_frameend(&nf);
    CHECK(nf.fdm == (uint32_t)AMBIENT_FDM);
    CHECK(!nf.atqa_exact);
    CHECK(nf.restores == 1);

    /* Non-Amiibo 2-byte frame and other frames keep WINDOWGRID, no restore. */
    model_tx_bytes(&nf, 2, false, false);
    CHECK(nf.window_tx == 1);
    CHECK(!nf.atqa_exact);
    model_tx_frameend(&nf);
    CHECK(nf.fdm == (uint32_t)AMBIENT_FDM);
    CHECK(nf.restores == 1);
    model_tx_bytes(&nf, 5, false, true);  /* UID, 5 bytes, no CRC */
    model_tx_frameend(&nf);
    CHECK(nf.window_tx == 2);
    CHECK(nf.fdm == (uint32_t)AMBIENT_FDM);
    CHECK(nf.restores == 1);

    /* Back-to-back Amiibo re-polls each save/restore independently. */
    model_tx_bytes(&nf, 2, false, true);
    CHECK(nf.fdm == 1172);
    model_tx_frameend(&nf);
    CHECK(nf.fdm == (uint32_t)AMBIENT_FDM);
    model_tx_bytes(&nf, 2, false, true);
    CHECK(nf.fdm == 1172);
    model_tx_frameend(&nf);
    CHECK(nf.fdm == (uint32_t)AMBIENT_FDM);
    CHECK(nf.exact_tx == 3);
    CHECK(nf.restores == 3);

    printf("%s: %d checks, %d failures\n", g_fail ? "FAIL" : "PASS", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
