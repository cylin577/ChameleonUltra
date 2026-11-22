/*
 * nfc_amiibo_refresh_feedback.h
 *
 * Deferred, non-blocking LED feedback for Amiibo refresh / arm / disarm.
 *
 * The command handlers (CMD 1070/1071) only REQUEST a pattern: they stamp the
 * current time and return immediately, so the response is not held up by the
 * old 140 ms busy-wait in offline_status_blink_color(). The main loop calls
 * nfc_amiibo_refresh_feedback_process() with bsp_timer_now_ms(); the animation
 * advances from elapsed time only. No delay, no blocking work, no ISR use.
 *
 * Hardware-free and header-only: host tests inject a fake clock and a step
 * callback, firmware passes bsp_timer_now_ms() and an LED driver.
 */
#ifndef NFC_AMIIBO_REFRESH_FEEDBACK_H
#define NFC_AMIIBO_REFRESH_FEEDBACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* One pattern per attempt. Colours match the old offline_status_* cues. */
typedef enum {
    NFC_AMIIBO_REFRESH_FB_NONE = 0,
    NFC_AMIIBO_REFRESH_FB_REFRESH_OK,    /* one green blink   */
    NFC_AMIIBO_REFRESH_FB_REFRESH_ERROR, /* one red blink     */
    NFC_AMIIBO_REFRESH_FB_ARM,           /* two green blinks  */
    NFC_AMIIBO_REFRESH_FB_DISARM,        /* three red blinks  */
} nfc_amiibo_refresh_feedback_kind_t;

#define NFC_AMIIBO_REFRESH_BLINK_COUNT    1u
#define NFC_AMIIBO_ARM_BLINK_COUNT        2u
#define NFC_AMIIBO_DISARM_BLINK_COUNT     3u

/* Visible phase lengths. The animation itself lasts a few hundred ms, but
 * it runs in the main loop and never delays a command response. */
#define NFC_AMIIBO_FB_ON_MS               60u
#define NFC_AMIIBO_FB_OFF_MS              60u
#define NFC_AMIIBO_FB_PERIOD_MS           (NFC_AMIIBO_FB_ON_MS + NFC_AMIIBO_FB_OFF_MS)

#define NFC_AMIIBO_FB_PHASE_NONE          0xFFu

typedef struct {
    nfc_amiibo_refresh_feedback_kind_t kind;
    uint32_t start_ms;
    uint8_t last_phase;       /* phase already emitted; 0xFF = none */
} nfc_amiibo_refresh_feedback_state_t;

/* on=true LED lit, on=false LED dark, done=true animation finished (the
 * driver restores the normal slot LEDs). `green` selects feedback colour. */
typedef void (*nfc_amiibo_fb_step_cb_t)(bool on, bool green, bool done, void *ctx);

static inline uint8_t nfc_amiibo_refresh_feedback_blink_count(
    nfc_amiibo_refresh_feedback_kind_t kind) {
    switch (kind) {
        case NFC_AMIIBO_REFRESH_FB_REFRESH_OK:
        case NFC_AMIIBO_REFRESH_FB_REFRESH_ERROR:
            return NFC_AMIIBO_REFRESH_BLINK_COUNT;
        case NFC_AMIIBO_REFRESH_FB_ARM:
            return NFC_AMIIBO_ARM_BLINK_COUNT;
        case NFC_AMIIBO_REFRESH_FB_DISARM:
            return NFC_AMIIBO_DISARM_BLINK_COUNT;
        default:
            return 0u;
    }
}

static inline bool nfc_amiibo_refresh_feedback_is_green(
    nfc_amiibo_refresh_feedback_kind_t kind) {
    return kind == NFC_AMIIBO_REFRESH_FB_REFRESH_OK ||
           kind == NFC_AMIIBO_REFRESH_FB_ARM;
}

/* Non-blocking request. Overwriting an in-flight animation keeps exactly one
 * feedback visible per attempt and avoids stacked/double animations. */
static inline void nfc_amiibo_refresh_feedback_request(
    nfc_amiibo_refresh_feedback_state_t *state,
    nfc_amiibo_refresh_feedback_kind_t kind,
    uint32_t now_ms) {
    state->kind = kind;
    state->start_ms = now_ms;
    state->last_phase = NFC_AMIIBO_FB_PHASE_NONE;
}

/* Main-loop tick. Pure function of elapsed time; emits a step only when the
 * phase changes. Unsigned subtraction keeps 32-bit ms wrap harmless. */
static inline void nfc_amiibo_refresh_feedback_process(
    nfc_amiibo_refresh_feedback_state_t *state,
    uint32_t now_ms,
    nfc_amiibo_fb_step_cb_t step,
    void *ctx) {
    if (state->kind == NFC_AMIIBO_REFRESH_FB_NONE || step == NULL) {
        return;
    }

    uint8_t blinks = nfc_amiibo_refresh_feedback_blink_count(state->kind);
    uint32_t elapsed = now_ms - state->start_ms;
    bool done = elapsed >= (uint32_t)blinks * NFC_AMIIBO_FB_PERIOD_MS;
    uint8_t phase;
    bool on = false;

    if (done) {
        phase = (uint8_t)(2u * blinks);   /* one terminal "restore" step */
    } else {
        uint32_t index = elapsed / NFC_AMIIBO_FB_PERIOD_MS;
        on = (elapsed % NFC_AMIIBO_FB_PERIOD_MS) < NFC_AMIIBO_FB_ON_MS;
        phase = (uint8_t)(2u * index + (on ? 0u : 1u));
    }

    if (phase == state->last_phase) {
        return;
    }
    state->last_phase = phase;
    step(on, nfc_amiibo_refresh_feedback_is_green(state->kind), done, ctx);
    if (done) {
        state->kind = NFC_AMIIBO_REFRESH_FB_NONE;
    }
}

#endif /* NFC_AMIIBO_REFRESH_FEEDBACK_H */
