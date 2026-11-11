/*
 * trace_buf.h — shared result buffer for the trace modes.
 *
 * authtrace, emultrace, hf14a_tap_sniff and nfc_canary all need the same
 * 2080-byte, word-aligned result buffer. Only one standalone mode is armed
 * at a time and each mode persists its buffer to FDS after every append, so
 * they share this one instead of carrying four private copies (6 KB of RAM
 * saved in the standalone builds — the RAM budget there is tight).
 *
 * The buffer therefore holds the data of WHICHEVER mode touched it last.
 * Every mode that uses it MUST follow these three rules:
 *
 *   1. Reload on arm: on_enter() clears the mode's "record loaded" flag and
 *      calls the loader, so the mode re-reads its own FDS record into the
 *      buffer every time it is armed. Loading only once per boot is wrong:
 *      after a mode switch the buffer still holds the other mode's bytes and
 *      the mode would serve them as its own capture.
 *   2. Reset the cursor before the reload: the loader drops the mode's
 *      cursor/session state before reading, so an empty record can never
 *      expose bytes left over from another mode.
 *   3. Reload when the buffer was taken over: the loader only trusts the
 *      mode's cached copy while the mode still owns the buffer
 *      (app_standalone_result_buf_owner()); if another mode loaded in the
 *      meantime, the cached copy is gone and the mode reloads its own
 *      record before serving it.
 *
 * The framework keeps the buffer exclusive: while a mode is armed it owns
 * the buffer, so no other mode may load into it (GET_SIZES reports the
 * persisted size for every other mode, GET_RESULT_FOR for another mode is
 * refused with INVALID_STATE, and clearing never loads).
 */
#ifndef STANDALONE_TRACE_BUF_H
#define STANDALONE_TRACE_BUF_H

#include <stdint.h>

/* authtrace/emultrace/hf14a_tap_sniff use 8 * (4 + 256) bytes,
 * nfc_canary 130 * 16 bytes — both are 2080. */
#define STANDALONE_TRACE_BUF_BYTES 2080u

extern uint32_t standalone_trace_words[STANDALONE_TRACE_BUF_BYTES / 4];

#endif /* STANDALONE_TRACE_BUF_H */
