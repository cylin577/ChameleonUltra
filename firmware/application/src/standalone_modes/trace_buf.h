/*
 * trace_buf.h — shared result buffer for the trace modes.
 *
 * authtrace, emultrace, hf14a_tap_sniff and nfc_canary all need the same
 * 2080-byte, word-aligned result buffer. Only one standalone mode is armed
 * at a time and each mode persists its buffer to FDS after every append, so
 * they share this one instead of carrying four private copies (6 KB of RAM
 * saved in the standalone builds — the RAM budget there is tight).
 */
#ifndef STANDALONE_TRACE_BUF_H
#define STANDALONE_TRACE_BUF_H

#include <stdint.h>

/* authtrace/emultrace/hf14a_tap_sniff use 8 * (4 + 256) bytes,
 * nfc_canary 130 * 16 bytes — both are 2080. */
#define STANDALONE_TRACE_BUF_BYTES 2080u

extern uint32_t standalone_trace_words[STANDALONE_TRACE_BUF_BYTES / 4];

#endif /* STANDALONE_TRACE_BUF_H */
