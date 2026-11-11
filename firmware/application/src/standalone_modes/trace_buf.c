/*
 * trace_buf.c — shared result buffer for the trace modes (see trace_buf.h).
 */
#include "trace_buf.h"

uint32_t standalone_trace_words[STANDALONE_TRACE_BUF_BYTES / 4];
