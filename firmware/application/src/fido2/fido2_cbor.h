/* Minimal definite-length CBOR reader/writer for CTAP2. */
#ifndef FIDO2_CBOR_H
#define FIDO2_CBOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct { uint8_t *buf; size_t cap, len; bool failed; } fido2_cbor_w_t;

void  cw_init(fido2_cbor_w_t*, uint8_t*, size_t);
void  cw_uint(fido2_cbor_w_t*, uint64_t);
void  cw_int (fido2_cbor_w_t*, int64_t);
void  cw_bytes(fido2_cbor_w_t*, const uint8_t*, size_t);
void  cw_text (fido2_cbor_w_t*, const char*, size_t);
void  cw_bool (fido2_cbor_w_t*, bool);
void  cw_array(fido2_cbor_w_t*, size_t);   /* header only */
void  cw_map  (fido2_cbor_w_t*, size_t);   /* header only */
size_t cw_finish(fido2_cbor_w_t*);         /* 0 on failure */

typedef struct { const uint8_t *buf; size_t len, pos; bool failed; } fido2_cbor_r_t;

void  cr_init(fido2_cbor_r_t*, const uint8_t*, size_t);
bool  cr_uint(fido2_cbor_r_t*, uint64_t*);
bool  cr_int (fido2_cbor_r_t*, int64_t*);
bool  cr_bytes(fido2_cbor_r_t*, const uint8_t**, size_t*);
bool  cr_text (fido2_cbor_r_t*, const uint8_t**, size_t*);
bool  cr_bool (fido2_cbor_r_t*, bool*);
bool  cr_array(fido2_cbor_r_t*, size_t*);
bool  cr_map  (fido2_cbor_r_t*, size_t*);

#endif /* FIDO2_CBOR_H */
