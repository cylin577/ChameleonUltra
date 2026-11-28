# Native (host) unit tests for the hardware-free standalone cores.
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wshadow -Wconversion -O1 -g -fsanitize=address,undefined

test: test_nfc_canary_core test_fido2_cbor test_fido2_format
	./test_nfc_canary_core
	./test_fido2_cbor
	./test_fido2_format

test_nfc_canary_core: test_nfc_canary_core.c ../nfc_canary_core.c ../nfc_canary_core.h
	$(CC) $(CFLAGS) -o $@ test_nfc_canary_core.c ../nfc_canary_core.c

test_fido2_cbor: test_fido2_cbor.c ../../fido2/fido2_cbor.c ../../fido2/fido2_cbor.h
	$(CC) $(CFLAGS) -o $@ test_fido2_cbor.c ../../fido2/fido2_cbor.c

test_fido2_format: test_fido2_format.c ../../fido2/fido2_format.c ../../fido2/fido2_cbor.c ../../fido2/fido2_format.h ../../fido2/fido2_cbor.h ../../fido2/fido2_types.h
	$(CC) $(CFLAGS) -o $@ test_fido2_format.c ../../fido2/fido2_format.c ../../fido2/fido2_cbor.c

clean:
	rm -f test_nfc_canary_core test_fido2_cbor test_fido2_format

.PHONY: test clean
