# Native (host) unit tests for the hardware-free standalone cores.
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wshadow -Wconversion -O1 -g -fsanitize=address,undefined

MICROECC_DIR  := ../../crypto/micro-ecc
MICROECC_FLAGS := -DuECC_SUPPORTS_secp256r1=1 -DuECC_SUPPORTS_secp160r1=0 \
                   -DuECC_SUPPORTS_secp192r1=0 -DuECC_SUPPORTS_secp224r1=0 \
                   -DuECC_SUPPORTS_secp256k1=0 -DuECC_OPTIMIZATION_LEVEL=2 \
                   -DuECC_SUPPORT_COMPRESSED_POINT=0

test: test_nfc_canary_core test_fido2_core test_fido2_hid test_fido2_ble
	./test_nfc_canary_core
	./test_fido2_core
	./test_fido2_hid
	./test_fido2_ble

test_nfc_canary_core: test_nfc_canary_core.c ../nfc_canary_core.c ../nfc_canary_core.h
	$(CC) $(CFLAGS) -o $@ test_nfc_canary_core.c ../nfc_canary_core.c

test_fido2_core: test_fido2_core.c ../fido2_core.c ../fido2_core.h $(MICROECC_DIR)/uECC.c
	$(CC) $(CFLAGS) -DFIDO2_HOST_BUILD=1 -I$(MICROECC_DIR) $(MICROECC_FLAGS) \
	    -o $@ test_fido2_core.c ../fido2_core.c $(MICROECC_DIR)/uECC.c

test_fido2_hid: test_fido2_hid.c ../fido2_hid.c ../fido2_hid.h ../fido2_core.c ../fido2_core.h $(MICROECC_DIR)/uECC.c
	$(CC) $(CFLAGS) -DFIDO2_HOST_BUILD=1 -I$(MICROECC_DIR) $(MICROECC_FLAGS) \
	    -o $@ test_fido2_hid.c ../fido2_hid.c ../fido2_core.c $(MICROECC_DIR)/uECC.c

test_fido2_ble: test_fido2_ble.c ../fido2_ble.h
	$(CC) $(CFLAGS) -o $@ test_fido2_ble.c

clean:
	rm -f test_nfc_canary_core test_fido2_core test_fido2_hid test_fido2_ble

.PHONY: test clean
