# Native (host) unit tests for the hardware-free standalone cores.
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wshadow -Wconversion -O1 -g -fsanitize=address,undefined

test: test_nfc_canary_core
	./test_nfc_canary_core

test_nfc_canary_core: test_nfc_canary_core.c ../nfc_canary_core.c ../nfc_canary_core.h
	$(CC) $(CFLAGS) -o $@ test_nfc_canary_core.c ../nfc_canary_core.c

clean:
	rm -f test_nfc_canary_core

.PHONY: test clean
