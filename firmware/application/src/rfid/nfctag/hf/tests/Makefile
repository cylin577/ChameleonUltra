# Native host tests for the Amiibo UID-refresh crypto core.
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wshadow -Wconversion -O1 -g -fsanitize=address,undefined
CFLAGS  += -Wno-deprecated-declarations
# Synthetic vectors use their own digests; the firmware build keeps the retail digests.
CPPFLAGS += -DAMIIBO_UID_REFRESH_HOST_BUILD=1 -I.. \
  -DAMIIBO_UID_REFRESH_DATA_RETAIL_KEY_SHA256='{0x5c, 0x21, 0x5a, 0xcd, 0x15, 0x19, 0x69, 0xc2, 0xd1, 0x05, 0xbe, 0x71, 0xd7, 0xab, 0x78, 0xa6, 0x6a, 0xb7, 0x62, 0x98, 0x08, 0x4f, 0xc1, 0xcd, 0x51, 0x73, 0x80, 0x22, 0x38, 0x6e, 0xc4, 0x24}' \
  -DAMIIBO_UID_REFRESH_TAG_RETAIL_KEY_SHA256='{0xff, 0x70, 0x7b, 0x87, 0x01, 0xe0, 0x86, 0x80, 0x7f, 0xe7, 0xbd, 0x7c, 0xac, 0x17, 0xa4, 0xa2, 0x30, 0xa5, 0x96, 0x7d, 0x6b, 0xc7, 0x01, 0xed, 0x31, 0xa4, 0xda, 0x0e, 0x91, 0xf8, 0x54, 0x0d}'
LDLIBS += -lcrypto

TESTS = test_nfc_amiibo_uid_refresh test_nfc_amiibo_keys_store \
        test_nfc_amiibo_auto_refresh test_nfc_amiibo_auto_refresh_store \
        test_nfc_amiibo_refresh_sleep test_nfc_amiibo_refresh_feedback \
        test_nfc_amiibo_slot_mark

.PHONY: test clean

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done

test_nfc_amiibo_uid_refresh: test_nfc_amiibo_uid_refresh.c amiibo_test_vectors.c \
         ../nfc_amiibo_uid_refresh.c ../nfc_amiibo_uid_refresh.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test_nfc_amiibo_uid_refresh.c \
	    amiibo_test_vectors.c ../nfc_amiibo_uid_refresh.c $(LDLIBS)

test_nfc_amiibo_keys_store: test_nfc_amiibo_keys_store.c amiibo_test_vectors.c \
         ../nfc_amiibo_uid_refresh.c ../nfc_amiibo_uid_refresh.h \
         ../nfc_amiibo_keys_store.c ../nfc_amiibo_keys_store.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test_nfc_amiibo_keys_store.c \
	    amiibo_test_vectors.c ../nfc_amiibo_uid_refresh.c \
	    ../nfc_amiibo_keys_store.c $(LDLIBS)

test_nfc_amiibo_auto_refresh: test_nfc_amiibo_auto_refresh.c \
         ../nfc_amiibo_auto_refresh.c ../nfc_amiibo_auto_refresh.h \
         ../nfc_amiibo_uid_refresh.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test_nfc_amiibo_auto_refresh.c \
	    ../nfc_amiibo_auto_refresh.c $(LDLIBS)

test_nfc_amiibo_auto_refresh_store: test_nfc_amiibo_auto_refresh_store.c \
         ../nfc_amiibo_auto_refresh_store.c ../nfc_amiibo_auto_refresh_store.h \
         ../nfc_amiibo_auto_refresh.c ../nfc_amiibo_auto_refresh.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test_nfc_amiibo_auto_refresh_store.c \
	    ../nfc_amiibo_auto_refresh_store.c ../nfc_amiibo_auto_refresh.c $(LDLIBS)

test_nfc_amiibo_refresh_sleep: test_nfc_amiibo_refresh_sleep.c ../nfc_amiibo_refresh_sleep.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test_nfc_amiibo_refresh_sleep.c $(LDLIBS)

test_nfc_amiibo_refresh_feedback: test_nfc_amiibo_refresh_feedback.c \
         ../nfc_amiibo_refresh_sleep.h ../nfc_amiibo_refresh_feedback.h \
         ../nfc_amiibo_auto_refresh.c ../nfc_amiibo_auto_refresh.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test_nfc_amiibo_refresh_feedback.c \
	    ../nfc_amiibo_auto_refresh.c $(LDLIBS)

test_nfc_amiibo_slot_mark: test_nfc_amiibo_slot_mark.c \
         ../nfc_amiibo_slot_mark.c ../nfc_amiibo_slot_mark.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test_nfc_amiibo_slot_mark.c \
	    ../nfc_amiibo_slot_mark.c $(LDLIBS)

clean:
	rm -f $(TESTS)
