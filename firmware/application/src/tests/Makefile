# Native (host) unit tests for hardware-free application helpers.
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wshadow -Wconversion -O1 -g -fsanitize=address,undefined

TESTS = test_app_button_tap test_app_button_edge test_app_button_tap_path \
        test_standalone_result_gate test_bsp_timer_ms test_nfc_amiibo_refresh_button \
        test_nfc_amiibo_auto_refresh_button test_nfc_amiibo_auto_refresh_feedback \
        test_ns2_compat_gate

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done

test_app_button_tap: test_app_button_tap.c ../app_button_tap.c ../app_button_tap.h
	$(CC) $(CFLAGS) -o $@ test_app_button_tap.c ../app_button_tap.c

test_app_button_edge: test_app_button_edge.c ../app_button_edge.c ../app_button_edge.h
	$(CC) $(CFLAGS) -o $@ test_app_button_edge.c ../app_button_edge.c

test_app_button_tap_path: test_app_button_tap_path.c ../app_button_edge.c ../app_button_edge.h ../app_button_tap.c ../app_button_tap.h
	$(CC) $(CFLAGS) -o $@ test_app_button_tap_path.c ../app_button_edge.c ../app_button_tap.c

test_bsp_timer_ms: test_bsp_timer_ms.c ../bsp/bsp_time.h
	$(CC) $(CFLAGS) -I../bsp -o $@ test_bsp_timer_ms.c

test_nfc_amiibo_refresh_button: test_nfc_amiibo_refresh_button.c ../nfc_amiibo_refresh_button.h ../app_status.h
	$(CC) $(CFLAGS) -I.. -o $@ test_nfc_amiibo_refresh_button.c

test_nfc_amiibo_auto_refresh_button: test_nfc_amiibo_auto_refresh_button.c ../nfc_amiibo_auto_refresh_button.h
	$(CC) $(CFLAGS) -I.. -o $@ test_nfc_amiibo_auto_refresh_button.c

test_nfc_amiibo_auto_refresh_feedback: test_nfc_amiibo_auto_refresh_feedback.c \
        ../nfc_amiibo_auto_refresh_feedback.h ../nfc_amiibo_auto_refresh_button.h \
        ../rfid/nfctag/hf/nfc_amiibo_refresh_sleep.h \
        ../rfid/nfctag/hf/nfc_amiibo_refresh_feedback.h
	$(CC) $(CFLAGS) -I.. -o $@ test_nfc_amiibo_auto_refresh_feedback.c

# Source assertions for the NS2-compatible main-loop gate in app_main.c.
test_ns2_compat_gate: test_ns2_compat_gate.c ../app_main.c
	$(CC) $(CFLAGS) -o $@ test_ns2_compat_gate.c

# The standalone framework against the SDK stubs in stubs/ — the real
# app_standalone.c is compiled, only the SDK/FDS/LED layer is faked.
test_standalone_result_gate: test_standalone_result_gate.c ../app_standalone.c ../app_standalone.h
	$(CC) $(CFLAGS) -Istubs -I.. -I../utils \
	    -DSTANDALONE_TEST_MODE_IFACE=mode_up_gated_iface -o $@ \
	    test_standalone_result_gate.c ../app_standalone.c

clean:
	rm -f $(TESTS)
