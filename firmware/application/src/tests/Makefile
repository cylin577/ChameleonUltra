# Native (host) unit tests for the hardware-free multi-tap button helpers.
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wshadow -Wconversion -O1 -g -fsanitize=address,undefined

TESTS = test_app_button_tap test_app_button_edge test_app_button_tap_path \
        test_standalone_result_gate

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done

test_app_button_tap: test_app_button_tap.c ../app_button_tap.c ../app_button_tap.h
	$(CC) $(CFLAGS) -o $@ test_app_button_tap.c ../app_button_tap.c

test_app_button_edge: test_app_button_edge.c ../app_button_edge.c ../app_button_edge.h
	$(CC) $(CFLAGS) -o $@ test_app_button_edge.c ../app_button_edge.c

test_app_button_tap_path: test_app_button_tap_path.c ../app_button_edge.c ../app_button_edge.h ../app_button_tap.c ../app_button_tap.h
	$(CC) $(CFLAGS) -o $@ test_app_button_tap_path.c ../app_button_edge.c ../app_button_tap.c

# The standalone framework against the SDK stubs in stubs/ — the real
# app_standalone.c is compiled, only the SDK/FDS/LED layer is faked.
test_standalone_result_gate: test_standalone_result_gate.c ../app_standalone.c ../app_standalone.h
	$(CC) $(CFLAGS) -Istubs -I.. -I../utils -o $@ \
	    test_standalone_result_gate.c ../app_standalone.c

clean:
	rm -f $(TESTS)
