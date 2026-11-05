# Native (host) unit tests for the hardware-free multi-tap button helpers.
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wshadow -Wconversion -O1 -g -fsanitize=address,undefined

TESTS = test_app_button_tap test_app_button_edge test_app_button_tap_path

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done

test_app_button_tap: test_app_button_tap.c ../app_button_tap.c ../app_button_tap.h
	$(CC) $(CFLAGS) -o $@ test_app_button_tap.c ../app_button_tap.c

test_app_button_edge: test_app_button_edge.c ../app_button_edge.c ../app_button_edge.h
	$(CC) $(CFLAGS) -o $@ test_app_button_edge.c ../app_button_edge.c

test_app_button_tap_path: test_app_button_tap_path.c ../app_button_edge.c ../app_button_edge.h ../app_button_tap.c ../app_button_tap.h
	$(CC) $(CFLAGS) -o $@ test_app_button_tap_path.c ../app_button_edge.c ../app_button_tap.c

clean:
	rm -f $(TESTS)
