# Native (host) unit tests for the hardware-free multi-tap button helper.
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wshadow -Wconversion -O1 -g -fsanitize=address,undefined

test: test_app_button_tap
	./test_app_button_tap

test_app_button_tap: test_app_button_tap.c ../app_button_tap.c ../app_button_tap.h
	$(CC) $(CFLAGS) -o $@ test_app_button_tap.c ../app_button_tap.c

clean:
	rm -f test_app_button_tap
