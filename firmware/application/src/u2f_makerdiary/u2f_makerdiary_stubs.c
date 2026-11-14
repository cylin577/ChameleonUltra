/*
 * Stubs for the vendored makerdiary nrf52-u2f implementation
 * (firmware/application/src/u2f_makerdiary/u2f_impl.c).
 *
 * ChameleonUltra provisions attestation at runtime via FDS, so these
 * provide safe default values that keep the reference module linkable
 * without changing existing behavior. Additive only.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "u2f.h"

uint8_t aes_key[16] = {0};

uint8_t attestation_cert[512] = {0x30, 0x00};
uint8_t attestation_private_key[32] = {0};
uint16_t attestation_cert_size = 2;
uint8_t attestation_private_key_size = sizeof(attestation_private_key);

bool is_user_button_pressed(void) { return true; }
