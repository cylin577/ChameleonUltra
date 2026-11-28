/* FIDO2 CTAP transport over BLE GATT (service 0xFFFD, FFF1..FFF4).
 *
 * All GATT registration is best-effort: a failure leaves NUS/BAS/CLI alone.
 * The mode calls f2_ble_poll() from its tick to pump notification fragments;
 * f2_core_dispatch() is deliberately deferred to that context so no crypto
 * runs in the BLE event callback. */
#ifndef FIDO2_BLE_H
#define FIDO2_BLE_H

#include <stdbool.h>
#include <stdint.h>

/* Register the service/characteristics. Returns false on any GATT error. */
bool f2_ble_init(void);

/* Gate CTAP commands; PING is answered even while disarmed. */
void f2_ble_set_armed(bool armed);

/* Perform one bounded batch of queued work (dispatch + notifications). */
void f2_ble_poll(void);

/* True when the GATT service was registered successfully. */
bool f2_ble_available(void);

#endif /* FIDO2_BLE_H */
