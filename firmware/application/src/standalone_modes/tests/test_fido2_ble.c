/*
 * Host tests for the BLE FIDO GATT protocol constants.
 */
#include "../fido2_ble.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

int main(void) {
    static const uint8_t expected_uuid[16] = {
        0xBB, 0x23, 0xD6, 0x7E, 0xBA, 0xC9, 0x2F, 0xB4,
        0xEE, 0xEC, 0xAA, 0xDE, 0x00, 0x00, 0xD0, 0xF1,
    };
    static const uint8_t uuid[16] = FIDO_BLE_BASE_UUID_BYTES;
    static const uint8_t revision[3] = FIDO_BLE_SERVICE_REVISION_BYTES;

    CHECK(sizeof(uuid) == sizeof(expected_uuid));
    CHECK(memcmp(uuid, expected_uuid, sizeof expected_uuid) == 0);
    CHECK(sizeof(revision) == 3);
    CHECK(memcmp(revision, "1.0", 3) == 0);

    CHECK(FIDO_BLE_CMD_PING == 0x81);
    CHECK(FIDO_BLE_CMD_KEEPALIVE == 0x82);
    CHECK(FIDO_BLE_CMD_MSG == 0x83);
    CHECK(FIDO_BLE_CMD_CANCEL == 0xBE);
    CHECK(FIDO_BLE_CMD_ERROR == 0xBF);
    CHECK(FIDO_BLE_KEEPALIVE_PROCESSING == 0x01);
    CHECK(FIDO_BLE_KEEPALIVE_UPNEEDED == 0x02);
    CHECK(FIDO_BLE_MAX_MESSAGE == 512);
    CHECK(FIDO_BLE_MIN_MTU == 23);

    printf("%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
