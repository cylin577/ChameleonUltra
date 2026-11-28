/*
 * fido2_dbg.h
 *
 * Host-facing debug hooks for the FIDO2 standalone authenticator (7020-7025).
 * Bound to DATA_CMD_FIDO2_* in m_data_cmd_map[] in app_cmd.c.
 *
 * Wire formats are little-endian (matches existing CU commands).
 */
#ifndef FIDO2_DBG_H
#define FIDO2_DBG_H

#include <stdint.h>

#include "dataframe.h"

#if CONFIG_STANDALONE_FIDO2

/* 7020: request { u8 gate } (1=UP, 2=UV) -> empty success */
data_frame_tx_t *cmd_handler_fido2_grant(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data);
/* 7021: request { u8 transport, u8 uv, u8[] ctap } -> { u8 ctap_status, u8[] } */
data_frame_tx_t *cmd_handler_fido2_ctap(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data);
/* 7022: -> f2_creds_list() text */
data_frame_tx_t *cmd_handler_fido2_creds_list(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data);
/* 7023: no request -> empty success (works while DISARMED) */
data_frame_tx_t *cmd_handler_fido2_creds_reset(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data);
/* 7024: -> f2_core_status() text */
data_frame_tx_t *cmd_handler_fido2_status(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data);
/* 7025: request raw U2F APDU -> raw response including SW1|SW2 */
data_frame_tx_t *cmd_handler_fido2_u2f_apdu(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data);

#endif /* CONFIG_STANDALONE_FIDO2 */

#endif /* FIDO2_DBG_H */
