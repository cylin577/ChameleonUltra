"use strict";
/* amiibo.js -- pure wire-format helpers for the on-device amiibo commands
 * CMD 1069..1073. No DOM, no BLE, so it loads in plain node for unit tests.
 *
 * Wire layout, from firmware application/src/app_cmd.c (cmd_processor_amiibo_*)
 * and nfc_amiibo_refresh_slot.h / nfc_amiibo_uid_refresh.h:
 *   1069 AMIIBO_UPLOAD_KEYS       in: [] (clear) or [data_key 80][tag_key 80]
 *                                 out: no payload; only a STATUS_* code
 *   1070 AMIIBO_REFRESH_UID       in: [flags u8] (bit0 = persist)
 *                                 out: [old_uid 7][new_uid 7]
 *   1071 AMIIBO_AUTO_REFRESH_SET  in: [enable u8][persist u8]
 *                                 out: no payload
 *   1072 AMIIBO_AUTO_REFRESH_GET  in: []
 *                                 out: 21 bytes: enabled, armed_slot,
 *                                      scan_count, last_ok, status u16 LE,
 *                                      old_uid[7], new_uid[7], activity u8
 *                                      (bit7 = PWD_AUTH, low7 = READ count)
 *   1073 AMIIBO_VERIFY_SLOT       in: []
 *                                 out: [valid u8][reason u8][uid 7]
 *
 * Nothing here ever renders the retail key bytes: they are only ever copied
 * into an outbound request, never into a message or an error.
 */

const AMIIBO_RETAIL_KEY_SIZE = 80;
const AMIIBO_KEYS_PAYLOAD_SIZE = 2 * AMIIBO_RETAIL_KEY_SIZE;
const AMIIBO_UID_SIZE = 7;
const AMIIBO_REFRESH_FLAG_PERSIST = 0x01;
const AMIIBO_STATUS_SNAPSHOT_SIZE = 21;
const AMIIBO_VERIFY_RESPONSE_SIZE = 9;
const AMIIBO_STATUS_SUCCESS = 0x68;

/* Firmware app_status.h STATUS_AMIIBO_* (merged into fullcmd.js STATUS_NAMES). */
const AMIIBO_STATUS_NAMES = {
  0x76: "AMIIBO_KEYS_MISSING",
  0x77: "AMIIBO_KEYS_INVALID",
  0x78: "AMIIBO_KEYS_FAIL",
  0x79: "AMIIBO_UID_INVALID",
  0x7A: "AMIIBO_UID_FAIL",
};

/* nfc_amiibo_verify_reason_t in nfc_amiibo_refresh_slot.h. */
const AMIIBO_VERIFY_REASON_NAMES = {
  0: "valid",
  1: "not NTAG215",
  2: "keys missing",
  3: "tag HMAC mismatch",
  4: "data HMAC mismatch",
  5: "signature present",
  6: "other",
};

function amiiboBytes(value, what) {
  if (value === null || value === undefined || typeof value.length !== "number")
    throw new Error(what + " must be bytes");
  const out = Array.from(value);
  for (const b of out) {
    if (!Number.isInteger(b) || b < 0 || b > 255)
      throw new Error(what + " must be bytes");
  }
  return out;
}

/* ---- request builders ---- */

/* An empty file is a deliberate "clear the device keys" request. */
function amiiboBuildKeyUpload(bytes) {
  const data = amiiboBytes(bytes, "retail key file");
  if (data.length !== 0 && data.length !== AMIIBO_KEYS_PAYLOAD_SIZE)
    throw new Error("retail key file must be exactly " + AMIIBO_KEYS_PAYLOAD_SIZE +
                    " bytes (two " + AMIIBO_RETAIL_KEY_SIZE + "-byte keys), or empty to clear");
  return data;
}
function amiiboBuildRefreshUid(persist) {
  return [persist ? AMIIBO_REFRESH_FLAG_PERSIST : 0];
}
function amiiboBuildAutoRefreshSet(enable, persist) {
  return [enable ? 1 : 0, persist ? 1 : 0];
}

/* ---- response parsers (structural only, no UI strings) ---- */

function amiiboParseKeyUpload(frame, wasClear) {
  if (!frame || typeof frame.status !== "number") throw new Error("malformed command reply");
  const ok = frame.status === AMIIBO_STATUS_SUCCESS;
  return { ok: ok, cleared: ok && !!wasClear, status: frame.status };
}
function amiiboParseRefreshUid(frame) {
  const d = (frame && frame.data) ? amiiboBytes(frame.data, "UID refresh reply") : [];
  if (d.length !== 2 * AMIIBO_UID_SIZE)
    throw new Error("UID refresh reply must be " + (2 * AMIIBO_UID_SIZE) + " bytes");
  return { oldUid: d.slice(0, AMIIBO_UID_SIZE), newUid: d.slice(AMIIBO_UID_SIZE) };
}
function amiiboParseAutoRefreshStatus(frame) {
  const d = (frame && frame.data) ? amiiboBytes(frame.data, "auto-refresh status reply") : [];
  if (d.length !== AMIIBO_STATUS_SNAPSHOT_SIZE)
    throw new Error("auto-refresh status reply must be " + AMIIBO_STATUS_SNAPSHOT_SIZE + " bytes");
  return {
    enabled: d[0] !== 0,
    armedSlot: d[1],
    scanCount: d[2],
    lastOk: d[3] !== 0,
    status: d[4] | (d[5] << 8),
    oldUid: d.slice(6, 6 + AMIIBO_UID_SIZE),
    newUid: d.slice(13, 13 + AMIIBO_UID_SIZE),
    activity: { pwdAuth: (d[20] & 0x80) !== 0, readCount: d[20] & 0x7f },
  };
}
function amiiboParseVerifySlot(frame) {
  const d = (frame && frame.data) ? amiiboBytes(frame.data, "slot verify reply") : [];
  if (d.length !== AMIIBO_VERIFY_RESPONSE_SIZE)
    throw new Error("slot verify reply must be " + AMIIBO_VERIFY_RESPONSE_SIZE + " bytes");
  return {
    valid: d[0] !== 0,
    reason: d[1],
    reasonName: AMIIBO_VERIFY_REASON_NAMES[d[1]] || ("reason " + d[1]),
    uid: d.slice(2, 2 + AMIIBO_UID_SIZE),
  };
}

/* ---- safe display helpers ---- */

function amiiboUidHex(bytes) {
  const d = amiiboBytes(bytes, "UID");
  if (d.length !== AMIIBO_UID_SIZE) throw new Error("UID must be 7 bytes");
  return d.map(b => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
}
function amiiboStatusName(code) {
  return AMIIBO_STATUS_NAMES[code] || ("0x" + code.toString(16).padStart(2, "0"));
}
function amiiboFormatKeyUpload(result) {
  if (!result.ok) return "Failed: device status " + amiiboStatusName(result.status);
  return result.cleared ? "Device retail keys cleared." : "Retail keys uploaded and persisted.";
}
function amiiboFormatRefreshUid(parsed) {
  return "UID refreshed (in RAM).\nOld UID: " + amiiboUidHex(parsed.oldUid) +
         "\nNew UID: " + amiiboUidHex(parsed.newUid);
}
function amiiboFormatAutoRefreshStatus(s) {
  return "Auto-refresh: " + (s.enabled ? "armed" : "disarmed") + "\n" +
         "Armed slot: " + s.armedSlot + "\n" +
         "Field scans: " + s.scanCount + "\n" +
         "Last refresh: " + (s.lastOk ? "ok" : "none/failed") + " (" + amiiboStatusName(s.status) + ")\n" +
         "Old UID: " + amiiboUidHex(s.oldUid) + "\n" +
         "New UID: " + amiiboUidHex(s.newUid) + "\n" +
         "Activity: PWD_AUTH " + (s.activity.pwdAuth ? "seen" : "not seen") +
         ", READ/FAST_READ " + s.activity.readCount;
}
function amiiboFormatVerifySlot(v) {
  return "Slot verify: " + (v.valid ? "VALID" : "INVALID") + " (" + v.reasonName + ")\n" +
         "Current UID: " + amiiboUidHex(v.uid);
}
