"use strict";
/* multitap.js -- pure multi-tap binding encode/decode shared by the Device
 * tab (fullcmd.js) and the in-browser terminal (terminal.js). No DOM, no
 * BLE, so it loads in plain node for unit testing.
 *
 * Wire format (firmware app_cmd.c cmd_processor_{get,set}_multi_tap_bindings):
 *   [fn_a2 u8][fn_a3 u8][fn_a4 u8][fn_a5 u8]
 *   [fn_b2 u8][fn_b3 u8][fn_b4 u8][fn_b5 u8]
 *   [threshold_ms u16 little endian]
 * The function codes are the same 0..9 values as the short/long press
 * bindings (0 = disabled). A tap count of 1 is the button's short-press
 * binding and is NOT part of this payload.
 * The device stores the threshold in units of 10 ms, so only multiples of
 * 10 ms can be represented; the firmware rejects the rest with STATUS_PAR_ERR.
 */
const MULTITAP_BIND_TAP_MIN = 2;   /* tap counts 2..5 are bindable; 1 == short press */
const MULTITAP_BIND_TAP_MAX = 5;
const MULTITAP_BIND_SLOTS = 4;     /* per button */
const MULTITAP_BIND_TOTAL = 8;     /* 2 buttons x 4 slots */
const MULTITAP_MIN_THRESHOLD_MS = 50;
const MULTITAP_MAX_THRESHOLD_MS = 1000;
const MULTITAP_DEFAULT_THRESHOLD_MS = 250;
const MULTITAP_THRESHOLD_UNIT_MS = 10;

function multitapSnapThreshold(ms) {
  if (typeof ms !== "number" || !Number.isFinite(ms)) throw new Error("threshold must be a number");
  const raw = Math.trunc(ms);
  if (raw < MULTITAP_MIN_THRESHOLD_MS || raw > MULTITAP_MAX_THRESHOLD_MS)
    throw new Error("threshold out of range");
  const snapped = Math.floor(raw / MULTITAP_THRESHOLD_UNIT_MS) * MULTITAP_THRESHOLD_UNIT_MS;
  if (snapped < MULTITAP_MIN_THRESHOLD_MS || snapped > MULTITAP_MAX_THRESHOLD_MS)
    throw new Error("threshold out of range");
  return snapped;
}
function multitapCheckFunction(fn) {
  if (!Number.isInteger(fn) || fn < 0 || fn > 9) throw new Error("invalid button function");
  return fn;
}
function multitapPack(bindingsA, bindingsB, thresholdMs) {
  if (!Array.isArray(bindingsA) || bindingsA.length !== MULTITAP_BIND_SLOTS)
    throw new Error("invalid bindings A");
  if (!Array.isArray(bindingsB) || bindingsB.length !== MULTITAP_BIND_SLOTS)
    throw new Error("invalid bindings B");
  const fns = [];
  for (const fn of bindingsA.concat(bindingsB)) fns.push(multitapCheckFunction(fn));
  if (typeof thresholdMs !== "number" || !Number.isFinite(thresholdMs))
    throw new Error("threshold must be a number");
  const th = Math.trunc(thresholdMs);
  if (th < MULTITAP_MIN_THRESHOLD_MS || th > MULTITAP_MAX_THRESHOLD_MS)
    throw new Error("threshold out of range");
  if (th % MULTITAP_THRESHOLD_UNIT_MS !== 0)
    throw new Error("threshold must be a multiple of 10 ms");
  return fns.concat([th & 255, (th >> 8) & 255]);
}
function multitapUnpack(bytes) {
  if (!bytes || bytes.length !== 10) throw new Error("malformed multi-tap bindings reply");
  return {
    a: [bytes[0], bytes[1], bytes[2], bytes[3]],
    b: [bytes[4], bytes[5], bytes[6], bytes[7]],
    thresholdMs: (bytes[8] | (bytes[9] << 8)),
  };
}
