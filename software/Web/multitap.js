"use strict";
/* multitap.js -- pure multi-tap config encode/decode shared by the Device
 * tab (fullcmd.js) and the in-browser terminal (terminal.js). No DOM, no
 * BLE, so it loads in plain node for unit testing.
 *
 * Wire format (firmware app_cmd.c cmd_processor_{get,set}_multi_tap_config):
 *   [taps_a u8][taps_b u8][threshold_ms u16 little endian]
 * The device stores the threshold in units of 10 ms, so only multiples of
 * 10 ms can be represented; the firmware rejects the rest with STATUS_PAR_ERR.
 */
const MULTITAP_TAP_NAMES = ["single", "double", "triple", "quadruple", "quintuple"];
const MULTITAP_COUNT_BY_NAME = { single: 1, double: 2, triple: 3, quadruple: 4, quintuple: 5 };
const MULTITAP_NAME_BY_COUNT = { 1: "single", 2: "double", 3: "triple", 4: "quadruple", 5: "quintuple" };
const MULTITAP_MIN_TAPS = 1;
const MULTITAP_MAX_TAPS = 5;
const MULTITAP_MIN_THRESHOLD_MS = 50;
const MULTITAP_MAX_THRESHOLD_MS = 1000;
const MULTITAP_DEFAULT_THRESHOLD_MS = 250;
const MULTITAP_THRESHOLD_UNIT_MS = 10;

function multitapCountByName(name) { return MULTITAP_COUNT_BY_NAME[name] || 0; }
function multitapNameByCount(n) { return MULTITAP_NAME_BY_COUNT[n] || String(n); }
function multitapCountText(n) { return n + " tap" + (n === 1 ? "" : "s"); }
function multitapLabel(n) { return multitapNameByCount(n) + " (" + multitapCountText(n) + ")"; }
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
function multitapPack(tapsA, tapsB, thresholdMs) {
  if (!Number.isInteger(tapsA) || tapsA < MULTITAP_MIN_TAPS || tapsA > MULTITAP_MAX_TAPS)
    throw new Error("invalid tap count A");
  if (!Number.isInteger(tapsB) || tapsB < MULTITAP_MIN_TAPS || tapsB > MULTITAP_MAX_TAPS)
    throw new Error("invalid tap count B");
  if (typeof thresholdMs !== "number" || !Number.isFinite(thresholdMs))
    throw new Error("threshold must be a number");
  const th = Math.trunc(thresholdMs);
  if (th < MULTITAP_MIN_THRESHOLD_MS || th > MULTITAP_MAX_THRESHOLD_MS)
    throw new Error("threshold out of range");
  if (th % MULTITAP_THRESHOLD_UNIT_MS !== 0)
    throw new Error("threshold must be a multiple of 10 ms");
  return [tapsA, tapsB, th & 255, (th >> 8) & 255];
}
function multitapUnpack(bytes) {
  if (!bytes || bytes.length !== 4) throw new Error("malformed multi-tap config reply");
  return { tapsA: bytes[0], tapsB: bytes[1], thresholdMs: (bytes[2] | (bytes[3] << 8)) };
}