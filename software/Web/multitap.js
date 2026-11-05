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
/* Snap a threshold that comes from the device into the valid range
 * (50..1000 ms, 10 ms steps): a corrupt stored value must not make the
 * "Set" fail, the device rejects such a value with STATUS_PAR_ERR. */
function multitapClampThreshold(ms) {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return MULTITAP_DEFAULT_THRESHOLD_MS;
  let raw = Math.trunc(ms);
  if (raw < MULTITAP_MIN_THRESHOLD_MS) raw = MULTITAP_MIN_THRESHOLD_MS;
  if (raw > MULTITAP_MAX_THRESHOLD_MS) raw = MULTITAP_MAX_THRESHOLD_MS;
  return Math.floor(raw / MULTITAP_THRESHOLD_UNIT_MS) * MULTITAP_THRESHOLD_UNIT_MS;
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
    /* A corrupt stored threshold is clamped here, so every caller (the
     * Device tab and the terminal) works with a value the device accepts. */
    thresholdMs: multitapClampThreshold(bytes[8] | (bytes[9] << 8)),
  };
}

/* Merge the slots the user actually changed into the device's current table.
 * overrides: [{index, value}] with index 0..3 = tap count 2..5.
 * The device table is never overwritten wholesale, so a "Set" without a
 * "Get" can no longer clear the slots the user did not touch. */
function multitapMergeSlots(current, overrides) {
  if (!Array.isArray(current) || current.length !== MULTITAP_BIND_SLOTS)
    throw new Error("invalid current bindings");
  const out = current.slice();
  for (const o of (overrides || [])) {
    if (!o || !Number.isInteger(o.index) || o.index < 0 || o.index >= MULTITAP_BIND_SLOTS)
      throw new Error("invalid override index");
    out[o.index] = multitapCheckFunction(o.value);
  }
  return out;
}

/* Build the payload of a "Set" from the device table and the slots the user
 * changed.
 *   deviceSlots:      {a: [4 fn], b: [4 fn], thresholdMs} (multitapUnpack)
 *   dirtySlots:       the slot keys the user changed: "a0".."a3" and "b0".."b3"
 *                     (index 0 = tap count 2)
 *   selectedSlots:    {a0: fn, a1: fn, ...} the current value of every slot
 *   thresholdDirty:   true when the user changed the threshold
 *   selectedThreshold: the threshold the user selected
 * The slots the user did not touch keep the value the device holds and the
 * threshold is preserved unless it was changed explicitly. */
function multitapBuildPayload(deviceSlots, dirtySlots, selectedSlots, thresholdDirty, selectedThreshold) {
  if (!deviceSlots || !Array.isArray(deviceSlots.a) || !Array.isArray(deviceSlots.b))
    throw new Error("invalid device slots");
  const overridesA = [], overridesB = [];
  for (const key of (dirtySlots || [])) {
    if (!selectedSlots || !Object.prototype.hasOwnProperty.call(selectedSlots, key))
      throw new Error("unknown slot " + key);
    const button = key[0];
    const index = Number(key.slice(1));
    if ((button !== "a" && button !== "b") || !Number.isInteger(index) ||
        index < 0 || index >= MULTITAP_BIND_SLOTS)
      throw new Error("invalid slot key");
    const value = multitapCheckFunction(selectedSlots[key]);
    (button === "a" ? overridesA : overridesB).push({index: index, value: value});
  }
  return {
    a: multitapMergeSlots(deviceSlots.a, overridesA),
    b: multitapMergeSlots(deviceSlots.b, overridesB),
    thresholdMs: thresholdDirty ? multitapSnapThreshold(selectedThreshold) : multitapClampThreshold(deviceSlots.thresholdMs),
  };
}
