"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const src = fs.readFileSync(path.join(__dirname, "..", "multitap.js"), "utf8");
const ctx = {};
vm.createContext(ctx);
vm.runInContext(src + "\n;globalThis.__mt = {" +
  "MULTITAP_BIND_TAP_MIN, MULTITAP_BIND_TAP_MAX, " +
  "MULTITAP_BIND_SLOTS, MULTITAP_BIND_TOTAL, " +
  "MULTITAP_MIN_THRESHOLD_MS, MULTITAP_MAX_THRESHOLD_MS, " +
  "MULTITAP_DEFAULT_THRESHOLD_MS, MULTITAP_THRESHOLD_UNIT_MS, " +
  "multitapSnapThreshold, multitapClampThreshold, multitapPack, multitapUnpack, multitapMergeSlots, " +
  "multitapBuildPayload};", ctx);
const M = ctx.__mt;

let pass = 0, fail = 0;
function check(cond, msg) {
  if (cond) { pass++; } else { fail++; console.error("FAIL:", msg); }
}
function throws(fn) {
  try { fn(); return false; } catch (e) { return true; }
}
check(M.MULTITAP_BIND_TAP_MIN === 2 && M.MULTITAP_BIND_TAP_MAX === 5, "bind tap range");
check(M.MULTITAP_BIND_SLOTS === 4 && M.MULTITAP_BIND_TOTAL === 8, "bind slot counts");
check(M.MULTITAP_MIN_THRESHOLD_MS === 50 && M.MULTITAP_MAX_THRESHOLD_MS === 1000, "threshold range");
check(M.MULTITAP_DEFAULT_THRESHOLD_MS === 250, "default threshold");
check(M.MULTITAP_THRESHOLD_UNIT_MS === 10, "threshold unit");

const packed = M.multitapPack([1, 2, 3, 4], [5, 6, 7, 8], 250);
check(Array.isArray(packed) && packed.length === 10, "pack length");
check(packed[0] === 1 && packed[3] === 4 && packed[4] === 5 && packed[7] === 8, "pack function bytes");
check(packed[8] === 250 && packed[9] === 0, "pack threshold LE");

const u = M.multitapUnpack(packed);
check(u.a[0] === 1 && u.a[3] === 4, "unpack a");
check(u.b[0] === 5 && u.b[3] === 8, "unpack b");
check(u.thresholdMs === 250, "unpack threshold");
check(M.multitapUnpack([0, 0, 0, 0, 0, 0, 0, 0, 0xe8, 0x03]).thresholdMs === 1000, "unpack threshold 1000 (LE)");
check(throws(() => M.multitapUnpack([1, 2, 3])), "unpack 9 bytes throws");
check(throws(() => M.multitapUnpack(null)), "unpack null throws");
check(throws(() => M.multitapPack([0, 0, 0], [0, 0, 0, 0], 250)), "pack bad slot count throws");
check(M.multitapPack([10, 0, 0, 0], [0, 0, 0, 0], 250)[0] === 10, "pack function 10 valid");
check(M.multitapPack([11, 0, 0, 0], [0, 0, 0, 0], 250)[0] === 11, "pack function 11 valid");
check(throws(() => M.multitapPack([12, 0, 0, 0], [0, 0, 0, 0], 250)), "pack function 12 throws");
check(throws(() => M.multitapPack([1, 0, 0, 0], [0, 0, 0, 0], 255)), "pack threshold 255 throws");
check(throws(() => M.multitapPack([1, 0, 0, 0], [0, 0, 0, 0], 49)), "pack threshold 49 throws");

check(M.multitapSnapThreshold(251) === 250, "snap 251 -> 250");
check(M.multitapSnapThreshold(255) === 250, "snap 255 -> 250");
check(M.multitapSnapThreshold(1000) === 1000, "snap 1000 -> 1000");
check(M.multitapSnapThreshold(50) === 50, "snap 50 -> 50");
check(throws(() => M.multitapSnapThreshold(49)), "snap 49 throws");
check(throws(() => M.multitapSnapThreshold(1001)), "snap 1001 throws");
check(throws(() => M.multitapSnapThreshold(NaN)), "snap NaN throws");

/* A corrupt threshold stored on the device is clamped into the valid range
 * instead of breaking the "Set". */
check(M.multitapClampThreshold(30) === 50, "clamp 30 -> 50");
check(M.multitapClampThreshold(0) === 50, "clamp 0 -> 50");
check(M.multitapClampThreshold(255) === 250, "clamp 255 -> 250");
check(M.multitapClampThreshold(1500) === 1000, "clamp 1500 -> 1000");
check(M.multitapClampThreshold(250) === 250, "clamp 250 -> 250");
check(M.multitapClampThreshold(NaN) === 250, "clamp NaN -> the default");
check(M.multitapUnpack([0, 0, 0, 0, 0, 0, 0, 0, 30, 0]).thresholdMs === 50, "unpack clamps a corrupt threshold");
check(M.multitapUnpack([0, 0, 0, 0, 0, 0, 0, 0, 0xd2, 0x05]).thresholdMs === 1000, "unpack clamps a too big threshold");

check(M.multitapMergeSlots([4,0,0,0], []).join(",") === "4,0,0,0", "merge without overrides keeps the device table");
check(M.multitapMergeSlots([4,0,0,0], [{index:1,value:7}]).join(",") === "4,7,0,0", "merge replaces only the dirty slot");
check((() => { const cur = [4,0,0,0]; M.multitapMergeSlots(cur, [{index:0,value:9}]); return cur.join(",") === "4,0,0,0"; })(), "merge does not modify the device table");
check(throws(() => M.multitapMergeSlots([4,0,0,0], [{index:4,value:1}])), "merge bad index throws");
check(throws(() => M.multitapMergeSlots([4,0,0,0], [{index:0,value:12}])), "merge bad function throws");

/* The "Set" payload: the device table plus the slots the user changed. */
const DEVICE = {a: [4,0,0,0], b: [0,7,0,0], thresholdMs: 250};
const SELECTED = {a0: 0, a1: 0, a2: 0, a3: 0, b0: 0, b1: 0, b2: 0, b3: 0};

const p0 = M.multitapBuildPayload(DEVICE, [], SELECTED, false, 500);
check(p0.a.join(",") === "4,0,0,0", "build keeps the untouched slots of A");
check(p0.b.join(",") === "0,7,0,0", "build keeps the untouched slots of B");
check(p0.thresholdMs === 250, "build keeps the threshold when it was not changed");

const p1 = M.multitapBuildPayload(DEVICE, ["a1"], Object.assign({}, SELECTED, {a1: 7}), false, 500);
check(p1.a.join(",") === "4,7,0,0", "build replaces the dirty slot");
check(p1.b.join(",") === "0,7,0,0", "build leaves the other button alone");
check(p1.thresholdMs === 250, "build keeps the threshold when it was not changed");

const p2 = M.multitapBuildPayload(DEVICE, ["a1"], Object.assign({}, SELECTED, {a1: 0}), false, 250);
check(p2.a.join(",") === "4,0,0,0", "build clears a slot the user disabled");

const p3 = M.multitapBuildPayload(DEVICE, [], SELECTED, true, 500);
check(p3.thresholdMs === 500, "build takes the changed threshold");
check(p3.a.join(",") === "4,0,0,0", "build with a changed threshold keeps the slots");

check(throws(() => M.multitapBuildPayload(DEVICE, ["a4"], SELECTED, false, 250)), "build bad slot index throws");
check(throws(() => M.multitapBuildPayload(DEVICE, ["c0"], SELECTED, false, 250)), "build bad slot key throws");
check(throws(() => M.multitapBuildPayload(DEVICE, ["a0"], Object.assign({}, SELECTED, {a0: 12}), false, 250)), "build bad function throws");
check(throws(() => M.multitapBuildPayload(null, [], SELECTED, false, 250)), "build without a device table throws");
check(throws(() => M.multitapBuildPayload(DEVICE, [], SELECTED, true, 40)), "build bad threshold throws");
/* A corrupt threshold on the device must not make the "Set" fail. */
const CORRUPT = {a: [4,0,0,0], b: [0,7,0,0], thresholdMs: 30};
const p4 = M.multitapBuildPayload(CORRUPT, [], SELECTED, false, 500);
check(p4.thresholdMs === 50, "build clamps a corrupt device threshold");
check(p4.a.join(",") === "4,0,0,0", "build keeps the slots with a corrupt device threshold");
check(M.multitapPack(p4.a, p4.b, p4.thresholdMs).length === 10, "pack accepts the clamped threshold");
check((() => { const cur = {a: [4,0,0,0], b: [0,0,0,0], thresholdMs: 250}; M.multitapBuildPayload(cur, ["a0"], SELECTED, false, 250); return cur.a.join(",") === "4,0,0,0"; })(), "build does not modify the device table");

/* ---- Button function 10 (AMIIBO_REFRESH) must render in the web console ---- */
const fullcmdSrc = fs.readFileSync(path.join(__dirname, "..", "fullcmd.js"), "utf8");
const fnNamesMatch = fullcmdSrc.match(/const BUTTON_FN_NAMES = (\{[^}]*\});/);
check(!!fnNamesMatch, "fullcmd.js declares BUTTON_FN_NAMES");
if (fnNamesMatch) {
  const fnNamesCtx = {};
  vm.createContext(fnNamesCtx);
  const fnNames = vm.runInContext("(" + fnNamesMatch[1] + ")", fnNamesCtx);
  check(fnNames[10] === "Refresh amiibo UID now",
    "fullcmd.js BUTTON_FN_NAMES[10] = Refresh amiibo UID now");
  check(fnNames[11] === "Toggle amiibo auto-refresh",
    "fullcmd.js BUTTON_FN_NAMES[11] = Toggle amiibo auto-refresh");
  check(fnNames[9] === "Standalone clear results", "fullcmd.js BUTTON_FN_NAMES[9] unchanged");
}

/* terminal.js must expose the same name/code mapping for its CLI -f flag. */
const terminalSrc = fs.readFileSync(path.join(__dirname, "..", "terminal.js"), "utf8");
check(/AMIIBO_ARM\s*:\s*11\b/.test(terminalSrc),
  "terminal.js BUTTON_FN_BY_NAME maps AMIIBO_ARM to 11");

const htmlSrc = fs.readFileSync(path.join(__dirname, "..", "phreakbyte.html"), "utf8");
function selectOptions(id) {
  const m = htmlSrc.match(new RegExp('<select id="' + id + '">([\\s\\S]*?)<\\/select>'));
  return m ? m[1] : null;
}
const FN10 = '<option value="10">Refresh amiibo UID now</option>';
const browserFnOpts = selectOptions("d_btnFn");
check(!!browserFnOpts && browserFnOpts.indexOf(FN10) >= 0,
  "phreakbyte.html d_btnFn has option 10 (Refresh amiibo UID now)");
for (const id of ["d_mtA2", "d_mtA3", "d_mtA4", "d_mtA5", "d_mtB2", "d_mtB3", "d_mtB4", "d_mtB5"]) {
  const opts = selectOptions(id);
  check(!!opts && opts.indexOf(FN10) >= 0,
    "phreakbyte.html " + id + " has option 10 (Refresh amiibo UID now)");
}

const FN11 = '<option value="11">Toggle amiibo auto-refresh</option>';
check(!!browserFnOpts && browserFnOpts.indexOf(FN11) >= 0,
  "phreakbyte.html d_btnFn has option 11 (Toggle amiibo auto-refresh)");
for (const id of ["d_mtA2", "d_mtA3", "d_mtA4", "d_mtA5", "d_mtB2", "d_mtB3", "d_mtB4", "d_mtB5"]) {
  const opts = selectOptions(id);
  check(!!opts && opts.indexOf(FN11) >= 0,
    "phreakbyte.html " + id + " has option 11 (Toggle amiibo auto-refresh)");
}

console.log(pass + " checks, " + fail + " failed");
process.exit(fail ? 1 : 0);
