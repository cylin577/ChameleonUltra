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
  "multitapSnapThreshold, multitapPack, multitapUnpack};", ctx);
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
check(throws(() => M.multitapPack([10, 0, 0, 0], [0, 0, 0, 0], 250)), "pack function 10 throws");
check(throws(() => M.multitapPack([1, 0, 0, 0], [0, 0, 0, 0], 255)), "pack threshold 255 throws");
check(throws(() => M.multitapPack([1, 0, 0, 0], [0, 0, 0, 0], 49)), "pack threshold 49 throws");

check(M.multitapSnapThreshold(251) === 250, "snap 251 -> 250");
check(M.multitapSnapThreshold(255) === 250, "snap 255 -> 250");
check(M.multitapSnapThreshold(1000) === 1000, "snap 1000 -> 1000");
check(M.multitapSnapThreshold(50) === 50, "snap 50 -> 50");
check(throws(() => M.multitapSnapThreshold(49)), "snap 49 throws");
check(throws(() => M.multitapSnapThreshold(1001)), "snap 1001 throws");
check(throws(() => M.multitapSnapThreshold(NaN)), "snap NaN throws");

console.log(pass + " checks, " + fail + " failed");
process.exit(fail ? 1 : 0);
