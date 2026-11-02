"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const src = fs.readFileSync(path.join(__dirname, "..", "multitap.js"), "utf8");
const ctx = {};
vm.createContext(ctx);
vm.runInContext(src + "\n;globalThis.__mt = {" +
  "MULTITAP_TAP_NAMES, MULTITAP_COUNT_BY_NAME, MULTITAP_NAME_BY_COUNT, " +
  "MULTITAP_MIN_TAPS, MULTITAP_MAX_TAPS, MULTITAP_MIN_THRESHOLD_MS, " +
  "MULTITAP_MAX_THRESHOLD_MS, MULTITAP_DEFAULT_THRESHOLD_MS, " +
  "MULTITAP_THRESHOLD_UNIT_MS, multitapCountByName, multitapNameByCount, " +
  "multitapLabel, multitapCountText, multitapSnapThreshold, multitapPack, " +
  "multitapUnpack};", ctx);
const M = ctx.__mt;

let pass = 0, fail = 0;
function check(cond, msg) {
  if (cond) { pass++; } else { fail++; console.error("FAIL:", msg); }
}
function throws(fn) {
  try { fn(); return false; } catch (e) { return true; }
}

check(Array.isArray(M.MULTITAP_TAP_NAMES) && M.MULTITAP_TAP_NAMES.length === 5, "5 tap names");
check(M.MULTITAP_COUNT_BY_NAME.single === 1, "count by name single");
check(M.MULTITAP_COUNT_BY_NAME.double === 2, "count by name double");
check(M.MULTITAP_COUNT_BY_NAME.triple === 3, "count by name triple");
check(M.MULTITAP_COUNT_BY_NAME.quadruple === 4, "count by name quadruple");
check(M.MULTITAP_COUNT_BY_NAME.quintuple === 5, "count by name quintuple");
check(M.MULTITAP_NAME_BY_COUNT[1] === "single", "name by count 1");
check(M.MULTITAP_NAME_BY_COUNT[3] === "triple", "name by count 3");
check(M.MULTITAP_NAME_BY_COUNT[5] === "quintuple", "name by count 5");
check(M.MULTITAP_MIN_TAPS === 1 && M.MULTITAP_MAX_TAPS === 5, "tap range");
check(M.MULTITAP_MIN_THRESHOLD_MS === 50 && M.MULTITAP_MAX_THRESHOLD_MS === 1000, "threshold range");
check(M.MULTITAP_DEFAULT_THRESHOLD_MS === 250, "default threshold");
check(M.MULTITAP_THRESHOLD_UNIT_MS === 10, "threshold unit");

check(M.multitapLabel(1) === "single (1 tap)", "label 1");
check(M.multitapLabel(2) === "double (2 taps)", "label 2");
check(M.multitapLabel(5) === "quintuple (5 taps)", "label 5");
check(M.multitapCountText(1) === "1 tap", "count text 1");
check(M.multitapCountText(2) === "2 taps", "count text 2");

const packed = M.multitapPack(3, 1, 250);
check(Array.isArray(packed) && packed.length === 4, "pack length");
check(packed[0] === 3 && packed[1] === 1 && packed[2] === 250 && packed[3] === 0, "pack 3,1,250 -> [3,1,250,0]");

const u = M.multitapUnpack([3, 1, 250, 0]);
check(u.tapsA === 3 && u.tapsB === 1 && u.thresholdMs === 250, "unpack round trip");
check(M.multitapUnpack([1, 2, 0xe8, 0x03]).thresholdMs === 1000, "unpack threshold 1000 (LE)");
check(throws(() => M.multitapUnpack([1, 2, 3])), "unpack 3 bytes throws");
check(throws(() => M.multitapUnpack(null)), "unpack null throws");

check(M.multitapSnapThreshold(251) === 250, "snap 251 -> 250");
check(M.multitapSnapThreshold(255) === 250, "snap 255 -> 250");
check(M.multitapSnapThreshold(1000) === 1000, "snap 1000 -> 1000");
check(M.multitapSnapThreshold(50) === 50, "snap 50 -> 50");
check(throws(() => M.multitapSnapThreshold(49)), "snap 49 throws");
check(throws(() => M.multitapSnapThreshold(1001)), "snap 1001 throws");
check(throws(() => M.multitapSnapThreshold(NaN)), "snap NaN throws");

check(throws(() => M.multitapPack(0, 1, 250)), "pack tapsA 0 throws");
check(throws(() => M.multitapPack(1, 6, 250)), "pack tapsB 6 throws");
check(throws(() => M.multitapPack(1, 1, 255)), "pack threshold 255 throws");
check(throws(() => M.multitapPack(1, 1, 49)), "pack threshold 49 throws");
check(M.multitapCountByName("nope") === 0, "unknown name -> 0");
check(M.multitapCountByName("double") === 2, "countByName double");

console.log(pass + " checks, " + fail + " failed");
process.exit(fail ? 1 : 0);