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

/* The CTAP2 CBOR codec lives in its own file so the terminal and the page
 * share it; it needs TextEncoder/TextDecoder, which a bare VM context lacks. */
const cborSrc = fs.readFileSync(path.join(__dirname, "..", "fido2_cbor.js"), "utf8");
const cborCtx = { TextEncoder, TextDecoder, Uint8Array, Array, Object, Number, Math, JSON };
vm.createContext(cborCtx);
vm.runInContext(cborSrc + "\n;globalThis.__cbor = {" +
  "fido2CborEncode, fido2CborDecode, fido2CborFormat, " +
  "fido2CborMakeCredentialParams, fido2CborGetAssertionParams};", cborCtx);
const C = cborCtx.__cbor;

let pass = 0, fail = 0;
function check(cond, msg) {
  if (cond) { pass++; } else { fail++; console.error("FAIL:", msg); }
}
function throws(fn) {
  try { fn(); return false; } catch (e) { return true; }
}
function sequenceIndex(haystack, needle) {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
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
check(throws(() => M.multitapMergeSlots([4,0,0,0], [{index:0,value:10}])), "merge bad function throws");

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
check(throws(() => M.multitapBuildPayload(DEVICE, ["a0"], Object.assign({}, SELECTED, {a0: 10}), false, 250)), "build bad function throws");
check(throws(() => M.multitapBuildPayload(null, [], SELECTED, false, 250)), "build without a device table throws");
check(throws(() => M.multitapBuildPayload(DEVICE, [], SELECTED, true, 40)), "build bad threshold throws");
/* A corrupt threshold on the device must not make the "Set" fail. */
const CORRUPT = {a: [4,0,0,0], b: [0,7,0,0], thresholdMs: 30};
const p4 = M.multitapBuildPayload(CORRUPT, [], SELECTED, false, 500);
check(p4.thresholdMs === 50, "build clamps a corrupt device threshold");
check(p4.a.join(",") === "4,0,0,0", "build keeps the slots with a corrupt device threshold");
check(M.multitapPack(p4.a, p4.b, p4.thresholdMs).length === 10, "pack accepts the clamped threshold");
check((() => { const cur = {a: [4,0,0,0], b: [0,0,0,0], thresholdMs: 250}; M.multitapBuildPayload(cur, ["a0"], SELECTED, false, 250); return cur.a.join(",") === "4,0,0,0"; })(), "build does not modify the device table");

/* ---- CTAP2 CBOR codec (fido2_cbor.js) ---- */
check(C.fido2CborEncode(0).join(",") === "0", "cbor encode 0");
check(C.fido2CborEncode(23).join(",") === "23", "cbor encode 23");
check(C.fido2CborEncode(24).join(",") === "24,24", "cbor encode 24");
check(C.fido2CborEncode(256).join(",") === "25,1,0", "cbor encode 256");
check(C.fido2CborEncode(-7).join(",") === "38", "cbor encode -7");
check(C.fido2CborEncode(true).join(",") === "245", "cbor encode true");
check(C.fido2CborEncode(false).join(",") === "244", "cbor encode false");
check(C.fido2CborEncode(null).join(",") === "246", "cbor encode null");
check(C.fido2CborEncode("none").join(",") === "100,110,111,110,101", "cbor encode text");
check(C.fido2CborEncode(new Uint8Array([1, 2])).join(",") === "66,1,2", "cbor encode byte string");
check(C.fido2CborEncode([1, 2]).join(",") === "130,1,2", "cbor encode array");
check(C.fido2CborEncode({1: 2}).join(",") === "161,1,2", "cbor encode map");

check(C.fido2CborDecode(new Uint8Array([0])) === 0, "cbor decode 0");
check(C.fido2CborDecode(new Uint8Array([0x26])) === -7, "cbor decode -7");
check(C.fido2CborDecode(new Uint8Array([0x64, 110, 111, 110, 101])) === "none", "cbor decode text");
check(C.fido2CborDecode(new Uint8Array([0x42, 1, 2])) instanceof Uint8Array, "cbor decode byte string");
check(C.fido2CborDecode(new Uint8Array([0xF4])) === false, "cbor decode false");
check(C.fido2CborDecode(new Uint8Array([0xF5])) === true, "cbor decode true");
check(C.fido2CborDecode(new Uint8Array([0xF6])) === null, "cbor decode null");

/* A CTAP2 request round-trips: clientDataHash + rp + pubKeyCredParams. */
const ctapReq = {1: new Uint8Array(32).fill(7), 2: {id: "example.com"}, 3: [{alg: -7, type: "public-key"}]};
const ctapBack = C.fido2CborDecode(C.fido2CborEncode(ctapReq));
check(ctapBack[1] instanceof Uint8Array && ctapBack[1].length === 32, "cbor round-trip byte string");
check(ctapBack[2].id === "example.com", "cbor round-trip text map");
check(ctapBack[3][0].alg === -7, "cbor round-trip negative int");
check(ctapBack[3][0].type === "public-key", "cbor round-trip nested map");

/* The CTAP2 builders must use the protocol's numeric parameter keys. */
const makeParams = C.fido2CborMakeCredentialParams(
  "example.com", new Uint8Array(32).fill(7));
const makeBack = C.fido2CborDecode(C.fido2CborEncode(makeParams));
check(makeBack[4] && makeBack[4][0].alg === -7,
  "make-credential pubKeyCredParams uses key 4");
check(makeBack[7] && makeBack[7].rk === false,
  "make-credential options uses key 7");
check(makeBack[5] === undefined, "make-credential does not use key 5");

const assertionParams = C.fido2CborGetAssertionParams(
  "example.com", new Uint8Array(32).fill(7), new Uint8Array(64).fill(9));
check(Object.keys(assertionParams[3][0]).join(",") === "id,type",
  "get-assertion descriptor key order");
const assertionEncoded = C.fido2CborEncode(assertionParams);
check(sequenceIndex(assertionEncoded, C.fido2CborEncode("id")) <
  sequenceIndex(assertionEncoded, C.fido2CborEncode("type")),
  "get-assertion wire descriptor order");

/* What the firmware's authenticatorGetInfo answers, built with explicit
 * map/array heads so the decoder sees the exact byte layout. */
const mapHead = n => [0xa0 | n];
const arrHead = n => [0x80 | n];
const infoRaw = C.fido2CborDecode(new Uint8Array([].concat(
  mapHead(4),
  [0x01], arrHead(2), C.fido2CborEncode("FIDO_2_0"), C.fido2CborEncode("U2F_V2"),
  [0x03], C.fido2CborEncode(new Uint8Array(16)),
  [0x04], mapHead(4), C.fido2CborEncode("rk"), C.fido2CborEncode(false),
  C.fido2CborEncode("up"), C.fido2CborEncode(true),
  C.fido2CborEncode("clientPin"), C.fido2CborEncode(false),
  C.fido2CborEncode("makeCredUvNotRqd"), C.fido2CborEncode(true),
  [0x09], arrHead(3), C.fido2CborEncode("usb"), C.fido2CborEncode("nfc"), C.fido2CborEncode("ble"))));
check(infoRaw[1][0] === "FIDO_2_0" && infoRaw[1][1] === "U2F_V2", "cbor get-info versions");
check(infoRaw[3] instanceof Uint8Array && infoRaw[3].length === 16, "cbor get-info aaguid");
check(infoRaw[4].rk === false && infoRaw[4].up === true, "cbor get-info options");
check(infoRaw[9].join(",") === "usb,nfc,ble", "cbor get-info transports");

check(throws(() => C.fido2CborDecode(new Uint8Array([]))), "cbor decode empty throws");
check(throws(() => C.fido2CborDecode(new Uint8Array([0x42, 1]))), "cbor decode truncated throws");
check(throws(() => C.fido2CborDecode(new Uint8Array([0xc0, 1]))), "cbor decode tag throws");
check(throws(() => C.fido2CborEncode(1.5)), "cbor encode float throws");
check(C.fido2CborFormat(new Uint8Array([0xde, 0xad]), 0) === "h'dead'", "cbor format byte string");
check(C.fido2CborFormat({1: 2}, 0).indexOf("1: 2") >= 0, "cbor format map");

console.log(pass + " checks, " + fail + " failed");
process.exit(fail ? 1 : 0);
