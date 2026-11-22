"use strict";
/* Node-only tests for the amiibo command surface (CMD 1069..1073):
 * pure request/response helpers plus static checks that the web console
 * actually wires up names, hints, buttons and controls. No device needed. */
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const src = fs.readFileSync(path.join(__dirname, "..", "amiibo.js"), "utf8");
const ctx = {};
vm.createContext(ctx);
vm.runInContext(src + "\n;globalThis.__a = {" +
  "AMIIBO_RETAIL_KEY_SIZE, AMIIBO_KEYS_PAYLOAD_SIZE, AMIIBO_UID_SIZE, " +
  "AMIIBO_STATUS_NAMES, AMIIBO_VERIFY_REASON_NAMES, " +
  "amiiboBuildKeyUpload, amiiboBuildRefreshUid, amiiboBuildAutoRefreshSet, " +
  "amiiboParseKeyUpload, amiiboParseRefreshUid, amiiboParseAutoRefreshStatus, amiiboParseVerifySlot, " +
  "amiiboUidHex, amiiboStatusName, amiiboFormatKeyUpload, amiiboFormatRefreshUid, " +
  "amiiboFormatAutoRefreshStatus, amiiboFormatVerifySlot};", ctx);
const A = ctx.__a;

let pass = 0, fail = 0;
function check(cond, msg) {
  if (cond) { pass++; } else { fail++; console.error("FAIL:", msg); }
}
function throws(fn) {
  try { fn(); return false; } catch (e) { return true; }
}
const frame = (data, status) => ({status: status === undefined ? 0x68 : status, data: data || []});

/* ---- constants / names ---- */
check(A.AMIIBO_RETAIL_KEY_SIZE === 80 && A.AMIIBO_KEYS_PAYLOAD_SIZE === 160, "retail key sizes");
check(A.AMIIBO_UID_SIZE === 7, "UID size");
check(A.AMIIBO_STATUS_NAMES[0x76] === "AMIIBO_KEYS_MISSING" &&
      A.AMIIBO_STATUS_NAMES[0x7A] === "AMIIBO_UID_FAIL", "STATUS_AMIIBO_* names");
check(A.AMIIBO_VERIFY_REASON_NAMES[0] === "valid" &&
      A.AMIIBO_VERIFY_REASON_NAMES[6] === "other", "verify reason names");

/* ---- request builders ---- */
const keyPayload = Array.from({length: 160}, (_, i) => (i * 37 + 11) & 255);
keyPayload[0] = 0xDE; keyPayload[1] = 0xAD; keyPayload[2] = 0xBE; keyPayload[3] = 0xEF;
check(A.amiiboBuildKeyUpload(keyPayload).length === 160, "build 160-byte key upload");
check(A.amiiboBuildKeyUpload(keyPayload)[0] === 0xDE, "builder copies key bytes, not the live array");
check(A.amiiboBuildKeyUpload([]).length === 0, "empty upload = clear keys");
check(throws(() => A.amiiboBuildKeyUpload(new Array(159).fill(0))), "short key payload throws");
check(throws(() => A.amiiboBuildKeyUpload(new Array(161).fill(0))), "long key payload throws");
check(A.amiiboBuildRefreshUid(false).join(",") === "0", "refresh without persist");
check(A.amiiboBuildRefreshUid(true).join(",") === "1", "refresh with persist");
check(A.amiiboBuildAutoRefreshSet(true, false).join(",") === "1,0", "arm without persist");
check(A.amiiboBuildAutoRefreshSet(true, true).join(",") === "1,1", "arm with persist");
check(A.amiiboBuildAutoRefreshSet(false, true).join(",") === "0,1", "disarm ignores persist");

/* ---- response parsers ---- */
const uploaded = A.amiiboParseKeyUpload(frame([]), false);
const cleared = A.amiiboParseKeyUpload(frame([]), true);
check(uploaded.ok && !uploaded.cleared, "parse successful upload");
check(cleared.ok && cleared.cleared, "parse successful clear");
check(!A.amiiboParseKeyUpload(frame([], 0x77), false).ok, "parse rejected keys");
check(A.amiiboParseKeyUpload(frame([], 0x70), false).status === 0x70, "parse flash-write failure status");

const refreshed = A.amiiboParseRefreshUid(frame([1,2,3,4,5,6,7, 8,9,10,11,12,13,14]));
check(refreshed.oldUid.join(",") === "1,2,3,4,5,6,7", "parse old UID");
check(refreshed.newUid.join(",") === "8,9,10,11,12,13,14", "parse new UID");
check(throws(() => A.amiiboParseRefreshUid(frame([1,2,3]))), "short UID refresh reply throws");

const snap = [];
snap[0] = 1; snap[1] = 2; snap[2] = 200; snap[3] = 1;
snap[4] = 0x77; snap[5] = 0x00; /* u16 LE status */
for (let i = 0; i < 7; i++) snap[6 + i] = i + 1;
for (let i = 0; i < 7; i++) snap[13 + i] = i + 11;
snap[20] = 0x85; /* PWD_AUTH seen + 5 READ/FAST_READ */
const st = A.amiiboParseAutoRefreshStatus(frame(snap));
check(st.enabled === true && st.armedSlot === 2 && st.scanCount === 200 && st.lastOk === true,
  "parse status header");
check(st.status === 0x77, "parse status u16 LE");
check(st.oldUid.join(",") === "1,2,3,4,5,6,7", "parse status old UID");
check(st.newUid.join(",") === "11,12,13,14,15,16,17", "parse status new UID");
check(st.activity.pwdAuth === true && st.activity.readCount === 5, "parse status activity byte");
const stHigh = snap.slice(); stHigh[5] = 0x01;
check(A.amiiboParseAutoRefreshStatus(frame(stHigh)).status === 0x177, "parse status u16 LE high byte");
const stQuiet = snap.slice(); stQuiet[0] = 0; stQuiet[20] = 0x03;
const quiet = A.amiiboParseAutoRefreshStatus(frame(stQuiet));
check(quiet.enabled === false && !quiet.activity.pwdAuth && quiet.activity.readCount === 3,
  "parse disarmed / no PWD_AUTH");
check(throws(() => A.amiiboParseAutoRefreshStatus(frame(new Array(20).fill(0)))), "short status throws");

const good = A.amiiboParseVerifySlot(frame([1, 0, 4,1,2,3,4,5,6]));
check(good.valid === true && good.reason === 0 && good.reasonName === "valid", "parse valid slot");
check(good.uid.join(",") === "4,1,2,3,4,5,6", "parse verified UID");
const bad = A.amiiboParseVerifySlot(frame([0, 3, 0,0,0,0,0,0,0]));
check(bad.valid === false && bad.reasonName === "tag HMAC mismatch", "parse invalid reason");
check(A.amiiboParseVerifySlot(frame([0, 99, 0,0,0,0,0,0,0])).reasonName === "reason 99", "unknown reason is safe");
check(throws(() => A.amiiboParseVerifySlot(frame([1, 0]))), "short verify reply throws");

/* ---- safe display (never retail key bytes) ---- */
check(A.amiiboUidHex([0x04,0xA2,0xB3,0xC4,0xD5,0xE6,0xF7]) === "04 A2 B3 C4 D5 E6 F7", "UID hex format");
check(throws(() => A.amiiboUidHex([1,2])), "short UID format throws");
check(A.amiiboStatusName(0x77) === "AMIIBO_KEYS_INVALID", "status name formatting");
const upMsg = A.amiiboFormatKeyUpload(uploaded);
const clrMsg = A.amiiboFormatKeyUpload(cleared);
check(upMsg === "Retail keys uploaded and persisted." && clrMsg === "Device retail keys cleared.",
  "upload/clear messages");
check(A.amiiboFormatKeyUpload(A.amiiboParseKeyUpload(frame([], 0x78), false)) ===
      "Failed: device status AMIIBO_KEYS_FAIL", "failure message shows only a status name");
const keyHex = keyPayload.map(b => b.toString(16).padStart(2, "0").toUpperCase()).join("");
check(upMsg.indexOf("DEADBEEF") === -1 && upMsg.indexOf(keyHex) === -1, "upload message never shows key bytes");
let buildErr = "";
try { A.amiiboBuildKeyUpload(keyPayload.slice(1)); } catch (e) { buildErr = e.message; }
check(buildErr.indexOf("DEADBEEF") === -1 && buildErr.indexOf(keyHex) === -1, "length error never shows key bytes");
const refMsg = A.amiiboFormatRefreshUid(refreshed);
check(refMsg.includes("Old UID: 01 02 03 04 05 06 07") && refMsg.includes("New UID: 08 09 0A 0B 0C 0D 0E"),
  "refresh display shows both UIDs");
const stMsg = A.amiiboFormatAutoRefreshStatus(st);
check(stMsg.includes("Auto-refresh: armed") && stMsg.includes("Armed slot: 2") &&
      stMsg.includes("Field scans: 200") && stMsg.includes("AMIIBO_KEYS_INVALID"),
  "status display fields");
check(stMsg.includes("PWD_AUTH seen") && stMsg.includes("READ/FAST_READ 5"), "status activity display");
check(A.amiiboFormatVerifySlot(good).includes("Slot verify: VALID (valid)"), "verify display valid");
check(A.amiiboFormatVerifySlot(bad).includes("INVALID (tag HMAC mismatch)"), "verify display invalid");

/* ---- web console wiring (static checks: fullcmd.js cannot run in node) ---- */
const fullcmdSrc = fs.readFileSync(path.join(__dirname, "..", "fullcmd.js"), "utf8");
const cuMatch = fullcmdSrc.match(/const CU = (\{[\s\S]*?\n\});/);
check(!!cuMatch, "fullcmd.js declares CU");
if (cuMatch) {
  const cuCtx = {};
  vm.createContext(cuCtx);
  const CU = vm.runInContext("(" + cuMatch[1] + ")", cuCtx);
  const expected = {
    AMIIBO_UPLOAD_KEYS:1069, AMIIBO_REFRESH_UID:1070, AMIIBO_AUTO_REFRESH_SET:1071,
    AMIIBO_AUTO_REFRESH_GET:1072, AMIIBO_VERIFY_SLOT:1073,
  };
  for (const name of Object.keys(expected))
    check(CU[name] === expected[name], "CU." + name + " = " + expected[name]);
}
check(fullcmdSrc.includes("Object.assign(STATUS_NAMES, AMIIBO_STATUS_NAMES)"),
  "fullcmd.js merges STATUS_AMIIBO_* names");
for (const name of ["AMIIBO_UPLOAD_KEYS", "AMIIBO_REFRESH_UID", "AMIIBO_AUTO_REFRESH_SET",
                    "AMIIBO_AUTO_REFRESH_GET", "AMIIBO_VERIFY_SLOT"])
  check(fullcmdSrc.includes('"' + name + '":'), "shell hint for " + name);
for (const id of ["d_amiiboUploadKeys", "d_amiiboClearKeys", "d_amiiboRefreshNow",
                  "d_amiiboArmApply", "d_amiiboArmStatus", "d_amiiboVerify"])
  check(fullcmdSrc.includes('wire("' + id + '"'), "fullcmd.js wires " + id);

const capsSrc = fs.readFileSync(path.join(__dirname, "..", "button_capabilities.js"), "utf8");
for (const id of ["d_amiiboUploadKeys", "d_amiiboClearKeys", "d_amiiboRefreshNow",
                  "d_amiiboArmApply", "d_amiiboArmStatus", "d_amiiboVerify"])
  check(capsSrc.includes('"' + id + '": ["AMIIBO_'), "button_capabilities.js gates " + id);

const htmlSrc = fs.readFileSync(path.join(__dirname, "..", "phreakbyte.html"), "utf8");
for (const id of ["d_amiiboKeyFile", "d_amiiboUploadKeys", "d_amiiboClearKeys",
                  "d_amiiboRefreshNow", "d_amiiboRefreshPersist", "d_amiiboArmEnable",
                  "d_amiiboArmPersist", "d_amiiboArmApply", "d_amiiboArmStatus",
                  "d_amiiboVerify", "d_amiiboResult"])
  check(htmlSrc.includes('id="' + id + '"'), "phreakbyte.html has control " + id);
check(htmlSrc.indexOf('<script src="amiibo.js') < htmlSrc.indexOf('<script src="fullcmd.js'),
  "amiibo.js loads before fullcmd.js");

console.log(pass + " checks, " + fail + " failed");
process.exit(fail ? 1 : 0);
