"use strict";
/* fido2_cbor.js -- minimal CBOR (RFC 8949) codec for the CTAP2 commands in the
 * web console. No DOM, no BLE, so it loads in plain node for unit testing.
 *
 * Mirrors software/script/fido2_cbor.py: integers, booleans, null, byte
 * strings (Uint8Array), text strings, arrays and maps. CTAP2 maps use integer
 * keys, so they decode to a plain object keyed by the number.
 *
 * Integers are JavaScript numbers: exact up to 2^53, which covers every
 * length and counter the authenticator uses.
 */

function fido2CborHead(major, value) {
  const v = value >>> 0;
  if (v < 24) return [(major << 5) | v];
  if (v < 0x100) return [(major << 5) | 24, v];
  if (v < 0x10000) return [(major << 5) | 25, (v >> 8) & 0xFF, v & 0xFF];
  if (v < 0x100000000)
    return [(major << 5) | 26, (v >>> 24) & 0xFF, (v >>> 16) & 0xFF, (v >>> 8) & 0xFF, v & 0xFF];
  const out = [(major << 5) | 27];
  for (let i = 7; i >= 0; i--) out.push(Math.floor(v / Math.pow(2, i * 8)) & 0xFF);
  return out;
}

function fido2CborEncode(value) {
  if (value === null || value === undefined) return [0xF6];
  if (typeof value === "boolean") return value ? [0xF5] : [0xF4];
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("only integers can be encoded");
    return value >= 0 ? fido2CborHead(0, value) : fido2CborHead(1, -value - 1);
  }
  if (typeof value === "string") {
    const raw = Array.from(new TextEncoder().encode(value));
    return fido2CborHead(3, raw.length).concat(raw);
  }
  if (value instanceof Uint8Array) {
    return fido2CborHead(2, value.length).concat(Array.from(value));
  }
  if (Array.isArray(value)) {
    let out = fido2CborHead(4, value.length);
    for (const item of value) out = out.concat(fido2CborEncode(item));
    return out;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value);
    let out = fido2CborHead(5, keys.length);
    for (const key of keys) {
      /* CTAP maps are keyed by integers; a numeric object key is encoded as
       * one, everything else as a text string. */
      const k = /^-?\d+$/.test(key) ? Number(key) : key;
      out = out.concat(fido2CborEncode(k)).concat(fido2CborEncode(value[key]));
    }
    return out;
  }
  throw new Error("unsupported CBOR value");
}

function fido2CborMakeCredentialParams(rpId, clientDataHash) {
  return {
    1: clientDataHash,
    2: {id: rpId, name: rpId},
    3: {id: new Uint8Array(32), name: rpId, displayName: rpId},
    4: [{alg: -7, type: "public-key"}],
    7: {rk: false},
  };
}

function fido2CborGetAssertionParams(rpId, clientDataHash, credentialId) {
  return {
    1: rpId,
    2: clientDataHash,
    3: [{id: credentialId, type: "public-key"}],
  };
}

function fido2CborReadHead(bytes, off) {
  if (off >= bytes.length) throw new Error("truncated CBOR");
  const initial = bytes[off++];
  const major = initial >> 5, minor = initial & 0x1F;
  if (minor < 24) return [major, minor, off];
  if (minor === 24) {
    if (off + 1 > bytes.length) throw new Error("truncated CBOR");
    return [major, bytes[off], off + 1];
  }
  if (minor === 25) {
    if (off + 2 > bytes.length) throw new Error("truncated CBOR");
    return [major, (bytes[off] << 8) | bytes[off + 1], off + 2];
  }
  if (minor === 26) {
    if (off + 4 > bytes.length) throw new Error("truncated CBOR");
    const v = bytes[off] * 0x1000000 + (bytes[off + 1] << 16) + (bytes[off + 2] << 8) + bytes[off + 3];
    return [major, v >>> 0, off + 4];
  }
  if (minor === 27) {
    if (off + 8 > bytes.length) throw new Error("truncated CBOR");
    let v = 0;
    for (let i = 0; i < 8; i++) v = v * 256 + bytes[off + i];
    return [major, v, off + 8];
  }
  throw new Error("unsupported CBOR additional information " + minor);
}

function fido2CborDecodeItem(bytes, off) {
  const head = fido2CborReadHead(bytes, off);
  const major = head[0], arg = head[1];
  off = head[2];
  if (major === 0) return [arg, off];
  if (major === 1) return [-1 - arg, off];
  if (major === 2) {
    if (off + arg > bytes.length) throw new Error("truncated byte string");
    return [bytes.slice(off, off + arg), off + arg];
  }
  if (major === 3) {
    if (off + arg > bytes.length) throw new Error("truncated text string");
    return [new TextDecoder().decode(bytes.slice(off, off + arg)), off + arg];
  }
  if (major === 4) {
    const out = [];
    for (let i = 0; i < arg; i++) {
      const r = fido2CborDecodeItem(bytes, off);
      out.push(r[0]);
      off = r[1];
    }
    return [out, off];
  }
  if (major === 5) {
    const out = {};
    for (let i = 0; i < arg; i++) {
      let r = fido2CborDecodeItem(bytes, off);
      const key = r[0];
      off = r[1];
      r = fido2CborDecodeItem(bytes, off);
      out[key] = r[0];
      off = r[1];
    }
    return [out, off];
  }
  if (major === 6) throw new Error("CBOR tags are not supported");
  if (arg === 20) return [false, off];
  if (arg === 21) return [true, off];
  if (arg === 22 || arg === 23) return [null, off];
  throw new Error("unsupported CBOR simple value " + arg);
}

function fido2CborDecode(bytes) {
  if (!bytes || !bytes.length) throw new Error("empty CBOR buffer");
  const buf = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  return fido2CborDecodeItem(buf, 0)[0];
}

/* Render a decoded value for the terminal: byte strings as h'..', maps and
 * arrays over several lines. */
function fido2CborFormat(value, indent) {
  const pad = "    ".repeat(indent || 0);
  if (value instanceof Uint8Array) return "h'" + Array.from(value).map(b => b.toString(16).padStart(2, "0")).join("") + "'";
  if (Array.isArray(value)) {
    if (!value.length) return "[]";
    const lines = ["["];
    for (const item of value) lines.push(pad + "    " + fido2CborFormat(item, (indent || 0) + 1));
    lines.push(pad + "]");
    return lines.join("\n");
  }
  if (value && typeof value === "object") {
    const keys = Object.keys(value);
    if (!keys.length) return "{}";
    const lines = ["{"];
    for (const key of keys) lines.push(pad + "    " + key + ": " + fido2CborFormat(value[key], (indent || 0) + 1));
    lines.push(pad + "}");
    return lines.join("\n");
  }
  return JSON.stringify(value);
}
