#!/usr/bin/env python3
"""Host-side smoke test for the FIDO2 standalone authenticator debug commands.

Assumes the firmware is already flashed and a ChameleonUltra is on --port.
Flashing is deliberately not done here; --skip-flash is a no-op acknowledgement.

Run:
    cd software/script && uv run --project .. python \
        /home/user/chameleonultra/ChameleonUltra/firmware/tools/fido2_smoke.py

Uses the Python CLI modules from software/script plus the already-installed
`cryptography` package for signature checks; no new dependencies.
"""

import argparse
import os
import sys

# Let the script run from any cwd while importing the installed CLI modules.
_SOFTWARE_SCRIPT = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "software", "script"))
if _SOFTWARE_SCRIPT not in sys.path:
    sys.path.insert(0, _SOFTWARE_SCRIPT)

from chameleon_com import ChameleonCom  # noqa: E402
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Wire commands kept numeric so this script also works with older CLI builds.
CMD_GET_APP_VERSION = 1000
CMD_GET_GIT_VERSION = 1017
CMD_SET_MODE = 7001
CMD_TRIGGER = 7006
CMD_DISARM = 7009
CMD_GRANT = 7020
CMD_CTAP = 7021
CMD_CREDS_LIST = 7022
CMD_CREDS_RESET = 7023
CMD_STATUS = 7024
CMD_U2F_APDU = 7025

STATUS_PAR_ERR = 0x60
STATUS_SUCCESS = 0x68
MODE_FIDO2 = 0x11
GATE_UP = 1
GATE_UV = 2
TRANSPORT_DBG = 3
CTAP_OK = 0x00
CTAP_PENDING = 0xFF
AAGUID = b"CHAMELEONFIDO2V1"  # exactly 16 bytes
CLIENT_DATA_HASH = bytes(range(32))
U2F_CHALLENGE = CLIENT_DATA_HASH
U2F_APP_ID = bytes(range(32, 64))  # distinct from the challenge

VERBOSE = False


# ---- minimal CBOR (definite-length, canonical key order) -------------------

def _head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def cbor_encode(value):
    """uint/negint/bytes/text/array/map; keys sorted by canonical encoded bytes."""
    if isinstance(value, bool):  # bool is an int subclass: handle first
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(cbor_encode(v) for v in value)
    if isinstance(value, dict):
        pairs = sorted(((cbor_encode(k), cbor_encode(v)) for k, v in value.items()),
                       key=lambda kv: (len(kv[0]), kv[0]))
        return _head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    raise TypeError(f"cannot CBOR-encode {type(value).__name__}")


class CborError(Exception):
    pass


def cbor_decode(buf, off=0):
    """Tiny recursive reader: returns (value, new_offset); enough for assertions."""
    if off >= len(buf):
        raise CborError("truncated CBOR")
    ib = buf[off]
    off += 1
    major, ai = ib >> 5, ib & 0x1F

    def length():
        nonlocal off
        if ai < 24:
            return ai
        nbytes = {24: 1, 25: 2, 26: 4, 27: 8}.get(ai)
        if nbytes is None:
            raise CborError(f"unsupported CBOR additional info 0x{ai:02X}")
        if off + nbytes > len(buf):
            raise CborError("truncated CBOR length")
        n = int.from_bytes(buf[off:off + nbytes], "big")
        off += nbytes
        return n

    if major == 0:
        return length(), off
    if major == 1:
        return -1 - length(), off
    if major in (2, 3):
        n = length()
        if off + n > len(buf):
            raise CborError("truncated CBOR string")
        raw = buf[off:off + n]
        off += n
        return (raw if major == 2 else raw.decode("utf-8", "replace")), off
    if major == 4:
        arr = []
        for _ in range(length()):
            v, off = cbor_decode(buf, off)
            arr.append(v)
        return arr, off
    if major == 5:
        result = {}
        for _ in range(length()):
            k, off = cbor_decode(buf, off)
            v, off = cbor_decode(buf, off)
            try:
                result[k] = v
            except TypeError:
                pass  # unhashable key: not needed for these assertions
        return result, off
    if major == 6:  # tag: skip, decode the tagged value
        length()
        return cbor_decode(buf, off)
    if major == 7:
        if ai == 20:
            return False, off
        if ai == 21:
            return True, off
        if ai in (22, 23):
            return None, off
    raise CborError(f"unsupported CBOR major type {major} (0x{ib:02X})")


def cbor_one(buf):
    value, off = cbor_decode(buf)
    if off != len(buf):
        raise CborError(f"trailing CBOR bytes after offset {off}")
    return value


# ---- key helpers -----------------------------------------------------------

def cose_p256_pub(auth):
    """Build a P-256 public key from the credentialPublicKey in authData."""
    if len(auth) < 55 or not (auth[32] & 0x40):  # AT flag: attested credential data
        raise ValueError("authData lacks attested credential data")
    off = 37 + 16  # rpIdHash(32) + flags(1) + signCount(4) + aaguid(16)
    cred_id_len = int.from_bytes(auth[off:off + 2], "big")
    off += 2 + cred_id_len
    cose, _ = cbor_decode(auth, off)
    if cose.get(1) != 2 or cose.get(3) != -7 or cose.get(-1) != 1:
        raise ValueError(f"unexpected COSE key: {cose!r}")
    x, y = cose.get(-2), cose.get(-3)
    if not isinstance(x, bytes) or len(x) != 32 or not isinstance(y, bytes) or len(y) != 32:
        raise ValueError(f"bad COSE EC coordinates: {cose!r}")
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"),
        ec.SECP256R1()).public_key()


def u2f_p256_pub(pub65):
    """Build a P-256 key from a U2F uncompressed point (0x04 || X || Y)."""
    if len(pub65) != 65 or pub65[0] != 0x04:
        raise ValueError("bad uncompressed U2F public key")
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(pub65[1:33], "big"), int.from_bytes(pub65[33:], "big"),
        ec.SECP256R1()).public_key()


def der_seq_length(buf, off=0):
    """Return the total byte length of a DER SEQUENCE at off (short or 0x81/0x82)."""
    if off + 1 >= len(buf) or buf[off] != 0x30:
        raise ValueError("expected DER SEQUENCE")
    first = buf[off + 1]
    if first < 0x80:
        n, hdr = first, 2
    elif first in (0x81, 0x82):
        count = first & 0x7F
        if off + 2 + count > len(buf):
            raise ValueError("truncated DER length")
        n, hdr = int.from_bytes(buf[off + 2:off + 2 + count], "big"), 2 + count
    else:
        raise ValueError(f"unsupported DER length form 0x{first:02X}")
    if off + hdr + n > len(buf):
        raise ValueError("truncated DER SEQUENCE")
    return hdr + n


# ---- device helpers --------------------------------------------------------

def payload(resp):
    return bytes(resp.data) if hasattr(resp, "data") else bytes(resp or b"")


def frame_status(resp):
    return getattr(resp, "status", None)


def frame_ok(resp):
    # FIDO2 handlers use 0x68 (STATUS_SUCCESS); accept 0x00 too for older builds.
    return frame_status(resp) in (STATUS_SUCCESS, 0x00)


def status_hex(resp):
    s = frame_status(resp)
    return f"0x{s:02X}" if isinstance(s, int) else str(s)


def send(dev, cmd, data=b"", timeout=5):
    data = bytes(data)
    if VERBOSE:
        print(f"  TX {cmd}: {data.hex()}")
    resp = dev.send_cmd_sync(cmd, data, timeout=timeout)
    if VERBOSE:
        print(f"  RX {cmd}: status={status_hex(resp)} data={payload(resp).hex()}")
    return resp


def ctap(dev, cmd_byte, body=b"", uv=False, pregrant=GATE_UV):
    """Send a CTAP command over DBG (7021) and return (ctap_status, cbor, resp).

    A GRANT sent before the request latches as a one-shot pre-grant, so we do
    that first; if the core instead parks the request (CTAP status 0xFF), we
    grant again and resend the identical request. Both paths are covered.
    """
    request = bytes([TRANSPORT_DBG, 1 if uv else 0, cmd_byte]) + bytes(body)
    if pregrant is not None:
        send(dev, CMD_GRANT, bytes([pregrant]))
    resp = send(dev, CMD_CTAP, request)
    data = payload(resp)
    ctap_status = data[0] if data else CTAP_PENDING
    if ctap_status == CTAP_PENDING:
        send(dev, CMD_GRANT, bytes([GATE_UV if uv else GATE_UP]))
        resp = send(dev, CMD_CTAP, request)
        data = payload(resp)
        ctap_status = data[0] if data else CTAP_PENDING
    return ctap_status, data[1:], resp


# ---- test steps ------------------------------------------------------------

FAILURES = []


def report(name, ok, detail, raw=b""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    if not ok:
        if raw:
            print(f"       raw: {bytes(raw).hex()}")
        FAILURES.append(name)
    return ok


def attempt(name, fn):
    try:
        ok, detail, raw = fn()
    except Exception as exc:  # noqa: BLE001 - a smoke test must report, not crash
        ok, detail, raw = False, f"{type(exc).__name__}: {exc}", b""
    return report(name, ok, detail, raw)


def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description="FIDO2 standalone host smoke test")
    parser.add_argument("--port", default="/dev/ttyACM0", help="serial port (default: /dev/ttyACM0)")
    parser.add_argument("--skip-flash", action="store_true",
                        help="no-op: flashing is done separately; firmware is assumed flashed")
    parser.add_argument("--verbose", action="store_true", help="print every TX/RX frame payload")
    args = parser.parse_args()
    VERBOSE = args.verbose
    if args.skip_flash:
        print("INFO --skip-flash: assuming firmware already flashed; no flash attempted")

    try:
        dev = ChameleonCom().open(args.port)
    except Exception as exc:
        report("1 connect", False, f"cannot open {args.port}: {exc}")
        return 1

    try:
        version = ""
        try:
            app = send(dev, CMD_GET_APP_VERSION)
            d = payload(app)
            if len(d) >= 2:
                version = f"app {d[0]}.{d[1]}"
        except Exception:
            pass
        try:
            git = send(dev, CMD_GET_GIT_VERSION)
            if payload(git):
                version += f" git {payload(git).decode('utf-8', 'replace').strip()}"
        except Exception:
            pass
        report("1 connect", bool(dev.isOpen()),
               f"{args.port} open" + (f", {version}" if version else ", version unavailable"))

        state = {}  # public keys / key handle handed between steps

        def step_reset():
            r = send(dev, CMD_CREDS_RESET)
            return frame_ok(r), f"frame status={status_hex(r)}", payload(r)
        attempt("2 CREDS_RESET", step_reset)

        def step_setup():
            # Spec says 1-byte mode; this firmware build may expect mode+flags (2 bytes).
            r = send(dev, CMD_SET_MODE, bytes([MODE_FIDO2]))
            if frame_status(r) == STATUS_PAR_ERR:
                r = send(dev, CMD_SET_MODE, bytes([MODE_FIDO2, 0x00]))
            if not frame_ok(r):
                return False, f"SET_MODE frame status={status_hex(r)}", payload(r)
            d = payload(r)
            if len(d) >= 2 and d[1] != MODE_FIDO2:
                return False, f"SET_MODE returned mode 0x{d[1]:02X}, expected 0x{MODE_FIDO2:02X}", d
            r = send(dev, CMD_TRIGGER)
            if not frame_ok(r):
                return False, f"TRIGGER frame status={status_hex(r)}", payload(r)
            r = send(dev, CMD_STATUS)
            text = payload(r).decode("utf-8", "replace").strip()
            low = text.lower()
            # This firmware's 7024 text is "gate=NONE,uv=0,creds=N"; FIDO mode is
            # confirmed from the 7001 response above, gate NONE from this text.
            if "gate" not in low or "none" not in low:
                return False, f"STATUS does not report gate NONE: {text!r}", payload(r)
            return True, f"mode=0x{MODE_FIDO2:02X} armed, STATUS={text!r}", payload(r)
        attempt("3 SET_MODE/TRIGGER/STATUS", step_setup)

        def step_get_info():
            ctap_status, cbor, _ = ctap(dev, 0x04, b"", uv=False, pregrant=GATE_UV)
            if ctap_status != CTAP_OK:
                return False, f"CTAP status 0x{ctap_status:02X} (want 0x00)", bytes([ctap_status]) + cbor
            info = cbor_one(cbor)
            versions = info.get(1)
            if not isinstance(versions, list) or "FIDO_2_0" not in versions or "U2F_V2" not in versions:
                return False, f"versions missing FIDO_2_0/U2F_V2: {versions!r}", cbor
            if info.get(3) != AAGUID:
                return False, f"AAGUID={info.get(3)!r}, want {AAGUID!r}", cbor
            opts = info.get(4)
            if not isinstance(opts, dict) or not (
                    opts.get("uv") is True and opts.get("rk") is True and
                    opts.get("up") is True and opts.get("clientPin") is False):
                return False, f"unexpected options map: {opts!r}", cbor
            return True, f"GET_INFO OK, versions={versions}, aaguid={info[3]!r}", cbor
        attempt("4 GET_INFO", step_get_info)

        make_request = cbor_encode({
            1: CLIENT_DATA_HASH,
            2: {"id": "example.com"},
            3: {"id": b"smoke-user-1"},
            4: [{"type": "public-key", "alg": -7}],
            7: {"rk": True, "uv": True},
        })

        def step_make_credential():
            ctap_status, cbor, _ = ctap(dev, 0x01, make_request, uv=True, pregrant=GATE_UV)
            if ctap_status != CTAP_OK:
                return False, f"CTAP status 0x{ctap_status:02X} (want 0x00)", bytes([ctap_status]) + cbor
            result = cbor_one(cbor)
            fmt, auth, att = result.get(1), result.get(2), result.get(3)
            if fmt != "packed" or not isinstance(auth, bytes) or len(auth) < 37 or not isinstance(att, dict):
                return False, f"bad MakeCredential map: fmt={fmt!r}, authData={type(auth).__name__}, attStmt={att!r}", cbor
            alg, sig = att.get("alg"), att.get("sig")
            if alg != -7 or not isinstance(sig, bytes) or not sig:
                return False, f"attStmt alg/sig: alg={alg!r}, sig={type(sig).__name__}", cbor
            pub = cose_p256_pub(auth)
            pub.verify(sig, auth + CLIENT_DATA_HASH, ec.ECDSA(hashes.SHA256()))
            state["ctap_pub"] = pub
            return True, f"packed self-attestation ES256 verified, authData={len(auth)}B", cbor
        attempt("5 MAKE_CREDENTIAL", step_make_credential)

        assert_request = cbor_encode({
            1: "example.com",
            2: CLIENT_DATA_HASH,
            5: {"uv": True},
        })

        def step_get_assertion():
            ctap_status, cbor, _ = ctap(dev, 0x02, assert_request, uv=True, pregrant=GATE_UV)
            if ctap_status != CTAP_OK:
                return False, f"CTAP status 0x{ctap_status:02X} (want 0x00)", bytes([ctap_status]) + cbor
            result = cbor_one(cbor)
            auth, sig = result.get(2), result.get(3)
            if not isinstance(auth, bytes) or len(auth) < 33:
                return False, f"missing/short authData: {auth!r}", cbor
            if not isinstance(sig, bytes) or not sig:
                return False, f"missing signature: {sig!r}", cbor
            flags = auth[32]
            if not (flags & 0x01) or not (flags & 0x04):
                return False, f"authData flags=0x{flags:02X} missing UP(0x01)/UV(0x04)", cbor
            pub = state.get("ctap_pub")
            if pub is None:
                return False, "no credential public key from step 5", cbor
            pub.verify(sig, auth + CLIENT_DATA_HASH, ec.ECDSA(hashes.SHA256()))
            return True, f"authData={len(auth)}B sig={len(sig)}B flags=0x{flags:02X} (UP+UV), ES256 verified", cbor
        attempt("6 GET_ASSERTION", step_get_assertion)

        def step_creds_list():
            r = send(dev, CMD_CREDS_LIST)
            text = payload(r).decode("utf-8", "replace")
            lines = [line for line in text.splitlines() if line.strip()]
            count = sum(1 for line in lines[1:]
                        if len(line.split()) >= 2 and line.split()[1] != "-")
            if not frame_ok(r) or count < 1:
                return False, f"frame status={status_hex(r)}, credentials found={count}", payload(r)
            return True, f"{count} credential(s) listed", payload(r)
        attempt("7 CREDS_LIST", step_creds_list)

        def step_u2f_version():
            r = send(dev, CMD_U2F_APDU, bytes.fromhex("0003000000"))
            data = payload(r)
            if not frame_ok(r) or b"U2F_V2" not in data or data[-2:] != b"\x90\x00":
                return False, f"frame status={status_hex(r)}, want U2F_V2 + 9000", data
            return True, "U2F VERSION -> U2F_V2 9000", data
        attempt("8 U2F VERSION APDU", step_u2f_version)

        def step_u2f_register():
            apdu = bytes.fromhex("0001000040") + U2F_CHALLENGE + U2F_APP_ID
            send(dev, CMD_GRANT, bytes([GATE_UP]))  # 7025 has no pending retry
            r = send(dev, CMD_U2F_APDU, apdu)
            data = payload(r)
            if not frame_ok(r) or len(data) < 78 or data[-2:] != b"\x90\x00":
                return False, f"frame status={status_hex(r)}, want REGISTER data + 9000", data
            body = data[:-2]
            if body[0] != 0x05:
                return False, f"REGISTER reserved byte=0x{body[0]:02X}, want 0x05", data
            pub65, kh_len = body[1:66], body[66]
            if len(pub65) != 65 or len(body) < 67 + kh_len + 8:
                return False, f"short REGISTER body: {len(body)}B, khLen={kh_len}", data
            kh = body[67:67 + kh_len]
            der = body[67 + kh_len:]
            cert_len = der_seq_length(der)
            cert, sig = der[:cert_len], der[cert_len:]
            if not sig:
                return False, "REGISTER body has no DER signature after cert", data
            # REGISTER carries a DER X.509 attestation cert: its key is the batch
            # attestation key, not the returned credential key (used by AUTH).
            att_pub = x509.load_der_x509_certificate(cert).public_key()
            base = b"\x00" + U2F_APP_ID + U2F_CHALLENGE + bytes([kh_len]) + kh + pub65
            att_pub.verify(sig, base, ec.ECDSA(hashes.SHA256()))
            pub = u2f_p256_pub(pub65)
            state["u2f_pub"], state["u2f_kh"] = pub, kh
            return True, f"U2F REGISTER ES256 verified with attestation cert, kh={kh_len}B", data
        attempt("9 U2F REGISTER", step_u2f_register)

        def step_u2f_authenticate():
            pub, kh = state.get("u2f_pub"), state.get("u2f_kh")
            if pub is None or not kh:
                return False, "no key handle from U2F REGISTER", b""
            apdu_data = U2F_CHALLENGE + U2F_APP_ID + bytes([len(kh)]) + kh
            apdu = bytes.fromhex("00020300") + bytes([len(apdu_data)]) + apdu_data
            send(dev, CMD_GRANT, bytes([GATE_UP]))  # P1=0x03 needs UP
            r = send(dev, CMD_U2F_APDU, apdu)
            data = payload(r)
            if not frame_ok(r) or len(data) < 17 or data[-2:] != b"\x90\x00":
                return False, f"frame status={status_hex(r)}, want AUTH data + 9000", data
            body = data[:-2]
            flags, counter = body[0], int.from_bytes(body[1:5], "big")
            sig = body[5:]
            if not (flags & 0x01):
                return False, f"AUTH flags=0x{flags:02X} missing UP(0x01)", data
            pub.verify(sig, U2F_APP_ID + bytes([flags]) + body[1:5] + U2F_CHALLENGE,
                       ec.ECDSA(hashes.SHA256()))
            return True, f"U2F AUTH ES256 verified, flags=0x{flags:02X} counter={counter}", data
        attempt("10 U2F AUTHENTICATE", step_u2f_authenticate)

        def step_disarm():
            r = send(dev, CMD_DISARM)
            if not frame_ok(r):
                return False, f"frame status={status_hex(r)}", payload(r)
            return True, f"frame status={status_hex(r)}", payload(r)
        attempt("11 DISARM", step_disarm)
    finally:
        dev.close()

    if FAILURES:
        print(f"FAILED steps ({len(FAILURES)}): " + ", ".join(FAILURES))
        return 1
    print("All 11 steps passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
