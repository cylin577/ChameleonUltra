"""cli_hw_u2f - drive the FIDO2/U2F standalone mode (hw u2f ...)."""

import argparse

import fido2_cbor
from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, hw

hw_u2f = hw.subgroup("u2f", "FIDO2/U2F standalone mode")

# CTAP2 command bytes (see CTAP2.1 §6).
CTAP_MAKE_CREDENTIAL = 0x01
CTAP_GET_ASSERTION = 0x02
CTAP_GET_INFO = 0x04

# CTAP2 status codes we bother naming.
CTAP_STATUS = {
    0x00: "ok",
    0x01: "invalid command",
    0x03: "invalid length",
    0x12: "invalid CBOR",
    0x14: "missing parameter",
    0x26: "unsupported algorithm",
    0x27: "operation denied",
    0x2B: "unsupported option",
    0x2D: "keepalive cancel",
    0x2E: "no credentials",
}


def _load_priv_scalar(path: str) -> bytes:
    """Return the 32-byte big-endian P-256 private scalar from a PEM or DER key."""
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_der_private_key)
    raw = open(path, "rb").read()
    try:
        k = load_pem_private_key(raw, password=None)
    except ValueError:
        k = load_der_private_key(raw, password=None)
    return k.private_numbers().private_value.to_bytes(32, "big")


def _load_cert_der(path: str) -> bytes:
    """Return the certificate as DER bytes, accepting PEM or DER input."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    raw = open(path, "rb").read()
    cert = x509.load_pem_x509_certificate(raw) if b"-----BEGIN" in raw \
        else x509.load_der_x509_certificate(raw)
    return cert.public_bytes(Encoding.DER)


@hw_u2f.command("set-attestation")
class HWU2fSetAttestation(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = ("Provision the U2F attestation key + cert into FDS "
                              "(no recompile). Accepts PEM or DER.")
        parser.add_argument("-k", "--key", required=True, metavar="<file>",
                            help="P-256 attestation private key (PEM or DER)")
        parser.add_argument("-c", "--cert", required=True, metavar="<file>",
                            help="attestation certificate (PEM or DER)")
        parser.epilog = ("example:\n"
                         "  firmware/tools/gen_u2f_attestation.sh   # or your own openssl key+cert\n"
                         "  hw u2f set-attestation -k att.key -c att.crt")
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            priv = _load_priv_scalar(args.key)
            cert = _load_cert_der(args.cert)
        except ImportError:
            print(" - Needs the 'cryptography' package: pip install cryptography")
            return
        except Exception as e:
            print(f" - Could not parse key/cert: {e}")
            return
        if len(cert) > 512:
            print(f" - Cert is {len(cert)} bytes; firmware cap is 512. Use a smaller cert.")
            return
        self.cmd.u2f_set_attestation(priv, cert)
        print(f" - Provisioned: 32-byte key + {len(cert)}-byte cert. Re-arm u2f to apply.")


# --------------------------------------------------------------------------
# CTAP2 helpers
# --------------------------------------------------------------------------
def _hex(value: str, name: str, length: int = 0) -> bytes:
    """Parse a hex string into bytes; `length` is the required byte count."""
    try:
        raw = bytes.fromhex(value.replace(" ", "").replace(":", ""))
    except ValueError:
        raise ValueError(f"{name} is not valid hex") from None
    if length and len(raw) != length:
        raise ValueError(f"{name} must be {length} bytes ({length * 2} hex chars), "
                         f"got {len(raw)}")
    return raw


def _fmt(value, indent: int = 0) -> str:
    """Render a decoded CBOR value for the terminal."""
    pad = "    " * indent
    if isinstance(value, bytes):
        return f"h'{value.hex()}'"
    if isinstance(value, dict):
        lines = ["{"]
        for key, item in value.items():
            lines.append(f"{pad}    {key}: {_fmt(item, indent + 1)}")
        lines.append(pad + "}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = ["["]
        for item in value:
            lines.append(f"{pad}    {_fmt(item, indent + 1)}")
        lines.append(pad + "]")
        return "\n".join(lines)
    return repr(value)


def _run_ctap(unit, request: bytes) -> None:
    """Send a CTAP request to the device and print the answer."""
    try:
        response = unit.cmd.fido2_ctap(request)
    except Exception as e:
        print(f" - CTAP request failed: {e}")
        return
    if not response:
        print(" - Empty CTAP response.")
        return
    status = response[0]
    print(f" - CTAP status: 0x{status:02x} ({CTAP_STATUS.get(status, 'unknown')})")
    if len(response) == 1:
        return
    payload = response[1:]
    try:
        decoded = fido2_cbor.decode(payload)
    except fido2_cbor.CBORError as e:
        print(f" - Response payload ({len(payload)} bytes, not CBOR: {e})")
        print(f"   h'{payload.hex()}'")
        return
    print(" - Response:")
    print(_fmt(decoded, 1))


def _build_request(args) -> bytes:
    """Build the raw CTAP request (command byte + CBOR params) from the args."""
    if args.raw:
        params = _hex(args.raw, "--raw")
    elif args.cmd == "make-credential":
        if not args.rp_id:
            raise ValueError("--rp-id is required for make-credential")
        if not args.client_data_hash:
            raise ValueError("--client-data-hash is required for make-credential")
        params = fido2_cbor.encode({
            1: _hex(args.client_data_hash, "--client-data-hash", 32),
            2: {"id": args.rp_id, "name": args.rp_id},
            3: {"id": bytes(32), "name": args.rp_id, "displayName": args.rp_id},
            4: [{"alg": -7, "type": "public-key"}],     # ES256
            7: {"rk": False},
        })
    elif args.cmd == "get-assertion":
        if not args.rp_id:
            raise ValueError("--rp-id is required for get-assertion")
        if not args.client_data_hash:
            raise ValueError("--client-data-hash is required for get-assertion")
        if not args.cred_id:
            raise ValueError("--cred-id is required for get-assertion")
        params = fido2_cbor.encode({
            1: args.rp_id,
            2: _hex(args.client_data_hash, "--client-data-hash", 32),
            3: [{"id": _hex(args.cred_id, "--cred-id", 64),
                 "type": "public-key"}],
        })
    else:
        params = b""
    return bytes([{
        "get-info": CTAP_GET_INFO,
        "make-credential": CTAP_MAKE_CREDENTIAL,
        "get-assertion": CTAP_GET_ASSERTION,
    }[args.cmd]]) + params


@hw_u2f.command("get-info")
class HWU2fGetInfo(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = ("Send CTAP2 authenticatorGetInfo to the device's "
                              "FIDO2 authenticator (the u2f mode must be armed).")
        return parser

    def on_exec(self, args: argparse.Namespace):
        _run_ctap(self, bytes([CTAP_GET_INFO]))


@hw_u2f.command("ctap")
class HWU2fCtap(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = ("Send a CTAP2 command to the device's FIDO2 "
                              "authenticator (the u2f mode must be armed).")
        parser.add_argument("--cmd", default="get-info",
                            choices=["get-info", "make-credential", "get-assertion"],
                            help="CTAP2 command to send (default: get-info)")
        parser.add_argument("--rp-id", help="relying party id (domain name)")
        parser.add_argument("--client-data-hash",
                            help="client data hash, 32 bytes hex")
        parser.add_argument("--cred-id",
                            help="credential id, 64 bytes hex (get-assertion)")
        parser.add_argument("--raw",
                            help="raw CBOR parameters, hex (replaces the built ones)")
        parser.epilog = ("examples:\n"
                         "  hw u2f ctap --cmd get-info\n"
                         "  hw u2f ctap --cmd make-credential --rp-id example.com \\\n"
                         "      --client-data-hash 000102030405060708090a0b0c0d0e0f"
                         "101112131415161718191a1b1c1d1e1f\n"
                         "  hw u2f ctap --cmd get-assertion --rp-id example.com \\\n"
                         "      --client-data-hash <64 hex chars> --cred-id <128 hex chars>")
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            request = _build_request(args)
        except ValueError as e:
            print(f" - {e}")
            return
        _run_ctap(self, request)
