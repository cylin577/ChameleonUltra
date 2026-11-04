#!/usr/bin/env python3
"""Verify Nordic DFU (nrfutil) packages against the rules the bootloader enforces.

The bootloader in firmware/bootloader is the authority:
  * The init packet hash is stored byte-reversed (little-endian) - nrfutil does
    this on purpose. nrf_dfu_validation_hash_ok() reverses the 32 stored bytes
    before comparing them with the big-endian SHA256 of the received image, so
    a package that stores a plain digest fails with VerificationFailed (0x0C).
  * The 64-byte ECDSA signature stores r and s byte-reversed; the bootloader
    reverses each half again before verifying it (double_swap_endian).
  * The bootloader only trusts the public key compiled into
    firmware/bootloader/src/dfu_public_key.c, so the signing key must match it.

Modes: --check ZIP... | --rule modern|legacy | --legacy OUT.zip IN.zip
       --key PATH | --bootloader-key PATH | --force. Standard library plus openssl only.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_KEY = REPO_ROOT / "resource" / "dfu_key" / "chameleon.pem"
DEFAULT_BOOTLOADER_KEY = REPO_ROOT / "firmware" / "bootloader" / "src" / "dfu_public_key.c"
FW_TYPES = {0: "APPLICATION", 1: "SOFTDEVICE", 2: "BOOTLOADER", 3: "SOFTDEVICE_BOOTLOADER"}


class DfuError(Exception):
    """Anything that makes a package unusable or unverifiable."""


class KeyUnreadable(DfuError):
    """A key file (or openssl itself) cannot be read at all."""


def first_line(text):
    """First non-empty line of a tool message, so errors stay one line."""
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


# --- minimal protobuf reader (varint + length-delimited is all nrfutil emits) ---

def read_varint(buf, pos):
    value = shift = 0
    while True:
        if pos >= len(buf):
            raise DfuError("truncated varint")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def encode_varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | 0x80 if value else byte)
        if not value:
            return bytes(out)


def parse_fields(buf):
    """Return {field_number: [(wire_type, value, value_offset), ...]}."""
    fields = {}
    pos = 0
    while pos < len(buf):
        key, pos = read_varint(buf, pos)
        field_no, wire = key >> 3, key & 0x07
        offset = pos
        if wire == 0:
            value, pos = read_varint(buf, pos)
        elif wire == 2:
            length, pos = read_varint(buf, pos)
            offset = pos
            value = buf[pos:pos + length]
            if len(value) != length:
                raise DfuError("truncated length-delimited field")
            pos += length
        else:
            raise DfuError("unsupported protobuf wire type %d" % wire)
        fields.setdefault(field_no, []).append((wire, value, offset))
    return fields


def one(fields, number, default=None):
    """First value of a field, or default when the field is absent."""
    values = fields.get(number)
    return values[0][1] if values else default


def parse_dat(data):
    """Parse an init packet into a dict with everything the checks need."""
    packet = parse_fields(data)
    signed = one(packet, 2)
    if signed is None:
        raise DfuError("packet carries no signed_command (unsigned package)")
    signed_fields = parse_fields(signed)
    command = one(signed_fields, 1)
    signature = one(signed_fields, 3)
    if command is None or signature is None:
        raise DfuError("signed_command is missing command or signature")
    command_fields = parse_fields(command)
    init = one(command_fields, 2)
    if init is None:
        raise DfuError("command carries no init payload")
    init_fields = parse_fields(init)

    sd_req = []
    for wire, value, _offset in init_fields.get(3, []):
        if wire == 0:
            sd_req.append(value)
        else:  # packed
            pos = 0
            while pos < len(value):
                number, pos = read_varint(value, pos)
                sd_req.append(number)

    hash_bytes, hash_type, hash_span = b"", 0, None
    hash_message = one(init_fields, 8)
    if hash_message is not None:
        hash_fields = parse_fields(hash_message)
        hash_type = one(hash_fields, 1)
        for _wire, value, offset in hash_fields.get(2, []):
            hash_bytes = value
            # Span of the digest inside the init bytes: needed to patch the hash
            # in place when generating a legacy package.
            base = init_fields[8][0][2]
            hash_span = (base + offset, base + offset + len(value))
            break

    return {"init": init, "signature": signature, "signature_type": one(signed_fields, 2),
            "op_code": one(command_fields, 1, 0),
            "hw_version": one(init_fields, 2), "sd_req": sd_req, "type": one(init_fields, 4),
            "sd_size": one(init_fields, 5), "bl_size": one(init_fields, 6),
            "app_size": one(init_fields, 7), "hash": hash_bytes, "hash_type": hash_type,
            "hash_span": hash_span,
            "boot_validation": [v for _w, v, _o in init_fields.get(10, [])]}


# --- keys and signatures (openssl CLI) ---

def run_openssl(args, stdin=None):
    try:
        return subprocess.run(["openssl"] + args, input=stdin, capture_output=True)
    except FileNotFoundError:
        raise KeyUnreadable("openssl CLI not found")


def public_key(key_path, directory):
    """Return (X||Y bytes, PEM path) of the EC key in key_path."""
    proc = run_openssl(["ec", "-in", str(key_path), "-pubout", "-outform", "DER"])
    if proc.returncode != 0:
        raise KeyUnreadable("cannot read %s: %s"
                            % (key_path, first_line(proc.stderr.decode(errors="replace"))))
    der = proc.stdout
    # SubjectPublicKeyInfo ends with the uncompressed point 04 || X || Y.
    if len(der) < 65 or der[-65] != 0x04:
        raise KeyUnreadable("unexpected public key DER from %s" % key_path)
    pem = Path(directory) / "pub.pem"
    proc = run_openssl(["ec", "-in", str(key_path), "-pubout", "-out", str(pem)])
    if proc.returncode != 0:
        raise KeyUnreadable("cannot read %s: %s"
                            % (key_path, first_line(proc.stderr.decode(errors="replace"))))
    return der[-64:], pem


def bootloader_public_key(path):
    """Return X||Y of the public key compiled into the bootloader."""
    try:
        text = Path(path).read_text()
    except OSError as exc:
        raise KeyUnreadable("cannot read %s: %s" % (path, exc))
    match = re.search(r"pk\[\s*\d+\s*\]\s*=\s*\{(.*?)\}", text, re.S)
    if not match:
        raise KeyUnreadable("no public key array found in %s" % path)
    data = bytes(int(h, 16) for h in re.findall(r"0x([0-9a-fA-F]{2})", match.group(1)))
    if len(data) != 64:
        raise KeyUnreadable("expected 64 key bytes in %s, got %d" % (path, len(data)))
    # The bootloader stores each 32-byte half byte-reversed (little-endian).
    return data[:32][::-1] + data[32:][::-1]


def der_encode_signature(r, s):
    """DER SEQUENCE of two INTEGERs, the way openssl writes an ECDSA signature."""
    def integer(value):
        value = value.lstrip(b"\x00") or b"\x00"
        if value[0] & 0x80:
            value = b"\x00" + value
        return b"\x02" + bytes([len(value)]) + value

    body = integer(r) + integer(s)
    return b"\x30" + bytes([len(body)]) + body


def der_decode_signature(der):
    """Return (r, s) from the DER signature openssl produced (short form only)."""
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise DfuError("unexpected DER signature")
    pos, values = 2, []
    for _ in range(2):
        if der[pos] != 0x02:
            raise DfuError("unexpected DER signature")
        length = der[pos + 1]
        values.append(int.from_bytes(der[pos + 2:pos + 2 + length], "big"))
        pos += 2 + length
    if any(value >> 256 for value in values):
        raise DfuError("signature component out of range")
    return values[0].to_bytes(32, "big"), values[1].to_bytes(32, "big")


def verify_signature(pub_pem, init_bytes, signature, directory):
    """ECDSA-P256-SHA256 over the raw init bytes, in bootloader byte order."""
    if len(signature) != 64:
        return False, "signature is %d bytes, expected 64" % len(signature)
    raw = signature[:32][::-1] + signature[32:][::-1]
    der_path = Path(directory) / "sig.der"
    der_path.write_bytes(der_encode_signature(raw[:32], raw[32:]))
    proc = run_openssl(["dgst", "-sha256", "-verify", str(pub_pem), "-signature", str(der_path)],
                       stdin=init_bytes)
    detail = first_line(proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace"))
    return proc.returncode == 0, detail


def sign_init(init_bytes, key_path):
    """Sign the init bytes and return the 64-byte bootloader-order signature."""
    proc = run_openssl(["dgst", "-sha256", "-sign", str(key_path)], stdin=init_bytes)
    if proc.returncode != 0:
        raise DfuError("openssl signing failed: %s"
                       % first_line(proc.stderr.decode(errors="replace")))
    r, s = der_decode_signature(proc.stdout)
    # The bootloader reverses each 32-byte half before verifying.
    return r[::-1] + s[::-1]


# --- package layout ---

def load_manifest(zf):
    """Return the manifest. Every nrfutil package has one - a missing manifest
    is a broken package, not an empty manifest."""
    if "manifest.json" not in zf.namelist():
        raise DfuError("manifest.json is missing from the package")
    try:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8")).get("manifest", {})
    except (ValueError, UnicodeDecodeError) as exc:
        raise DfuError("manifest.json is not valid JSON: %s" % exc)
    if not manifest:
        raise DfuError("manifest.json has no manifest section")
    return manifest


def manifest_pairs(manifest):
    """Return [(section, spec), ...] for every image in the manifest."""
    return [(section, spec) for section, spec in manifest.items() if isinstance(spec, dict)]


def manifest_spec_for_dat(manifest, dat_name):
    """Return the manifest section that owns dat_name, or an empty dict."""
    for _section, spec in manifest_pairs(manifest):
        if spec.get("dat_file") == dat_name:
            return spec
    return {}


def covered_bin_names(names, manifest):
    """Return the .bin files that a .dat init packet covers."""
    covered = set()
    for name in names:
        if name.endswith(".dat"):
            spec = manifest_spec_for_dat(manifest, name)
            covered.add(spec.get("bin_file") or name[:-4] + ".bin")
    return covered


def build_dat(init_bytes, signature):
    """Rebuild an init packet with the exact layout nrfutil produces."""
    command = b"\x08\x01" + b"\x12" + encode_varint(len(init_bytes)) + init_bytes
    signed = (b"\x0a" + encode_varint(len(command)) + command +
              b"\x10\x00" + b"\x1a" + encode_varint(len(signature)) + signature)
    return b"\x12" + encode_varint(len(signed)) + signed


def check_sizes(packet, image_size):
    """Compare the init packet sizes with the image size."""
    ftype = packet["type"]
    if ftype == 0:
        expected, name = packet["app_size"], "app_size"
    elif ftype == 1:
        expected, name = packet["sd_size"], "sd_size"
    elif ftype == 2:
        expected, name = packet["bl_size"], "bl_size"
    elif ftype == 3:
        if packet["sd_size"] is None or packet["bl_size"] is None:
            return False, "sd_size/bl_size missing"
        expected, name = packet["sd_size"] + packet["bl_size"], "sd_size+bl_size"
    else:
        return True, "no size field for this firmware type"
    if expected is None:
        return False, "%s missing" % name
    if expected != image_size:
        return False, "%s=%d but image is %d bytes" % (name, expected, image_size)
    return True, "%s=%d" % (name, expected)


# --- checking ---

def check_dat(zf, name, manifest, rule, key_ok, pem_path, directory, reasons):
    """Check one .dat member against its .bin. Returns the parsed packet."""
    try:
        packet = parse_dat(zf.read(name))
    except DfuError as exc:
        reasons.append("%s: %s" % (name, exc))
        print("  %-24s FAIL %s" % (name, exc))
        return None
    results = []
    spec = manifest_spec_for_dat(manifest, name)
    bin_name = spec.get("bin_file") or name[:-4] + ".bin"
    if bin_name not in zf.namelist():
        reasons.append("%s: image %s is missing from the package" % (name, bin_name))
        results.append("FAIL missing image %s" % bin_name)
        print("  %-24s %s" % (name, " | ".join(results)))
        return packet
    # build_dat() can only emit ECDSA_P256_SHA256, so anything else is refused.
    if packet["signature_type"] != 0:
        reasons.append("SIGNATURE TYPE %s: %s is not ECDSA_P256_SHA256"
                       % (packet["signature_type"], name))
        results.append("SIGNATURE TYPE %s unsupported" % packet["signature_type"])
        print("  %-24s %s" % (name, " | ".join(results)))
        return packet
    # The DFU protocol defines exactly one command, DFU_OP_CODE_INIT (1), and
    # the bootloader only accepts SHA256 digests
    # (nrf_dfu_ver_validation.c: fw_hash_type_ok()).
    op_code = packet["op_code"]
    if op_code != 1:
        reasons.append("OP CODE %s: %s is not an INIT command" % (op_code, name))
        results.append("OP CODE %s not INIT" % op_code)
    if packet["hash_type"] != 3:
        reasons.append("HASH TYPE %s: %s is not SHA256" % (packet["hash_type"], name))
        results.append("HASH TYPE %s not SHA256" % packet["hash_type"])
    # The bootloader rejects an init packet without a hw_version
    # (nrf_dfu_ver_validation.c: has_hw_version == false -> INIT_COMMAND_INVALID).
    if packet["hw_version"] is None:
        reasons.append("HW VERSION MISSING: %s has no hw_version" % name)
        results.append("HW VERSION MISSING")
    image = zf.read(bin_name)
    digest = hashlib.sha256(image).hexdigest()
    stored = packet["hash"]
    if not stored:
        reasons.append("%s: no hash in the init packet" % name)
        results.append("FAIL no hash field")
        print("  %-24s %s" % (name, " | ".join(results)))
        return packet

    # Modern bootloaders reverse the stored digest, legacy ones do not.
    expected = stored[::-1].hex() if rule == "modern" else stored.hex()
    if expected != digest:
        reasons.append("HASH MISMATCH: %s: stored %s, sha256(%s) is %s"
                       % (name, expected, bin_name, digest))
        results.append("HASH MISMATCH stored=%s expected=%s" % (expected, digest))
    else:
        results.append("HASH MATCH sha256=%s" % digest)

    if key_ok:
        ok, detail = verify_signature(pem_path, packet["init"], packet["signature"], directory)
        if not ok:
            reasons.append("SIGNATURE INVALID: %s: %s" % (name, detail))
            results.append("SIGNATURE INVALID %s" % detail)
        else:
            results.append("SIGNATURE ok (ECDSA-P256-SHA256)")

    sizes_ok, size_detail = check_sizes(packet, len(image))
    if not sizes_ok:
        reasons.append("SIZES MISMATCH: %s: %s" % (name, size_detail))
        results.append("SIZES MISMATCH %s" % size_detail)
    else:
        results.append("SIZES ok %s" % size_detail)

    # The manifest metadata has to agree with the sizes in the init packet.
    meta = spec.get("info_read_only_metadata") or {}
    for role in ("bl_size", "sd_size"):
        if role in meta and (packet[role] is None or packet[role] != meta[role]):
            reasons.append("SIZES MISMATCH: manifest %s=%d, init packet says %s"
                           % (role, meta[role], packet[role]))
            results.append("SIZES MISMATCH manifest %s=%d" % (role, meta[role]))
    print("  %-24s type=%s %s" % (name, FW_TYPES.get(packet["type"], packet["type"]),
                                  " | ".join(results)))
    return packet


def check_package(zip_path, rule, key_path, bootloader_key_path):
    """Verify one package. Returns a list of failure reasons (empty == good)."""
    reasons = []
    print("== %s" % zip_path)
    try:
        archive = zipfile.ZipFile(zip_path)
    except (OSError, zipfile.BadZipFile) as exc:
        print("  CANNOT OPEN: %s" % exc)
        return ["cannot open %s: %s" % (zip_path, exc)]

    with archive as zf:
        names = zf.namelist()
        try:
            manifest = load_manifest(zf)
        except DfuError as exc:
            manifest = {}
            reasons.append("MANIFEST: %s" % exc)
            print("  manifest          FAIL  %s" % exc)

        # The bootloader only trusts its own compiled key, so the signing key
        # has to match it - otherwise nothing this tool checks can be accepted.
        key_ok = True
        with tempfile.TemporaryDirectory() as tmp:
            try:
                pem_public, pem_path = public_key(key_path, tmp)
                bootloader_public = bootloader_public_key(bootloader_key_path)
            except (KeyUnreadable, DfuError, OSError) as exc:
                reasons.append("KEY UNREADABLE: %s" % exc)
                print("  KEY MATCH        FAIL  KEY UNREADABLE (%s)" % exc)
                pem_path, key_ok = None, False
            if key_ok and pem_public != bootloader_public:
                reasons.append("KEY MISMATCH: %s does not match the public key in %s"
                               % (key_path, bootloader_key_path))
                print("  KEY MATCH        FAIL  KEY MISMATCH (%s != %s)"
                      % (key_path, bootloader_key_path))
                key_ok = False
            elif key_ok:
                print("  KEY MATCH        ok  (%s)" % bootloader_key_path)

            dat_names = [name for name in names if name.endswith(".dat")]
            if not dat_names:
                reasons.append("NO INIT PACKET: the package contains no .dat init packet")
                print("  init packets     FAIL  the package contains no .dat member")

            for name in names:
                data = zf.read(name)
                if name.endswith(".bin"):
                    print("  %-24s %8d bytes  sha256=%s"
                          % (name, len(data), hashlib.sha256(data).hexdigest()))
                elif name.endswith(".dat"):
                    check_dat(zf, name, manifest, rule, key_ok, pem_path, tmp, reasons)
                elif name.endswith(".json"):
                    print("  %-24s %8d bytes  manifest" % (name, len(data)))
                else:
                    print("  %-24s %8d bytes" % (name, len(data)))

            # Every image has to be covered by an init packet, otherwise the
            # bootloader would never check it.
            covered = covered_bin_names(names, manifest)
            for name in names:
                if name.endswith(".bin") and name not in covered:
                    reasons.append("NO INIT PACKET: no .dat init packet covers %s" % name)
                    print("  %-24s FAIL  no .dat init packet covers this image" % name)

        # Every file the manifest names has to be part of the package.
        for section, spec in manifest_pairs(manifest):
            for role in ("bin_file", "dat_file"):
                target = spec.get(role)
                if target and target not in names:
                    reasons.append("manifest: %s.%s (%s) is not in the package"
                                   % (section, role, target))
                    print("  manifest          FAIL  %s.%s (%s) missing" % (section, role, target))
    return reasons


# --- legacy package generation ---

def write_zip_atomic(path, infos, contents):
    path = Path(path)
    tmp = path.with_name("%s.%d.tmp" % (path.name, os.getpid()))
    try:
        with zipfile.ZipFile(tmp, "w") as zf:
            for info in infos:
                zf.writestr(info, contents[info.filename])
        with open(tmp, "rb") as handle:
            os.fsync(handle.fileno())
        os.replace(str(tmp), str(path))
    finally:
        if tmp.exists():
            tmp.unlink()


def generate_legacy(out_path, in_path, key_path, bootloader_key_path):
    """Write a pre-SDK-15 compatible copy of in_path (plain hash) to out_path."""
    print("== legacy %s -> %s" % (in_path, out_path))
    with zipfile.ZipFile(in_path) as zf:
        infos = zf.infolist()
        contents = {info.filename: zf.read(info.filename) for info in infos}
        manifest = load_manifest(zf)
    for info in infos:
        name = info.filename
        if not name.endswith(".dat"):
            continue
        bin_name = manifest_spec_for_dat(manifest, name).get("bin_file") or name[:-4] + ".bin"
        if bin_name not in contents:
            raise DfuError("%s: image %s is missing from the package" % (name, bin_name))
        digest = hashlib.sha256(contents[bin_name]).digest()
        packet = parse_dat(contents[name])
        span = packet["hash_span"]
        if span is None or span[1] - span[0] != 32:
            raise DfuError("%s: no 32-byte hash field to patch" % name)
        # build_dat() hardcodes the nrfutil layout, so rebuilding the untouched
        # packet has to reproduce the original file byte for byte. If it does
        # not, nrfutil changed its layout and this tool must not guess.
        if build_dat(packet["init"], packet["signature"]) != contents[name]:
            raise DfuError("%s: init packet layout differs from the nrfutil format "
                           "this tool rebuilds - refusing to rewrite it" % name)
        # Patch the digest in place, then re-sign the patched init bytes.
        patched = packet["init"][:span[0]] + digest + packet["init"][span[1]:]
        contents[name] = build_dat(patched, sign_init(patched, key_path))
        print("  %-24s hash -> %s, re-signed" % (name, digest.hex()))
    write_zip_atomic(out_path, infos, contents)
    print("  wrote %s" % out_path)
    reasons = check_package(out_path, "legacy", key_path, bootloader_key_path)
    if reasons:
        # A package that does not verify must not stay on disk: it would look
        # flashable and the next run would need --force to replace it.
        detail = "; ".join(reasons)
        try:
            Path(out_path).unlink()
        except OSError as exc:
            raise DfuError("generated package does not verify: %s (%s could not be "
                           "removed: %s)" % (detail, out_path, exc))
        raise DfuError("generated package does not verify: %s (removed %s)"
                       % (detail, out_path))
    print("PASS %s (legacy rule)" % out_path)


# --- entry point ---

def main(argv):
    # argparse refuses an option as the value of --legacy, so pull --force out
    # of the argument list first: both "--legacy --force OUT.zip" and
    # "--legacy OUT.zip --force" have to work.
    force = "--force" in argv
    argv = [arg for arg in argv if arg != "--force"]
    parser = argparse.ArgumentParser(description="Verify Nordic DFU packages.")
    parser.add_argument("--check", action="store_true", help="verify packages (default)")
    parser.add_argument("--legacy", nargs=1, metavar="OUT.zip",
                        help="write a pre-SDK-15 compatible package (OUT.zip, or a directory "
                             "when several inputs are given); refuses to overwrite unless --force")
    parser.add_argument("--rule", choices=("modern", "legacy"), default="modern",
                        help="hash convention to check against (default: modern)")
    parser.add_argument("--key", default=str(DEFAULT_KEY), help="signing key")
    parser.add_argument("--bootloader-key", default=str(DEFAULT_BOOTLOADER_KEY),
                        help="bootloader public key C file")
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing --legacy output file")
    parser.add_argument("zips", nargs="*", help="package(s) to check or convert")
    args = parser.parse_args(argv)
    args.force = force
    key_path = Path(args.key)
    bootloader_key_path = Path(args.bootloader_key)

    if args.legacy:
        out = Path(args.legacy[0])
        if not args.zips:
            parser.error("--legacy needs at least one input package")
        if len(args.zips) == 1:
            targets = [(args.zips[0], out)]
        else:
            # Several inputs are written by basename, so two inputs with the
            # same name would silently overwrite each other.
            seen = {}
            for src in args.zips:
                base = Path(src).name
                if base in seen:
                    print("FAIL %s: --legacy writes by basename and %s is already used "
                          "by %s" % (src, base, seen[base]))
                    return 1
                seen[base] = src
            if out.exists() and not out.is_dir():
                print("FAIL %s: --legacy output %s exists and is not a directory"
                      % (args.zips[0], out))
                return 1
            out.mkdir(parents=True, exist_ok=True)
            targets = [(src, out / Path(src).name) for src in args.zips]
        failed = False
        for src, dst in targets:
            if dst.exists() and not args.force:
                failed = True
                print("FAIL %s: refusing to overwrite the existing %s "
                      "(pass --force to replace it)" % (src, dst))
                continue
            try:
                generate_legacy(dst, src, key_path, bootloader_key_path)
            except (DfuError, OSError, zipfile.BadZipFile, zlib.error) as exc:
                failed = True
                print("FAIL %s: %s" % (src, exc))
        return 1 if failed else 0

    if not args.zips:
        parser.error("no package given")
    failed = False
    for zip_path in args.zips:
        try:
            reasons = check_package(zip_path, args.rule, key_path, bootloader_key_path)
        except zlib.error as exc:
            reasons = ["%s: corrupt zip member: %s" % (zip_path, exc)]
        except (DfuError, OSError, zipfile.BadZipFile) as exc:
            reasons = ["%s: %s" % (zip_path, exc)]
        if reasons:
            failed = True
            print("FAIL %s" % zip_path)
            for reason in reasons:
                print("  - %s" % reason)
        else:
            print("PASS %s" % zip_path)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
