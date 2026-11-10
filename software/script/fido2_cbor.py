"""fido2_cbor - minimal CBOR (RFC 8949) codec for the CTAP2 CLI helpers.

CTAP2 request/response parameters are CBOR maps with integer keys. This
module encodes/decodes exactly the subset the authenticator uses:

    int / bool / None          major 0, 1, 7
    bytes (byte string)        major 2
    str (text string)          major 3
    list                       major 4
    dict                       major 5

Integers are plain Python ints, byte strings are ``bytes``, text strings are
``str``. Map keys keep their Python type, so a CTAP map decodes to
``{1: b'...', 2: {'id': 'example.com'}}``.
"""

import struct
from typing import Any, Tuple

__all__ = ["CBORError", "encode", "decode", "decode_first"]


class CBORError(ValueError):
    """Raised when a value cannot be encoded or a buffer cannot be decoded."""


# --------------------------------------------------------------------------
# encode
# --------------------------------------------------------------------------
def _head(major: int, value: int) -> bytes:
    """Encode a major type and its argument (the RFC 8949 head)."""
    if value < 0:
        raise CBORError("negative length")
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack("!H", value)
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack("!I", value)
    return bytes([(major << 5) | 27]) + struct.pack("!Q", value)


def _canonical_key_order(encoded: bytes) -> Tuple[Any, ...]:
    """Order integers numerically and text keys by length, then bytes."""
    major, arg, offset = _read_head(encoded, 0)

    if major == 0:
        return (0, arg)
    if major == 1:
        return (0, -1 - arg)
    if major == 3:
        body = encoded[offset:offset + arg]
        return (1, len(body), body)
    return (major + 2, len(encoded), encoded)


def encode(obj: Any) -> bytes:
    """Encode a Python value into canonical CTAP2 CBOR bytes."""
    if obj is None:
        return b"\xf6"
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return _head(0, obj) if obj >= 0 else _head(1, -obj - 1)
    if isinstance(obj, (bytes, bytearray, memoryview)):
        raw = bytes(obj)
        return _head(2, len(raw)) + raw
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        out = _head(4, len(obj))
        for item in obj:
            out += encode(item)
        return out
    if isinstance(obj, dict):
        entries = [(encode(key), value) for key, value in obj.items()]
        entries.sort(key=lambda entry: _canonical_key_order(entry[0]))
        out = _head(5, len(entries))
        for key, value in entries:
            out += key + encode(value)
        return out
    raise CBORError(f"unsupported type: {type(obj).__name__}")


# --------------------------------------------------------------------------
# decode
# --------------------------------------------------------------------------
def _read_head(data: bytes, off: int) -> Tuple[int, int, int]:
    """Return (major_type, argument, next_offset)."""
    if off >= len(data):
        raise CBORError("truncated CBOR")
    initial = data[off]
    off += 1
    major = initial >> 5
    minor = initial & 0x1F
    if minor < 24:
        return major, minor, off
    if minor == 24:
        if off + 1 > len(data):
            raise CBORError("truncated CBOR")
        return major, data[off], off + 1
    if minor == 25:
        if off + 2 > len(data):
            raise CBORError("truncated CBOR")
        return major, struct.unpack_from("!H", data, off)[0], off + 2
    if minor == 26:
        if off + 4 > len(data):
            raise CBORError("truncated CBOR")
        return major, struct.unpack_from("!I", data, off)[0], off + 4
    if minor == 27:
        if off + 8 > len(data):
            raise CBORError("truncated CBOR")
        return major, struct.unpack_from("!Q", data, off)[0], off + 8
    raise CBORError(f"unsupported additional information {minor}")


def _decode_item(data: bytes, off: int) -> Tuple[Any, int]:
    major, arg, off = _read_head(data, off)
    if major == 0:
        return arg, off
    if major == 1:
        return -1 - arg, off
    if major == 2:
        if off + arg > len(data):
            raise CBORError("truncated byte string")
        return data[off:off + arg], off + arg
    if major == 3:
        if off + arg > len(data):
            raise CBORError("truncated text string")
        try:
            return data[off:off + arg].decode("utf-8"), off + arg
        except UnicodeDecodeError as e:
            raise CBORError(f"invalid UTF-8 text string: {e}") from e
    if major == 4:
        items = []
        for _ in range(arg):
            item, off = _decode_item(data, off)
            items.append(item)
        return items, off
    if major == 5:
        result = {}
        for _ in range(arg):
            key, off = _decode_item(data, off)
            value, off = _decode_item(data, off)
            try:
                result[key] = value
            except TypeError as e:
                raise CBORError(f"unusable map key: {e}") from e
        return result, off
    if major == 6:
        raise CBORError("CBOR tags are not supported")
    # major == 7: simple values and floats
    if arg == 20:
        return False, off
    if arg == 21:
        return True, off
    if arg == 22:
        return None, off
    if arg == 23:
        return None, off           # undefined -> None
    if arg == 25:
        return struct.unpack("!e", struct.pack("!H", 0))[0], off
    if arg == 26:
        return struct.unpack("!f", struct.pack("!I", 0))[0], off
    if arg == 27:
        return struct.unpack("!d", struct.pack("!Q", 0))[0], off
    raise CBORError(f"unsupported simple value {arg}")


def decode(data: bytes) -> Any:
    """Decode one CBOR item from `data`; trailing bytes are ignored."""
    value, _ = decode_first(data)
    return value


def decode_first(data: bytes) -> Tuple[Any, int]:
    """Decode one CBOR item; return (value, number_of_bytes_consumed)."""
    if not data:
        raise CBORError("empty CBOR buffer")
    return _decode_item(bytes(data), 0)
