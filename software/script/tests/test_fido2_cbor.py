import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fido2_cbor import CBORError, decode, decode_first, encode


class Fido2CborTest(unittest.TestCase):
    def test_ints(self):
        self.assertEqual(encode(0), b'\x00')
        self.assertEqual(encode(1), b'\x01')
        self.assertEqual(encode(23), b'\x17')
        self.assertEqual(encode(24), b'\x18\x18')
        self.assertEqual(encode(255), b'\x18\xff')
        self.assertEqual(encode(256), b'\x19\x01\x00')
        self.assertEqual(encode(65535), b'\x19\xff\xff')
        self.assertEqual(encode(65536), b'\x1a\x00\x01\x00\x00')
        self.assertEqual(encode(4294967296), b'\x1b\x00\x00\x00\x01\x00\x00\x00\x00')
        self.assertEqual(encode(-1), b'\x20')
        self.assertEqual(encode(-7), b'\x26')

    def test_bools_and_none(self):
        self.assertEqual(encode(True), b'\xf5')
        self.assertEqual(encode(False), b'\xf4')
        self.assertEqual(encode(None), b'\xf6')

    def test_strings(self):
        self.assertEqual(encode(b'\x01\x02'), b'\x42\x01\x02')
        self.assertEqual(encode('none'), b'\x64none')
        self.assertEqual(encode(''), b'\x60')

    def test_containers(self):
        self.assertEqual(encode([1, 2]), b'\x82\x01\x02')
        self.assertEqual(encode({}), b'\xa0')
        self.assertEqual(encode({1: 2}), b'\xa1\x01\x02')

    def test_canonical_map_order(self):
        value = {7: 'g', 4: 'd', 1: 'a'}
        encoded = encode(value)
        self.assertEqual(encoded, b'\xa3\x01\x61a\x04\x61d\x07\x61g')
        self.assertEqual(decode(encoded), value)

        text_value = {'bb': 2, 'a': 1, 'cccc': 3}
        text_encoded = encode(text_value)
        self.assertEqual(text_encoded, b'\xa3\x61a\x01\x62bb\x02\x64cccc\x03')
        self.assertEqual(decode(text_encoded), text_value)

    def test_decode_scalars(self):
        self.assertEqual(decode(b'\x00'), 0)
        self.assertEqual(decode(b'\x26'), -7)
        self.assertEqual(decode(b'\x42\x01\x02'), b'\x01\x02')
        self.assertEqual(decode(b'\x64none'), 'none')
        self.assertIs(decode(b'\xf4'), False)
        self.assertIs(decode(b'\xf5'), True)
        self.assertIsNone(decode(b'\xf6'))

    def test_round_trip(self):
        value = {
            1: bytes(range(32)),
            2: {'id': 'example.com', 'name': 'Example'},
            3: [{'alg': -7, 'type': 'public-key'}],
            6: {'rk': False},
        }
        self.assertEqual(decode(encode(value)), value)

    def test_ctap_get_info_shape(self):
        # what the firmware's authenticatorGetInfo answers
        def map_head(n):
            return bytes([0xa0 | n])

        def array_head(n):
            return bytes([0x80 | n])

        raw = (map_head(4)
               + encode(1) + array_head(2) + encode('FIDO_2_0') + encode('U2F_V2')
               + encode(3) + encode(b'\x00' * 16)
               + encode(4) + map_head(4) + encode('rk') + encode(False)
               + encode('up') + encode(True)
               + encode('clientPin') + encode(False)
               + encode('makeCredUvNotRqd') + encode(True)
               + encode(9) + array_head(3) + encode('usb') + encode('nfc') + encode('ble'))
        info = decode(raw)
        self.assertEqual(info[1], ['FIDO_2_0', 'U2F_V2'])
        self.assertEqual(info[3], b'\x00' * 16)
        self.assertIs(info[4]['rk'], False)
        self.assertIs(info[4]['up'], True)
        self.assertEqual(info[9], ['usb', 'nfc', 'ble'])

    def test_decode_first_reports_length(self):
        value, used = decode_first(b'\x01\x02\x03')
        self.assertEqual(value, 1)
        self.assertEqual(used, 1)

    def test_errors(self):
        with self.assertRaises(CBORError):
            decode(b'')
        with self.assertRaises(CBORError):
            decode(b'\x42\x01')          # truncated byte string
        with self.assertRaises(CBORError):
            decode(b'\x64no')            # truncated text string
        with self.assertRaises(CBORError):
            decode(b'\xc0\x01')          # tag
        with self.assertRaises(CBORError):
            encode(object())


if __name__ == '__main__':
    unittest.main()
