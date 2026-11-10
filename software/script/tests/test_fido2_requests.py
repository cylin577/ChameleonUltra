import argparse
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cli_hw_u2f import _build_request
from fido2_cbor import decode


class Fido2RequestTest(unittest.TestCase):
    def test_make_credential_uses_ctap_parameter_keys(self):
        request = _build_request(argparse.Namespace(
            raw=None,
            cmd='make-credential',
            rp_id='example.com',
            client_data_hash='00' * 32,
            cred_id=None,
        ))

        self.assertEqual(request[0], 0x01)
        params = decode(request[1:])
        self.assertEqual(list(params), [1, 2, 3, 4, 7])
        self.assertEqual(params[4], [{'alg': -7, 'type': 'public-key'}])
        self.assertEqual(params[7], {'rk': False})
        self.assertNotIn(5, params)

    def test_get_assertion_descriptor_puts_id_before_type(self):
        request = _build_request(argparse.Namespace(
            raw=None,
            cmd='get-assertion',
            rp_id='example.com',
            client_data_hash='22' * 32,
            cred_id='11' * 64,
        ))

        self.assertEqual(request[0], 0x02)
        params = decode(request[1:])
        self.assertEqual(list(params), [1, 2, 3])
        descriptor = params[3][0]
        self.assertEqual(list(descriptor), ['id', 'type'])
        self.assertEqual(descriptor['id'], bytes.fromhex('11' * 64))
        self.assertEqual(descriptor['type'], 'public-key')

        id_key = request.rindex(b'\x62id')
        type_key = request.index(b'\x64type')
        self.assertLess(id_key, type_key)


if __name__ == '__main__':
    unittest.main()
