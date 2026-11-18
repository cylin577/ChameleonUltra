import io
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import chameleon_com
import chameleon_cmd
from chameleon_enum import Command, Status
from cli_hw_u2f import HWU2fTriggerUp


class FakeDevice:
    def __init__(self, response):
        self.response = response
        self.sent = []

    def send_cmd_sync(self, cmd, data=b''):
        self.sent.append((cmd, data))
        return self.response


class FakeCmd:
    def __init__(self, response):
        self.response = response

    def fido2_grant_up(self):
        return self.response


class Fido2UserPresenceCli(unittest.TestCase):
    def test_command_layer_preserves_payload(self):
        for payload in (b'\x00', b'\x01'):
            device = FakeDevice(chameleon_com.Response(
                cmd=Command.FIDO2_GRANT_UP,
                status=Status.SUCCESS,
                data=payload,
            ))
            cmd = chameleon_cmd.ChameleonCMD(device)
            self.assertEqual(cmd.fido2_grant_up(), payload)
            self.assertEqual(device.sent, [(Command.FIDO2_GRANT_UP, b'')])

    def test_cli_reports_granted_presence(self):
        unit = HWU2fTriggerUp()
        unit._device_cmd = FakeCmd(b'\x00')
        args = unit.args_parser().parse_args([])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertIn('User presence is granted', out.getvalue())

    def test_cli_reports_denied_presence(self):
        unit = HWU2fTriggerUp()
        unit._device_cmd = FakeCmd(b'\x01')
        args = unit.args_parser().parse_args([])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertIn('not granted', out.getvalue())
        self.assertIn('press A or B', out.getvalue())

    def test_help_does_not_claim_a_button_bypass(self):
        help_text = ' '.join(HWU2fTriggerUp().args_parser().format_help().split())
        self.assertIn('physical button press', help_text)
        self.assertIn('cannot grant presence', help_text)
        self.assertNotIn('bypasses the button', help_text)


if __name__ == '__main__':
    unittest.main()
