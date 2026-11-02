import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import io
from contextlib import redirect_stdout

from chameleon_cli_unit import (
    HWSettingsMultiTap,
    MULTITAP_COUNT_BY_NAME,
    MULTITAP_NAME_BY_COUNT,
    MULTITAP_TAP_NAMES,
    multitap_count_text,
    multitap_tap_label,
)
from chameleon_utils import ArgsParserError, UnexpectedResponseError
import chameleon_com
import chameleon_cmd
from chameleon_enum import Command, Status


class FakeCmd:
    """Minimal stand-in for chameleon_cmd.ChameleonCMD (no hardware needed)."""

    def __init__(self, taps_a=1, taps_b=1, threshold_ms=250, supported=True, reject=False):
        self.current = (taps_a, taps_b, threshold_ms)
        self.supported = supported
        self.reject = reject
        self.gets = 0
        self.written = []

    def get_multi_tap_config(self):
        self.gets += 1
        if not self.supported:
            raise chameleon_com.CMDInvalidException("unsupported")
        return self.current

    def set_multi_tap_config(self, taps_a, taps_b, threshold_ms):
        if self.reject:
            raise UnexpectedResponseError("device refused")
        self.written.append((taps_a, taps_b, threshold_ms))
        self.current = (taps_a, taps_b, threshold_ms)


def make_unit(fake):
    unit = HWSettingsMultiTap()
    unit._device_cmd = fake
    return unit


class FakeDevice:
    """Minimal stand-in for chameleon_com.ChameleonCom (no hardware needed)."""

    def __init__(self, response=None):
        self.response = response
        self.sent = []

    def send_cmd_sync(self, cmd, data=b''):
        self.sent.append((cmd, data))
        if self.response is not None:
            return self.response
        return chameleon_com.Response(cmd=cmd, status=Status.SUCCESS)


class MultiTapCli(unittest.TestCase):
    def test_tap_label_mapping(self):
        self.assertEqual(MULTITAP_TAP_NAMES[0], "single")
        self.assertEqual(MULTITAP_TAP_NAMES[4], "quintuple")
        self.assertEqual(MULTITAP_COUNT_BY_NAME["single"], 1)
        self.assertEqual(MULTITAP_COUNT_BY_NAME["double"], 2)
        self.assertEqual(MULTITAP_COUNT_BY_NAME["triple"], 3)
        self.assertEqual(MULTITAP_COUNT_BY_NAME["quadruple"], 4)
        self.assertEqual(MULTITAP_COUNT_BY_NAME["quintuple"], 5)
        self.assertEqual(MULTITAP_NAME_BY_COUNT[3], "triple")
        self.assertEqual(multitap_count_text(1), "1 tap")
        self.assertEqual(multitap_count_text(2), "2 taps")
        self.assertEqual(multitap_tap_label(2), "double (2 taps)")
        self.assertEqual(multitap_tap_label(5), "quintuple (5 taps)")

    def test_invalid_tap_name_rejected(self):
        parser = HWSettingsMultiTap().args_parser()
        with self.assertRaises(ArgsParserError):
            parser.parse_args(["--button-a-taps", "six"])
        with self.assertRaises(ArgsParserError):
            parser.parse_args(["--button-b-taps", "triple-tap"])
        # a valid name is accepted
        args = parser.parse_args(["--button-a-taps", "double", "--threshold-ms", "250"])
        self.assertEqual(args.button_a_taps, "double")
        self.assertEqual(args.threshold_ms, 250)

    def test_threshold_out_of_range_never_touches_device(self):
        fake = FakeCmd()
        unit = make_unit(fake)
        for bad in (10, 5000):
            args = unit.args_parser().parse_args(["--threshold-ms", str(bad)])
            out = io.StringIO()
            with redirect_stdout(out):
                unit.on_exec(args)
            self.assertIn("--threshold-ms", out.getvalue())
            self.assertEqual(fake.gets, 0)
            self.assertEqual(fake.written, [])

    def test_successful_set(self):
        fake = FakeCmd(taps_a=1, taps_b=1, threshold_ms=250)
        unit = make_unit(fake)
        args = unit.args_parser().parse_args(["--button-a-taps", "triple"])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertEqual(fake.written, [(3, 1, 250)])
        self.assertIn("triple (3 taps)", out.getvalue())

    def test_old_firmware_reports_unsupported(self):
        fake = FakeCmd(supported=False)
        unit = make_unit(fake)
        args = unit.args_parser().parse_args([])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertIn(
            "Multi-tap settings are not supported by the current firmware.",
            out.getvalue(),
        )
        self.assertEqual(fake.written, [])

    def test_threshold_snapped_down_to_multiple_of_10(self):
        # the device stores units of 10 ms, so 251 ms must become 250 ms
        fake = FakeCmd(taps_a=1, taps_b=1, threshold_ms=500)
        unit = make_unit(fake)
        args = unit.args_parser().parse_args(["--threshold-ms", "251"])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertEqual(fake.written, [(1, 1, 250)])
        printed = out.getvalue()
        self.assertIn("250 ms", printed)
        self.assertNotIn("251 ms", printed)

    def test_threshold_already_at_snapped_value_writes_nothing(self):
        fake = FakeCmd(taps_a=1, taps_b=1, threshold_ms=250)
        unit = make_unit(fake)
        args = unit.args_parser().parse_args(["--threshold-ms", "251"])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertEqual(fake.written, [])
        self.assertIn("250 ms", out.getvalue())

    def test_omitted_flags_leave_values_unchanged(self):
        # no flags at all: pure read, nothing is written
        fake = FakeCmd(taps_a=3, taps_b=2, threshold_ms=400)
        unit = make_unit(fake)
        args = unit.args_parser().parse_args([])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertEqual(fake.written, [])
        printed = out.getvalue()
        self.assertIn("triple (3 taps)", printed)
        self.assertIn("double (2 taps)", printed)
        self.assertIn("400 ms", printed)

        # only button A is set: B and the threshold keep their values
        args = unit.args_parser().parse_args(["--button-a-taps", "quintuple"])
        with redirect_stdout(io.StringIO()):
            unit.on_exec(args)
        self.assertEqual(fake.written, [(5, 2, 400)])

    def test_device_rejection_is_reported_without_traceback(self):
        fake = FakeCmd(taps_a=1, taps_b=1, threshold_ms=250, reject=True)
        unit = make_unit(fake)
        args = unit.args_parser().parse_args(["--button-a-taps", "double"])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertIn(
            "The device rejected the multi-tap settings; nothing was changed.",
            out.getvalue(),
        )
        self.assertEqual(fake.written, [])

    def test_help_text_is_honest(self):
        parser = HWSettingsMultiTap().args_parser()
        # argparse wraps long help lines, so compare on collapsed whitespace
        help_text = " ".join(parser.format_help().split())
        self.assertIn("unchanged if omitted (factory default: single)", help_text)
        self.assertIn("rounded down to a multiple of 10 ms", help_text)

    def test_set_multi_tap_config_sends_expected_bytes(self):
        # the real ChameleonCMD must put the config on the wire as
        # taps_a, taps_b, threshold_ms (little endian)
        device = FakeDevice()
        cmd = chameleon_cmd.ChameleonCMD(device)
        cmd.set_multi_tap_config(3, 1, 250)
        self.assertEqual(
            device.sent,
            [(Command.SET_MULTI_TAP_CONFIG, b'\x03\x01\xfa\x00')],
        )

    def test_get_multi_tap_config_parses_valid_response(self):
        # a valid 4 byte payload is decoded by the real ChameleonCMD
        device = FakeDevice(
            response=chameleon_com.Response(
                cmd=Command.GET_MULTI_TAP_CONFIG,
                status=Status.SUCCESS,
                data=b'\x03\x01\xfa\x00',
            )
        )
        cmd = chameleon_cmd.ChameleonCMD(device)
        self.assertEqual(cmd.get_multi_tap_config(), (3, 1, 250))

    def test_get_multi_tap_config_rejects_malformed_response(self):
        # a short payload must raise UnexpectedResponseError, not struct.error
        device = FakeDevice(
            response=chameleon_com.Response(
                cmd=Command.GET_MULTI_TAP_CONFIG,
                status=Status.SUCCESS,
                data=b'\x03\x01\xfa',
            )
        )
        cmd = chameleon_cmd.ChameleonCMD(device)
        with self.assertRaises(UnexpectedResponseError):
            cmd.get_multi_tap_config()


if __name__ == '__main__':
    unittest.main()
