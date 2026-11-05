import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import io
from contextlib import redirect_stdout

from chameleon_cli_unit import (
    HWButtonSettingsGet,
    HWSettingsMultiTap,
    multitap_count_text,
)
from chameleon_utils import ArgsParserError, UnexpectedResponseError
import chameleon_com
import chameleon_cmd
from chameleon_enum import ButtonPressFunction, ButtonType, Command, Status


class FakeCmd:
    """Minimal stand-in for chameleon_cmd.ChameleonCMD (no hardware needed)."""

    def __init__(self, bindings_a=(0, 0, 0, 0), bindings_b=(0, 0, 0, 0), threshold_ms=250,
                 supported=True, reject=False):
        self.current = {'a': tuple(bindings_a), 'b': tuple(bindings_b), 'threshold_ms': threshold_ms}
        self.supported = supported
        self.reject = reject
        self.gets = 0
        self.written = []
        self.short_written = []

    def get_multi_tap_bindings(self):
        self.gets += 1
        if not self.supported:
            raise chameleon_com.CMDInvalidException("unsupported")
        return self.current

    def set_multi_tap_bindings(self, a, b, threshold_ms):
        if self.reject:
            raise UnexpectedResponseError("device refused")
        self.written.append((tuple(a), tuple(b), threshold_ms))
        self.current = {'a': tuple(a), 'b': tuple(b), 'threshold_ms': threshold_ms}

    def set_multi_tap_binding(self, button, tap_count, function):
        a = list(self.current['a'])
        b = list(self.current['b'])
        slot = tap_count - 2
        (a if button == ButtonType.A else b)[slot] = int(function)
        self.set_multi_tap_bindings(tuple(a), tuple(b), self.current['threshold_ms'])

    def get_button_press_config(self, button):
        return 1

    def get_long_button_press_config(self, button):
        return 3

    def set_button_press_config(self, button, function):
        self.short_written.append((button, function))


def make_unit(fake, cls=HWSettingsMultiTap):
    unit = cls()
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
    def test_tap_count_text(self):
        self.assertEqual(multitap_count_text(1), "1 tap")
        self.assertEqual(multitap_count_text(2), "2 taps")
        self.assertEqual(multitap_count_text(5), "5 taps")

    def test_invalid_taps_value_rejected(self):
        parser = HWSettingsMultiTap().args_parser()
        with self.assertRaises(ArgsParserError):
            parser.parse_args(["--taps", "six"])
        with self.assertRaises(ArgsParserError):
            parser.parse_args(["--taps", "9"])
        # a valid tap count is accepted
        args = parser.parse_args(["--taps", "3", "-f", "BATTERY"])
        self.assertEqual(args.taps, 3)
        self.assertEqual(args.function, "BATTERY")

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

    def test_threshold_snapped_down_to_multiple_of_10(self):
        # the device stores units of 10 ms, so 251 ms must become 250 ms
        fake = FakeCmd(threshold_ms=500)
        unit = make_unit(fake)
        args = unit.args_parser().parse_args(["--threshold-ms", "251"])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertEqual(fake.written, [((0, 0, 0, 0), (0, 0, 0, 0), 250)])
        printed = out.getvalue()
        self.assertIn("250 ms", printed)
        self.assertNotIn("251 ms", printed)

    def test_threshold_already_at_snapped_value_writes_nothing(self):
        fake = FakeCmd(threshold_ms=250)
        unit = make_unit(fake)
        args = unit.args_parser().parse_args(["--threshold-ms", "251"])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertEqual(fake.written, [])
        self.assertIn("250 ms", out.getvalue())

    def test_old_firmware_reports_unsupported(self):
        fake = FakeCmd(supported=False)
        unit = make_unit(fake)
        args = unit.args_parser().parse_args([])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertIn(
            "Multi-tap bindings are not supported by the current firmware.",
            out.getvalue(),
        )
        self.assertEqual(fake.written, [])

    def test_successful_set(self):
        # --taps 3 binds BATTERY to Button A's 3-tap slot
        fake = FakeCmd()
        unit = make_unit(fake)
        args = unit.args_parser().parse_args(["-a", "--taps", "3", "-f", "BATTERY"])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertEqual(fake.written, [((0, int(ButtonPressFunction.BATTERY), 0, 0), (0, 0, 0, 0), 250)])
        self.assertIn("3 taps", out.getvalue())

    def test_device_rejection_is_reported_without_traceback(self):
        fake = FakeCmd(reject=True)
        unit = make_unit(fake)
        args = unit.args_parser().parse_args(["-a", "--taps", "2", "-f", "BATTERY"])
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
        self.assertIn("2-5", help_text)
        self.assertIn("rounded down to a multiple of 10 ms", help_text)
        btnpress_help = " ".join(HWButtonSettingsGet().args_parser().format_help().split())
        self.assertIn("--multitap", btnpress_help)
        self.assertIn("--taps", btnpress_help)
        self.assertIn("1 = the short-press binding", btnpress_help)

    def test_help_text_states_the_threshold_latency_rule(self):
        # a tap count waits for the threshold when a higher tap count is
        # bound on the same button
        help_text = " ".join(HWSettingsMultiTap().args_parser().format_help().split())
        self.assertIn(
            "the action of a tap count waits for the threshold when a higher "
            "tap count is bound on the same button",
            help_text,
        )
        btnpress_help = " ".join(HWButtonSettingsGet().args_parser().format_help().split())
        self.assertIn(
            "the action of a tap count waits for the threshold when a higher "
            "tap count is bound on the same button",
            btnpress_help,
        )

    def test_set_multi_tap_bindings_sends_expected_bytes(self):
        # the real ChameleonCMD must put the bindings on the wire as
        # fn[8] (A2..A5,B2..B5) + threshold_ms (little endian)
        device = FakeDevice()
        cmd = chameleon_cmd.ChameleonCMD(device)
        cmd.set_multi_tap_bindings((0, 0, 0, 0), (0, 0, 0, 0), 250)
        self.assertEqual(
            device.sent,
            [(Command.SET_MULTI_TAP_BINDINGS, b'\x00\x00\x00\x00\x00\x00\x00\x00\xfa\x00')],
        )

    def test_get_multi_tap_bindings_parses_valid_response(self):
        # a valid 10 byte payload is decoded by the real ChameleonCMD
        device = FakeDevice(
            response=chameleon_com.Response(
                cmd=Command.GET_MULTI_TAP_BINDINGS,
                status=Status.SUCCESS,
                data=b'\x00\x01\x02\x03\x04\x05\x06\x07\xfa\x00',
            )
        )
        cmd = chameleon_cmd.ChameleonCMD(device)
        self.assertEqual(
            cmd.get_multi_tap_bindings(),
            {'a': (0, 1, 2, 3), 'b': (4, 5, 6, 7), 'threshold_ms': 250},
        )

    def test_get_multi_tap_bindings_rejects_malformed_response(self):
        # a short payload must raise UnexpectedResponseError, not struct.error
        device = FakeDevice(
            response=chameleon_com.Response(
                cmd=Command.GET_MULTI_TAP_BINDINGS,
                status=Status.SUCCESS,
                data=b'\x00\x01\x02',
            )
        )
        cmd = chameleon_cmd.ChameleonCMD(device)
        with self.assertRaises(UnexpectedResponseError):
            cmd.get_multi_tap_bindings()

    def test_multitap_requires_button(self):
        fake = FakeCmd()
        unit = make_unit(fake, HWButtonSettingsGet)
        args = unit.args_parser().parse_args(["--multitap", "--taps", "3", "-f", "BATTERY"])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertIn("You must specify which button", out.getvalue())
        self.assertEqual(fake.written, [])
        self.assertEqual(fake.gets, 0)

    def test_multitap_requires_taps(self):
        fake = FakeCmd()
        unit = make_unit(fake, HWButtonSettingsGet)
        args = unit.args_parser().parse_args(["--multitap", "-a", "-f", "BATTERY"])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertIn("--multitap requires --taps", out.getvalue())
        self.assertEqual(fake.written, [])
        self.assertEqual(fake.gets, 0)

    def test_multitap_requires_function(self):
        fake = FakeCmd()
        unit = make_unit(fake, HWButtonSettingsGet)
        args = unit.args_parser().parse_args(["--multitap", "-a", "--taps", "3"])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertIn("--multitap requires --function", out.getvalue())
        self.assertEqual(fake.written, [])
        self.assertEqual(fake.gets, 0)

    def test_taps_without_multitap_is_rejected(self):
        fake = FakeCmd()
        unit = make_unit(fake, HWButtonSettingsGet)
        args = unit.args_parser().parse_args(["--taps", "3"])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertIn("--taps requires --multitap", out.getvalue())
        self.assertEqual(fake.written, [])
        self.assertEqual(fake.gets, 0)

    def test_multitap_with_long_is_rejected(self):
        # --multitap and --long are mutually exclusive
        parser = HWButtonSettingsGet().args_parser()
        with self.assertRaises(ArgsParserError):
            parser.parse_args(["--multitap", "-l", "--taps", "3", "-f", "BATTERY"])

    def test_multitap_with_short_is_rejected(self):
        # --multitap and --short are mutually exclusive: argparse rejects the
        # combination before on_exec runs, so the device is never touched
        fake = FakeCmd()
        unit = make_unit(fake, HWButtonSettingsGet)
        with self.assertRaises(ArgsParserError):
            unit.args_parser().parse_args(
                ["--multitap", "--short", "--taps", "3", "-f", "BATTERY"]
            )
        self.assertEqual(fake.written, [])
        self.assertEqual(fake.gets, 0)
        self.assertEqual(fake.short_written, [])

    def test_taps_one_sets_the_short_press(self):
        fake = FakeCmd()
        unit = make_unit(fake, HWButtonSettingsGet)
        args = unit.args_parser().parse_args(["--multitap", "-a", "--taps", "1", "-f", "BATTERY"])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        self.assertEqual(fake.short_written, [(ButtonType.A, ButtonPressFunction.BATTERY)])
        self.assertEqual(fake.written, [])
        self.assertIn("1 tap (short-press)", out.getvalue())

    def test_taps_two_preserves_the_other_slots_and_threshold(self):
        fake = FakeCmd(bindings_a=(1, 2, 3, 4), bindings_b=(5, 6, 7, 8), threshold_ms=400)
        unit = make_unit(fake, HWButtonSettingsGet)
        args = unit.args_parser().parse_args(["--multitap", "-a", "--taps", "2", "-f", "BATTERY"])
        with redirect_stdout(io.StringIO()):
            unit.on_exec(args)
        self.assertEqual(
            fake.written,
            [((int(ButtonPressFunction.BATTERY), 2, 3, 4), (5, 6, 7, 8), 400)],
        )

    def test_btnpress_shows_all_ten_bindings(self):
        fake = FakeCmd(bindings_a=(4, 0, 0, 0), bindings_b=(0, 0, 0, 9))
        unit = make_unit(fake, HWButtonSettingsGet)
        args = unit.args_parser().parse_args([])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        printed = out.getvalue()
        self.assertIn("A short (1 tap)", printed)
        self.assertIn("A long", printed)
        self.assertIn("A 2 taps", printed)
        self.assertIn("A 3 taps", printed)
        self.assertIn("A 4 taps", printed)
        self.assertIn("A 5 taps", printed)
        self.assertIn("B short (1 tap)", printed)
        self.assertIn("B long", printed)
        self.assertIn("B 2 taps", printed)
        self.assertIn("B 5 taps", printed)
        self.assertIn("250 ms", printed)

    def test_multitap_command_shows_the_table_and_threshold(self):
        fake = FakeCmd(bindings_a=(4, 0, 0, 0), bindings_b=(0, 0, 0, 9), threshold_ms=300)
        unit = make_unit(fake)
        args = unit.args_parser().parse_args([])
        out = io.StringIO()
        with redirect_stdout(out):
            unit.on_exec(args)
        printed = out.getvalue()
        self.assertIn("Multi-tap button bindings", printed)
        self.assertIn("Button A 2 taps", printed)
        self.assertIn("Button A 5 taps", printed)
        self.assertIn("Button B 2 taps", printed)
        self.assertIn("Button B 5 taps", printed)
        self.assertIn("300 ms", printed)
        self.assertEqual(fake.written, [])


if __name__ == '__main__':
    unittest.main()
