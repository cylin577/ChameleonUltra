# Standalone Modes — Tester's Guide

This is a host-less workflow subsystem for ChameleonUltra. With it, you can
configure the device once over USB/BLE, walk away with the device, run
captures or workflows using the two physical buttons, then come back and
pull the results.

arm        → "I'm starting a session"      (one gesture per session)
trigger    → "capture now"                  (many gestures per session)
disarm     → "I'm done, back to normal"    (one gesture per session)

This guide walks through bench-testing the feature end-to-end. It assumes
you have a ChameleonUltra (not Lite — the only mode that does anything
useful, AuthTrace, needs reader hardware) and that you've built and flashed
the firmware with the standalone-modes patch applied.

If you find something that doesn't behave the way this doc describes,
that's exactly the kind of bug I want to hear about.


## What you need

- A **ChameleonUltra** with the standalone-modes firmware flashed.
- The matching **CLI** (`chameleon_cli_main.py` from the same patch set —
  the firmware exposes new commands the unpatched CLI doesn't know about).
- A **MIFARE Classic** card (1K or 4K) for AuthTrace testing. Any card
  you have keys for works; even a card you don't have keys for is useful
  for capturing key-discovery traces.
- Optional: `mfkey32v2` from the Proxmark3 repo, if you want to verify
  that captured traces actually recover keys.


## Quick start (5 minutes)

This is the lowest-friction path — uses CLI for everything, so you can verify
the firmware works without touching device buttons.

```
# 1. Confirm the firmware speaks the new commands
chameleon --> standalone status
state: DISARMED  mode: DISABLED  flags: (none)

# 2. Pick a mode and configure it
chameleon --> standalone set-mode authtrace
ok: state=DISARMED mode=AUTHTRACE flags=0x00

chameleon --> standalone config --block 4 --key-type A --key FFFFFFFFFFFF --timeout 5000 authtrace
ok: type=A block=4 timeout=5000ms key=ffffffffffff

# 3. Place a MIFARE card on the CU antenna, then trigger a capture
chameleon --> standalone trigger
triggered

# 4. Pull the result
chameleon --> standalone get-result --dump
1 authtrace sessions

=== session #0  status=ok ===
  -->  [  7 bits]  26
  <--  [ 16 bits]  0400
  -->  [ 16 bits]  9320
  <--  [ 40 bits]  XXXXXXXXXX        (your card's UID + BCC)
  -->  [ 72 bits]  9370...
  <--  [ 24 bits]  08...             (SAK + CRC)
  -->  [ 32 bits]  6004XXXX          (AUTH KEY_A block 4 + CRC)
  <--  [ 32 bits]  XXXXXXXX          (NT - tag nonce)
  -->  [ 64 bits]  XXXXXXXXXXXXXXXX  (NR || AR)
  <--  [ 32 bits]  XXXXXXXX          (AT)
```

If you got something that looks like the output above, the feature works. The
rest of this doc is about exercising the device-side buttons and the other
modes.


## Button functions (reference)

Standalone is driven by single-button functions. Bind them first with
`hw settings btnpress`, e.g.:

```
hw settings btnpress -a -l -f STANDALONE_TOGGLE
hw settings btnpress -b -l -f STANDALONE_ACTION
hw settings btnpress -b -s -f STANDALONE_CLEAR
hw settings store
```

| Function | Event | Action |
|---|---|---|
| `STANDALONE_ACTION` | `BOTH_SHORT` | Mode's primary action (capture / advance slot / etc.) |
| `STANDALONE_TOGGLE` | `BOTH_LONG` | Toggle arm / disarm |
| `STANDALONE_CLEAR`  | `BOTH_VLONG` | Destructive — clear captured data |

The `BOTH_*` event names are historical. A button bound to one of these no
longer does its previous job.

A button can also bind a function to a tap count (`hw settings btnpress -a
--multitap --taps 3 -f STANDALONE_ACTION`). While any 2-5 tap binding is set
on a button, that button's single tap waits for the inter-tap threshold
(default 250 ms) before it runs, so a short-press bound standalone action on
the same button is delayed by that threshold -- check that delay when testing
a button that carries both a short and a multi-tap binding. When a higher tap
count is bound on the same button, the lower one also waits for the threshold.


## LED feedback

CU has 8 RGB slot LEDs, all driven by one shared color. The feedback patterns:

| Pattern | Meaning |
|---|---|
| Color sweep across LEDs, then solid | Just armed in the mode color |
| Reverse sweep, then off | Just disarmed |
| Red double-flash | Refused (mode needed `--opt-in`) |
| Green triple-flash | Successful operation (e.g. card captured) |
| Red triple-flash | Failed operation (e.g. buffer full) |
| Quick mode-color wave | Long operation starting/ending |

Mode colors:

| Mode | Color | Notes |
|---|---|---|
| AuthTrace | Magenta | May appear as blue/cyan on some CU hardware |
| Slot Cycle | Yellow | |

If magenta looks wrong on your unit, that's a known cosmetic issue —
the underlying capture still works, it's just the indication that's off.
Cosmetic palette tweaks live in `firmware/application/src/standalone_led.c`
at `m_palette[]`.


## AuthTrace mode workflow

What it does: each trigger fires one HF14A reader-side authentication
attempt and captures the complete wire trace (REQA, ATQA, anticollision,
SELECT, SAK, RATS/ATS if present, auth command, NT, NR||AR, AT). Stores up
to 8 sessions; you pull them when you're back at the bench.

Use case: walk up to a reader/card pair, capture 2+ sessions on the same
block with the same key, walk back, feed the traces to mfkey32v2 to recover
the actual block key.

**Bench test — device buttons only:**

```
# Set the mode (still over CLI — modes persist in FDS)
chameleon --> standalone set-mode authtrace
chameleon --> standalone config --block 4 --key-type A --timeout 3000 authtrace

# Disconnect USB if you want a fully host-less test. Optional.

# === Now on the device ===
# Press the TOGGLE button → magenta LED sweep → ARMED
# Place card on antenna
# Press the ACTION button → quick flash → one session captured
# Repeat with same card 2-3 times (need ≥2 sessions for mfkey32v2)
# Press the TOGGLE button → reverse sweep → DISARMED

# === Reconnect USB ===
chameleon --> standalone get-result --dump
# Shows the captured sessions
```

**Verifying the data with mfkey32v2:**

From any pair of sessions on the same card/block/key-type, extract:

```
UID  = first 4 bytes of the anticollision response (5-byte response, last byte is BCC)
NT   = the 4-byte tag response after the auth command
NR   = first 4 bytes of the 8-byte reader response  
AR   = last 4 bytes of the 8-byte reader response
```

Then:

```
mfkey32v2 <UID> <NT0> <NR0> <AR0> <NT1> <NR1> <AR1>
```

If mfkey32v2 prints a 12-hex-char key, the capture is good and the key
actually works for that block + key-type.

**Config knobs:**

```
standalone config --block N --key-type A|B --key <12 hex> --timeout MS authtrace
```

- `--block`: target block to authenticate against. Defaults to 4 (first
  block of sector 1, typical user data on a fresh card). For
  key-discovery use 0 (manufacturer block, every card has it).
- `--key-type`: `A` or `B`. Default `A`.
- `--key`: 6-byte candidate key as 12 hex chars. Doesn't need to be
  correct — auth-fail sessions are still useful (NT + NR||AR are what
  mfkey32v2 wants). Default `FFFFFFFFFFFF`.
- `--timeout`: how long the device polls for a card before giving up,
  in ms. 100–30000. Default 3000.

Read the current config (no setters, no write):

```
standalone config authtrace
```


## Slot Cycle mode workflow

What it does: rotates through enabled emulation slots at a configurable
interval. No tag interaction, no flash writes, no destructive side
effects. The simplest possible reference mode — handy for verifying the
button/arm/disarm path on a unit without reading the AuthTrace output.

**Bench test:**

```
chameleon --> standalone set-mode slot_cycle

# Press the TOGGLE button → yellow LED sweep → ARMED, starts cycling
# Watch the slot LEDs change every few seconds
# Press the ACTION button → manually advance one slot
# Press the CLEAR button → pause/resume (slot_cycle's CLEAR action)
# Press the TOGGLE button → disarm
```

By default it cycles through all 8 slots at 3000 ms each. Currently the only
way to change timing is to set the config blob via raw bytes (no fancy
config flags in the CLI yet). If you need that, file a bug.


## U2F / FIDO2 mode workflow

What it does: the device becomes a FIDO2 authenticator. CTAP2 is served over
NFC (NFCCTAP_MSG), USB (CTAPHID) and BLE (FIDO GATT 0xFFFD); the old U2F
applet stays as the CTAP1 fallback on NFC. There is nothing to "capture" and
no result buffer — the mode is a live service.

**Bench test:**

```
chameleon --> standalone set-mode u2f
# Press the TOGGLE button -> the mode color sweep -> ARMED

# Then, over the same link:
chameleon --> hw u2f get-info
```

Expected shape:

```
 - CTAP status: 0x00 (ok)
 - Response:
     1: ['FIDO_2_0', 'U2F_V2']
     3: h'00000000000000000000000000000000'
     4: {'rk': False, 'up': True, 'clientPin': False, 'makeCredUvNotRqd': True}
     9: ['usb', 'nfc', 'ble']
```

If the status is `0x01` (invalid command), the mode is not armed — arm it and
try again. `GetInfo` does not require user presence.

To exercise CTAP2 user presence:

1. Send `MakeCredential` or `GetAssertion` over USB, BLE or NFC.
2. USB/BLE clients should report `KEEPALIVE(UP_NEEDED)`; NFC keeps the reader
   waiting.
3. Physically short-press the button bound to `STANDALONE_ACTION`.
4. Confirm the operation completes. The grant expires after 5 seconds and is
   consumed by one operation.

Bind that button first if needed:

```
hw settings btnpress -b -s -f STANDALONE_ACTION
hw settings store
```

Over the serial/web host link, press ACTION physically first and send the CTAP
command within 5 seconds. `hw u2f ctap --cmd make-credential --rp-id
example.com --client-data-hash <64 hex chars>` then exercises the credential
path; a successful answer carries the credential id, which `hw u2f ctap --cmd
get-assertion --rp-id ... --cred-id <128 hex chars>` can use. Without the
prior physical grant the host path returns CTAP status `0x27` (operation
denied). `standalone trigger` may arm the mode, but it cannot grant user
presence.

The transports can be checked independently:

- **USB:** plug the device in while armed; it enumerates as a FIDO HID
  device (usage page `0xF1D0`). `hw u2f get-info` over the serial link proves
  the core is alive, but the USB transport only answers when a CTAPHID client
  talks to it.
- **BLE:** pair and look for the `0xFFFD` service.
- **NFC:** present the device to an NFC reader. CTAP2 needs a host that speaks
  NFCCTAP (Android/Chrome, desktop browsers over NFC); the CTAP1 applet works
  with the older U2F NFC path.

Not supported, by design: client PIN, resident keys, user verification,
`authenticatorReset`, `authenticatorGetNextAssertion`, packed/basic
attestation, and U2F-over-CTAPHID. See
[`docs/fido2.md`](../../../../docs/fido2.md) for the full matrix.

**Host test suites** (no hardware needed):

```
make -C firmware/application/src/standalone_modes/tests test   # core + HID + BLE + nfc_canary
(cd software/script && uv run --project .. python -m unittest \
    tests.test_fido2_cbor tests.test_fido2_requests)
node software/Web/tests/test_multitap_web.js                  # includes the JS CBOR codec
```

These checks are hardware-free. This checkout has no ChameleonUltra available
for an end-to-end run, so USB CTAPHID, BLE FIDO GATT and NFC CTAP2
interoperability, physical-button timing and the NFC wait-for-UP timeout are
still unverified on real hardware.


## CLI reference

All commands live under the `standalone` subgroup:

```
standalone status                     Show current state, mode, flags
standalone set-mode <name> [--opt-in] Pick the active mode
standalone config <mode> [knobs...]   Read/write mode-specific config
standalone trigger                    Manually fire the active mode's primary action
                                       (not a physical-UP gesture)
standalone get-result [--dump|--json|--raw|-f FILE]
                                      Read the active mode's result buffer
standalone clear-result               Discard captured results
```

**Mode names:** `disabled`, `autoclone`, `read_replay`, `authtrace`,
`slot_cycle`, `dict_check`, `emul_trace`, `relay`, `hf14a_tap_sniff`,
`nfc_canary`, `gdb_gateway`, `u2f`. (Only the modes compiled into your
firmware are available — `standalone ls` shows what this build has.)

**`--opt-in`** is required for any future mode that writes to tag memory
or modifies emulation slots. Not needed for AuthTrace or Slot Cycle.


## Persistence behavior

What survives a reboot:

- Selected mode and flags (saved to FDS file `0x1010`, record `0x0001`)
- Per-mode config blobs (saved to FDS file `0x1010`, record `0x0100 + mode_id`)

What does NOT survive a reboot:

- The armed/disarmed state — every boot starts DISARMED, even if you were
  armed when power was lost
- Captured session data (lives in RAM only)

This means: configure once, captures must be pulled before powering off.
If you walk away with a USB battery and capture 8 sessions over hours,
make sure the device stays powered until you can drain the result buffer.


## Troubleshooting

**`standalone` subcommand doesn't exist in the CLI**

You're using an unpatched CLI. The standalone commands are added by the
same patch as the firmware — both halves need to be in sync.

**Button doesn't arm the device (no LED sweep)**

Check that a button is bound to `STANDALONE_TOGGLE` (`hw settings btnpress`)
and that a mode is selected. `standalone status` shows whether arming
succeeded — `state: ARMED_IDLE` means yes. `standalone trigger` arms from the
host.

**LEDs are the wrong color**

CU's LED hardware has some quirks where certain RGB enum values render
differently on different units. Doesn't affect functionality. Swap colors
in `standalone_led.c::m_palette[]` if it bothers you.

**Device disconnects ("Serial Error")**

If you can reproduce a disconnect with a specific sequence of commands,
please report it with the exact command order and what was happening on
the device (armed/disarmed, captures in buffer, etc.). The most useful
debugging info is whether the disconnect is deterministic or
intermittent.

**AuthTrace captures with `status=no_tag`**

The device polled for a card during the timeout window and didn't find
one. Check: is the card actually in the antenna's field? CU's HF antenna
is at the top of the device, sweet spot is about 0–10mm from the card.

**AuthTrace captures with `status=auth_fail`**

Tag responded but the auth didn't complete — usually means the candidate
key in your config is wrong. That's fine — the NT and NR||AR from the
trace are still captured and useful for mfkey32v2 attacks. You don't
need correct keys to capture key-recovery traces.

**`get-result` returns empty after captures**

Result buffer is RAM-only and clears on reboot. If the device reset
between capture and read, the captures are gone. If you didn't reboot,
double-check the active mode matches the mode you captured in.


## Reporting bugs

Useful details to include in a bug report:

- Firmware version (`hw version` output)
- Hardware variant (Ultra/Lite, hw rev if you know it)
- Exact CLI command sequence to reproduce
- What you expected to happen
- What actually happened (verbatim CLI output, with the prompt lines)
- Whether it's deterministic (always happens) or intermittent

If the device crashes, including the state it was in (`standalone status`
output right before the crash) is high-value. If you have SEGGER RTT
hooked up to read `NRF_LOG_*` output, attach the log lines — the
standalone subsystem emits diagnostic logs that pinpoint a lot of
failures.
