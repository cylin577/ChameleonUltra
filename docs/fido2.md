# FIDO2 / CTAP2 authenticator (the `u2f` standalone mode)

The `u2f` standalone mode turns the ChameleonUltra into a FIDO2 authenticator.
One authenticator, three transports, one shared core:

| Transport | Protocol | Where the code lives |
|-----------|----------|-----------------------|
| NFC | ISO-14443-4 T=CL. `NFCCTAP_MSG` (INS `0x10`) carries a CTAP2 command. The U2F applet (AID `A0000006472F0001`, INS `0x01`/`0x02`) stays as the CTAP1 fallback. | `firmware/application/src/standalone_modes/mode_u2f.c` |
| USB | CTAPHID: 64-byte HID reports on usage page `0xF1D0`, USB interface 2. | `firmware/application/src/standalone_modes/fido2_hid.c` |
| BLE | FIDO GATT service `0xFFFD`. | `firmware/application/src/standalone_modes/fido2_ble.c` |
| Host link | `DATA_CMD_FIDO2_CTAP` (1067): `u8 ctap_cmd | u8[] cbor` → `u8 ctap_status | u8[] response`. | `firmware/application/src/app_cmd.c` |

All transports hand their bytes to the same transport-independent core,
`firmware/application/src/standalone_modes/fido2_core.c`, which owns the CBOR
codec, the crypto and a single request slot. The CTAP1 (U2F) path shares the
core's master key and sign counter, so the counter never repeats across the two
protocol versions.

A transport that cannot be registered is switched off automatically: if the
SoftDevice or the FIDO GATT service fails to come up, the firmware keeps
running and the mode offers only the transports that really work.

> **Verification status:** this implementation is covered by host unit tests
> and compile-only firmware builds. No ChameleonUltra hardware was available in
> this checkout, so USB CTAPHID, BLE FIDO GATT and NFC CTAP2 interoperability,
> physical-button timing and the NFC wait-for-UP timeout still need hardware
> testing.

> **This repository contains no GitHub wiki.** Everything about this feature
> lives in this file and in the sources it names. The upstream project has a
> wiki, but it does not describe this fork's authenticator, and this fork does
> not mirror or link a wiki of its own.

## Build

The mode is **off by default** (all standalone modes are). Build it with:

```sh
cd firmware/application
make -j CURRENT_DEVICE_TYPE=ultra STANDALONE_U2F=1
```

`CURRENT_DEVICE_TYPE` is `ultra` (default) or `lite`. The build also needs
micro-ecc vendored into `firmware/application/src/crypto/micro-ecc/` — the
whole repository, because `uECC.c` includes its `.h` and `.inc` files.

For a persistent configuration, copy `firmware/standalone_modes.mk.sample` to
`firmware/standalone_modes.mk` and set `STANDALONE_U2F=1` there; the Makefile
picks that file up automatically.

The USB CTAPHID interface needs the USB HID class, so the build also enables
`APP_USBD_HID_ENABLED` / `APP_USBD_HID_GENERIC_ENABLED` in
`firmware/application/src/sdk_config.h`. CDC (the serial CLI) keeps USB
interfaces 0 and 1; the FIDO HID interface is number 2.

## Arm it

```sh
standalone set-mode u2f     # no --opt-in needed: the mode writes no tag/slot
```

Then press the **TOGGLE** button to arm it (blue LED). While armed, the
authenticator answers on whichever transport the peer uses. Disarm with the
same button or `standalone disarm`.

**User presence is granted by pressing either button A or B (short press) while
the mode is armed — no button binding required.** You will see a green
triple-flash confirming the grant. The grant lasts 5 seconds and is consumed
by one CTAP2 operation.

You can also bind `STANDALONE_ACTION` to a button for the traditional flow:

```sh
hw settings btnpress -b -s -f STANDALONE_ACTION
hw settings store
```

CTAP2 uses `none` attestation, so no key/cert is needed for CTAP2. The CTAP1
`REGISTER` reply does carry an attestation certificate; provision one with:

```sh
firmware/tools/gen_u2f_attestation.sh          # make a P-256 key + cert
hw u2f set-attestation -k att.key -c att.crt   # stored in FDS, survives reboot
```

## What CTAP2 works

| Feature | State |
|---------|-------|
| `authenticatorGetInfo` (0x04) | implemented |
| `authenticatorMakeCredential` (0x01) | implemented, non-resident, `none` attestation |
| `authenticatorGetAssertion` (0x02) | implemented, allow-list checked against the handle MAC |
| User verification / client PIN | **not** implemented |
| Resident keys (`rk`) | **not** implemented (the authenticator reports `rk: false`) |
| `authenticatorReset` | **not** implemented |
| `authenticatorGetNextAssertion` | **not** implemented |
| `pinUvAuthProtocols`, `maxMsgSize` | **not** reported |
| Packed / basic attestation | **not** implemented (`none` only) |

That is the UV-discouraged, second-factor profile. WebAuthn sites that insist
on a passkey (UV required) will refuse this authenticator, and that is the
expected answer, not a bug.

`authenticatorMakeCredential` and `authenticatorGetAssertion` require a
physical user-presence gesture. USB and BLE advertise
`KEEPALIVE(UP_NEEDED)` while the request waits; NFC holds the ISO-DEP request
until the gesture arrives. Press **either button A or B** (short press) once. You will see a green
triple-flash confirming the grant. The grant expires after 5 seconds and is
consumed by one CTAP2 operation.
`authenticatorGetInfo` does not require user presence.

The host CLI/web link is synchronous and cannot carry CTAP KEEPALIVE frames.
Press **either button A or B** (short press) first — you will see a green
triple-flash — then send the MakeCredential or GetAssertion command within 5
seconds. Without that prior physical grant the firmware rejects the host request
with CTAP status `0x27` (operation denied). `standalone trigger` may arm the
mode from the host, but it deliberately cannot grant user presence.

## Talking to it from the host

The CLI and the web console both drive the same core over the device link.

```sh
hw u2f get-info
```

prints the decoded `authenticatorGetInfo` answer:

```
 - CTAP status: 0x00 (ok)
 - Response:
     1: ['FIDO_2_0', 'U2F_V2']
     3: h'00000000000000000000000000000000'
     4: {'rk': False, 'up': True, 'clientPin': False, 'makeCredUvNotRqd': True}
     9: ['usb', 'nfc', 'ble']
```

`hw u2f ctap` sends an arbitrary CTAP2 command:

```sh
hw u2f ctap --cmd get-info
hw u2f ctap --cmd make-credential --rp-id example.com \
    --client-data-hash 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
hw u2f ctap --cmd get-assertion --rp-id example.com \
    --client-data-hash <64 hex chars> --cred-id <128 hex chars>
hw u2f ctap --cmd get-info --raw a16e636c69656e7444617461486173684100
```

`--raw` replaces the CBOR parameters with raw hex, for commands this CLI does
not wrap yet.

The web console has the same commands in its terminal tab: `hw u2f get-info`
and `hw u2f ctap ...`. The CBOR codec is shared between the Python CLI
(`software/script/fido2_cbor.py`) and the page (`software/Web/fido2_cbor.js`).

The device has to be armed for these commands to do anything: with no armed
transport the firmware answers CTAP status `0x01` (invalid command).

## Architecture

```
firmware/application/src/standalone_modes/
  fido2_core.c/.h   transport-independent CTAP2 core: CBOR, SHA-256/HMAC,
                    ECDSA, stateless key wrapping, the request slot
  fido2_hid.c/.h    CTAPHID transport (64-byte reports, INIT/PING/CBOR/CANCEL)
  fido2_ble.c/.h    FIDO GATT 0xFFFD transport (fragmented device data)
  mode_u2f.c        the standalone mode: NFC glue (T=CL), FDS hooks, RNG
```

**Stateless key wrapping, no per-credential flash.** A credential's private
key is derived on the fly:

```
priv = HMAC-SHA256(mk, 0x01 | rpIdHash32 | nonce32)   (P-256 scalar)
kh   = nonce32 | HMAC-SHA256(mk, 0x02 | rpIdHash32 | nonce32)
```

Only a 32-byte master key and a 4-byte global counter live in FDS (file
`0x1020`). The handle's MAC binds it to its `rpId`, so a handle cannot be
replayed on another origin. Crypto is self-contained SHA-256/HMAC plus
micro-ecc (uECC) for P-256.

**Keys live in internal flash, not a secure element.** This is a research
device: the master key is readable with physical access and a flash reader.
Do not use it as your only second factor for anything that matters.

## Tests

```sh
make -C firmware/application/src/standalone_modes/tests test
(cd software/script && uv run --project .. python -m unittest \
    tests.test_fido2_cbor tests.test_fido2_requests)
node software/Web/tests/test_multitap_web.js
```

The host test suite covers the core (GetInfo, options, algorithms, UP,
allow-list matching, CBOR, key derivation and signatures), CTAPHID INIT/CANCEL
and buffer separation, the BLE UUID/revision constants, and the Python/web CTAP
request encoders. It does not replace the hardware checks listed above.

## Not implemented, on purpose

- **U2F over CTAPHID (`CTAPHID_MSG` with CTAP1 commands).** CTAP1 stays on NFC
  only; the USB and BLE transports speak CTAP2.
- **BTDIS.** The BLE transport does the FIDO GATT service only.
- **PIN / UV.** No client PIN, no built-in UV, no `pinUvAuthParam`.
