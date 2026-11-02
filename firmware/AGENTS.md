# Firmware (nRF52840)

C firmware built with Nordic nRF5 SDK + ARM GCC. Device types: `ultra` (default) and `lite`.

## Build

```
cd firmware
CURRENT_DEVICE_TYPE=ultra ./build.sh     # or lite
```

- `CURRENT_DEVICE_TYPE` selects ultra/lite (default ultra). Unknown value aborts.
- Standalone modes are compile-time flags (`STANDALONE_*`), all default 0. Persist via `firmware/standalone_modes.mk` (gitignored; copy from `standalone_modes.mk.sample`) or one-shot env prefix, e.g. `STANDALONE_AUTOCLONE=1 ./build.sh`. CI builds a recovery variant (none) and a standalone variant (all modes).
- `build.sh` runs `make` in `bootloader/` and `application/`, then packages DFU zips/UF2 in `objects/`. It requires `nrfutil` **with the nrf5sdk-tools plugin**, `mergehex` (shim using `intelhex`), `arm-none-eabi-gcc`, and `zip`.
- **arm64 local builds cannot produce DFU packages** (`nrf5sdk-tools` unavailable on arm64). Compile-only via `make -C application` / `make -C bootloader`; get DFU/UF2 artifacts from GitHub CI (`build-dfu.yaml`).

## Flash

- UF2: enter UF2 mode (hold A, plug USB), then `./flash-uf2-app.sh` (copies `objects/*-application.uf2` to `CHAMELEON` drive).
- DFU: `./flash-dfu-app.sh` / `flash-dfu-full.sh` / `flash-dfu-sdbl.sh` (requires serial DFU device `1915:521f` and nrfutil).
- Bootloader lives at `0xF3000` (44 KB) and is a superset of stock: UF2 + CDC serial DFU. Stock firmware installs through it; no bootloader swap needed.

## Tests (host, no hardware)

```
make -C firmware/application/src/tests test
make -C firmware/application/src/standalone_modes/tests test
make -C firmware/application/src/rfid/nfctag/lf/tests test
```

- DESFire core tests: `cd firmware/application/src/rfid/nfctag/hf/desfire/tests && make test` (default mbedtls backend needs `mbedtls3` headers/libs; on this box only mbedtls 2.28 is installed, so use `CRYPTO_BACKEND=tiny` only if `tiny-crypto-c` is available).

## Layout

- `application/` — app firmware + Makefile (standalone flags, source list).
- `bootloader/` — composite UF2/CDC bootloader.
- `common/`, `nrf52_sdk/` — shared code / vendored SDK (patched).
- `tools/` — `uf2conv.py`, `RECOVERY_BUILD.md`, `UF2_INSTALL.md`.
- `application/src/standalone_modes/` — standalone mode framework; `CONTRIBUTING STANDALONE.md`, `TESTING.md`.