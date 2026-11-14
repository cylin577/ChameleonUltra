# ChameleonUltra (Phreakbyte fork)

Phreakbyte is a UF2-bootloader fork of RfidResearchGroup/ChameleonUltra: nRF52840 firmware plus a Python CLI. GPLv3.

## Layout

- `firmware/` — nRF52840 firmware (C, Nordic SDK, GCC ARM). See `firmware/AGENTS.md`.
- `software/` — Python CLI (`script/`), native C helpers (`src/`), web console (`Web/`). See `software/AGENTS.md`.
- `hardware/` — schematics/PCBs. `docs/` — fork docs. `resource/` — DFU keys, drivers, tools.

## Build & release

- Every push to `main` (touching `firmware/**`) triggers `.github/workflows/build-dfu.yaml`: builds 4 firmware variants (ultra/lite × recovery/standalone) and publishes a `nightly` GitHub release. Tag pushes `v*` publish versioned releases.
- Device version comes from `git describe` against `v*.*` tags (`firmware/Makefile.defs`); `hw version` reports tag + commits + short hash. Do not rewrite history / expect version bumps without tags.
- **Local build caveat (this box is arm64):** `nrfutil` is installed but the `nrf5sdk-tools` plugin is not available for arm64, so `build.sh` stops at DFU packaging (`nrfutil nrf5sdk-tools pkg generate`). Firmware still compiles via `make` in `firmware/application` and `firmware/bootloader`; DFU/UF2 artifacts come from GitHub CI. Use `CURRENT_DEVICE_TYPE=ultra|lite`.
- `firmware/tools/dfu_pkg_check.py` verifies DFU packages (init hash byte order, ECDSA signature, signing key vs the bootloader key); `--legacy` writes a pre-SDK-15 variant.
- `firmware/build.sh` runs that verifier on every package it builds; a failing check aborts the build, so no bad package can reach a release.

## Quick commands

```
# firmware (compile only locally)
cd firmware && CURRENT_DEVICE_TYPE=ultra ./build.sh        # full build; DFU step fails locally
cd firmware/application && make -j
cd firmware/bootloader && make -j

# software
cd software && uv sync                        # dev deps for lint/tests
cd software && uv tool install --editable .   # installs the `chameleonultra` CLI

# tests
cd software/script && uv run --project .. python -m unittest discover -s tests
make -C firmware/application/src/tests test
make -C firmware/application/src/standalone_modes/tests test
make -C firmware/application/src/rfid/nfctag/lf/tests test
```

## Build & commit (user notes)

- Use `make -j5` for local testing (not -j or other counts).
- Every push to `main` (touching `firmware/**`) triggers the nightly DFU build CI.
  Do not push until work is fully done and verified locally.
- DFU/UF2 artifacts come from CI; local builds are compile-only on this arm64 box.

## Conventions

- Indent: 4 spaces for C/Python (root `.editorconfig`: `*.{c,h,py}`).
- Standalone modes are off by default; opt in via env vars or `firmware/standalone_modes.mk` (gitignored).
- `software/script/bin/` holds built native helpers; regenerate with CMake (see `software/AGENTS.md`).
- Command reference is generated: `cd software/script && python3 gen_command_md.py > ../../docs/command.md`.

## Don't

- Don't assume `nrf5sdk-tools` works locally on arm64; route DFU builds to CI.
- Don't commit `standalone_modes.mk` or build artifacts under `firmware/objects/`, `software/src/out/`.