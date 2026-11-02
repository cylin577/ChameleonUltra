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

## Quick commands

```
# firmware (compile only locally)
cd firmware && CURRENT_DEVICE_TYPE=ultra ./build.sh        # full build; DFU step fails locally
cd firmware/application && make -j
cd firmware/bootloader && make -j

# software
cd software && uv sync
cd software/script && uv run --project .. python chameleon_cli_main.py

# tests
cd software/script && uv run --project .. python -m unittest discover -s tests
make -C firmware/application/src/tests test
make -C firmware/application/src/standalone_modes/tests test
make -C firmware/application/src/rfid/nfctag/lf/tests test
```

## Conventions

- Indent: 4 spaces for C/Python (root `.editorconfig`: `*.{c,h,py}`).
- Standalone modes are off by default; opt in via env vars or `firmware/standalone_modes.mk` (gitignored).
- `software/script/bin/` holds built native helpers; regenerate with CMake (see `software/AGENTS.md`).
- Command reference is generated: `cd software/script && python3 gen_command_md.py > ../../docs/command.md`.

## Don't

- Don't assume `nrf5sdk-tools` works locally on arm64; route DFU builds to CI.
- Don't commit `standalone_modes.mk` or build artifacts under `firmware/objects/`, `software/src/out/`.