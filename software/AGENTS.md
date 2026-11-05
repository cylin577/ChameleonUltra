# Software (Python CLI + native helpers + web console)

## Package management

- Uses `uv` (see `software/pyproject.toml`, `software/uv.lock`). Runtime deps: colorama, prompt-toolkit, pyserial, cryptography. Dev deps: ruff, pyrefly.
```
cd software && uv sync
```

The package is built with hatchling; `script/` is installed as top-level modules and the `chameleonultra` entry point maps to `chameleon_cli_main:main`.

## Run CLI

```
cd software && uv tool install --editable .   # installs `chameleonultra` on PATH
chameleonultra
```

- The install is editable, so the tool reads `software/script/` live: Python edits take effect immediately, and `script/bin/` (native helpers) plus `script/dictionaries/` resolve in place. It needs the checkout to stay put — it is not a self-contained binary. Re-run the install with `--force` only if the checkout moves.
- Legacy (no uv): `cd software/script && python3 -m pip install -r requirements.txt && python3 chameleon_cli_main.py`.

- Connect device first (`hw connect`); most tests/commands require a device.

## Native helpers

`software/src/` is a CMake project (mfkey, nested, darkside, hardnested, etc.) that builds into `software/script/bin/`. Required for `hf mf` key-recovery commands.

```
cd software/src && mkdir -p out && cd out && cmake .. && make -j
```

## Tests

Python unit tests live in `software/script/tests/` (unittest, not pytest).

```
cd software/script && uv run --project .. python -m unittest discover -s tests
# single file
cd software/script && uv run --project .. python -m unittest tests.test_canary_cmd
```

- `test_ultra.py` requires a connected device (7 failures expected in CI-less env).
- `test_hard_acquire.py` is a manual script, not a unittest module.
- Ruff/pyrefly are available (`uv run ruff check script/`, `uv run pyrefly check`) but the codebase currently has many lint/type findings; not a clean gate.

## Web console

`software/Web/` is a static single-page Web Bluetooth console (`phreakbyte.html`); no build step. Docs in `software/Web/instructions.md`.

## Command reference

`docs/command.md` is generated from the live CLI parser:

```
cd software/script && python3 gen_command_md.py > ../../docs/command.md
```