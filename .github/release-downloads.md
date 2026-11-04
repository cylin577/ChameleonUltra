<!-- chameleon-downloads -->
## Downloads

Every release attaches 20 firmware artifacts (5 per build) plus GitHub's
automatically generated source archives, 22 files in total.

| File | Device / variant | What it is / when to use |
|---|---|---|
| `ultra-dfu-bl.zip` | Ultra, regular | SoftDevice + composite bootloader. First-time install over serial DFU (`flash-dfu-sdbl.sh`). |
| `ultra-application.uf2` | Ultra, regular | Application-only UF2. Drag-and-drop app updates. |
| `ultra-dfu-app.zip` | Ultra, regular | Application-only serial DFU package. |
| `ultra-dfu-full.zip` | Ultra, regular | SoftDevice + bootloader + application serial DFU package (flash everything). |
| `ultra-fullimage.uf2` | Ultra, regular | Whole image (MBR + SD + BL + app). For an external programmer / SWD only. |
| `ultra-standalone-dfu-bl.zip` | Ultra, standalone | SoftDevice + composite bootloader, standalone modes enabled. |
| `ultra-standalone-application.uf2` | Ultra, standalone | Application-only UF2 with standalone modes enabled. |
| `ultra-standalone-dfu-app.zip` | Ultra, standalone | Application-only serial DFU package, standalone modes enabled. |
| `ultra-standalone-dfu-full.zip` | Ultra, standalone | Full serial DFU package, standalone modes enabled. |
| `ultra-standalone-fullimage.uf2` | Ultra, standalone | Whole image, standalone modes enabled. |
| `lite-dfu-bl.zip` | Lite, regular | SoftDevice + composite bootloader. First-time install over serial DFU. |
| `lite-application.uf2` | Lite, regular | Application-only UF2. Drag-and-drop app updates. |
| `lite-dfu-app.zip` | Lite, regular | Application-only serial DFU package. |
| `lite-dfu-full.zip` | Lite, regular | Full serial DFU package (flash everything). |
| `lite-fullimage.uf2` | Lite, regular | Whole image (MBR + SD + BL + app). For an external programmer / SWD only. |
| `lite-standalone-dfu-bl.zip` | Lite, standalone | SoftDevice + composite bootloader, standalone modes enabled. |
| `lite-standalone-application.uf2` | Lite, standalone | Application-only UF2 with standalone modes enabled. |
| `lite-standalone-dfu-app.zip` | Lite, standalone | Application-only serial DFU package, standalone modes enabled. |
| `lite-standalone-dfu-full.zip` | Lite, standalone | Full serial DFU package, standalone modes enabled. |
| `lite-standalone-fullimage.uf2` | Lite, standalone | Whole image, standalone modes enabled. |
| `Source code (zip)` | All | Repository snapshot (zip). |
| `Source code (tar.gz)` | All | Repository snapshot (tar.gz). |

## Verifying

CI does not publish a checksum file. Check a downloaded file yourself:

```
shasum -a 256 ultra-application.uf2
```

GitHub shows the SHA256 digest of each attached asset on the release page.

Every published DFU package is checked in CI (init hash, ECDSA signature, and
the signing key against the public key the bootloader trusts) before it is
attached. To check a downloaded package yourself:

```
python3 firmware/tools/dfu_pkg_check.py --check ultra-dfu-app.zip
```

The tool prints `PASS` for the package when all of those checks pass.
