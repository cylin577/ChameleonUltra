#!/usr/bin/env python3
"""
download_artifacts.py — Download CI artifacts from GitHub releases into firmware/objects/.

Usage:
    python3 download_artifacts.py                    # Download from 'nightly' release
    python3 download_artifacts.py --tag v1.2.3       # Download from specific tag
    python3 download_artifacts.py --latest           # Download from latest release
    python3 download_artifacts.py --all              # Download all variants (recovery + standalone)
    python3 download_artifacts.py --device ultra     # Only download ultra artifacts
    python3 download_artifacts.py --device lite      # Only download lite artifacts

Artifacts are saved to firmware/objects/ with names matching what build.sh produces:
    ultra-dfu-bl.zip, ultra-dfu-app.zip, ultra-dfu-full.zip, ultra-application.uf2, ultra-fullimage.uf2
    (and lite-*, plus *-standalone-* variants if --all is used)
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path


def get_repo_from_git():
    """Get the GitHub repo from the git remote origin."""
    try:
        result = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            capture_output=True, text=True, check=True
        )
        url = result.stdout.strip()
        # Handle both HTTPS and SSH URLs
        # https://github.com/user/repo.git -> user/repo
        # git@github.com:user/repo.git -> user/repo
        if url.startswith("https://github.com/"):
            repo = url[len("https://github.com/"):].removesuffix(".git")
        elif url.startswith("git@github.com:"):
            repo = url[len("git@github.com:"):].removesuffix(".git")
        else:
            # Fallback: try to extract user/repo from any github URL
            match = re.search(r"github\.com[/:]([^/]+/[^/]+)", url)
            if match:
                repo = match.group(1).removesuffix(".git")
            else:
                return "Phreakbyte/ChameleonUltra"  # default fallback
        return repo
    except Exception:
        return "Phreakbyte/ChameleonUltra"  # default fallback


REPO = get_repo_from_git()
ARTIFACT_PATTERNS = {
    "recovery": [
        "ultra-dfu-bl.zip",
        "ultra-dfu-app.zip",
        "ultra-dfu-full.zip",
        "ultra-application.uf2",
        "ultra-fullimage.uf2",
        "lite-dfu-bl.zip",
        "lite-dfu-app.zip",
        "lite-dfu-full.zip",
        "lite-application.uf2",
        "lite-fullimage.uf2",
    ],
    "standalone": [
        "ultra-standalone-dfu-bl.zip",
        "ultra-standalone-dfu-app.zip",
        "ultra-standalone-dfu-full.zip",
        "ultra-standalone-application.uf2",
        "ultra-standalone-fullimage.uf2",
        "lite-standalone-dfu-bl.zip",
        "lite-standalone-dfu-app.zip",
        "lite-standalone-dfu-full.zip",
        "lite-standalone-application.uf2",
        "lite-standalone-fullimage.uf2",
    ],
}


def run(cmd, check=True, capture=True):
    """Run a shell command."""
    result = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{result.stderr}")
    return result


def has_gh():
    """Check if gh CLI is available."""
    try:
        run("gh --version", check=False)
        return True
    except Exception:
        return False


def get_release_info(tag=None, latest=False):
    """Get release info from GitHub API using gh CLI or direct HTTP."""
    if has_gh():
        if tag:
            cmd = f"gh release view {tag} --repo {REPO} --json name,tagName,assets"
        elif latest:
            cmd = f"gh release view --latest --repo {REPO} --json name,tagName,assets"
        else:
            cmd = f"gh release view nightly --repo {REPO} --json name,tagName,assets"
        result = run(cmd)
        return json.loads(result.stdout)
    else:
        # Fallback to direct GitHub API
        if tag:
            url = f"https://api.github.com/repos/{REPO}/releases/tags/{tag}"
        elif latest:
            url = f"https://api.github.com/repos/{REPO}/releases/latest"
        else:
            url = f"https://api.github.com/repos/{REPO}/releases/tags/nightly"

        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())


def download_with_gh(tag, asset_name, dest):
    """Download an asset using gh CLI."""
    cmd = f"gh release download {tag} --repo {REPO} -p '{asset_name}' -O '{dest}' --clobber"
    run(cmd)


def download_with_http(asset_url, dest):
    """Download an asset using HTTP."""
    req = urllib.request.Request(asset_url, headers={"Accept": "application/octet-stream"})
    with urllib.request.urlopen(req) as resp, open(dest, "wb") as f:
        f.write(resp.read())


def filter_assets(assets, device=None, include_standalone=False):
    """Filter assets by device and variant."""
    patterns = ARTIFACT_PATTERNS["recovery"]
    if include_standalone:
        patterns += ARTIFACT_PATTERNS["standalone"]

    if device:
        patterns = [p for p in patterns if p.startswith(f"{device}-")]

    # Match assets to expected patterns
    asset_map = {a["name"]: a for a in assets}
    matched = {}
    for pattern in patterns:
        if pattern in asset_map:
            matched[pattern] = asset_map[pattern]
    return matched


def main():
    parser = argparse.ArgumentParser(description="Download CI artifacts from GitHub releases")
    parser.add_argument("--tag", help="Specific release tag (e.g., v1.2.3)")
    parser.add_argument("--latest", action="store_true", help="Download from latest release")
    parser.add_argument("--all", action="store_true", help="Include standalone variants")
    parser.add_argument("--device", choices=["ultra", "lite"], help="Only download for this device")
    parser.add_argument("--list", action="store_true", help="List available assets without downloading")
    args = parser.parse_args()

    # Determine release
    if args.tag:
        tag = args.tag
    elif args.latest:
        tag = "latest"
    else:
        tag = "nightly"

    print(f"Fetching release info for '{tag}'...")
    try:
        release = get_release_info(tag=args.tag, latest=args.latest)
    except Exception as e:
        print(f"Error fetching release: {e}", file=sys.stderr)
        return 1

    assets = release.get("assets", [])
    print(f"Release: {release.get('tagName')} ({len(assets)} assets)")

    matched = filter_assets(assets, args.device, args.all)

    if not matched:
        print("No matching artifacts found.")
        if args.list:
            print("\nAvailable assets:")
            for a in assets:
                print(f"  {a['name']} ({a['size']} bytes)")
        return 1

    print(f"\nFound {len(matched)} matching artifacts:")
    for name, asset in matched.items():
        size_mb = asset["size"] / (1024 * 1024)
        print(f"  {name} ({size_mb:.1f} MB)")

    if args.list:
        return 0

    # Determine output directory
    script_dir = Path(__file__).parent
    objects_dir = script_dir.parent / "objects"
    objects_dir.mkdir(exist_ok=True)
    print(f"\nDownloading to {objects_dir}...")

    # Download each asset
    for name, asset in matched.items():
        dest = objects_dir / name
        print(f"  Downloading {name}...", end=" ", flush=True)
        try:
            if has_gh():
                download_with_gh(release["tagName"], name, str(dest))
            else:
                download_with_http(asset["browser_download_url"], str(dest))
            print("done")
        except Exception as e:
            print(f"FAILED: {e}")
            return 1

    print(f"\nAll artifacts downloaded to {objects_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())