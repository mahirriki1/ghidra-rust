# Build, package, and release

## Repeatable local builds

Use Rust 1.98.1 with `rustfmt` and `clippy`. Build and test each desktop on
its native platform. GitHub Actions runs the same build scripts with tests
disabled. Report the platforms you ran locally.

On Ubuntu 24.04, install the build and packaging dependencies, then run:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends -y \
  build-essential pkg-config binutils python3 openssl bubblewrap \
  libx11-dev libxi-dev libxrandr-dev libxcursor-dev libxinerama-dev \
  libxkbcommon-dev libwayland-dev libgl1-mesa-dev
rustup toolchain install 1.98.1 --component rustfmt,clippy
rustup run 1.98.1 bash scripts/build-linux.sh
```

Linux worker tests require working unprivileged user namespaces.
[Linux runtime setup](linux.md#runtime-compatibility) ·
[Windows build and package steps](windows.md#reproduce-the-windows-checks-and-portable-zip)

The scripts format-check, lint, test, build, and package. Find the outputs in
`target/dist` or `CARGO_TARGET_DIR/dist`.

| Platform | Standalone executable | Portable archive |
| --- | --- | --- |
| Linux x64 | `ghidra-rust-VERSION-linux-x64` | `ghidra-rust-VERSION-linux-x64.tar.gz` |
| Windows x64 | `ghidra-rust-VERSION-windows-x64.exe` | `ghidra-rust-VERSION-windows-x64.zip` |

Each download has a `.sha256` file. The archives include the headless tool,
documentation, and notices. Keep the notices with redistributed copies.
Use `python3 scripts/package-linux.py` or `.\scripts\package-windows.ps1`
to package an existing native release build.

The scripts run tests with `--features test-hooks`, which adds worker fault
hooks for tests only. The release executables they package are built
without it. Each
packager runs both staged executables with a test fault argument and stops
before publishing anything unless each refuses it. A build made with
`--features test-hooks` therefore cannot be packaged, even when you run a
packager directly.

Each packager reads executables from one Cargo target directory and one
release layout, so the probed, archived, and standalone executables are the
same build.

- **Target directory:** `--target-directory` (`-TargetDirectory` on
  Windows), then a nonempty `CARGO_TARGET_DIR`, then Cargo metadata, which
  includes Cargo config. A relative path resolves against the current
  directory, as Cargo does for `CARGO_TARGET_DIR`.
- **Layout:** `--target` (`-Target`) names the native triple for builds made
  with Cargo `--target`, or `host` for plain `release`. Without it, a nonempty
  `CARGO_BUILD_TARGET` is used. Otherwise the packager takes the only
  complete executable pair and fails if both layouts have one.

## Automatic releases after main updates

**Automatic main release** runs after a push to `main`. It chooses the next
patch above the highest version tag unless the manifest requests a higher
version. The tag points at a snapshot with matching manifest and lockfile
versions. Main keeps its development version.

The workflow builds both platforms, verifies the assets, and publishes a
GitHub Release. Versions below 1.0.0 are pre-releases. The description
collects new or amended release-note entries since the previous published
version and includes the complete commit history.
[Writing release notes](release-notes/README.md)

Rerun the same Actions run to retry a failed build or draft upload with its
reserved tag. Failed builds can leave gaps in version numbers. To start a
new release from current main, use manual dispatch on `main`. Preparation and
publication need write access through the workflow's `GITHUB_TOKEN`.

## Manual version tags and GitHub Actions

Set the application version in `Cargo.toml` and `Cargo.lock`, commit it, and
push a matching `vX.Y.Z` tag. **Versioned native packages** validates the
version and builds both platforms. Manual dispatch builds a chosen revision.
Download the `ghidra-rust-linux-x64` and `ghidra-rust-windows-x64` artifacts
from Actions within 14 days. Publish a GitHub Release separately if needed.

## Release checks

Run the native desktop check on each intended platform. The hosted jobs
verify formatting, lint, build, and package output. Local worker and GUI
checks cover runtime behavior. [Linux desktop check](linux.md#build-and-desktop-check) ·
[Windows desktop check](windows.md#desktop-check)

Checksums detect file changes when obtained from a trusted source. The
executables are unsigned at the OS level. The separate update manifest
authenticates releases for the in-app updater.

## In-app updates

1. On Linux x64 or Windows x64, choose **Help → Check for updates…**.
   Alpha builds can see newer pre-releases.
2. Choose **Download update** and review the verified license and dependency
   notices. Accept the notices to enable **Install and restart**.
3. Resolve the save/discard prompt. The updater replaces the desktop at its
   existing path, which must be writable. A saved project reopens on restart.

The updater verifies the signed manifest and hashes the executable and
notices. A rejected download or failed replacement leaves the old executable
in place. A failed relaunch leaves the verified new executable installed.
Windows reports errors in a dialog. Linux writes them to stderr.

The updater replaces only the desktop executable. Download a fresh archive
to update the headless tool or the bundled docs. To roll back, download an
older release and check that it supports your project version. Windows
temporary cleanup is best effort. If the failure dialog identifies a
temporary folder, remove it after the updater exits.

### Configure release signing once

Keep the private Ed25519 key outside the repository. It must match
`data/update-public-key.txt`. Configure the `UPDATE_SIGNING_KEY` Actions
secret with the PEM. Without a signing key, releases remain downloadable but
in-app installation is unavailable.

```sh
gh secret set UPDATE_SIGNING_KEY --repo mahirriki1/ghidra-rust < /secure/path/update-signing.pem
```

For a new fork before distribution, change the repository constants in the
updater and signer, remove the inherited public key, and initialize a new one.
Existing clients trust the old key, so rotation after distribution requires a
transition signed by that key.

```sh
python3 scripts/sign-updates.py --init-key /secure/path/update-signing.pem
```

For manual releases, verify the asset directory, sign it, then upload
`update.json`, `update.json.sig`, and the versioned update notices with the
native assets.

```sh
python3 scripts/verify-release-assets.py target/release-assets
python3 scripts/sign-updates.py --sign target/release-assets --key-file /secure/path/update-signing.pem
python3 -m unittest discover -s scripts -p 'test_updates.py'
```
