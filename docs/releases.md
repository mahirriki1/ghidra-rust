# Building and shipping each version

Rust's `cargo build --release --locked` compiles and links the native desktop.
Windows uses the x64 MSVC linker and Windows SDK. The target-specific setting in
`.cargo/config.toml` links the MSVC runtime statically; SQLite, engine data, and
fonts are also included in the application. The Windows output is an EXE. Linux
produces an ELF executable that uses compatible system libraries and a desktop
graphics driver. Neither shipped application needs Rust, Java, or Python.

## Repeatable local builds

Use Rust 1.98.1 with `rustfmt` and `clippy`. Build each operating system on that
operating system; a cross-typecheck does not produce a tested native release.

On Linux x64, install a C/C++ toolchain, pkg-config, binutils (`strip`/`readelf`),
Python 3.11 or newer, the X11/Wayland/OpenGL development libraries, and bubblewrap.
Python is used only to assemble the release package. On Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends -y \
  build-essential pkg-config binutils python3 bubblewrap \
  libx11-dev libxi-dev libxrandr-dev libxcursor-dev libxinerama-dev \
  libxkbcommon-dev libwayland-dev libgl1-mesa-dev
rustup toolchain install 1.98.1 --component rustfmt,clippy
rustup run 1.98.1 bash scripts/build-linux.sh
```

On Windows x64, install Rust and Visual Studio Build Tools with **Desktop
development with C++** and the Windows SDK. From PowerShell in a local checkout:

```powershell
rustup toolchain install 1.98.1-x86_64-pc-windows-msvc --component rustfmt,clippy
rustup run 1.98.1-x86_64-pc-windows-msvc powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
```

Both scripts check formatting, unit tests, strict Clippy, the release build, and
the real release worker integration test before packaging. They write the
following files under `target/dist` (or `CARGO_TARGET_DIR/dist`):

| Platform | Direct executable | Complete distribution |
| --- | --- | --- |
| Linux x64 | `ghidra-rust-VERSION-linux-x64` | `ghidra-rust-VERSION-linux-x64.tar.gz` |
| Windows x64 | `ghidra-rust-VERSION-windows-x64.exe` | `ghidra-rust-VERSION-windows-x64.zip` |

Each file has an adjacent `.sha256` checksum. Names and package metadata come
from `Cargo.toml`; the scripts do not contain a release version to edit. The
complete distributions include documentation, `LICENSE`, `NOTICE`, and dependency
and embedded-font notices. Retain those notices when redistributing the app.

To package an already-built release without rerunning the build checks:

```sh
python3 scripts/package-linux.py
```

```powershell
.\scripts\package-windows.ps1
```

Linux packaging strips a copy of the executable to reduce download size and
leaves the original build output intact. Its `BUILD-INFO.json` records the
compiler, direct shared-library dependencies, and measured GLIBC symbol versions.
Read [Linux runtime compatibility](linux.md) and the [Windows guide](windows.md)
before shipping to another machine.

## Version tags and GitHub Actions

For each release:

1. Change `[package].version` in `Cargo.toml`. Update the corresponding
   `ghidra-rust` entry in `Cargo.lock`, or run `cargo check` to refresh it.
2. Commit the intended application changes, version, lockfile, and workflow files.
3. Create and push a matching version tag. For example, after setting `0.0.2`:

   ```sh
   git tag -a v0.0.2 -m "Ghidra Rust 0.0.2"
   git push origin v0.0.2
   ```

The **Versioned native packages** workflow checks that the tag is exactly
`v<Cargo.toml version>` and that the lockfile agrees. It then calls the same
Linux and Windows build jobs used by regular CI. Linux builds on `ubuntu-24.04`;
Windows builds on `windows-2025`. An incorrect tag/version fails before the
expensive builds. You can also run the workflow manually from GitHub Actions
to build the selected revision without creating a tag.

After both jobs succeed, download **ghidra-rust-linux-x64** and
**ghidra-rust-windows-x64** from that workflow run's **Artifacts** section.
Artifact storage lasts 14 days. For permanent public downloads, create a GitHub
Release for the tag and attach the versioned executable, archive, and checksum
files from both artifacts. The workflow has read-only repository permissions and
does not create or publish a GitHub Release itself.

GitHub documents [version-tag workflow triggers](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#push)
and [workflow artifact downloads](https://docs.github.com/en/actions/tutorials/store-and-share-data).

## Release checks

Run the desktop checks in each platform's guide on the intended systems before
publishing. Worker tests and headless UI tests do not test every graphics driver.
Windows remains for trusted inputs and trusted project files; its Job Objects
are resource controls rather than a filesystem/network sandbox.

The packages are unsigned. Checksums detect changes when obtained through a
trusted channel, but do not authenticate the publisher. Signing and automatic
publication are separate from this build-and-package workflow. A configured
workflow is not evidence of a successful hosted run; inspect the actual jobs and
their test results for the tagged commit.
