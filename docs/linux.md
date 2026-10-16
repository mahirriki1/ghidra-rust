# Linux x64

The Linux desktop is a native Rust executable. It does not need a Rust, Java,
or Python runtime. It requires a conventional glibc-based x86-64 Linux system,
an OpenGL-capable X11 or Wayland desktop, and compatible system shared libraries.
Analysis workers require **bubblewrap** (`bwrap`), working unprivileged user
namespaces, and the conventional `/usr`-based filesystem described in the README.
The app reports sandbox startup failures rather than starting an unrestricted
worker. Nix-style layouts and other architectures are not covered by this package.

## Run a download

Extract `ghidra-rust-VERSION-linux-x64.tar.gz`, enter the extracted directory, and
launch the desktop:

```sh
./ghidra-rust
```

For the separately downloaded executable, give it execute permission first:

```sh
chmod +x ghidra-rust-VERSION-linux-x64
./ghidra-rust-VERSION-linux-x64
```

Replace `VERSION` with the downloaded version. The tar.gz includes documentation,
dependency/font licenses, and `BUILD-INFO.json`; retain the notices when
redistributing the application. Install bubblewrap and the runtime packages for
your distribution, and run the app from your normal desktop session.

## Runtime compatibility

The package does not bundle glibc, the graphics driver, or every desktop library.
The tagged-release workflow builds on Ubuntu 24.04; this is the intended build
baseline, not a claim that the executable runs on every Linux distribution.
`BUILD-INFO.json` records its measured GLIBC symbol requirement and direct
shared-library dependencies. X11/Wayland and OpenGL components loaded at runtime
are additional requirements. Use `ldd ./ghidra-rust` on a trusted downloaded build
to diagnose missing direct libraries.

A package made locally inherits that build machine's library requirements.
The current local Arch/WSL build requires `GLIBC_2.43`; it is not a substitute for
a package actually built and tested on the Ubuntu 24.04 release runner. Build on
your oldest supported distribution and test on each intended target. An AppImage
or distro-specific installer is not produced by these scripts.

Ubuntu 24.04 and some other distributions can additionally restrict unprivileged
user namespaces through local security policy. Bubblewrap must be allowed by that
policy; do not disable the application's worker sandbox to make it launch.

## Build and desktop check

Follow [building and shipping each version](releases.md) for prerequisites and
`scripts/build-linux.sh`. Python 3.11+ is a packaging tool on the build machine
only; it is not distributed with or used by the desktop.

Open the original C fixture built by the worker tests or compile it manually as
shown in [the fixture guide](../tests/fixtures/README.md). Check listing/CFG and
decompiler results, mapped instruction selection, navigation/renaming, strings
and decoding, FindCrypt, and saving/reopening an embedded `.grproj`. Verify the
input bytes remain unchanged and workers exit when the app closes. Projects
still require trusted sources because SQLite parses them in a GUI background
thread.
