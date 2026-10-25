# Linux x64

The Linux desktop is a native Rust executable. It does not need a Rust, Java,
or Python runtime. It requires a conventional glibc-based x86-64 Linux system,
an OpenGL-capable X11 or Wayland desktop, and compatible system shared libraries.
Analysis workers require **bubblewrap** (`bwrap`), working unprivileged user
namespaces, and the conventional `/usr`-based filesystem described under
[Worker isolation](#worker-isolation).
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

Locally built packages inherit the build host's library requirements. Inspect
`BUILD-INFO.json` and test on each intended distribution. The scripts do not
produce an AppImage or distro-specific installer.

Ubuntu 24.04 and some other distributions can additionally restrict unprivileged
user namespaces through local security policy. Bubblewrap must be allowed by that
policy; do not disable the application's worker sandbox to make it launch.
Ubuntu supplies its purpose-built `bwrap-userns-restrict` profile in the optional
`apparmor-profiles` package. On Ubuntu 24.04 with AppArmor enabled, an administrator
can install and load that distribution-provided profile:

```sh
sudo apt-get install --no-install-recommends -y apparmor apparmor-profiles
if [ ! -e /etc/apparmor.d/bwrap-userns-restrict ]; then
  sudo install -m 0644 \
    /usr/share/apparmor/extra-profiles/bwrap-userns-restrict \
    /etc/apparmor.d/bwrap-userns-restrict
fi
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
```

This uses Ubuntu's scoped policy and leaves the global user-namespace restriction
enabled. See [Ubuntu's security explanation](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007)
and [profile packaging announcement](https://lists.ubuntu.com/archives/noble-changes/2024-September/041745.html).
Load it before running the worker tests locally; the hosted Linux build job
does not run tests and does not need it.

## Build and desktop check

Follow [building and shipping each version](releases.md) for prerequisites and
`scripts/build-linux.sh`. Python 3.11+ and OpenSSL support packaging and update
signing tests on the build machine; neither is used by the desktop.

Build the [original C fixture](../tests/fixtures/README.md) and check Listing/CFG,
mapped pseudocode selection, call navigation/history, rename/undo, strings,
decoding, FindCrypt, Hex, and embedded/external project save/reopen with saved
provenance. Verify unchanged input bytes and worker shutdown. See
[project trust boundaries](analysis.md#resource-limits-and-trust-boundaries).

## Worker isolation

Workers use bubblewrap private namespaces, no network, restricted read-only
system-library mounts, a read-only executable, and only the selected input from
user data. The analysis image is immutable for the session. Conventional
`/usr`-based systems are supported, with `/lib` and `/lib64` either mounted
read-only or resolved under `/usr`.

Workers have a 2 GiB address-space limit, an approximately 20-second per-request
CPU budget, no core dumps, and no privilege escalation. Missing containment or
identity setup fails closed. These controls reduce exposure; they do not prove
the app or upstream engine is free of vulnerabilities.

## Troubleshooting

If Wayland/Mesa cannot initialize OpenGL, try the documented X11 software-rendering
fallback:

```sh
env -u WAYLAND_DISPLAY LIBGL_ALWAYS_SOFTWARE=1 cargo run --release --locked
```

Software rendering is a compatibility workaround, not a speed improvement.
