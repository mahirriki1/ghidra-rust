# Linux x64

## Run a download

Extract `ghidra-rust-VERSION-linux-x64.tar.gz` and run `./ghidra-rust` from
the extracted directory. If you downloaded the standalone executable, give
it execute permission with `chmod +x` first. [GitHub Releases](https://github.com/mahirriki1/ghidra-rust/releases)

You need a glibc-based x86-64 system, an X11 or Wayland desktop with OpenGL,
and bubblewrap (`bwrap`) with working unprivileged user namespaces. Keep the
archive's licenses and notices when redistributing the app.

## Runtime compatibility

Release packages are built on Ubuntu 24.04. Check `BUILD-INFO.json` in the
archive for the measured glibc requirement and direct shared libraries.
Graphics and desktop libraries may also load at runtime. Run
`ldd ./ghidra-rust` on a trusted build to diagnose missing direct libraries.

On Ubuntu 24.04 with AppArmor restrictions, an administrator can load the
distribution's scoped bubblewrap profile. This leaves the system-wide
user-namespace restriction enabled.

```sh
sudo apt-get install --no-install-recommends apparmor apparmor-profiles
if [ ! -e /etc/apparmor.d/bwrap-userns-restrict ]; then
  sudo install -m 0644 \
    /usr/share/apparmor/extra-profiles/bwrap-userns-restrict \
    /etc/apparmor.d/bwrap-userns-restrict
fi
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
```

See the distribution's documentation for other user-namespace policies.
[Ubuntu AppArmor guidance](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007) ·
[Ubuntu profile packaging](https://lists.ubuntu.com/archives/noble-changes/2024-September/041745.html)

## Build and desktop check

Install the native build dependencies and run `scripts/build-linux.sh`.
The script checks the worker and builds the portable archive. Open the C
fixture in the running desktop to check navigation, selection syncing, and
project save/reopen. [Build steps](releases.md#repeatable-local-builds) ·
[Fixture checklist](../tests/fixtures/README.md)

## Worker isolation

Bubblewrap gives the worker private namespaces, no network, and read-only
access to the executable, selected input, and required system libraries.
It requires a conventional `/usr`-based layout. Nix-style layouts are outside
package coverage. If containment or file identity setup fails, analysis stops.

Each worker has a 2 GiB address-space limit and an approximately 20-second
per-request CPU budget. SQLite project parsing runs in the desktop process.
[Project trust boundaries](analysis.md#resource-limits-and-trust-boundaries)

## Troubleshooting

If Wayland/Mesa cannot initialize OpenGL, try X11 software rendering. Use the
downloaded executable in place of the Cargo command if running a package.

```sh
env -u WAYLAND_DISPLAY LIBGL_ALWAYS_SOFTWARE=1 cargo run --release --locked
```
