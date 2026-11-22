# Windows x64

## Run the prebuilt EXE

Download `ghidra-rust-VERSION-windows-x64.exe` or extract the portable ZIP and
double-click `ghidra-rust.exe`. Use a local Windows 10 or newer x64 desktop
with an OpenGL driver. The EXE is unsigned. Download it from a trusted source and use the
adjacent `.sha256` file to check the download.
[GitHub Releases](https://github.com/mahirriki1/ghidra-rust/releases)

Put the app, inputs, projects, and temp folder on local drives with working
file IDs. NTFS is recommended. The file chooser supports spaces and Unicode.
Press **Ctrl+L** to type a path. UNC shares, mapped network drives, alternate
data streams, and device paths are unsupported.

## Build and launch

Install Rust through rustup and Visual Studio Build Tools with **Desktop
development with C++**, the x64 MSVC toolchain, a Windows SDK, and **C++ Clang
tools for Windows** (`Microsoft.VisualStudio.Component.VC.Llvm.Clang`). The
build script needs its clang and lld-link for the DWARF PE fixtures. Open a new
PowerShell window and run these commands in a native checkout.
[Rust setup for Windows](https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup)

```powershell
rustup toolchain install 1.98.1-x86_64-pc-windows-msvc --component rustfmt,clippy
cargo +1.98.1-x86_64-pc-windows-msvc build --release --locked --target x86_64-pc-windows-msvc
.\target\x86_64-pc-windows-msvc\release\ghidra-rust.exe
```

The menu bar contains window controls. Drag an empty part to move the window
or double-click it to maximize or restore. Drag the edges to resize.

Each worker is created inside its own kill-on-close Job Object, so the job
applies before the worker runs. The job limits it to one process and 2 GiB
of process memory. The worker inherits only its protocol and diagnostic pipes
and has no console. A watchdog limits CPU time per request and ends the worker
with exit code 124, which the app reports as the CPU time limit. The worker
retains filesystem and network access, and SQLite parses projects in the
desktop. **Use trusted binaries and projects.**

### Debug info on Windows

Windows always runs optional DWARF work in a separate, single-use sibling
worker with its own Job Object. The sibling opens its own copy of the binary,
so it can briefly add a second snapshot to memory use. Starting it, opening
the image, and replaying names count against a setup budget. The budget is
two seconds for the first sibling of an image, then adapts between one and
five seconds. The render gets its own budget once the sibling is ready. On a
cold or busy system, the function can keep its inferred prototype with
`Debug setup timed out`. A later Refresh gets at least the same budget. Use
the `performance` host trace to measure the phases. Linux timings say nothing
about Windows latency. [Debug information](analysis.md#debug-information)

## Reproduce the Windows checks and portable ZIP

Install Python 3.11+ on PATH as `python` to collect dependency notices during
packaging. Run this from the repository root.

```powershell
rustup run 1.98.1-x86_64-pc-windows-msvc powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
```

The script builds the PE fixture and the clang DWARF PE fixtures, runs checks
including worker integration, and packages the EXE, ZIP, and checksums in
`target\dist`, or `CARGO_TARGET_DIR\dist`. Tests use `--features test-hooks`
in debug and release, and the DWARF tests check the fixture's named
declarations in both. Release tests also run the desktop executable in worker
mode to exercise its inherited pipes. The packaged executables are built
without the feature. GitHub Actions runs the script with `-SkipTests`.

To check the packaging gate natively, pass release pairs built with and
without the feature:

```powershell
.\scripts\test-package-windows.ps1 -HookedRelease <dir> -CleanRelease <dir>
```
[Release workflow](releases.md)

## Native updater process checks

The build script sets `GHIDRA_RUST_TEST_UPDATER_DRIVER` for the native
updater tests. These exercise process replacement, project handoff,
cancellation, and cleanup, including with the release GUI subsystem.

```powershell
cargo build --locked --target x86_64-pc-windows-msvc --example updater-test-driver
$env:GHIDRA_RUST_TEST_UPDATER_DRIVER = (Resolve-Path target/x86_64-pc-windows-msvc/debug/examples/updater-test-driver.exe).Path
cargo test --locked --target x86_64-pc-windows-msvc --test windows_updater
```

If you set `CARGO_TARGET_DIR`, resolve the driver under that directory.

## Desktop check

Open `target\windows-fixture\sample.exe` in the release desktop. Check
Listing, Graph, and Decompiler selection, then follow a call and go Back.
Rename and undo, add a comment, and reopen an embedded and an external
project. Verify saved provenance, unchanged fixture bytes, and worker
shutdown. [Fixture checklist](../tests/fixtures/README.md)

Then open `target\windows-fixture\sample-dwarf.exe`. Check that inferred
code is usable while optional work runs and that the debug declaration
replaces it in place. Click an instruction or call during the wait and check
that selection still follows its exact mapping. Save during an optional
render and reopen to see the saved inferred view, then Refresh and save the
debug view. Navigate or close during a render and check that the next
function still works.

## Troubleshooting

- If OpenGL startup fails, try a local desktop session with a working driver.
- If `cl.exe`, `link.exe`, or SDK libraries are missing, check the C++ workload
  and try an **x64 Native Tools Command Prompt for Visual Studio**.
- If the build script reports missing clang or lld-link, add **C++ Clang
  tools for Windows** to the Build Tools installation.
- If a parent job or endpoint policy blocks creating the worker inside its
  job, the app reports the startup failure and stops analysis.
- If a PE is flagged as a conventional UPX stub, the app can still show
  listing, graph, strings, and bytes. [Packed-image coverage](analysis.md#confirmed-calls-and-functions)
