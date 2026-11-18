# Windows x64

## Run the prebuilt EXE

Download `ghidra-rust-VERSION-windows-x64.exe` or extract the portable ZIP and
double-click `ghidra-rust.exe`. Use a local x64 Windows desktop with an OpenGL
driver. The EXE is unsigned. Download it from a trusted source and use the
adjacent `.sha256` file to check the download.
[GitHub Releases](https://github.com/mahirriki1/ghidra-rust/releases)

Put the app, inputs, projects, and temp folder on local drives with working
file IDs. NTFS is recommended. The file chooser supports spaces and Unicode.
Press **Ctrl+L** to type a path. UNC shares, mapped network drives, alternate
data streams, and device paths are unsupported.

## Build and launch

Install Rust through rustup and Visual Studio Build Tools with **Desktop
development with C++**, the x64 MSVC toolchain, and a Windows SDK. Open a new
PowerShell window and run these commands in a native checkout.
[Rust setup for Windows](https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup)

```powershell
rustup toolchain install 1.98.1-x86_64-pc-windows-msvc --component rustfmt,clippy
cargo +1.98.1-x86_64-pc-windows-msvc build --release --locked --target x86_64-pc-windows-msvc
.\target\x86_64-pc-windows-msvc\release\ghidra-rust.exe
```

The menu bar contains window controls. Drag an empty part to move the window
or double-click it to maximize or restore. Drag the edges to resize.

The worker starts suspended and joins a Job Object before it runs. The job
limits it to one process and 2 GiB of process memory. A watchdog also limits
CPU time. The worker retains filesystem and network access, and SQLite
parses projects in the desktop. **Use trusted binaries and projects.**

## Reproduce the Windows checks and portable ZIP

Install Python 3.11+ on PATH as `python` to collect dependency notices during
packaging. Run this from the repository root.

```powershell
rustup run 1.98.1-x86_64-pc-windows-msvc powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
```

The script builds the PE fixture, runs checks including worker integration,
and packages the EXE, ZIP, and checksums in `target\dist`, or
`CARGO_TARGET_DIR\dist`. GitHub Actions runs the script with `-SkipTests`.
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

## Troubleshooting

- If OpenGL startup fails, try a local desktop session with a working driver.
- If `cl.exe`, `link.exe`, or SDK libraries are missing, check the C++ workload
  and try an **x64 Native Tools Command Prompt for Visual Studio**.
- If a parent job or endpoint policy blocks child process creation or job
  assignment, the app reports the failure and stops analysis. If the error
  says the initial thread was not suspended exactly once, record the
  `ResumeThread` count shown in the message.
- If a PE is flagged as a conventional UPX stub, the app can still show
  listing, graph, strings, and bytes. [Packed-image coverage](analysis.md#confirmed-calls-and-functions)
