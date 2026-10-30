# Windows x64

The desktop uses eframe/egui with native OpenGL. It runs without WSL, Java,
Python, an external Ghidra checkout, or a SQLite installation. Use trusted
binaries and trusted `.grproj` files: Windows Job Objects restrict worker
resources and lifetime, but do not isolate its filesystem or network access.
See [project trust boundaries](analysis.md#resource-limits-and-trust-boundaries).

## Run the prebuilt EXE

Download `ghidra-rust-VERSION-windows-x64.exe` to a local Windows folder, then
double-click it. No build tools are required to run it. The file can be renamed
or moved to another local folder. Windows x64 and a working OpenGL driver are required.

Replace `VERSION` with the downloaded version. For producing both Linux and
Windows downloads for each release, see [the release workflow](releases.md).

The matching `.exe.sha256` file contains its SHA-256 checksum. The EXE is unsigned;
obtain it from a trusted source. For documentation, dependency licenses, or
redistribution, use the ZIP bundle described below and retain its notices.

## Build and launch

1. Install [Rust with rustup](https://rustup.rs/) and
   [Visual Studio Build Tools](https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup)
   with **Desktop development with C++**, an **x64/x86 MSVC toolchain**, and
   the **Windows SDK**. Restart PowerShell after installation.
2. Put the repository on a local drive, for example `C:\src\ghidra-rust`.
   Use a native Windows checkout. Input/project files and `%TEMP%` must also be
   on local drives with working file-ID support; NTFS is recommended.
3. From PowerShell in the repository:

   ```powershell
   rustup toolchain install 1.98.1-x86_64-pc-windows-msvc --component rustfmt,clippy
   cargo +1.98.1-x86_64-pc-windows-msvc build --release --locked --target x86_64-pc-windows-msvc
   .\target\x86_64-pc-windows-msvc\release\ghidra-rust.exe
   ```

The first optimized build can take a long time; subsequent builds reuse the
`target` cache. The MSVC runtime and SQLite are
linked into the EXE; there are no application DLLs or engine-data files to copy.
Windows system libraries and a working OpenGL graphics driver are still required.
Release builds open a desktop window without a console. A renderer/window startup
failure displays a native error dialog and returns a failing process exit code.

Choose **Open binary**, **Open project**, or drag a file into the window.
The menu row includes minimize, maximize/restore, and close controls. Drag empty
menu-row space to move the window, double-click it to maximize/restore, or drag
the window edges to resize; there is no separate native title bar.
In the built-in file chooser, pick a drive under Places, or click the path bar
(or press **Ctrl+L**), type a directory such as `D:\Binaries` and press Enter.
You can also enter an absolute file path in **Name**.
Spaces and Unicode paths are supported. UNC/network shares (including
`\\wsl.localhost`), mapped network drives, device paths, and alternate data streams
are rejected. Copy files to a local drive before opening them.

The EXE starts its disposable worker suspended, with inherited stdio pipes and
no console. It assigns a kill-on-close Job Object with a 2 GiB process-memory
limit and one-process limit before resuming; a per-request CPU watchdog also
applies. These controls provide no filesystem or network isolation.
The GUI process must be allowed to start a child process and assign it to a job.
A restrictive parent job or endpoint policy can prevent analysis; the app reports
this failure instead of proceeding without its worker controls.

For detected conventional UPX PE stubs, analysis is restricted as described in
[analysis coverage](analysis.md#confirmed-calls-and-functions). Unpack a separate
copy with `upx -d -o unpacked.exe original.exe`, then open that copy to inspect
the original code. The app does not run or unpack executables.

## Reproduce the Windows checks and portable ZIP

With the prerequisites installed, this runs the full local checks, including
compiling the original C fixture with MSVC. Run it before pushing; the Windows CI
job runs the same script with `-SkipTests`:

```powershell
rustup run 1.98.1-x86_64-pc-windows-msvc powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
```

Python 3.11+ must be on PATH as `python` for build-time dependency notice collection.
The desktop does not require Python.

The script checks formatting, tests, strict Clippy, and the release build,
including worker/project integration against the release GUI-subsystem EXE.
Products stay under `target` (or `CARGO_TARGET_DIR`); it installs no toolchain.

The results under `target\dist` are a directly runnable
`ghidra-rust-VERSION-windows-x64.exe`, a matching `.exe.sha256`, and
`ghidra-rust-VERSION-windows-x64.zip` with its `.zip.sha256` file.
Alternatively, extract the ZIP and double-click its `ghidra-rust.exe`. Rust and Visual Studio
are needed to build it, not to run the extracted desktop. Keep the included
`LICENSE`, `NOTICE`, `THIRD-PARTY.json`, and `third-party` license files when
redistributing the bundle. The package is unsigned. Packaging an existing release
build separately is possible with `scripts\package-windows.ps1`.

After a successful Windows CI run, the same EXE, ZIP, and checksums are retained as
the **ghidra-rust-windows-x64** workflow artifact. The hosted job builds and
packages but runs no tests, so it does not establish a passing native run. The
local tests also do not exercise an actual OpenGL window; use the desktop check
below on the intended machine.

## Native updater process checks

`scripts/build-windows.ps1` builds the disposable `updater-test-driver` fixture and
sets `GHIDRA_RUST_TEST_UPDATER_DRIVER` before running `tests/windows_updater.rs`.
These tests execute the production helper and cleanup entry points with native
Windows processes: replacement of a running app, saved-project handoff,
cancellation, parent-exit timeout, blocked publication, failed relaunch, and
protected-file aliases. They do not open the OpenGL desktop. The build script
repeats these checks with the release fixture's GUI subsystem to exercise inherited
pipes without a console. To run just the debug process checks:

```powershell
cargo build --locked --target x86_64-pc-windows-msvc --example updater-test-driver
$env:GHIDRA_RUST_TEST_UPDATER_DRIVER = (Resolve-Path target/x86_64-pc-windows-msvc/debug/examples/updater-test-driver.exe).Path
cargo test --locked --target x86_64-pc-windows-msvc --test windows_updater
```

Use the matching path beneath `CARGO_TARGET_DIR` if that variable is set.
The optional failure janitor uses Windows' built-in PowerShell; if it is unavailable
or restricted, the error identifies the temporary folder for manual cleanup.

## Desktop check

1. Open `target\windows-fixture\sample.exe` from the release desktop. Verify
   Listing, Function Graph, and Decompiler; select instructions and mapped
   pseudocode in turn. Check call double-click navigation and Back/Forward.
2. Rename a function and supported local with **L**. Verify declaration/uses,
   revisit the function, and undo with **Ctrl+Z**. Add a comment and inspect it
   in Listing, Graph, Decompiler, and **View → Annotations**.
3. Decode the fixture's `aGVsbG8gcmV2ZXJzZXI=` as Base64 (`hello reverser`), and
   check FindCrypt's AES S-box result. In Hex / Memory Map, page and jump by VA,
   select bytes, and Decode selection. Check zero-fill offsets, invalid jumps,
   focus handling, and Retry after cancellation.
4. Save and replace an embedded `.grproj`, then reopen. Check annotations, local
   rename replay after Refresh, selection, and **Saved analysis** provenance.
   Discover replaces saved references; Rediscover starts fresh. Hex page and
   selection remain transient and do not dirty the project.
5. Repeat with **Include binary in project** disabled; reopening must ask for
   the binary and verify its hash. Close the app and check workers exit.

PE export names and x64 exception-table function entries now load automatically.
The fixture should list `branch_loop`; its integration test also removes exports
from a private copy to verify recovery of stripped functions. For large images,
the function list prioritizes the entry point, exports, and nearby runtime
functions. **Partial function list** appears only when entries are omitted.
**G** accepts a known function's hexadecimal virtual address. Click the status-bar
warning indicator for coverage limits.

Windows ARM64 PE supports primary-entry recovery from packed and supported full
unwind records, plus exact ADRP/LDR/BR import-veneer naming. Fragments do not
independently seed functions; parent links and unsupported unwind forms remain
omitted. See [architecture coverage](architectures.md). This is input support,
not a native ARM64 Windows desktop build.

Import slots and recognized x86 jump thunks gain their imported names, but PDB types,
API prototypes, library signature matching, delay imports, and Control Flow Guard
substitutions remain incomplete. **Discover functions** can find additional
functions, but complete function/name recovery is not guaranteed. For comparisons,
follow the [matched measurement guidance](analysis-performance.md).

## Troubleshooting

If startup reports `Worker initial thread was not suspended exactly once`, record
the actual `ResumeThread` return count included in the error. The cause is
unconfirmed. Startup fails closed and terminates the worker rather than bypassing
suspension or Job Object checks.

If the desktop cannot create an OpenGL context, update the graphics driver from
the GPU vendor and try a local desktop session. Remote/virtual sessions can expose
different graphics capabilities. If compilation cannot find `link.exe`, `cl.exe`,
or Windows SDK libraries, repair the C++ workload/SDK or build from an **x64 Native
Tools Command Prompt for Visual Studio**. A GNU/MinGW toolchain check on Linux
does not substitute for the native MSVC build, bundled SQLite C compilation,
linking, worker execution, or this desktop check.
