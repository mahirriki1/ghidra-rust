# Windows x64

The desktop uses eframe/egui with native OpenGL. It runs without WSL, Java,
Python, an external Ghidra checkout, or a SQLite installation. Use trusted
binaries and trusted `.grproj` files: Windows Job Objects restrict worker
resources and lifetime, but do not isolate its filesystem or network access.
SQLite project parsing runs in a GUI background thread.

## Run the prebuilt EXE

Download `ghidra-rust-VERSION-windows-x64.exe` to a local Windows folder, then
double-click it. It opens the desktop directly; Rust, Visual Studio, WSL, Java,
Python, and a separate SQLite installation are unnecessary. The file can be
renamed or moved to another local folder. Windows x64 and a working OpenGL
graphics driver are required.

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
In the built-in file chooser, enter a directory such as `D:\Binaries` into the
location field and press **Go**, or enter an absolute file path in **File name**.
Spaces and Unicode paths are supported. UNC/network shares (including
`\\wsl.localhost`), mapped network drives, device paths, and alternate data streams
are rejected. Copy files to a local drive before opening them.

The EXE launches its own disposable worker with inherited stdio pipes, no worker
console, a suspended startup, and a resource-limited kill-on-close Job Object.
The GUI process must be allowed to start a child process and assign it to a job.
A restrictive parent job or endpoint policy can prevent analysis; the app reports
this failure instead of proceeding without its worker controls.

If a file such as standard Rufus 4.15 has `UPX0`/`UPX1` sections, it may be
UPX-packed: the visible entry point belongs to its unpacker rather than the
original program. Detected conventional UPX images show an explanation and skip
decompilation/function discovery to avoid exhausting worker memory. Unpack a
separate copy with UPX (`upx -d -o unpacked.exe original.exe`) and open that copy
to analyze the original code. The app does not run or unpack input executables.

## Reproduce the Windows checks and portable ZIP

With the prerequisites installed, this runs the full local checks, including
compiling the original C fixture with MSVC. Run it before pushing; the Windows CI
job runs the same script with `-SkipTests`:

```powershell
rustup run 1.98.1-x86_64-pc-windows-msvc powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
```

The script checks formatting, runs Windows unit tests and a real PE worker/project
test, runs strict Clippy, builds the release GUI, then repeats the worker/project
test against the **release GUI-subsystem EXE**. The latter checks that worker pipes
also function without a console. It saves, atomically replaces, and reopens an
embedded `.grproj`, including CFG/pseudocode mappings, Unicode filenames, file
identity/write exclusion, and extracted-binary cleanup. Build products stay under
`target` (or `CARGO_TARGET_DIR`). No toolchain is installed by the script.

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

Local validation on Windows x64 with Rust 1.98.1 and MSVC passed the unit/UI and
debug/release PE integration checks, and exercised the release OpenGL desktop,
project saving, and reopening embedded saved analysis. Graphics and endpoint
policies still vary by machine. The GitHub Actions run for a commit shows only
its hosted build; Windows test results come from local runs.

## Desktop check

1. Launch the release EXE on the local Windows desktop. Open
   `target\windows-fixture\sample.exe` produced by the build script.
2. Select the entry point. Verify Listing, Function Graph, and Decompiler show
   results. Select an instruction and a mapped pseudocode expression in turn;
   verify the corresponding selection changes. Check navigation/history and
   rename a function with **L**.
   Select a supported local in the Decompiler, press **L**, and rename it. Check
   its declaration and uses, navigate away/back, then undo with **Ctrl+Z**.
   Double-click a direct call name and return with **Alt+Left**.
3. In Strings, find `aGVsbG8gcmV2ZXJzZXI=` and decode Base64 to `hello reverser`.
   Run FindCrypt and check the AES S-box result.
4. Save a project to a local writable directory with **Include binary in project**
   enabled. Add a comment and save again to exercise replacement. Close the binary
   after checking the comment in Listing, Graph and Decompiler and filtering it
   in **View → Annotations**. Save a local rename too; after reopening, refresh
   the function to check that its verified name is replayed.
   Reopen the `.grproj`; verify annotations, saved graph/pseudocode, and
   selection. If discovery ran before saving, verify References and Data accesses
   show **Saved analysis** on reopen. Run Discover to replace them with fresh
   results; **Analysis → Rediscover from scratch** starts another pass. Refresh
   the function to exercise a new worker for the embedded input.
5. Repeat with **Include binary in project** disabled. Reopening must ask you to
   locate the original binary and verify its hash. Close the app and verify no
   analysis-worker process remains.

PE export names and x64 exception-table function entries now load automatically.
The fixture should list `branch_loop`; its integration test also removes exports
from a private copy to verify recovery of stripped functions. For large images,
the 262,144-function list prioritizes the entry point, exports, and nearby runtime
functions and displays **Partial function list**. **G** accepts a known function's
hexadecimal virtual address. Open **Analysis notes** for coverage limits.

Windows ARM64 PE inputs use the AArch64 Windows ABI; ARM64 unwind-based function
recovery and import-veneer naming remain deferred. See
[architecture coverage](architectures.md). These are input formats, not a native
ARM64 Windows desktop build claim.

Import slots and recognized x86 jump thunks gain their imported names, but PDB types,
API prototypes, library signature matching, delay imports, and Control Flow Guard
substitutions remain incomplete. **Discover functions** can find additional
functions, but complete function/name recovery is not guaranteed. Compare file
SHA-256 values and the same function address against Ghidra; a saved Ghidra program
may predate an installed application's update.

An intermittent worker-start rejection was observed during local release testing:
`Worker initial thread was not suspended exactly once`. It did not recur across
123 subsequent contained worker starts. The cause is unconfirmed; the error now
includes the actual `ResumeThread` return count for diagnosis. Startup fails
closed and terminates that worker; the app does not bypass the suspension or Job
Object checks. Record the returned count if the problem recurs.

If the desktop cannot create an OpenGL context, update the graphics driver from
the GPU vendor and try a local desktop session. Remote/virtual sessions can expose
different graphics capabilities. If compilation cannot find `link.exe`, `cl.exe`,
or Windows SDK libraries, repair the C++ workload/SDK or build from an **x64 Native
Tools Command Prompt for Visual Studio**. A GNU/MinGW toolchain check on Linux
does not substitute for the native MSVC build, bundled SQLite C compilation,
linking, worker execution, or this desktop check.
