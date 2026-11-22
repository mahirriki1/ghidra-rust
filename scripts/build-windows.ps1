# Run from PowerShell on Windows with Rust/MSVC tools installed. No downloads or
# system configuration changes are performed by this script. Tests run by
# default; run them locally before pushing. GitHub CI passes -SkipTests and
# only builds, lints, and packages.
[CmdletBinding()]
param([switch]$SkipTests)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
    throw 'Run this script on native Windows x64.'
}

$root = Split-Path $PSScriptRoot -Parent
$previousUpdaterDriver = $env:GHIDRA_RUST_TEST_UPDATER_DRIVER
$previousNotices = $env:GHIDRA_RUST_EMBEDDED_NOTICES
$previousFixture = $env:GHIDRA_RUST_TEST_PE
$previousDwarfFixture = $env:GHIDRA_RUST_TEST_PE_DWARF
$previousCallerFixture = $env:GHIDRA_RUST_TEST_PE_DWARF_CALLER
$previousCppFixture = $env:GHIDRA_RUST_TEST_PE_CPP
Push-Location $root
try {
    $compiler = & rustc -vV
    if ($LASTEXITCODE -ne 0 -or $compiler -notcontains 'host: x86_64-pc-windows-msvc') {
        throw 'Select the x86_64-pc-windows-msvc Rust toolchain (see docs/windows.md).'
    }
    $target = 'x86_64-pc-windows-msvc'
    # The same target directory the packager uses: a nonempty CARGO_TARGET_DIR,
    # otherwise Cargo metadata (which includes Cargo config).
    $targetDir = $env:CARGO_TARGET_DIR
    if ([string]::IsNullOrEmpty($targetDir)) {
        # Windows PowerShell 5 otherwise decodes cargo's UTF-8 JSON using the
        # OEM code page, corrupting paths under Unicode user profiles.
        $previousEncoding = [Console]::OutputEncoding
        try {
            [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
            $metadataText = & cargo metadata --locked --format-version 1 --no-deps
            $cargoExit = $LASTEXITCODE
        } finally {
            [Console]::OutputEncoding = $previousEncoding
        }
        if ($cargoExit -ne 0) { throw 'cargo metadata failed; fetch the locked dependencies first.' }
        $targetDir = (($metadataText -join "`n") | ConvertFrom-Json).target_directory
    }
    # PowerShell's current location can differ from the process/.NET current
    # directory, especially when invoked through rustup or WSL interop.
    if (![IO.Path]::IsPathRooted($targetDir)) { $targetDir = Join-Path $root $targetDir }
    $targetDir = [IO.Path]::GetFullPath($targetDir)
    $fixtureDir = Join-Path $targetDir 'windows-fixture'
    New-Item -ItemType Directory -Force -Path $fixtureDir | Out-Null
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (!(Test-Path -LiteralPath $vswhere)) {
        throw 'Install Visual Studio Build Tools with Desktop development with C++ and the Windows SDK.'
    }
    $vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or !$vs) { throw 'An x64 MSVC C++ toolchain is required.' }
    $vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
    if (!$SkipTests) {
        $fixture = Join-Path $fixtureDir 'sample.exe'
        $source = Join-Path $root 'tests\fixtures\sample.c'
        # Keep all compiler/linker products out of the source tree. Disable
        # incremental-link thunks so exported functions point at their actual code.
        & cmd.exe /d /c "`"$vcvars`" && cl /nologo /Od /Zi /Fo`"$fixtureDir\sample.obj`" /Fd`"$fixtureDir\compiler.pdb`" /Fe`"$fixture`" `"$source`" /link /INCREMENTAL:NO /PDB:`"$fixtureDir\sample.pdb`" /EXPORT:branch_loop /EXPORT:base64_message /EXPORT:aes_sbox_prefix"
        if ($LASTEXITCODE -ne 0) { throw 'Building the original PE fixture failed.' }
        $env:GHIDRA_RUST_TEST_PE = $fixture
        # Bundled LLVM is mandatory for the independent DWARF-in-PE fixture.
        $llvm = Join-Path $vs 'VC\Tools\Llvm\x64\bin'
        $clang = Join-Path $llvm 'clang.exe'
        $lld = Join-Path $llvm 'lld-link.exe'
        if (!(Test-Path -LiteralPath $clang) -or !(Test-Path -LiteralPath $lld)) {
            throw 'DWARF PE tests require the VS Build Tools bundled LLVM clang and lld-link (C++ Clang tools for Windows).'
        }
        $dwarfFixture = Join-Path $fixtureDir 'sample-dwarf.exe'
        # /DEBUG:DWARF retains .debug_* sections and the COFF symbol table;
        # exported exact entries also make the original fixture navigable.
        & cmd.exe /d /c "`"$vcvars`" && `"$clang`" --target=x86_64-pc-windows-msvc -O0 -g -gdwarf-4 -fno-inline -fuse-ld=lld -o `"$dwarfFixture`" `"$source`" -Wl,/debug:dwarf,/incremental:no,/opt:noref,/export:main,/export:decode_xor,/export:branch_loop"
        if ($LASTEXITCODE -ne 0) { throw 'Building the mandatory original DWARF PE fixture failed.' }
        $env:GHIDRA_RUST_TEST_PE_DWARF = $dwarfFixture

        # Keep caller and support code untyped. Only the callee emits DWARF.
        $callerFixture = Join-Path $fixtureDir 'dwarf-caller.dll'
        $callerObjects = @()
        foreach ($unit in @('debug_caller_submit', 'debug_caller_schedule', 'debug_caller_windows_stubs')) {
            $unitSource = Join-Path $root "tests/fixtures/$unit.c"
            $unitObject = Join-Path $fixtureDir "$unit.obj"
            $debugFlags = @()
            if ($unit -eq 'debug_caller_schedule') { $debugFlags = @('-g', '-gdwarf-4') }
            & $clang --target=x86_64-pc-windows-msvc -O2 -ffreestanding -fno-stack-protector @debugFlags -c $unitSource -o $unitObject
            if ($LASTEXITCODE -ne 0) { throw "Compiling the DWARF PE caller fixture unit $unit failed." }
            $callerObjects += $unitObject
        }
        & $lld /dll /noentry /nodefaultlib /debug:dwarf /opt:noref /export:sample_entry /export:sample_entry_positive /export:sample_schedule "/out:$callerFixture" @callerObjects
        if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $callerFixture)) {
            throw 'Linking the DWARF PE caller fixture failed.'
        }
        $env:GHIDRA_RUST_TEST_PE_DWARF_CALLER = $callerFixture

        # An MSVC C++ DLL whose decorated exports must stay raw.
        $cppFixture = Join-Path $fixtureDir 'demangle.dll'
        $cppSource = Join-Path $root 'tests\fixtures\demangle_program.cpp'
        & cmd.exe /d /c "`"$vcvars`" && cl /nologo /Od /LD /Fo`"$fixtureDir\demangle.obj`" /Fe`"$cppFixture`" `"$cppSource`" /link /INCREMENTAL:NO"
        if ($LASTEXITCODE -ne 0) { throw 'Building the original C++ DLL fixture failed.' }
        $env:GHIDRA_RUST_TEST_PE_CPP = $cppFixture
    }

    $env:GHIDRA_RUST_EMBEDDED_NOTICES = & python "$PSScriptRoot/embed-notices.py" --target $target
    if ($LASTEXITCODE -ne 0) { throw 'Collecting embedded dependency notices failed (Python 3 is required).' }

    & cargo fmt --all --check
    if ($LASTEXITCODE -ne 0) { throw 'Formatting check failed.' }
    if (!$SkipTests) {
        & cargo build --locked --target $target --example updater-test-driver
        if ($LASTEXITCODE -ne 0) { throw 'Building the updater process fixture failed.' }
        $env:GHIDRA_RUST_TEST_UPDATER_DRIVER = Join-Path $targetDir "$target/debug/examples/updater-test-driver.exe"
        # Tests use workers with the test-only fault hook; distributables never do.
        & cargo test --locked --target $target --features test-hooks
        if ($LASTEXITCODE -ne 0) { throw 'Windows tests failed.' }
        & cargo clippy --workspace --all-targets --locked --target $target --features test-hooks -- -D warnings
        if ($LASTEXITCODE -ne 0) { throw 'Windows test-hooks Clippy check failed.' }
    }
    & cargo clippy --workspace --all-targets --locked --target $target -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Windows Clippy check failed.' }
    & cargo build --release --locked --target $target
    if ($LASTEXITCODE -ne 0) { throw 'Windows release build failed.' }
    if (!$SkipTests) {
        & cargo build --release --locked --target $target --example updater-test-driver
        if ($LASTEXITCODE -ne 0) { throw 'Building the release updater fixture failed.' }
        $env:GHIDRA_RUST_TEST_UPDATER_DRIVER = Join-Path $targetDir "$target/release/examples/updater-test-driver.exe"
        & cargo test --release --locked --target $target --features test-hooks --test windows_updater
        if ($LASTEXITCODE -ne 0) { throw 'Windows release updater lifecycle tests failed.' }
        # The release EXE uses the Windows GUI subsystem. Test its inherited worker
        # pipes explicitly; the debug/console-subsystem test cannot establish this.
        & cargo test --release --locked --target $target --features test-hooks --test debug_info
        if ($LASTEXITCODE -ne 0) { throw 'Release DWARF PE fixture tests failed.' }
        & cargo test --release --locked --target $target --features test-hooks --test windows_worker
        if ($LASTEXITCODE -ne 0) { throw 'Windows release worker/project test failed.' }
        & cargo test --release --locked --target $target --features test-hooks --test aarch64
        if ($LASTEXITCODE -ne 0) { throw 'AArch64 release worker/project test failed.' }
        & cargo test --release --locked --target $target --features test-hooks --test headless
        if ($LASTEXITCODE -ne 0) { throw 'Release headless API tests failed.' }
        # The test-hooks tests relinked the release executables; restore the
        # distributable build before packaging.
        & cargo build --release --locked --target $target
        if ($LASTEXITCODE -ne 0) { throw 'Windows release build failed.' }
    }
    # The packager probes its staged copies of this exact pair for the
    # test-only worker fault hook before publishing anything.
    & "$PSScriptRoot\package-windows.ps1" -TargetDirectory $targetDir -Target $target
} finally {
    $env:GHIDRA_RUST_TEST_UPDATER_DRIVER = $previousUpdaterDriver
    $env:GHIDRA_RUST_EMBEDDED_NOTICES = $previousNotices
    $env:GHIDRA_RUST_TEST_PE = $previousFixture
    $env:GHIDRA_RUST_TEST_PE_CPP = $previousCppFixture
    $env:GHIDRA_RUST_TEST_PE_DWARF = $previousDwarfFixture
    $env:GHIDRA_RUST_TEST_PE_DWARF_CALLER = $previousCallerFixture
    Pop-Location
}
