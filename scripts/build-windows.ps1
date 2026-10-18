# Run from PowerShell on Windows with Rust/MSVC tools installed. No downloads or
# system configuration changes are performed by this script.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
    throw 'Run this script on native Windows x64.'
}

$root = Split-Path $PSScriptRoot -Parent
$previousFixture = $env:GHIDRA_RUST_TEST_PE
Push-Location $root
try {
    $compiler = & rustc -vV
    if ($LASTEXITCODE -ne 0 -or $compiler -notcontains 'host: x86_64-pc-windows-msvc') {
        throw 'Select the x86_64-pc-windows-msvc Rust toolchain (see docs/windows.md).'
    }
    $target = 'x86_64-pc-windows-msvc'
    $targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { 'target' }
    # PowerShell's current location can differ from the process/.NET current
    # directory, especially when invoked through rustup or WSL interop.
    if (![IO.Path]::IsPathRooted($targetDir)) { $targetDir = Join-Path $root $targetDir }
    $fixtureDir = Join-Path ([IO.Path]::GetFullPath($targetDir)) 'windows-fixture'
    New-Item -ItemType Directory -Force -Path $fixtureDir | Out-Null
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (!(Test-Path -LiteralPath $vswhere)) {
        throw 'Install Visual Studio Build Tools with Desktop development with C++ and the Windows SDK.'
    }
    $vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or !$vs) { throw 'An x64 MSVC C++ toolchain is required.' }
    $vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
    $fixture = Join-Path $fixtureDir 'sample.exe'
    $source = Join-Path $root 'tests\fixtures\sample.c'
    # Keep all compiler/linker products out of the source tree. Disable
    # incremental-link thunks so exported functions point at their actual code.
    & cmd.exe /d /c "`"$vcvars`" && cl /nologo /Od /Zi /Fo`"$fixtureDir\sample.obj`" /Fd`"$fixtureDir\compiler.pdb`" /Fe`"$fixture`" `"$source`" /link /INCREMENTAL:NO /PDB:`"$fixtureDir\sample.pdb`" /EXPORT:branch_loop /EXPORT:base64_message /EXPORT:aes_sbox_prefix"
    if ($LASTEXITCODE -ne 0) { throw 'Building the original PE fixture failed.' }
    $env:GHIDRA_RUST_TEST_PE = $fixture

    & cargo fmt --all --check
    if ($LASTEXITCODE -ne 0) { throw 'Formatting check failed.' }
    & cargo test --locked --target $target
    if ($LASTEXITCODE -ne 0) { throw 'Windows tests failed.' }
    & cargo clippy --workspace --all-targets --locked --target $target -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Windows Clippy check failed.' }
    & cargo build --release --locked --target $target
    if ($LASTEXITCODE -ne 0) { throw 'Windows release build failed.' }
    # The release EXE uses the Windows GUI subsystem. Test its inherited worker
    # pipes explicitly; the debug/console-subsystem test cannot establish this.
    & cargo test --release --locked --target $target --test windows_worker
    if ($LASTEXITCODE -ne 0) { throw 'Windows release worker/project test failed.' }
    & cargo test --release --locked --target $target --test aarch64
    if ($LASTEXITCODE -ne 0) { throw 'AArch64 release worker/project test failed.' }
    & "$PSScriptRoot\package-windows.ps1"
} finally {
    $env:GHIDRA_RUST_TEST_PE = $previousFixture
    Pop-Location
}
