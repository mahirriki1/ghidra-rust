# Native packaging gate test for Windows x64, runnable outside CI from Windows
# PowerShell 5.1 or pwsh. Pass directories holding real release pairs
# (ghidra-rust.exe and ghidra-rust-headless.exe) built with and without
# `--features test-hooks`. The pairs are copied into private roots whose paths
# contain spaces and non-ASCII characters; nothing is written under the
# repository. Relative release paths resolve against the current location.
# Throws on the first failed expectation.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$HookedRelease,
    [Parameter(Mandatory = $true)][string]$CleanRelease
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$platform = 'x86_64-pc-windows-msvc'
$packager = Join-Path $PSScriptRoot 'package-windows.ps1'
# Windows PowerShell 5.1 does not move the .NET current directory with
# Set-Location, so relative paths are resolved by the provider instead.
$HookedRelease = (Resolve-Path -LiteralPath $HookedRelease).ProviderPath
$CleanRelease = (Resolve-Path -LiteralPath $CleanRelease).ProviderPath
# Windows PowerShell 5.1 reads BOM-less scripts in the ANSI code page, so the
# non-ASCII path characters are built from code points.
$umlaut = [string][char]0x00E4
$base = Join-Path ([IO.Path]::GetTempPath()) ("pkg g$($umlaut)te " + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$savedTargetDir = $env:CARGO_TARGET_DIR
$savedBuildTarget = $env:CARGO_BUILD_TARGET
$savedBuildTargetDir = $env:CARGO_BUILD_TARGET_DIR
$passed = 0

function Set-Pair([string]$Root, [string]$Layout, [string]$Desktop, [string]$Headless) {
    if ($Layout -eq 'host') { $release = Join-Path $Root 'release' } else { $release = Join-Path $Root "$platform\release" }
    [IO.Directory]::CreateDirectory($release) | Out-Null
    Copy-Item -LiteralPath (Join-Path $Desktop 'ghidra-rust.exe') -Destination (Join-Path $release 'ghidra-rust.exe') -Force
    Copy-Item -LiteralPath (Join-Path $Headless 'ghidra-rust-headless.exe') -Destination (Join-Path $release 'ghidra-rust-headless.exe') -Force
}

function Clear-CargoEnvironment {
    $env:CARGO_TARGET_DIR = $null
    $env:CARGO_BUILD_TARGET = $null
    $env:CARGO_BUILD_TARGET_DIR = $null
}

# Runs the packager in this process; returns $null on success, otherwise the
# failure message. Restores the Cargo environment afterwards.
function Invoke-Packager([hashtable]$Arguments, [hashtable]$Environment) {
    Clear-CargoEnvironment
    foreach ($name in $Environment.Keys) { Set-Item -LiteralPath "env:$name" -Value $Environment[$name] }
    try {
        & $packager @Arguments | Out-Null
        return $null
    } catch {
        return [string]$_.Exception.Message
    } finally {
        Clear-CargoEnvironment
    }
}

function Get-Public([string]$Root) {
    $dist = Join-Path $Root 'dist'
    $state = @{}
    if (Test-Path -LiteralPath $dist) {
        foreach ($entry in Get-ChildItem -LiteralPath $dist -Force) {
            if ($entry.PSIsContainer) { $state[$entry.Name] = 'directory' }
            else { $state[$entry.Name] = (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash }
        }
    }
    return $state
}

function Assert-SameState([hashtable]$Expected, [hashtable]$Actual, [string]$Case) {
    $left = ($Expected.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ';'
    $right = ($Actual.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ';'
    if ($left -ne $right) { throw "${Case}: public files changed or staging debris remained ($right)" }
}

function Assert-Failure([string]$Message, [string]$Expected, [string]$Case) {
    if ($null -eq $Message) { throw "${Case}: packaging unexpectedly succeeded" }
    if (!$Message.Contains($Expected)) { throw "${Case}: unexpected failure: $Message" }
    $script:passed++
}

function Assert-Published([string]$Root, [string]$Case) {
    $dist = Join-Path $Root 'dist'
    $entries = @(Get-ChildItem -LiteralPath $dist -Force)
    if (@($entries | Where-Object { $_.Name -like '.package-*' }).Count -ne 0) { throw "${Case}: staging debris remained" }
    $zip = @($entries | Where-Object { $_.Name -like '*.zip' })
    if ($zip.Count -ne 1) { throw "${Case}: expected one ZIP" }
    $zip = $zip[0]
    $bundle = $zip.Name.Substring(0, $zip.Name.Length - 4)
    $standalone = Join-Path $dist "$bundle.exe"
    foreach ($file in @($zip.FullName, $standalone)) {
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        $expected = "$hash  $([IO.Path]::GetFileName($file))`n"
        if ([IO.File]::ReadAllText("$file.sha256") -cne $expected) { throw "${Case}: checksum mismatch for $file" }
    }
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($zip.FullName)
    try {
        $members = @{}
        foreach ($entry in $archive.Entries) { $members[$entry.FullName] = $entry }
        foreach ($name in @('ghidra-rust.exe', 'ghidra-rust-headless.exe')) {
            if (!$members.ContainsKey("$bundle/$name")) { throw "${Case}: archive lacks $name" }
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        $stream = $members["$bundle/ghidra-rust.exe"].Open()
        try { $archived = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') } finally { $stream.Dispose(); $sha.Dispose() }
    } finally {
        $archive.Dispose()
    }
    if ($archived -ne (Get-FileHash -LiteralPath $standalone -Algorithm SHA256).Hash) {
        throw "${Case}: the standalone executable differs from the archived desktop"
    }
    $script:passed++
}

$outside = Join-Path $base 'elsewhere'
[IO.Directory]::CreateDirectory($outside) | Out-Null
Push-Location -LiteralPath $outside
try {
    # (1)-(3): a hooked member fails on the named staged executable and leaves
    # previously published files untouched.
    $root = Join-Path $base "r$($umlaut)ot one"
    Set-Pair $root 'host' $CleanRelease $CleanRelease
    $failure = Invoke-Packager @{ TargetDirectory = $root; Target = 'host' } @{}
    if ($null -ne $failure) { throw "baseline: $failure" }
    $previous = Get-Public $root
    foreach ($case in @(
            @($HookedRelease, $HookedRelease, 'ghidra-rust.exe'),
            @($CleanRelease, $HookedRelease, 'ghidra-rust-headless.exe'),
            @($HookedRelease, $CleanRelease, 'ghidra-rust.exe'))) {
        Set-Pair $root 'host' $case[0] $case[1]
        $failure = Invoke-Packager @{ TargetDirectory = $root; Target = 'host' } @{}
        Assert-Failure $failure "Staged $($case[2]) failed the test-hook refusal gate" "hooked $($case[2])"
        Assert-SameState $previous (Get-Public $root) "hooked $($case[2])"
    }

    # (4): the clean pair from the requested root and layout, with decoys.
    $root = Join-Path $base "r$($umlaut)ot two"
    $decoy = Join-Path $base "dec$($umlaut)y"
    Set-Pair $root $platform $CleanRelease $CleanRelease
    Set-Pair $root 'host' $HookedRelease $HookedRelease
    Set-Pair $decoy 'host' $HookedRelease $HookedRelease
    Assert-Failure (Invoke-Packager @{ TargetDirectory = $root } @{}) 'hold a release pair' 'ambiguous layouts'
    $failure = Invoke-Packager @{ TargetDirectory = $root; Target = $platform } @{ CARGO_TARGET_DIR = $decoy; CARGO_BUILD_TARGET = 'host' }
    if ($null -ne $failure) { throw "explicit directory and target: $failure" }
    Assert-Published $root 'explicit directory and target'
    if (Test-Path -LiteralPath (Join-Path $decoy 'dist')) { throw 'the decoy root was written' }
    # The environment, then Cargo config, select the root without an argument.
    $failure = Invoke-Packager @{} @{ CARGO_TARGET_DIR = $root; CARGO_BUILD_TARGET = $platform }
    if ($null -ne $failure) { throw "environment directory: $failure" }
    Assert-Published $root 'environment directory'
    $failure = Invoke-Packager @{} @{ CARGO_BUILD_TARGET_DIR = $root; CARGO_BUILD_TARGET = $platform }
    if ($null -ne $failure) { throw "Cargo config directory: $failure" }
    Assert-Published $root 'Cargo config directory'
    # A relative argument or CARGO_TARGET_DIR resolves against the current
    # location, as Cargo does, never against the repository.
    $repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $relative = "rel$($umlaut) " + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $relativeRoot = Join-Path $outside $relative
    Set-Pair $relativeRoot $platform $CleanRelease $CleanRelease
    $failure = Invoke-Packager @{ TargetDirectory = $relative; Target = $platform } @{}
    if ($null -ne $failure) { throw "relative directory: $failure" }
    Assert-Published $relativeRoot 'relative directory'
    $failure = Invoke-Packager @{} @{ CARGO_TARGET_DIR = $relative; CARGO_BUILD_TARGET = $platform }
    if ($null -ne $failure) { throw "relative environment directory: $failure" }
    Assert-Published $relativeRoot 'relative environment directory'
    if (Test-Path -LiteralPath (Join-Path $repository $relative)) { throw 'a relative root resolved against the repository' }

    # A missing second member is never filled from the other layout.
    $root = Join-Path $base "r$($umlaut)ot three"
    Set-Pair $root 'host' $CleanRelease $CleanRelease
    $native = Join-Path $root "$platform\release"
    [IO.Directory]::CreateDirectory($native) | Out-Null
    Copy-Item -LiteralPath (Join-Path $CleanRelease 'ghidra-rust.exe') -Destination (Join-Path $native 'ghidra-rust.exe')
    Assert-Failure (Invoke-Packager @{ TargetDirectory = $root; Target = $platform } @{}) 'is missing' 'missing member'
    if (Test-Path -LiteralPath (Join-Path $root 'dist')) {
        if (@(Get-ChildItem -LiteralPath (Join-Path $root 'dist') -Force).Count -ne 0) { throw 'missing member: files were written' }
    }
    Assert-Failure (Invoke-Packager @{ TargetDirectory = $root; Target = 'aarch64-pc-windows-msvc' } @{}) 'Unsupported packaging target' 'unsupported target'
    Write-Host "Windows packaging gate: $passed checks passed"
} finally {
    Pop-Location
    $env:CARGO_TARGET_DIR = $savedTargetDir
    $env:CARGO_BUILD_TARGET = $savedBuildTarget
    $env:CARGO_BUILD_TARGET_DIR = $savedBuildTargetDir
    if (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Recurse -Force }
}
