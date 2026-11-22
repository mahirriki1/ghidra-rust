# Package an existing Windows x64 release build. Does not build or publish.
# The target directory is -TargetDirectory, then a nonempty CARGO_TARGET_DIR,
# then Cargo metadata (which includes Cargo config); a relative directory
# resolves against the current location, as Cargo resolves CARGO_TARGET_DIR.
# -Target selects the
# release layout: the native triple (TARGET\release, as built with Cargo
# --target) or 'host' (release). Without it, a nonempty CARGO_BUILD_TARGET is
# used, and otherwise the sole complete pair of those two layouts.
[CmdletBinding()]
param(
    [string]$TargetDirectory,
    [string]$Target
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
# The caller's location, before the repository is entered for cargo metadata.
$callerDirectory = (Get-Location -PSProvider FileSystem).ProviderPath
$platform = 'x86_64-pc-windows-msvc'
$utf8 = New-Object Text.UTF8Encoding($false)
$previousEncoding = [Console]::OutputEncoding

function Copy-BundleFile([string]$Source, [string]$Destination) {
    if (!(Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Required packaging file is missing: $Source"
    }
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Destination)) | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination
}

function Get-NoticeFiles([string]$Root) {
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        foreach ($entry in Get-ChildItem -LiteralPath $current -Force) {
            # Never follow dependency symlinks/junctions outside the package.
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                continue
            }
            if ($entry.PSIsContainer) {
                if ($entry.Name -notin @('.git', '.agents', '.codex', '.aws', 'target')) {
                    $pending.Push($entry.FullName)
                }
            } elseif ($entry.Name -match '(?i)(LICENSE|COPYRIGHT|COPYING|NOTICE|^OFL(?:[._-]|$))') {
                $entry.FullName
            }
        }
    }
}

# The test-only worker fault hook (--features test-hooks) must never ship. A
# distributed worker refuses it as an unknown argument before startup. Uses only
# .NET Framework APIs available to Windows PowerShell 5.1. Both outputs are
# drained asynchronously; the GUI-subsystem desktop gets explicit pipes.
function Assert-NoTestHooks([string]$Executable) {
    $name = [IO.Path]::GetFileName($Executable)
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = '--analysis-worker --test-debug-fault=stall@0x0'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = $null
    try {
        try {
            $process = [System.Diagnostics.Process]::Start($info)
        } catch {
            throw "Staged $name could not run the test-hook probe: $($_.Exception.Message)"
        }
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Close()
        if (!$process.WaitForExit(15000)) {
            try { $process.Kill() } catch { }
            $null = $process.WaitForExit(5000)
            throw "Staged $name did not refuse the test-only worker fault hook within 15 s"
        }
        if (!$output.Wait(5000) -or !$errors.Wait(5000)) {
            throw "Staged $name kept its output open after the test-hook probe"
        }
        $code = $process.ExitCode
        $lines = @($errors.Result -split "`r?`n")
        if ($code -eq 0) {
            throw "Staged $name failed the test-hook refusal gate: it exited successfully, so the fault hook may have been accepted"
        }
        if ($lines -cnotcontains 'Unexpected analysis worker argument') {
            $detail = @($lines | Where-Object { $_.Trim() }) | Select-Object -Last 1
            if (!$detail) { $detail = 'no diagnostic' }
            throw "Staged $name failed the test-hook refusal gate: it exited $code without the refusal ($detail)"
        }
    } finally {
        if ($process) { $process.Dispose() }
    }
}

# Removes a staging file or directory. Real-time scanning can briefly hold an
# executable that was just probed, so removal is retried for up to 10 s; a
# path that still cannot be removed is reported as a warning rather than
# replacing the packaging result.
function Remove-Staging([string]$Path) {
    for ($attempt = 1; ; $attempt++) {
        if (!(Test-Path -LiteralPath $Path)) { return }
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            return
        } catch {
            if ($attempt -ge 20) {
                Write-Warning "Could not remove packaging staging ${Path}: $($_.Exception.Message)"
                return
            }
            Start-Sleep -Milliseconds 500
        }
    }
}

function Test-ReleasePair([string]$Directory) {
    foreach ($member in @('ghidra-rust.exe', 'ghidra-rust-headless.exe')) {
        if (!(Test-Path -LiteralPath (Join-Path $Directory $member) -PathType Leaf)) { return $false }
    }
    return $true
}

function Assert-X64Executable([string]$Path) {
    $reader = New-Object IO.BinaryReader([IO.File]::OpenRead($Path))
    try {
        if ($reader.BaseStream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) {
            throw 'Release executable is not a Windows PE image'
        }
        $reader.BaseStream.Position = 60
        $header = $reader.ReadUInt32()
        if ($header -gt $reader.BaseStream.Length - 6) {
            throw 'Release executable has an invalid PE header'
        }
        $reader.BaseStream.Position = $header
        if ($reader.ReadUInt32() -ne 0x00004550 -or $reader.ReadUInt16() -ne 0x8664) {
            throw 'Release executable must be Windows x64 (AMD64)'
        }
    } finally {
        $reader.Dispose()
    }
}

Push-Location $repository
$staging = $null
$temporaryZip = $null
try {
    # Windows PowerShell 5 otherwise decodes cargo's UTF-8 JSON using the OEM
    # code page, corrupting manifest/cache paths under Unicode user profiles.
    [Console]::OutputEncoding = $utf8
    if (!(Get-Command cargo -CommandType Application -ErrorAction SilentlyContinue)) {
        throw 'cargo was not found on PATH; use a shell with the Windows Rust toolchain available'
    }
    $metadataText = & cargo metadata --locked --format-version 1 --filter-platform $platform
    $cargoExit = $LASTEXITCODE
    if ($cargoExit -ne 0) {
        throw 'cargo metadata failed; fetch the locked dependencies before packaging'
    }
    try {
        $metadata = ($metadataText -join "`n") | ConvertFrom-Json
    } catch {
        throw "Cannot parse cargo metadata: $_"
    }
    if (!$metadata.resolve -or !$metadata.resolve.nodes) {
        throw 'cargo metadata returned no resolved dependency graph'
    }
    $manifest = Join-Path $repository 'Cargo.toml'
    $application = @($metadata.packages | Where-Object {
        [IO.Path]::GetFullPath($_.manifest_path) -eq $manifest
    })
    if ($application.Count -ne 1) {
        throw 'cargo metadata did not identify the application package'
    }
    $application = $application[0]
    if ([string]::IsNullOrEmpty($TargetDirectory)) { $TargetDirectory = $env:CARGO_TARGET_DIR }
    if ([string]::IsNullOrEmpty($TargetDirectory)) { $TargetDirectory = $metadata.target_directory }
    if (![IO.Path]::IsPathRooted($TargetDirectory)) {
        $TargetDirectory = Join-Path $callerDirectory $TargetDirectory
    }
    $targetRoot = [IO.Path]::GetFullPath($TargetDirectory)
    # The option takes precedence over the environment's build target.
    $layout = $Target
    if ([string]::IsNullOrEmpty($layout)) { $layout = $env:CARGO_BUILD_TARGET }
    $hostRelease = Join-Path $targetRoot 'release'
    $tripleRelease = Join-Path $targetRoot "$platform\release"
    if ($layout -ceq 'host') {
        $release = $hostRelease
    } elseif ($layout -ceq $platform) {
        $release = $tripleRelease
    } elseif (![string]::IsNullOrEmpty($layout)) {
        throw "Unsupported packaging target '$layout'; use $platform or host"
    } else {
        # Never combine members from different layouts.
        $complete = @(@($hostRelease, $tripleRelease) | Where-Object { Test-ReleasePair $_ })
        if ($complete.Count -eq 2) {
            throw "Both $hostRelease and $tripleRelease hold a release pair; pass -Target host or -Target $platform to select one"
        }
        if ($complete.Count -eq 0) {
            throw "No complete Windows release pair under $hostRelease or $tripleRelease; run cargo build --release --locked --target $platform first"
        }
        $release = $complete[0]
    }
    $executable = Join-Path $release 'ghidra-rust.exe'
    $headless = Join-Path $release 'ghidra-rust-headless.exe'
    foreach ($member in @($executable, $headless)) {
        if (!(Test-Path -LiteralPath $member -PathType Leaf)) {
            throw "Windows release executable is missing: $member"
        }
    }

    $bundleName = "ghidra-rust-$($application.version)-windows-x64"
    if ($bundleName -notmatch '^[A-Za-z0-9_.+-]+$') {
        throw 'Application version cannot be used safely as an archive filename'
    }
    $dist = Join-Path $targetRoot 'dist'
    [IO.Directory]::CreateDirectory($dist) | Out-Null
    # Short staging names keep the deepest bundled notice paths under the
    # 260-character MAX_PATH limit of Windows PowerShell 5.1 / .NET Framework.
    do {
        $unique = [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $staging = Join-Path $dist ".package-$unique"
    } while ((Test-Path -LiteralPath $staging) -or (Test-Path -LiteralPath (Join-Path $dist ".package-$unique.zip")))
    $bundle = Join-Path $staging $bundleName
    [IO.Directory]::CreateDirectory($bundle) | Out-Null
    $bundledDesktop = [IO.Path]::GetFullPath((Join-Path $bundle 'ghidra-rust.exe'))
    $bundledHeadless = [IO.Path]::GetFullPath((Join-Path $bundle 'ghidra-rust-headless.exe'))
    Copy-BundleFile $executable $bundledDesktop
    Copy-BundleFile $headless $bundledHeadless
    # Validate and probe the exact staged bytes that are archived and published.
    Assert-X64Executable $bundledDesktop
    Assert-X64Executable $bundledHeadless
    Assert-NoTestHooks $bundledDesktop
    Assert-NoTestHooks $bundledHeadless
    foreach ($relative in @('README.md', 'LICENSE', 'NOTICE', 'docs/releases.md', 'docs/windows.md', 'docs/linux.md', 'docs/crypto-signatures.md', 'docs/architectures.md', 'docs/headless.md')) {
        Copy-BundleFile (Join-Path $repository $relative) (Join-Path $bundle $relative)
    }
    $images = Join-Path $repository 'docs/images'
    if (Test-Path -LiteralPath $images -PathType Container) {
        Copy-Item -LiteralPath $images -Destination (Join-Path $bundle 'docs/images') -Recurse
    }

    $resolved = @{}
    foreach ($node in $metadata.resolve.nodes) { $resolved[$node.id] = $true }
    $destinations = @{}
    $packages = @()
    foreach ($package in @($metadata.packages | Sort-Object name, version, id)) {
        if (!$resolved.ContainsKey($package.id)) { continue }
        if ($package.id -eq $application.id) {
            # The application's notices are already at the bundle root. Do not
            # recursively scan its checkout (which may contain this staging dir).
            $packages += [ordered]@{
                name = $package.name
                version = $package.version
                license = $package.license
                authors = @($package.authors)
                repository = $package.repository
                source = 'local workspace'
                notice_directory = '.'
                notice_files = @('LICENSE', 'NOTICE')
            }
            continue
        }
        $directoryName = "$($package.name)-$($package.version)"
        if ($directoryName -notmatch '^[A-Za-z0-9_.+-]+$') {
            throw "Unsafe dependency directory name: $directoryName"
        }
        if ($destinations.ContainsKey($directoryName)) {
            throw "Multiple dependency sources share $directoryName; refusing to overwrite their notices"
        }
        $destinations[$directoryName] = $true
        $root = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($package.manifest_path))
        $prefix = $root + [IO.Path]::DirectorySeparatorChar
        $files = @(Get-NoticeFiles $root)
        $codeLicense = [string]$package.license
        if ($package.name -eq 'epaint_default_fonts') {
            # This pinned package licenses its Rust code separately from its
            # fonts. Preserve every supplied font text, including Hack and
            # Ubuntu notices whose filenames do not contain "LICENSE".
            if ($codeLicense -cne '(MIT OR Apache-2.0) AND OFL-1.1 AND Ubuntu-font-1.0') {
                throw "Review changed font-package licenses before packaging: $codeLicense"
            }
            foreach ($fontNotice in @('fonts/Hack-Regular.txt', 'fonts/OFL.txt', 'fonts/UFL.txt',
                'fonts/emoji-icon-font-mit-license.txt', 'fonts/egui-icons.txt')) {
                $fontPath = Join-Path $root $fontNotice
                if (!(Test-Path -LiteralPath $fontPath -PathType Leaf)) {
                    throw "Required bundled-font notice is missing: $fontPath"
                }
                $files += $fontPath
            }
            $codeLicense = 'MIT OR Apache-2.0'
        }
        if ($package.license_file) {
            $licenseFile = [IO.Path]::GetFullPath((Join-Path $root $package.license_file))
            if (!$licenseFile.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Dependency license_file escapes its package: $($package.name)"
            }
            if (!(Test-Path -LiteralPath $licenseFile -PathType Leaf)) {
                throw "Declared dependency license file is missing: $licenseFile"
            }
            # The recursive traversal omitted reparse points deliberately.
            # Reject a declared license path that would bypass that check.
            $component = Get-Item -LiteralPath $licenseFile -Force
            while ($component.FullName -ne $root) {
                if (($component.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Dependency license_file traverses a reparse point: $licenseFile"
                }
                if ($component.PSIsContainer) {
                    $component = $component.Parent
                } else {
                    $component = $component.Directory
                }
                if (!$component) { throw "Cannot inspect dependency license path: $licenseFile" }
            }
            $files += $licenseFile
        }
        $copied = @()
        foreach ($file in @($files | Sort-Object -Unique)) {
            $relative = $file.Substring($prefix.Length)
            $destination = Join-Path $bundle (Join-Path "third-party/$directoryName" $relative)
            Copy-BundleFile $file $destination
            $copied += $relative.Replace('\', '/')
        }
        $fallback = $null
        $licenseFiles = @($files | Where-Object {
            # A nested font/asset license does not cover the crate's Rust code.
            # Keep those texts, but require a package-root code license here
            # unless Cargo names a specific license_file below.
            [IO.Path]::GetDirectoryName($_) -eq $root -and
                [IO.Path]::GetFileName($_) -match '(?i)(LICENSE|COPYING|^OFL(?:[._-]|$))'
        })
        if (!$package.license_file -and $licenseFiles.Count -eq 0) {
            # Some published crates omit their workspace's license files. Select
            # one offered license only for plain SPDX alternatives; AND/WITH
            # expressions require their own supplied texts and notices.
            $choices = @($codeLicense.Replace('(', '').Replace(')', '') -split '\s+OR\s+' |
                ForEach-Object { $_.Trim() })
            $unsupported = @($choices | Where-Object { $_ -cnotmatch '^[A-Za-z0-9.+-]+$' })
            if ($unsupported.Count -eq 0 -and $choices -ccontains 'Apache-2.0') {
                $fallback = [ordered]@{
                    license = 'Apache-2.0'
                    source = 'https://www.apache.org/licenses/LICENSE-2.0.txt'
                    file = 'LICENSE-APACHE-2.0.txt'
                }
                $fallbackPath = Join-Path $repository 'LICENSE'
            } elseif ($unsupported.Count -eq 0 -and $choices -ccontains 'BSL-1.0') {
                $fallback = [ordered]@{
                    license = 'BSL-1.0'
                    source = 'https://www.boost.org/LICENSE_1_0.txt'
                    file = 'LICENSE-BSL-1.0.txt'
                }
                # Vendored verbatim from the official Boost URL above.
                $fallbackPath = Join-Path $PSScriptRoot 'licenses/BSL-1.0.txt'
            } else {
                throw "No license text supplied by $directoryName; unsupported fallback expression: '$($package.license)'"
            }
            Copy-BundleFile $fallbackPath (Join-Path $bundle "third-party/$directoryName/$($fallback.file)")
            $copied += $fallback.file
        }
        $packages += [ordered]@{
            name = $package.name
            version = $package.version
            license = $package.license
            authors = @($package.authors)
            repository = $package.repository
            source = $(if ($package.source) { $package.source } else { 'local workspace' })
            notice_directory = "third-party/$directoryName"
            notice_files = @($copied)
            fallback_license = $fallback
        }
    }
    $thirdParty = [ordered]@{
        target = $platform
        description = 'Windows-resolved Cargo packages, including build dependencies; embedded asset licenses retain their package-relative paths.'
        packages = @($packages)
    } | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText((Join-Path $bundle 'THIRD-PARTY.json'), $thirdParty + "`n", $utf8)

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $temporaryZip = Join-Path $dist ".package-$unique.zip"
    # .NET Framework used by Windows PowerShell 5 can emit backslash entry
    # names with CreateFromDirectory. Always write standard ZIP separators so
    # the same archive also extracts correctly with non-Windows tools.
    $zip = [IO.Compression.ZipFile]::Open($temporaryZip, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in Get-ChildItem -LiteralPath $bundle -Recurse -File) {
            $entry = $file.FullName.Substring($staging.Length + 1).Replace('\', '/')
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip, $file.FullName, $entry, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    } finally {
        $zip.Dispose()
    }
    $archive = Join-Path $dist "$bundleName.zip"
    Move-Item -LiteralPath $temporaryZip -Destination $archive -Force
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksum = "$archive.sha256"
    [IO.File]::WriteAllText($checksum, "$hash  $bundleName.zip`n", $utf8)
    Write-Host "Created $archive"
    Write-Host "SHA-256 $checksum"

    # The application already embeds its engine data, fonts, SQLite and MSVC
    # runtime. Offer the same executable directly for local single-file use.
    # The ZIP retains the accompanying documentation and redistribution notices.
    $standaloneName = "$bundleName.exe"
    $standalone = Join-Path $dist $standaloneName
    Copy-BundleFile $bundledDesktop $standalone
    $standaloneHash = (Get-FileHash -LiteralPath $standalone -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$standalone.sha256", "$standaloneHash  $standaloneName`n", $utf8)
    Write-Host "Created $standalone"
} finally {
    if ($staging) { Remove-Staging $staging }
    if ($temporaryZip) { Remove-Staging $temporaryZip }
    [Console]::OutputEncoding = $previousEncoding
    Pop-Location
}
