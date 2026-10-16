# Package an existing Windows x64 release build. Does not build or publish.
[CmdletBinding()]
param(
    [string]$TargetDirectory = $env:CARGO_TARGET_DIR
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
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
    if ($LASTEXITCODE -ne 0) {
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
    if ([string]::IsNullOrWhiteSpace($TargetDirectory)) {
        $TargetDirectory = $metadata.target_directory
    }
    if (![IO.Path]::IsPathRooted($TargetDirectory)) {
        $TargetDirectory = Join-Path $repository $TargetDirectory
    }
    $target = [IO.Path]::GetFullPath($TargetDirectory)
    $executable = Join-Path $target "$platform/release/ghidra-rust.exe"
    if (!(Test-Path -LiteralPath $executable -PathType Leaf)) {
        $executable = Join-Path $target 'release/ghidra-rust.exe'
    }
    if (!(Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Windows release executable is missing under $target; run cargo build --release --locked --target $platform first"
    }
    Assert-X64Executable $executable

    $bundleName = "ghidra-rust-$($application.version)-windows-x64"
    if ($bundleName -notmatch '^[A-Za-z0-9_.+-]+$') {
        throw 'Application version cannot be used safely as an archive filename'
    }
    $dist = Join-Path $target 'dist'
    [IO.Directory]::CreateDirectory($dist) | Out-Null
    $unique = [Guid]::NewGuid().ToString('N')
    $staging = Join-Path $dist ".package-$unique"
    $bundle = Join-Path $staging $bundleName
    [IO.Directory]::CreateDirectory($bundle) | Out-Null
    Copy-BundleFile $executable (Join-Path $bundle 'ghidra-rust.exe')
    foreach ($relative in @('README.md', 'LICENSE', 'NOTICE', 'docs/releases.md', 'docs/windows.md', 'docs/linux.md', 'docs/crypto-signatures.md')) {
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
    Copy-BundleFile $executable $standalone
    $standaloneHash = (Get-FileHash -LiteralPath $standalone -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$standalone.sha256", "$standaloneHash  $standaloneName`n", $utf8)
    Write-Host "Created $standalone"
} finally {
    if ($staging -and (Test-Path -LiteralPath $staging)) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
    if ($temporaryZip -and (Test-Path -LiteralPath $temporaryZip)) {
        Remove-Item -LiteralPath $temporaryZip -Force
    }
    [Console]::OutputEncoding = $previousEncoding
    Pop-Location
}
