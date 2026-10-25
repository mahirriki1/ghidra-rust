# Building and shipping each version

Native release builds produce Linux ELF and Windows x64 MSVC executables.
Engine data, fonts, and SQLite are included; neither desktop needs Rust, Java,
or Python. See the platform guides for runtime requirements.

## Repeatable local builds

Use Rust 1.98.1 with `rustfmt` and `clippy`. Build each operating system on that
operating system; a cross-typecheck does not produce a tested native release.

On Linux x64, install a C/C++ toolchain, pkg-config, binutils (`strip`/`readelf`),
Python 3.11 or newer, OpenSSL, the X11/Wayland/OpenGL development libraries, and
bubblewrap. Python and OpenSSL support packaging, update signing, and the Linux
signer/verifier interoperability test; neither is a desktop runtime dependency.
On Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends -y \
  build-essential pkg-config binutils python3 openssl bubblewrap \
  libx11-dev libxi-dev libxrandr-dev libxcursor-dev libxinerama-dev \
  libxkbcommon-dev libwayland-dev libgl1-mesa-dev
rustup toolchain install 1.98.1 --component rustfmt,clippy
rustup run 1.98.1 bash scripts/build-linux.sh
```

On Ubuntu with AppArmor user-namespace restrictions, load the distribution's
bubblewrap profile as described in [Linux runtime compatibility](linux.md)
before running the sandboxed tests.

For Windows prerequisites and commands, see [Build and launch](windows.md#build-and-launch)
and [Reproduce the Windows checks and portable ZIP](windows.md#reproduce-the-windows-checks-and-portable-zip).

Both scripts check formatting, unit tests, strict Clippy, the release build, and
the real release worker integration test before packaging. **Run them locally and
confirm the tests pass before pushing:** GitHub Actions runs the same scripts with
`--skip-tests` (Linux) or `-SkipTests` (Windows), so hosted runs only check
formatting and Clippy, build, and package. Branch builds run for pull requests
(and on manual dispatch), not for every branch push. Output goes under
`target/dist` (or `CARGO_TARGET_DIR/dist`):

| Platform | Direct executable | Complete distribution |
| --- | --- | --- |
| Linux x64 | `ghidra-rust-VERSION-linux-x64` | `ghidra-rust-VERSION-linux-x64.tar.gz` |
| Windows x64 | `ghidra-rust-VERSION-windows-x64.exe` | `ghidra-rust-VERSION-windows-x64.zip` |

Each file has an adjacent `.sha256` checksum. Names and package metadata come
from `Cargo.toml`; the scripts do not contain a release version to edit. The
complete distributions include documentation, `LICENSE`, `NOTICE`, and dependency
and embedded-font notices. Retain those notices when redistributing the app.

To package an already-built release without rerunning the build checks:

```sh
python3 scripts/package-linux.py
```

```powershell
.\scripts\package-windows.ps1
```

Linux packaging strips a copy of the executable to reduce download size and
leaves the original build output intact. Its `BUILD-INFO.json` records the
compiler, direct shared-library dependencies, and measured GLIBC symbol versions.
Read [Linux runtime compatibility](linux.md) and the [Windows guide](windows.md)
before shipping to another machine.

## Automatic releases after main updates

The **Automatic main release** workflow runs for every push to `main`, including
merged pull requests. It prepares the next patch version (for example, `v0.0.4`,
then `v0.0.5`), builds Linux and Windows, verifies the complete package
set and checksums, and publishes a GitHub Release. While the version is `0.x`,
each release is published as a **pre-release** and is never marked latest; the
first `1.0.0` manifest version publishes the first stable release. Its description starts with
detailed bullets from every added or amended `docs/release-notes/*.md` entry
since the previous published version. Add an entry with each PR or direct change;
see [writing release notes](release-notes/README.md) for the format and local
preview command. Notes describe only changes new in that release, rather than
recapping earlier versions or repeating only the most recent PR title.

An expandable list retains every commit in the release range, including direct
commits and all merged branches, with no 100-commit cutoff. If the range has no
entries, the complete commit list supplies the change bullets instead. The
release links its exact source commit, native build run, and full GitHub change
comparison. Only a published lower version whose source is in the current
source's history can establish the baseline; draft, failed, reserved, and newer
source releases cannot hide changes. The first release covers the full history.
The release does not run tests; anything merged to main must already have passed
them locally.

Version allocation uses the highest existing `vX.Y.Z` tag and the version in
`Cargo.toml`. An intentional higher version in the manifest is respected; otherwise
the latest patch is incremented. Keep the manifest and lockfile synchronized.
Automatic versioning requires a plain `X.Y.Z` application version.

Each version tag points to a release snapshot whose parent is the triggering main
commit. Only the application versions in `Cargo.toml` and `Cargo.lock` change in
that snapshot. The workflow does not push version commits back to main, so it
cannot trigger a release loop. Main retains its development version; inspect the
release tag for the shipped version. Tags reserved by failed builds are retained,
so successful release numbers may have gaps. Concurrent updates reserve different
tags, and rerunning a failed workflow reuses its original tag.

The workflow calls the same native jobs used by PR CI. Main pushes use this release
pipeline instead of starting duplicate unversioned native builds. Both platforms
must pass before publication; partial asset uploads remain in an unpublished draft
and can be resumed by rerunning the workflow, which refreshes the draft's notes.
A rerun of an already published release leaves its notes and assets intact.
For stable versions, a slower older main update does not replace the current main
update as the latest release. The published executables, archives,
and four adjacent `.sha256` files are permanent release assets.

The preparation and publication jobs use the repository's built-in `GITHUB_TOKEN`
with `contents: write`; build jobs retain read-only repository access. No personal
token or additional repository secret is required. Tags pushed with that token do
not trigger the separate tag-build workflow; this run invokes the native jobs
directly for the reserved snapshot. Repository/organization policy must allow the
workflow's write permission. To retry a failure, rerun the existing Actions run.
To create another release from current main, manually dispatch **Automatic main
release** on `main`; dispatches on other branches are skipped.

## Manual version tags and GitHub Actions

For a manually versioned package build:

1. Change `[package].version` in `Cargo.toml`. Update the corresponding
   `ghidra-rust` entry in `Cargo.lock`, or run `cargo check` to refresh it.
2. Commit the intended application changes, version, lockfile, and workflow files.
3. Create and push a matching version tag. For example, after setting `0.0.2`:

   ```sh
   git tag -a v0.0.2 -m "Ghidra Rust 0.0.2"
   git push origin v0.0.2
   ```

The **Versioned native packages** workflow checks that the tag is exactly
`v<Cargo.toml version>` and that the lockfile agrees. It then calls the same
Linux and Windows build jobs used by regular CI. Linux builds on `ubuntu-24.04`;
Windows builds on `windows-2025`. An incorrect tag/version fails before the
expensive builds. You can also run the workflow manually from GitHub Actions
to build the selected revision without creating a tag.

After both jobs succeed, download **ghidra-rust-linux-x64** and
**ghidra-rust-windows-x64** from that workflow run's **Artifacts** section.
Artifact storage lasts 14 days. For permanent public downloads, create a GitHub
Release for the tag and attach the versioned executable, archive, and checksum
files from both artifacts. The workflow has read-only repository permissions and
does not create or publish a GitHub Release itself.

GitHub documents [version-tag workflow triggers](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#push)
and [workflow artifact downloads](https://docs.github.com/en/actions/tutorials/store-and-share-data).

## Release checks

Run the desktop checks in each platform's guide on the intended systems before
publishing. Worker tests and headless UI tests do not test every graphics driver.
Follow the [Windows trust limits](windows.md) and
[project trust boundaries](analysis.md#resource-limits-and-trust-boundaries).

The executables do not have OS code signatures. Checksums detect changes when
obtained through a trusted channel, but do not authenticate the publisher.
When configured, the separate update-manifest signature authenticates in-app
updates; it does not provide Windows Authenticode signing. A configured
workflow is not evidence of a successful hosted run; inspect the actual jobs for
the tagged commit. Hosted jobs do not run tests, so record local test results
for each platform you validated.

## In-app updates

Linux x64 and Windows x64 portable desktops provide **Help → Check for updates…**.
Checking and downloading are explicit user actions; there are no startup checks
or automatic installations. The app examines at most 60 recent published releases
and chooses the highest newer `vX.Y.Z` version. Alpha (`0.x`) builds include
pre-releases; stable builds exclude them. Drafts and downgrades are rejected.
Missing or invalid signatures stop the update and leave a GitHub Releases link.

The app authenticates the exact `update.json` bytes using the Ed25519 public key
embedded from `data/update-public-key.txt`. The manifest binds the repository,
version, platform, filenames, lengths, and SHA-256 hashes of both standalone
executables and a combined dependency-notice file. Only matching HTTPS release
assets are accepted. Responses, downloads, release counts, and timeouts are
bounded. Downloads stream to a private staging directory rather than retaining
the executable in memory. Files are hashed again during installation.

**Download update** stages the executable and notices. **Install and restart**
uses the normal save/discard/cancel flow, stops and reaps the current analysis
worker, stages files beside the installed executable, and retains the previous
version. The executable is replaced only after validation. Linux uses atomic
replacement; Windows first renames the running executable to its recovery path,
then publishes the new file without overwriting a file that appeared meanwhile.
A failed Windows publication attempts to restore the previous path; if that is
not possible, the error identifies the retained executable for manual recovery.
An unexpected interruption between those Windows renames can also require manual
recovery. Input-file identity guards remain in force, including hard links: an
app analyzing its own executable must close that binary before updating.

The desktop exits before launching the new version. A saved project reopens;
unsaved binary-only sessions are not automatically restored. The installation
folder must be writable. The updater does not request elevation or manage system
packages. Installed documentation is not replaced; updated application and
dependency notices are collected from both release packages into a new
`ghidra-rust-VERSION-notices-*.txt` beside the executable. Keep this file when
redistributing an updated app.

Recovery copies use `ghidra-rust-previous-VERSION-*` (with `.exe` on Windows).
Keep them until the new release works, then remove obsolete copies manually.
To recover, close the app and copy the desired previous executable back to the
normal executable path. Older releases may reject projects saved in a newer
format; retain project backups before upgrading. Failed downloads and
verification never replace the installed executable. A failed relaunch leaves
the verified new executable installed. Windows shows the manual launch path in
a native error dialog; Linux reports it through stderr, which may not be visible
when launched from a desktop menu. Linux directory entries are not explicitly
fsynced, so atomic replacement is not a power-loss durability guarantee.

### Configure release signing once

The repository's public key must match the private PEM supplied in the
**UPDATE_SIGNING_KEY** GitHub Actions secret. The private key is never committed
or embedded in the app. The maintainer must retain the corresponding private key
securely outside the repository/build directory, back it up, and configure the
repository secret:

```sh
gh secret set UPDATE_SIGNING_KEY --repo mahirriki1/ghidra-rust < /secure/path/update-signing.pem
```

To initialize a new fork before distributing its first updater-enabled build,
remove its inherited public key, change the repository constants in the updater
and signing script, then run:

```sh
python3 scripts/sign-updates.py --init-key /secure/path/update-signing.pem
```

This refuses to overwrite an existing key or trust root. Replacing the public
key after distribution breaks the existing clients' trust chain; key rotation
requires a planned transition release authenticated by the old key.

The automatic publisher verifies both complete native packages first, then signs
the update manifest using OpenSSL and uploads `update.json`, `update.json.sig`,
and `ghidra-rust-VERSION-update-notices.txt` alongside the usual eight assets.
Signing fails if the secret does not match the embedded public key. Without the
secret, publication emits a warning and retains the existing downloadable package
workflow, but that release cannot be installed in-app. Manual releases can add
the same files after package verification:

```sh
python3 scripts/verify-release-assets.py target/release-assets
python3 scripts/sign-updates.py --sign target/release-assets --key-file /secure/path/update-signing.pem
python3 -m unittest discover -s scripts -p 'test_updates.py'
```

The first updater-enabled version requires a manual download. Installation and
restart still need native Windows validation before being described as tested
there; Linux checks do not establish Windows runtime support.
