- Check GitHub Releases through Help → Check for updates, including newer alpha
  releases from alpha builds, and download updates with progress and cancellation.
- Authenticate update manifests with an embedded Ed25519 key and verify signed
  sizes and SHA-256 hashes before download adoption and again before installation.
  Unsigned, malformed, incompatible, and older releases cannot be installed.
- Create Linux download staging with owner-only directory and file permissions,
  reject existing artifact names and symlinks, and reopen only regular files for
  installation. Persist verified license notices with readable permissions.
- Install portable Linux x64 and Windows x64 updates from writable folders using
  the existing save/discard/cancel prompt, stop and reap the analysis worker,
  restart the desktop, and reopen a saved project. Binary-only sessions are not
  restored automatically, and the updater does not request administrator access.
- Retain a recovery executable and current application, dependency, and embedded
  font notices beside the app. Preserve analyzed-input protection through renamed
  paths and hard links. Windows publication failures attempt restoration; an
  interruption between renames can require manual recovery from the retained copy.
- Add optional release-manifest signing to automatic publication through the
  UPDATE_SIGNING_KEY repository secret. Releases published without this setup
  remain manually downloadable but cannot be installed in-app. Update signatures
  do not provide operating-system code signing; the first updater-enabled version
  still requires a manual download.
