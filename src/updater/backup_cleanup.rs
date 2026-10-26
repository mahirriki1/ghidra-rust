//! Cleanup requires a pre-publication directory capability. Linux deliberately
//! retains recovery copies: pathname unlink cannot delete a validated open inode.
use crate::session::BinaryProtection;
use std::fs::File;
use std::path::Path;

pub(super) struct BackupCleanup {
    #[cfg(windows)]
    directory: Option<crate::windows::PinnedUpdateDirectory>,
}

#[cfg(windows)]
#[derive(Clone, Copy)]
/// Hook invoked immediately before the named operation.
pub(super) enum Boundary {
    Seal,
    Open,
    Delete,
}

impl BackupCleanup {
    #[cfg(all(test, windows))]
    pub(super) fn available(&self) -> bool {
        self.directory.is_some()
    }
    pub(super) fn prepare(path: &Path, running: &BinaryProtection) -> Self {
        #[cfg(windows)]
        {
            let directory = crate::windows::PinnedUpdateDirectory::open(path)
                .ok()
                .filter(|directory| {
                    running
                        .path()
                        .file_name()
                        .and_then(|name| directory.identity(name).ok())
                        .and_then(|file| crate::model::FileIdentity::from_file(&file))
                        == Some(running.file_identity())
                });
            Self { directory }
        }
        #[cfg(not(windows))]
        {
            let _ = (path, running);
            Self {}
        }
    }

    pub(super) fn check_member(&mut self, path: &Path, file: &File) {
        #[cfg(windows)]
        {
            let expected = crate::model::FileIdentity::from_file(file);
            let actual = self
                .identity_file(path)
                .as_ref()
                .and_then(crate::model::FileIdentity::from_file);
            if expected.is_none() || actual != expected {
                self.directory = None;
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (path, file);
        }
    }

    #[cfg(windows)]
    fn identity_file(&self, path: &Path) -> Option<File> {
        self.directory.as_ref()?.identity(path.file_name()?).ok()
    }

    #[cfg(windows)]
    pub(super) fn recovery_file(&self, path: &Path) -> Option<File> {
        self.identity_file(path)
    }

    #[cfg(windows)]
    pub(super) fn check_guard(&mut self, path: &Path, guard: &BinaryProtection) {
        let actual = self
            .identity_file(path)
            .as_ref()
            .and_then(crate::model::FileIdentity::from_file);
        if actual != Some(guard.file_identity()) {
            self.directory = None;
        }
    }

    #[cfg(any(windows, test))]
    pub(super) fn prune(&self, protections: &[BinaryProtection]) {
        #[cfg(windows)]
        self.prune_with(protections, |_, _| {});
        #[cfg(not(windows))]
        let _ = protections;
    }

    #[cfg(windows)]
    pub(super) fn prune_with(
        &self,
        protections: &[BinaryProtection],
        mut hook: impl FnMut(Boundary, &std::ffi::OsStr),
    ) {
        use std::collections::BTreeSet;
        let Some(directory) = &self.directory else {
            return;
        };
        hook(Boundary::Seal, std::ffi::OsStr::new(""));
        let Ok(directory) = directory.sealed() else {
            return;
        };
        let mut names = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for guard in protections {
            // Eligible names are strictly ASCII. Retain all copies if a guard's
            // spelling cannot be compared conservatively without filesystem case
            // tables; never approximate Unicode aliases with lossy conversion.
            let Some(name) = guard
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| name.is_ascii())
            else {
                return;
            };
            names.insert(name.to_ascii_lowercase());
            let id = guard.file_identity();
            identities.insert((id.device, id.inode, id.inode_high));
        }
        let mut removed = 0;
        let _ = directory.visit(super::MAX_BACKUP_ENTRIES_SCANNED, |name| {
            if !super::is_backup_name(name) {
                return true;
            }
            let Some(text) = name.to_str().filter(|name| name.is_ascii()) else {
                return true;
            };
            if names.contains(&text.to_ascii_lowercase()) {
                return true;
            }
            hook(Boundary::Open, name);
            let Ok(file) = directory.deletion(name) else {
                return true;
            };
            let Some(id) = crate::model::FileIdentity::from_file(&file) else {
                return true;
            };
            if identities.contains(&(id.device, id.inode, id.inode_high)) {
                return true;
            }
            hook(Boundary::Delete, name);
            if crate::windows::delete_open_file(&file).is_ok() {
                removed += 1;
            }
            removed < super::MAX_BACKUPS_REMOVED
        });
    }
}
