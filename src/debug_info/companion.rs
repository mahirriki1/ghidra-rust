//! Bounded, read-only dSYM snapshots. UUID and baseline arm64 slice must match.
use object::Object;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugSource {
    #[serde(deserialize_with = "crate::bounded::string::<_, 4096>")]
    pub path: String,
    #[serde(deserialize_with = "crate::bounded::string::<_, 32>")]
    pub uuid: String,
    #[serde(deserialize_with = "crate::bounded::string::<_, 64>")]
    pub sha256: String,
    #[serde(default)]
    pub identity: Option<crate::model::FileIdentity>,
}
/// Pure path construction; directory traversal and file reads happen in the worker.
pub fn automatic(binary: &Path) -> Option<PathBuf> {
    let mut bundle = binary.as_os_str().to_os_string();
    bundle.push(".dSYM");
    Some(
        PathBuf::from(bundle)
            .join("Contents/Resources/DWARF")
            .join(binary.file_name()?),
    )
}
pub(super) fn read(
    binary: &[u8],
    path: &Path,
) -> Option<(Arc<[u8]>, DebugSource, Arc<std::fs::File>)> {
    let image = object::File::parse(binary).ok()?;
    if image.format() != object::BinaryFormat::MachO {
        return None;
    }
    let uuid = image.mach_uuid().ok()??;
    let prepared = super::companion_path::prepare(path).ok()?;
    let mut file = prepared.file.try_clone().ok()?;
    if !file.metadata().ok()?.is_file()
        || file.metadata().ok()?.len() > crate::analysis::MAX_IMAGE_BYTES
    {
        return None;
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(crate::analysis::MAX_IMAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > crate::analysis::MAX_IMAGE_BYTES {
        return None;
    }
    // Select exactly one baseline-arm64 slice before reading its UUID.
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let selected = select(&bytes)?;
    let debug = object::File::parse(selected).ok()?;
    let target = crate::architecture::Target::for_image(&debug).ok()?;
    if target.name != "AArch64"
        || debug.format() != object::BinaryFormat::MachO
        || debug.mach_uuid().ok()? != Some(uuid)
    {
        return None;
    }
    let source = DebugSource {
        path: path.to_string_lossy().into_owned(),
        uuid: uuid.iter().map(|b| format!("{b:02x}")).collect(),
        sha256: hash,
        identity: crate::model::FileIdentity::from_file(&file),
    };
    source.validate().ok()?;
    Some((Arc::from(selected), source, Arc::new(file)))
}

fn select(bytes: &[u8]) -> Option<&[u8]> {
    use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
    fn arch<'a, T: FatArch>(arches: &[T], bytes: &'a [u8]) -> Option<&'a [u8]> {
        if arches.len() > 64 {
            return None;
        }
        let mut matches = arches.iter().filter(|a| {
            a.architecture() == object::Architecture::Aarch64
                && a.cpusubtype() == object::macho::CPU_SUBTYPE_ARM64_ALL
        });
        let slice = matches.next()?.data(bytes).ok()?;
        if matches.next().is_some() {
            return None;
        }
        Some(slice)
    }
    match object::FileKind::parse(bytes).ok()? {
        object::FileKind::MachOFat32 => arch(MachOFatFile32::parse(bytes).ok()?.arches(), bytes),
        object::FileKind::MachOFat64 => arch(MachOFatFile64::parse(bytes).ok()?.arches(), bytes),
        object::FileKind::MachO64 => Some(bytes),
        _ => None,
    }
}
impl DebugSource {
    pub fn validate(&self) -> Result<(), String> {
        if self.path.is_empty()
            || self.path.len() > 4096
            || self.uuid.len() != 32
            || self.sha256.len() != 64
            || !self
                .uuid
                .bytes()
                .chain(self.sha256.bytes())
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("Invalid debug companion provenance".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image(uuid: u8) -> Vec<u8> {
        let (mut bytes, _) = crate::architecture::fixtures::macho();
        let commands = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let size = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let at = 32 + size as usize;
        bytes[at..at + 4].copy_from_slice(&0x1bu32.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&24u32.to_le_bytes());
        bytes[at + 8..at + 24].fill(uuid);
        bytes[16..20].copy_from_slice(&(commands + 1).to_le_bytes());
        bytes[20..24].copy_from_slice(&(size + 24).to_le_bytes());
        bytes
    }
    #[test]
    fn companion_requires_exact_uuid_and_slice_and_records_independent_hash() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("debug");
        let binary = image(1);
        std::fs::write(&path, image(2)).unwrap();
        assert!(read(&binary, &path).is_none());
        std::fs::write(&path, &binary).unwrap();
        let (snapshot, source, file) = read(&binary, &path).unwrap();
        assert_eq!(&*snapshot, binary.as_slice());
        assert_eq!(source.sha256, format!("{:x}", Sha256::digest(&binary)));
        assert_eq!(source.uuid, "01".repeat(16));
        // The retained handle denies writers on Windows; release it before
        // replacing the companion.
        drop(file);
        let mut wrong = binary.clone();
        wrong[8..12].copy_from_slice(&2u32.to_le_bytes());
        std::fs::write(&path, wrong).unwrap();
        assert!(read(&binary, &path).is_none());
        std::fs::write(&path, [0; 17]).unwrap();
        assert!(read(&binary, &path).is_none());
    }
    #[test]
    fn missing_uuid_and_oversized_companions_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("debug");
        std::fs::write(&path, image(1)).unwrap();
        assert!(read(&crate::architecture::fixtures::macho().0, &path).is_none());
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(crate::analysis::MAX_IMAGE_BYTES + 1).unwrap();
        assert!(read(&image(1), &path).is_none());
    }
}
