//! Main-image address translation for one local Linux x86-64 inferior.
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use crate::model::{BinaryInfo, FileIdentity, SectionInfo};

use super::Error;

const MAX_MAP_BYTES: usize = 2 * 1024 * 1024;
const MAX_MAP_COUNT: usize = 16_384;
const MAX_AUXV_BYTES: usize = 4096;
const AT_ENTRY: u64 = 9;

pub(super) struct Inferior {
    pidfd: OwnedFd,
    directory: File,
}

impl Inferior {
    pub(super) fn open(pid: u32, parent: u32) -> Result<Self, Error> {
        let pid = i32::try_from(pid)
            .ok()
            .filter(|&pid| pid > 1)
            .ok_or_else(|| Error::protocol("Invalid GDB inferior PID"))?;
        let directory = File::open(format!("/proc/{pid}"))?;
        // SAFETY: pidfd_open accepts a PID and zero flags and returns a new
        // descriptor on success. The proc directory below pins this PID entry.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: successful pidfd_open returned an owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let inferior = Self { pidfd, directory };
        let status = read_limited(&inferior.path("status"), 64 * 1024)?;
        let status = String::from_utf8_lossy(&status);
        let ppid = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|v| v.trim().parse().ok());
        if ppid != Some(parent) {
            return Err(Error::protocol(
                "GDB inferior is not a child of this debugger",
            ));
        }
        Ok(inferior)
    }

    pub(super) fn path(&self, name: &str) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/{name}",
            self.directory.as_raw_fd()
        ))
    }

    pub(super) fn terminate(&self) {
        // SAFETY: the owned pidfd identifies only this tracked child, even if
        // its PID is reused. With a null siginfo the kernel supplies defaults.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0_u32,
            );
        }
    }
}

pub(super) struct Image {
    identity: FileIdentity,
    entry: u64,
    sections: Vec<SectionInfo>,
}

impl Image {
    pub(super) fn new(info: &BinaryInfo, identity: FileIdentity) -> Self {
        let sections = info
            .sections
            .iter()
            .filter(|s| s.executable && s.file_size > 0)
            .cloned()
            .collect();
        Self {
            identity,
            entry: info.entry,
            sections,
        }
    }

    pub(super) fn mapping(&self, inferior: &Inferior) -> Result<Mapping, Error> {
        let executable = fs::metadata(inferior.path("exe"))?;
        if FileIdentity::from_metadata(&executable) != Some(self.identity) {
            return Err(Error::Invalid(
                "The running executable differs from the analyzed image".into(),
            ));
        }
        let auxv = read_limited(&inferior.path("auxv"), MAX_AUXV_BYTES)?;
        let (pairs, remainder) = auxv.as_chunks::<16>();
        if !remainder.is_empty() {
            return Err(Error::protocol("Invalid x86-64 auxiliary vector"));
        }
        let mut entry = None;
        for pair in pairs {
            let kind = u64::from_le_bytes(pair[..8].try_into().expect("8 bytes"));
            if kind == 0 {
                break;
            }
            if kind == AT_ENTRY {
                let value = u64::from_le_bytes(pair[8..].try_into().expect("8 bytes"));
                if value == 0 || entry.replace(value).is_some() {
                    return Err(Error::protocol("Invalid runtime entry address"));
                }
            }
        }
        let entry = entry.ok_or_else(|| Error::protocol("Missing runtime entry address"))?;
        let bias = i128::from(entry) - i128::from(self.entry);
        let maps = read_limited(&inferior.path("maps"), MAX_MAP_BYTES)?;
        let mut ranges = Vec::new();
        let mut last_end = 0;
        for (i, line) in maps
            .split(|&byte| byte == b'\n')
            .filter(|line| !line.is_empty())
            .enumerate()
        {
            if i >= MAX_MAP_COUNT {
                return Err(Error::protocol("Too many process mappings"));
            }
            // Paths are unnecessary and can contain non-UTF-8 bytes. The
            // kernel supplies the address, permissions, offset and identity.
            let mut fields = line
                .split(|b| b.is_ascii_whitespace())
                .filter(|part| !part.is_empty());
            let mut next = || {
                fields
                    .next()
                    .and_then(|part| std::str::from_utf8(part).ok())
                    .ok_or_else(|| Error::protocol("Invalid process mapping"))
            };
            let (start, end) = next()?
                .split_once('-')
                .ok_or_else(|| Error::protocol("Invalid process mapping range"))?;
            let start = hex(start)?;
            let end = hex(end)?;
            let perm = next()?.as_bytes();
            let offset = hex(next()?)?;
            let (major, minor) = next()?
                .split_once(':')
                .ok_or_else(|| Error::protocol("Invalid process mapping device"))?;
            let inode: u64 = next()?
                .parse()
                .map_err(|_| Error::protocol("Invalid process mapping inode"))?;
            if start < last_end || start >= end || perm.len() != 4 {
                return Err(Error::protocol("Unordered or invalid process mapping"));
            }
            last_end = end;
            if perm[2] == b'x'
                && inode == self.identity.inode
                && hex(major)? == u64::from(libc::major(self.identity.device))
                && hex(minor)? == u64::from(libc::minor(self.identity.device))
            {
                ranges.push(Region { start, end, offset });
            }
        }
        let mapping = Mapping { bias, ranges };
        if mapping.to_static(self, entry) != Some(self.entry) {
            return Err(Error::Invalid(
                "The live entry does not match the analyzed executable mapping".into(),
            ));
        }
        Ok(mapping)
    }
}

struct Region {
    start: u64,
    end: u64,
    offset: u64,
}

pub(super) struct Mapping {
    bias: i128,
    ranges: Vec<Region>,
}

impl Mapping {
    pub(super) fn to_static(&self, image: &Image, runtime: u64) -> Option<u64> {
        let address = u64::try_from(i128::from(runtime) - self.bias).ok()?;
        let section = image.sections.get(
            image
                .sections
                .partition_point(|s| s.address <= address)
                .checked_sub(1)?,
        )?;
        let region = self.ranges.get(
            self.ranges
                .partition_point(|r| r.start <= runtime)
                .checked_sub(1)?,
        )?;
        if !section.backs(address, 1) || runtime >= region.end {
            return None;
        }
        let static_offset = section
            .file_offset
            .checked_add(address.checked_sub(section.address)?)?;
        let runtime_offset = region
            .offset
            .checked_add(runtime.checked_sub(region.start)?)?;
        (static_offset == runtime_offset).then_some(address)
    }

    pub(super) fn to_runtime(&self, image: &Image, address: u64) -> Option<u64> {
        let runtime = u64::try_from(i128::from(address) + self.bias).ok()?;
        (self.to_static(image, runtime) == Some(address)).then_some(runtime)
    }
}

fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    let mut data = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > limit {
        return Err(Error::protocol("Process metadata exceeded the size limit"));
    }
    Ok(data)
}

pub(super) fn hex(text: &str) -> Result<u64, Error> {
    u64::from_str_radix(text, 16).map_err(|_| Error::protocol("Invalid hexadecimal address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_checks_file_offsets_permissions_and_file_backing() {
        let image = Image {
            identity: FileIdentity {
                device: 0,
                inode: 0,
                inode_high: 0,
            },
            entry: 0x1000,
            sections: vec![SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 0x100,
                file_offset: 0x2000,
                file_size: 0x80,
                executable: true,
            }],
        };
        let mapping = Mapping {
            bias: 0x4000,
            ranges: vec![
                Region {
                    start: 0x5000,
                    end: 0x5040,
                    offset: 0x2000,
                },
                Region {
                    start: 0x5040,
                    end: 0x5100,
                    offset: 0x9000,
                },
                Region {
                    start: 0x6000,
                    end: 0x6100,
                    offset: 0x2000,
                },
            ],
        };
        assert_eq!(mapping.to_static(&image, 0x5010), Some(0x1010));
        assert_eq!(mapping.to_runtime(&image, 0x1010), Some(0x5010));
        assert_eq!(mapping.to_static(&image, 0x5040), None);
        assert_eq!(mapping.to_static(&image, 0x6000), None);
        let mapping = Mapping {
            bias: 0x4000,
            ranges: vec![Region {
                start: 0x5000,
                end: 0x5100,
                offset: 0x2000,
            }],
        };
        assert_eq!(mapping.to_runtime(&image, 0x107f), Some(0x507f));
        assert_eq!(mapping.to_runtime(&image, 0x1080), None);
    }
}
