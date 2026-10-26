//! Independent declaration metadata. Never changes engine registration inputs.
use super::{Headers, Image, u16_at, u32_at, u64_at};
use crate::analysis::linkage::{Builder, ExportSpec, ImportSpec};
use crate::linkage::{ExportTarget, ImportKind, LinkageGap, MAX_LINKAGE_LABEL_BYTES};
use crate::model::MAX_SYMBOL_RAW_BYTES;

pub(super) fn parse(headers: &Headers<'_>) -> Builder {
    let mut out = Builder::default();
    for (index, delay) in [(1, false), (13, true)] {
        if let Some((rva, size)) = headers.directory(index) {
            imports(&headers.image, rva, size, headers.is64, delay, &mut out);
        }
    }
    if let Some((rva, size)) = headers.directory(0) {
        exports(&headers.image, rva, size, &mut out);
    }
    out
}

fn malformed(out: &mut Builder) {
    out.gap(LinkageGap::Malformed);
}

fn name<'a>(image: &Image<'a>, rva: u32, maximum: usize, out: &mut Builder) -> Option<&'a [u8]> {
    let region = image.region(rva, 1)?;
    let length = usize::try_from(region.end - u64::from(rva))
        .ok()?
        .min(maximum + 1);
    let data = image.data(rva, length)?;
    out.c_string(data, maximum)
}

fn imports(image: &Image<'_>, rva: u32, size: u32, is64: bool, delay: bool, out: &mut Builder) {
    let Some(data) = image.directory(rva, size) else {
        return malformed(out);
    };
    let width = if is64 { 8 } else { 4 };
    let stride = if delay { 32 } else { 20 };
    let flag = if is64 { 1u64 << 63 } else { 1u64 << 31 };
    for descriptor in data.chunks_exact(stride) {
        if !out.scan_bytes(1, stride) {
            return;
        }
        if descriptor.iter().all(|b| *b == 0) {
            return;
        }
        if delay && u32_at(descriptor, 0) != Some(1) {
            out.gap(LinkageGap::DelayVariant);
            continue;
        }
        let library_rva = u32_at(descriptor, if delay { 4 } else { 12 }).unwrap_or(0);
        let library = name(image, library_rva, MAX_LINKAGE_LABEL_BYTES, out)
            .and_then(|name| out.library(name));
        if library.is_none() {
            malformed(out);
        }
        let iat = u32_at(descriptor, if delay { 12 } else { 16 }).unwrap_or(0);
        let original = u32_at(descriptor, if delay { 16 } else { 0 }).unwrap_or(0);
        let lookup = if original == 0 && !delay {
            iat
        } else {
            original
        };
        if iat == 0 || lookup == 0 {
            malformed(out);
            continue;
        }
        let mut terminated = false;
        for index in 0..=crate::linkage::MAX_IMPORTS {
            if !out.scan_bytes(1, width * 2) {
                return;
            }
            if out.imports_full() {
                out.gap(LinkageGap::ImportLimit);
                return;
            }
            let offset = (index * width) as u32;
            let value = lookup
                .checked_add(offset)
                .and_then(|rva| image.data(rva, width))
                .and_then(|entry| {
                    if is64 {
                        u64_at(entry, 0)
                    } else {
                        u32_at(entry, 0).map(u64::from)
                    }
                });
            let Some(value) = value else {
                break;
            };
            if value == 0 {
                terminated = true;
                break;
            }
            let Some(slot) = iat
                .checked_add(offset)
                .filter(|rva| image.data(*rva, width).is_some())
                .and_then(|rva| image.address(rva))
            else {
                break;
            };
            let (raw, ordinal) = if value & flag != 0 {
                if value & !(flag | 0xffff) != 0 {
                    malformed(out);
                    continue;
                }
                (None, Some((value & 0xffff) as u32))
            } else {
                let raw = u32::try_from(value)
                    .ok()
                    .filter(|rva| *rva <= 0x7fff_ffff)
                    .filter(|rva| image.data(*rva, 2).is_some())
                    .and_then(|rva| rva.checked_add(2))
                    .and_then(|rva| name(image, rva, MAX_SYMBOL_RAW_BYTES, out));
                if raw.is_none() {
                    malformed(out);
                    continue;
                }
                (raw, None)
            };
            out.import(ImportSpec {
                raw,
                ordinal,
                library,
                scope: None,
                version: None,
                kind: if delay {
                    ImportKind::Delay
                } else {
                    ImportKind::Normal
                },
                weak: false,
                slot: Some(slot),
            });
        }
        if !terminated {
            malformed(out);
        }
    }
    malformed(out);
}

fn exports(image: &Image<'_>, rva: u32, size: u32, out: &mut Builder) {
    let Some(directory) = image.directory(rva, size).filter(|data| data.len() >= 40) else {
        return malformed(out);
    };
    let count = u32_at(directory, 20).unwrap_or(0) as usize;
    let names = u32_at(directory, 24).unwrap_or(0) as usize;
    if count > crate::linkage::MAX_LINKAGE_SCAN || names > crate::linkage::MAX_LINKAGE_SCAN {
        out.gap(LinkageGap::ScanLimit);
        return;
    }
    if count == 0 {
        if names != 0 {
            malformed(out);
        }
        return;
    }
    let Some(addresses) = image.data(u32_at(directory, 28).unwrap_or(0), count * 4) else {
        return malformed(out);
    };
    let base = u32_at(directory, 16).unwrap_or(0);
    let forward_end = u64::from(rva) + u64::from(size);
    let mut named = std::collections::BTreeSet::new();
    let emit = |index: usize, raw: Option<&[u8]>, out: &mut Builder| {
        let Some(ordinal) = base.checked_add(index as u32) else {
            return malformed(out);
        };
        let target_rva = u32_at(addresses, index * 4).unwrap_or(0);
        if target_rva == 0 {
            return;
        }
        let target = if (u64::from(rva)..forward_end).contains(&u64::from(target_rva)) {
            let available = (forward_end - u64::from(target_rva)) as usize;
            let forward = image
                .data(
                    target_rva,
                    available.min(MAX_SYMBOL_RAW_BYTES + MAX_LINKAGE_LABEL_BYTES + 1),
                )
                .and_then(|data| out.c_string(data, MAX_SYMBOL_RAW_BYTES + MAX_LINKAGE_LABEL_BYTES))
                .and_then(|data| std::str::from_utf8(data).ok())
                .filter(|text| {
                    text.rsplit_once('.')
                        .is_some_and(|(library, symbol)| !library.is_empty() && !symbol.is_empty())
                });
            match forward {
                Some(target) => ExportTarget::Forwarder {
                    target: target.into(),
                },
                None => {
                    malformed(out);
                    ExportTarget::Unresolved
                }
            }
        } else {
            image
                .address(target_rva)
                .map_or(ExportTarget::Unresolved, |address| ExportTarget::Data {
                    address,
                })
        };
        out.export(ExportSpec {
            raw,
            ordinal: Some(ordinal),
            version: None,
            target,
        });
    };
    if names != 0 {
        let tables = image
            .data(u32_at(directory, 32).unwrap_or(0), names * 4)
            .zip(image.data(u32_at(directory, 36).unwrap_or(0), names * 2));
        if let Some((pointers, ordinals)) = tables {
            for index in 0..names {
                if !out.scan_bytes(1, 10) {
                    return;
                }
                let ordinal = u16_at(ordinals, index * 2).unwrap_or(u16::MAX) as usize;
                if ordinal >= count {
                    malformed(out);
                    continue;
                }
                let raw = name(
                    image,
                    u32_at(pointers, index * 4).unwrap_or(0),
                    MAX_SYMBOL_RAW_BYTES,
                    out,
                );
                if raw.is_none() {
                    malformed(out);
                }
                emit(ordinal, raw, out);
                named.insert(ordinal);
                if out.exports_full() {
                    out.gap(LinkageGap::ExportLimit);
                    return;
                }
            }
        } else {
            malformed(out);
        }
    }
    for index in 0..count {
        if !out.scan_bytes(1, 4) {
            return;
        }
        if !named.contains(&index) {
            emit(index, None, out);
        }
        if out.exports_full() {
            out.gap(LinkageGap::ExportLimit);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linkage::{LinkageFetch, LinkageRecord};
    use crate::pe::tests::{file, fixture, put16, put32};

    fn original_declarations(is64: bool) -> (Vec<u8>, crate::model::BinaryInfo) {
        let (mut bytes, sections) = fixture(is64);
        let base = if is64 { 0x1_4000_0000 } else { 0x40_0000 };
        let directories = 0x98 + if is64 { 112 } else { 96 };
        // Five export slots: two aliases of code, a forwarder, named data,
        // ordinal-only code, and an out-of-image declaration.
        for (offset, value) in [
            (16, 11),
            (20, 5),
            (24, 3),
            (28, 0x2500),
            (32, 0x2520),
            (36, 0x2530),
        ] {
            put32(&mut bytes, file(0x2200) + offset, value);
        }
        for (index, rva) in [0x1040, 0x2250, 0x2400, 0x1060, 0xffff_ffff]
            .into_iter()
            .enumerate()
        {
            put32(&mut bytes, file(0x2500) + index * 4, rva);
        }
        for (index, (rva, ordinal, name)) in [
            (0x2540, 0, "branch_loop"),
            (0x2550, 0, "?foo@demo@@YAXXZ"),
            (0x2570, 2, "data_export"),
        ]
        .into_iter()
        .enumerate()
        {
            put32(&mut bytes, file(0x2520) + index * 4, rva);
            put16(&mut bytes, file(0x2530) + index * 2, ordinal);
            bytes[file(rva as usize)..file(rva as usize) + name.len()]
                .copy_from_slice(name.as_bytes());
        }
        bytes[file(0x2250)..file(0x2250) + 15].copy_from_slice(b"KERNEL32.Sleep\0");
        // Conventional RVA-form delay imports, one named and one ordinal.
        put32(&mut bytes, directories + 13 * 8, 0x2400);
        put32(&mut bytes, directories + 13 * 8 + 4, 64);
        for (offset, value) in [(0, 1), (4, 0x24a0), (12, 0x2480), (16, 0x2460)] {
            put32(&mut bytes, file(0x2400) + offset, value);
        }
        bytes[file(0x24a0)..file(0x24a0) + 10].copy_from_slice(b"DELAY.dll\0");
        bytes[file(0x24c2)..file(0x24c2) + 13].copy_from_slice(b"?f@@YAXXZ\0\0\0\0");
        let width = if is64 { 8 } else { 4 };
        for (index, value) in [0x24c0u64, (if is64 { 1 << 63 } else { 1 << 31 }) | 37]
            .into_iter()
            .enumerate()
        {
            let at = file(0x2460) + index * width;
            bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
        }
        let info = crate::model::BinaryInfo {
            path: "original PE declarations".into(),
            architecture: if is64 { "x86-64" } else { "x86" }.into(),
            format: "PE".into(),
            entry: base + 0x1000,
            file_len: bytes.len() as u64,
            sha256: "0".repeat(64),
            source_identity: None,
            sections,
            functions: vec![],
            functions_truncated: false,
            warnings: vec![],
        };
        (bytes, info)
    }

    #[test]
    fn pe_linkage_retains_libraries_delay_ordinals_aliases_data_and_forwarders() {
        for is64 in [false, true] {
            let (bytes, info) = original_declarations(is64);
            let before = crate::pe::parse(&bytes, &info.sections).unwrap().unwrap();
            let table = crate::pe::linkage(&bytes, &info.sections)
                .unwrap()
                .unwrap()
                .finish(&info, crate::symbol_names::SymbolFormat::Pe);
            assert_eq!(table.summary().imports, 4);
            assert_eq!(table.summary().exports, 6);
            assert!(
                table.summary().gaps.is_empty(),
                "{:?}",
                table.summary().gaps
            );
            let mut fetch = LinkageFetch::new(table.summary().clone(), &info.sha256).unwrap();
            fetch.accept(table.page(0).unwrap(), &info).unwrap();
            let linkage = fetch.finish().unwrap();
            assert_eq!(
                linkage
                    .libraries
                    .iter()
                    .map(|library| library.name.as_str())
                    .collect::<Vec<_>>(),
                ["KERNEL32.dll", "DELAY.dll"]
            );
            assert_eq!(linkage.imports[1].ordinal, Some(7));
            assert_eq!(linkage.imports[1].raw, None);
            assert_eq!(linkage.imports[2].kind, ImportKind::Delay);
            assert_eq!(linkage.imports[2].display.as_deref(), Some("f"));
            assert_eq!(linkage.imports[3].ordinal, Some(37));
            let aliases: Vec<_> = linkage
                .exports
                .iter()
                .filter(|export| export.ordinal == Some(11))
                .collect();
            assert_eq!(aliases.len(), 2);
            assert_eq!(aliases[0].target, aliases[1].target);
            assert_eq!(aliases[1].display.as_deref(), Some("demo::foo"));
            assert!(linkage.exports.iter().any(|export| export.target
                == ExportTarget::Forwarder {
                    target: "KERNEL32.Sleep".into()
                }));
            assert!(linkage.exports.iter().any(|export| matches!(
                export.target,
                ExportTarget::Data { .. }
            ) && export.raw.as_deref()
                == Some("data_export")));
            assert!(
                linkage
                    .exports
                    .iter()
                    .any(|export| export.ordinal == Some(15)
                        && export.target == ExportTarget::Unresolved)
            );
            let after = crate::pe::parse(&bytes, &info.sections).unwrap().unwrap();
            assert_eq!(before.functions, after.functions);
            assert_eq!(before.imports, after.imports);
            assert_eq!(
                before.imports.len(),
                2,
                "delay imports never seed analysis registration"
            );
        }
    }

    #[test]
    fn malformed_pe_linkage_is_bounded_and_keeps_metadata_without_inventing_addresses() {
        let (mut bytes, info) = original_declarations(true);
        put32(&mut bytes, file(0x2400), 0); // Old VA-form delay descriptor.
        put32(&mut bytes, file(0x2200) + 16, u32::MAX); // Ordinal-base overflow.
        put16(&mut bytes, file(0x2530), u16::MAX); // Invalid named alias.
        let table = crate::pe::linkage(&bytes, &info.sections)
            .unwrap()
            .unwrap()
            .finish(&info, crate::symbol_names::SymbolFormat::Pe);
        assert!(table.summary().gaps.contains(&LinkageGap::DelayVariant));
        assert!(table.summary().gaps.contains(&LinkageGap::Malformed));
        assert_eq!(table.summary().imports, 2);
        assert!(table.records().iter().all(|record| !matches!(record, LinkageRecord::Import(import) if import.kind == ImportKind::Delay)));
        for end in (0..bytes.len()).step_by(53) {
            let _ = crate::pe::linkage(&bytes[..end], &info.sections);
        }
    }
}
