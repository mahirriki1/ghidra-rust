//! Original minimal linked containers, generated only in temporary test paths.
//! Instruction bytes come from the reviewed source fixture, never real programs.

pub const SYMBOLS: [(&str, u64); 4] = [
    ("fixture_entry", 0),
    ("fixture_sum", 48),
    ("fixture_indirect", 76),
    ("fixture_indirect_call", 80),
];
pub fn code() -> Vec<u8> {
    include_str!("../fixtures/aarch64.S")
        .lines()
        .filter_map(|line| {
            line.trim().strip_prefix(".inst 0x").map(|value| {
                u32::from_str_radix(value.split_whitespace().next().unwrap(), 16)
                    .unwrap()
                    .to_le_bytes()
            })
        })
        .flatten()
        .collect()
}
fn p16(b: &mut [u8], at: usize, value: u16) {
    b[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn p32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn p64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn name(b: &mut [u8], at: usize, value: &str) {
    b[at..at + value.len()].copy_from_slice(value.as_bytes());
}

pub fn elf(symbols: bool) -> (Vec<u8>, u64) {
    let base = 0x401000;
    let text = code();
    let mut b = vec![0; 0x600];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    p16(&mut b, 16, 2);
    p16(&mut b, 18, 183);
    p32(&mut b, 20, 1);
    p64(&mut b, 24, base);
    p64(&mut b, 32, 64);
    p64(&mut b, 40, 0x400);
    p16(&mut b, 52, 64);
    p16(&mut b, 54, 56);
    p16(&mut b, 56, 1);
    p16(&mut b, 58, 64);
    p16(&mut b, 60, 5);
    p16(&mut b, 62, 4);
    p32(&mut b, 64, 1);
    p32(&mut b, 68, 5);
    p64(&mut b, 72, 0x100);
    p64(&mut b, 80, base);
    p64(&mut b, 88, base);
    p64(&mut b, 96, text.len() as u64);
    p64(&mut b, 104, text.len() as u64);
    p64(&mut b, 112, 0x100);
    b[0x100..0x100 + text.len()].copy_from_slice(&text);
    let shnames = "\0.text\0.symtab\0.strtab\0.shstrtab\0";
    name(&mut b, 0x380, shnames);
    let mut str_at = 1;
    for (i, (symbol, offset)) in SYMBOLS.iter().enumerate() {
        let at = 0x200 + (i + 1) * 24;
        p32(&mut b, at, str_at as u32);
        b[at + 4] = 0x12;
        p16(&mut b, at + 6, 1);
        p64(&mut b, at + 8, base + offset);
        name(&mut b, 0x300 + str_at, symbol);
        str_at += symbol.len() + 1;
    }
    for (slot, n, t, flags, addr, off, len, link, align, entsize) in [
        (1, 1, 1, 6, base, 0x100, text.len() as u64, 0, 4, 0),
        (
            2,
            7,
            2,
            0,
            0,
            0x200,
            if symbols { 120 } else { 24 },
            3,
            8,
            24,
        ),
        (3, 15, 3, 0, 0, 0x300, str_at as u64, 0, 1, 0),
        (4, 23, 3, 0, 0, 0x380, shnames.len() as u64, 0, 1, 0),
    ] {
        let at = 0x400 + slot * 64;
        p32(&mut b, at, n);
        p32(&mut b, at + 4, t);
        p64(&mut b, at + 8, flags);
        p64(&mut b, at + 16, addr);
        p64(&mut b, at + 24, off);
        p64(&mut b, at + 32, len);
        p32(&mut b, at + 40, link);
        if t == 2 {
            p32(&mut b, at + 44, 1);
        }
        p64(&mut b, at + 48, align);
        p64(&mut b, at + 56, entsize);
    }
    (b, base)
}

pub fn pe() -> (Vec<u8>, u64) {
    let image_base = 0x140000000;
    let base = image_base + 0x1000;
    let text = code();
    let mut b = vec![0; 0x600];
    name(&mut b, 0, "MZ");
    p32(&mut b, 0x3c, 0x80);
    name(&mut b, 0x80, "PE\0\0");
    p16(&mut b, 0x84, 0xaa64);
    p16(&mut b, 0x86, 2);
    p16(&mut b, 0x94, 240);
    p16(&mut b, 0x96, 0x22);
    let o = 0x98;
    p16(&mut b, o, 0x20b);
    p32(&mut b, o + 4, 0x200);
    p32(&mut b, o + 16, 0x1000);
    p32(&mut b, o + 20, 0x1000);
    p64(&mut b, o + 24, image_base);
    p32(&mut b, o + 32, 0x1000);
    p32(&mut b, o + 36, 0x200);
    p16(&mut b, o + 40, 6);
    p16(&mut b, o + 48, 6);
    p32(&mut b, o + 56, 0x3000);
    p32(&mut b, o + 60, 0x200);
    p16(&mut b, o + 68, 3);
    p64(&mut b, o + 72, 0x100000);
    p64(&mut b, o + 80, 0x1000);
    p64(&mut b, o + 88, 0x100000);
    p64(&mut b, o + 96, 0x1000);
    p32(&mut b, o + 108, 16);
    p32(&mut b, o + 112, 0x2000);
    p32(&mut b, o + 116, 0x200);
    for (at, n, rva, offset, flags) in [
        (0x188, ".text", 0x1000, 0x200, 0x60000020),
        (0x1b0, ".rdata", 0x2000, 0x400, 0x40000040),
    ] {
        name(&mut b, at, n);
        p32(&mut b, at + 8, 0x200);
        p32(&mut b, at + 12, rva);
        p32(&mut b, at + 16, 0x200);
        p32(&mut b, at + 20, offset);
        p32(&mut b, at + 36, flags);
    }
    b[0x200..0x200 + text.len()].copy_from_slice(&text);
    p32(&mut b, 0x410, 1);
    p32(&mut b, 0x414, 4);
    p32(&mut b, 0x418, 4);
    p32(&mut b, 0x41c, 0x2040);
    p32(&mut b, 0x420, 0x2050);
    p32(&mut b, 0x424, 0x2060);
    let mut at = 0x480;
    for (i, (symbol, offset)) in SYMBOLS.iter().enumerate() {
        p32(&mut b, 0x440 + i * 4, 0x1000 + *offset as u32);
        p32(&mut b, 0x450 + i * 4, (at - 0x400 + 0x2000) as u32);
        p16(&mut b, 0x460 + i * 2, i as u16);
        name(&mut b, at, symbol);
        at += symbol.len() + 1;
    }
    (b, base)
}

pub fn arm64_pe_metadata() -> (Vec<u8>, u64) {
    let (mut b, base) = pe();
    b.resize(0xc00, 0);
    b[0x108..0x110].fill(0); // stripped: no exports
    p32(&mut b, 0x1b8, 0x800); // .rdata virtual/raw extent
    p32(&mut b, 0x1c0, 0x800);
    let words: Vec<_> = include_str!("../fixtures/arm64-pe.S")
        .lines()
        .filter_map(|line| line.trim().strip_prefix(".inst 0x"))
        .map(|value| u32::from_str_radix(value.split_whitespace().next().unwrap(), 16).unwrap())
        .collect();
    let mut source = 0;
    for (offset, count) in [(0x80, 2), (0x90, 2), (0xa0, 5), (0xc0, 3)] {
        for index in 0..count {
            p32(&mut b, 0x200 + offset + index * 4, words[source]);
            source += 1;
        }
    }
    assert_eq!(source, words.len());
    // Ordered .pdata: normal packed, isolated normal packed, fragment, full xdata.
    p32(&mut b, 0x108 + 3 * 8, 0x2200);
    p32(&mut b, 0x108 + 3 * 8 + 4, 32);
    for (index, (start, unwind)) in [
        (0x1000, 0x00e0_0029), // 40 bytes, frame16, chained FP/LR
        (0x1080, 9),           // 8 bytes, no frame
        (0x1090, 10),          // 8-byte fragment; no independent function evidence
        (0x10a0, 0x2300),
    ]
    .into_iter()
    .enumerate()
    {
        p32(&mut b, 0x600 + index * 8, start);
        p32(&mut b, 0x604 + index * 8, unwind);
    }
    p32(&mut b, 0x700, 0x0820_0005); // length20, E=1/index0, one code word
    b[0x704..0x708].copy_from_slice(&[0xe1, 0x81, 0xe4, 0xe3]);
    // Named, loader-written IAT: do not use the on-disk lookup value as a PC.
    p32(&mut b, 0x110, 0x2400);
    p32(&mut b, 0x114, 40);
    p32(&mut b, 0x800, 0x2460);
    p32(&mut b, 0x80c, 0x2480);
    p32(&mut b, 0x810, 0x2500);
    p64(&mut b, 0x860, 0x24a0);
    name(&mut b, 0x880, "fixture.dll\0");
    name(&mut b, 0x8a2, "fixture_import\0");
    p64(&mut b, 0x900, 0x24a0);
    (b, base)
}

pub fn macho() -> (Vec<u8>, u64) {
    let base = 0x100001000;
    let text = code();
    let mut b = vec![0; 0x1200];
    p32(&mut b, 0, 0xfeedfacf);
    p32(&mut b, 4, 0x100000c);
    p32(&mut b, 8, 0);
    p32(&mut b, 12, 2);
    p32(&mut b, 16, 3);
    p32(&mut b, 20, 152 + 24 + 24);
    p32(&mut b, 24, 1);
    // LC_SEGMENT_64 with one __text section.
    let s = 32;
    p32(&mut b, s, 0x19);
    p32(&mut b, s + 4, 152);
    name(&mut b, s + 8, "__TEXT");
    p64(&mut b, s + 24, base - 0x1000);
    p64(&mut b, s + 32, 0x2000);
    p64(&mut b, s + 40, 0);
    p64(&mut b, s + 48, 0x1200);
    p32(&mut b, s + 56, 5);
    p32(&mut b, s + 60, 5);
    p32(&mut b, s + 64, 1);
    name(&mut b, s + 72, "__text");
    name(&mut b, s + 88, "__TEXT");
    p64(&mut b, s + 104, base);
    p64(&mut b, s + 112, text.len() as u64);
    p32(&mut b, s + 120, 0x1000);
    p32(&mut b, s + 124, 2);
    p32(&mut b, s + 136, 0x80000400);
    let sym = s + 152;
    p32(&mut b, sym, 2);
    p32(&mut b, sym + 4, 24);
    p32(&mut b, sym + 8, 0x1080);
    p32(&mut b, sym + 12, 4);
    p32(&mut b, sym + 16, 0x1100);
    p32(&mut b, sym + 20, 0x100);
    let main = sym + 24;
    p32(&mut b, main, 0x80000028);
    p32(&mut b, main + 4, 24);
    p64(&mut b, main + 8, 0x1000);
    b[0x1000..0x1000 + text.len()].copy_from_slice(&text);
    let mut str_at = 1;
    for (i, (symbol, offset)) in SYMBOLS.iter().enumerate() {
        let at = 0x1080 + i * 16;
        p32(&mut b, at, str_at as u32);
        b[at + 4] = 0xf;
        b[at + 5] = 1;
        p64(&mut b, at + 8, base + offset);
        name(&mut b, 0x1100 + str_at, &format!("_{symbol}"));
        str_at += symbol.len() + 2;
    }
    (b, base)
}

/// The baseline linked arm64 Mach-O plus an instruction-marked symbol-stub section.
#[allow(dead_code)] // Shared fixture module is also included by non-Mach-O test targets.
pub fn macho_with_stubs() -> (Vec<u8>, u64) {
    let (mut bytes, base) = macho();
    bytes.copy_within(184..232, 264);
    bytes[184..264].fill(0);
    p32(&mut bytes, 20, 280);
    p32(&mut bytes, 36, 232);
    p32(&mut bytes, 96, 2);
    name(&mut bytes, 184, "__stubs");
    name(&mut bytes, 200, "__TEXT");
    p64(&mut bytes, 216, base + 0x180);
    p64(&mut bytes, 224, 4);
    p32(&mut bytes, 232, 0x1180);
    p32(&mut bytes, 236, 2);
    p32(&mut bytes, 248, 0x80000408);
    p32(&mut bytes, 256, 4);
    bytes[0x1180..0x1184].copy_from_slice(&0xd65f03c0_u32.to_le_bytes());
    (bytes, base)
}

/// Minimal original DWARF v4 prototype, independent of any cross linker.
#[allow(dead_code)]
pub fn dwarf_prototype(macho_format: bool, register: u8) -> (Vec<u8>, u64) {
    let (mut image, base) = if macho_format { macho() } else { elf(true) };
    let abbrev = vec![
        1, 0x11, 1, 0, 0, 2, 0x2e, 1, 0x11, 1, 0x03, 8, 0x49, 0x13, 0, 0, 3, 5, 0, 3, 8, 0x49,
        0x13, 2, 0x18, 0, 0, 4, 0x24, 0, 0x0b, 0x0b, 0x3e, 0x0b, 0, 0, 0,
    ];
    let mut info = vec![0; 11];
    info[4..6].copy_from_slice(&4u16.to_le_bytes());
    info[10] = 8;
    info.extend_from_slice(&[1, 2]);
    info.extend_from_slice(&base.to_le_bytes());
    info.extend_from_slice(b"fixture_entry\0");
    let output = info.len();
    info.extend_from_slice(&[0; 4]);
    info.extend_from_slice(b"\x03count\0");
    let input = info.len();
    info.extend_from_slice(&[0; 4]);
    info.extend_from_slice(&[1, 0x50 + register, 0]);
    let ty = info.len() as u32;
    info.extend_from_slice(&[4, 4, 5, 0]);
    info[output..output + 4].copy_from_slice(&ty.to_le_bytes());
    info[input..input + 4].copy_from_slice(&ty.to_le_bytes());
    let size = (info.len() - 4) as u32;
    info[..4].copy_from_slice(&size.to_le_bytes());
    if macho_format {
        let old = u32::from_le_bytes(image[20..24].try_into().unwrap());
        let at = 32 + old as usize;
        p32(&mut image, 16, 4);
        p32(&mut image, 20, old + 232);
        p32(&mut image, at, 0x19);
        p32(&mut image, at + 4, 232);
        name(&mut image, at + 8, "__DWARF");
        p32(&mut image, at + 64, 2);
        for (i, (n, data)) in [("__debug_info", &info), ("__debug_abbrev", &abbrev)]
            .into_iter()
            .enumerate()
        {
            let offset = image.len();
            image.extend_from_slice(data);
            let section = at + 72 + i * 80;
            name(&mut image, section, n);
            name(&mut image, section + 16, "__DWARF");
            p64(&mut image, section + 40, data.len() as u64);
            p32(&mut image, section + 48, offset as u32);
        }
    } else {
        let names = b"\0.text\0.symtab\0.strtab\0.shstrtab\0.debug_info\0.debug_abbrev\0";
        image[0x380..0x380 + names.len()].copy_from_slice(names);
        p64(&mut image, 0x400 + 4 * 64 + 32, names.len() as u64);
        p16(&mut image, 60, 7);
        image.resize(0x400 + 7 * 64, 0);
        for (i, data) in [&info, &abbrev].into_iter().enumerate() {
            // Name offsets derive from the literal above, independent of parser output.
            let n = if i == 0 {
                names
                    .windows(12)
                    .position(|s| s == b".debug_info\0")
                    .unwrap()
            } else {
                names
                    .windows(14)
                    .position(|s| s == b".debug_abbrev\0")
                    .unwrap()
            };
            let offset = image.len();
            image.extend_from_slice(data);
            let at = 0x400 + (5 + i) * 64;
            p32(&mut image, at, n as u32);
            p32(&mut image, at + 4, 1);
            p64(&mut image, at + 24, offset as u64);
            p64(&mut image, at + 32, data.len() as u64);
            p64(&mut image, at + 48, 1);
        }
    }
    (image, base)
}

#[allow(dead_code)]
pub fn replace_elf_dwarf(mut image: Vec<u8>, info: &[u8], abbrev: &[u8]) -> Vec<u8> {
    for (i, bytes) in [info, abbrev].into_iter().enumerate() {
        let at = 0x400 + (5 + i) * 64;
        let offset = image.len();
        image.extend_from_slice(bytes);
        p64(&mut image, at + 24, offset as u64);
        p64(&mut image, at + 32, bytes.len() as u64);
    }
    image
}

#[allow(dead_code)]
pub fn with_macho_uuid(mut image: Vec<u8>, value: u8) -> Vec<u8> {
    let count = u32::from_le_bytes(image[16..20].try_into().unwrap());
    let size = u32::from_le_bytes(image[20..24].try_into().unwrap());
    let at = 32 + size as usize;
    p32(&mut image, at, 0x1b);
    p32(&mut image, at + 4, 24);
    image[at + 8..at + 24].fill(value);
    p32(&mut image, 16, count + 1);
    p32(&mut image, 20, size + 24);
    image
}

/// Append an unallocated section and relocate the ELF section table. Existing
/// linked code and symbol addresses remain unchanged.
#[allow(dead_code)]
pub fn elf_debug_section(mut image: Vec<u8>, section_name: &str, data: &[u8]) -> Vec<u8> {
    let shoff = u64::from_le_bytes(image[40..48].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(image[60..62].try_into().unwrap()) as usize;
    let strings = u16::from_le_bytes(image[62..64].try_into().unwrap()) as usize;
    let mut headers = image[shoff..shoff + count * 64].to_vec();
    let old_names = u64::from_le_bytes(
        headers[strings * 64 + 24..strings * 64 + 32]
            .try_into()
            .unwrap(),
    ) as usize;
    let old_size = u64::from_le_bytes(
        headers[strings * 64 + 32..strings * 64 + 40]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut names = image[old_names..old_names + old_size].to_vec();
    let name = names.len();
    names.extend_from_slice(section_name.as_bytes());
    names.push(0);
    let names_offset = image.len();
    image.extend_from_slice(&names);
    p64(&mut headers, strings * 64 + 24, names_offset as u64);
    p64(&mut headers, strings * 64 + 32, names.len() as u64);
    let data_offset = image.len();
    image.extend_from_slice(data);
    let new_shoff = image.len();
    image.extend_from_slice(&headers);
    image.resize(image.len() + 64, 0);
    let at = new_shoff + count * 64;
    p32(&mut image, at, name as u32);
    p32(&mut image, at + 4, 1);
    p64(&mut image, at + 24, data_offset as u64);
    p64(&mut image, at + 32, data.len() as u64);
    p64(&mut image, at + 48, 1);
    p64(&mut image, 40, new_shoff as u64);
    p16(&mut image, 60, (count + 1) as u16);
    image
}
