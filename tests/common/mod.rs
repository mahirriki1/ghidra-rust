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
