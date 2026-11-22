use std::{env, fs, path::PathBuf};

fn main() {
    windows_icon_resource();
    println!("cargo:rerun-if-env-changed=GHIDRA_RUST_EMBEDDED_NOTICES");
    println!("cargo:rerun-if-changed=LICENSE");
    println!("cargo:rerun-if-changed=NOTICE");
    let notices = match env::var_os("GHIDRA_RUST_EMBEDDED_NOTICES") {
        Some(path) => {
            println!("cargo:rerun-if-changed={}", PathBuf::from(&path).display());
            fs::read_to_string(path).expect("read generated dependency notices")
        }
        None => format!(
            "Source build: dependency licenses are supplied in their source packages.\n\n{}\n\n{}",
            fs::read_to_string("LICENSE").expect("application license"),
            fs::read_to_string("NOTICE").expect("application notices")
        ),
    };
    assert!(
        notices.len() <= 16 * 1024 * 1024,
        "notice bundle exceeds the update budget"
    );
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("notices.txt"),
        notices,
    )
    .expect("write embedded notices");
}

/// Embeds docs/images/ghidra-rust-icon.ico in Windows MSVC executables, so
/// Explorer, Start, and pinned taskbar entries show the application icon.
///
/// The compiled resource (.res) format is written directly and given to the
/// MSVC linker, which accepts .res inputs. This needs no resource compiler.
fn windows_icon_resource() {
    const ICON: &str = "docs/images/ghidra-rust-icon.ico";
    println!("cargo:rerun-if-changed={ICON}");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }
    let ico = fs::read(ICON).expect("read the Windows application icon");
    let resource = icon_resource(&ico).unwrap_or_else(|error| panic!("{ICON}: {error}"));
    let path = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("ghidra-rust-icon.res");
    fs::write(&path, resource).expect("write the Windows icon resource");
    println!("cargo:rustc-link-arg-bins={}", path.display());
}

/// Converts an .ico file into a .res file with one RT_ICON per image and an
/// RT_GROUP_ICON with ID 1, the icon Explorer shows for the executable.
fn icon_resource(ico: &[u8]) -> Result<Vec<u8>, String> {
    const RT_ICON: u16 = 3;
    const RT_GROUP_ICON: u16 = 14;
    let u16_at = |offset: usize| -> Result<u16, String> {
        ico.get(offset..offset + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .ok_or_else(|| "truncated icon header".to_owned())
    };
    let u32_at = |offset: usize| -> Result<u32, String> {
        ico.get(offset..offset + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| "truncated icon header".to_owned())
    };
    if u16_at(0)? != 0 || u16_at(2)? != 1 {
        return Err("not an icon file".to_owned());
    }
    let count = u16_at(4)?;
    if count == 0 || count > 32 {
        return Err(format!("unexpected image count {count}"));
    }
    // An empty leading entry marks a 32-bit resource file.
    let mut res = Vec::new();
    push_resource(&mut res, 0, 0, 0, &[]);
    let mut group = Vec::new();
    group.extend_from_slice(&[0, 0, 1, 0]);
    group.extend_from_slice(&count.to_le_bytes());
    for index in 0..count {
        let entry = 6 + 16 * usize::from(index);
        let header = ico
            .get(entry..entry + 12)
            .ok_or_else(|| "truncated icon directory".to_owned())?;
        let size = u32_at(entry + 8)?;
        let offset = u32_at(entry + 12)?;
        let image = usize::try_from(offset)
            .ok()
            .zip(usize::try_from(size).ok())
            .and_then(|(start, length)| ico.get(start..start.checked_add(length)?))
            .filter(|image| !image.is_empty())
            .ok_or_else(|| format!("image {index} lies outside the file"))?;
        let id = index + 1;
        push_resource(&mut res, RT_ICON, id, 0x1010, image);
        // GRPICONDIRENTRY: the ICONDIRENTRY fields with a resource ID in
        // place of the file offset.
        group.extend_from_slice(header);
        group.extend_from_slice(&id.to_le_bytes());
    }
    push_resource(&mut res, RT_GROUP_ICON, 1, 0x1030, &group);
    Ok(res)
}

/// Appends a resource with ordinal type and name, neutral language.
fn push_resource(res: &mut Vec<u8>, kind: u16, name: u16, flags: u16, data: &[u8]) {
    let length = u32::try_from(data.len()).expect("icon image fits a resource");
    res.extend_from_slice(&length.to_le_bytes());
    res.extend_from_slice(&32u32.to_le_bytes());
    for ordinal in [kind, name] {
        res.extend_from_slice(&0xffffu16.to_le_bytes());
        res.extend_from_slice(&ordinal.to_le_bytes());
    }
    res.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
    res.extend_from_slice(&flags.to_le_bytes());
    res.extend_from_slice(&0u16.to_le_bytes()); // LANG_NEUTRAL
    res.extend_from_slice(&0u32.to_le_bytes()); // Version
    res.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    res.extend_from_slice(data);
    res.resize(res.len().next_multiple_of(4), 0);
}
