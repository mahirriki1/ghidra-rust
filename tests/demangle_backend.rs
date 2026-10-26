//! Exercise the backend with original symbols emitted by native compilers.
//! Object files here test demangling only, not application loader support.
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use ghidra_rust::symbol_names::{DemangleOutcome, SymbolFormat, demangle};
use object::{Object, ObjectSymbol};

fn names(path: &Path) -> BTreeMap<String, String> {
    let bytes = std::fs::read(path).unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    let format = if object.format() == object::BinaryFormat::MachO {
        SymbolFormat::MachO
    } else if object.format() == object::BinaryFormat::Coff
        || object.format() == object::BinaryFormat::Pe
    {
        SymbolFormat::Pe
    } else {
        SymbolFormat::Other
    };
    object
        .symbols()
        .filter(|symbol| {
            symbol.is_definition()
                && matches!(
                    symbol.kind(),
                    object::SymbolKind::Text | object::SymbolKind::Data
                )
        })
        .filter_map(|symbol| {
            let raw = symbol.name().unwrap();
            let before = raw.to_owned();
            match demangle(raw, format) {
                DemangleOutcome::Display(name) => {
                    assert_eq!(raw, before);
                    Some((before, name.text))
                }
                _ => None,
            }
        })
        .collect()
}

#[test]
fn native_rust_v0_object_preserves_raw_symbols_and_unicode_display() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("rust.obj");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let compilation = Command::new(rustc)
        .args([
            "--crate-name=demangle_fixture",
            "--crate-type=lib",
            "--emit=obj",
            "-Csymbol-mangling-version=v0",
            "-Copt-level=0",
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/demangle.rs"))
        .arg("-o")
        .arg(&output)
        .output()
        .expect("The pinned Rust toolchain is required for the original fixture");
    assert!(
        compilation.status.success(),
        "{}",
        String::from_utf8_lossy(&compilation.stderr)
    );
    let symbols = names(&output);
    for expected in ["demangle_fixture::demangle_probe", "demangle_fixture::café"] {
        let raw: Vec<_> = symbols
            .iter()
            .filter(|(_, display)| display.as_str() == expected)
            .collect();
        assert_eq!(raw.len(), 1, "Missing exact fixture symbol: {symbols:?}");
        assert!(raw[0].0.starts_with("_R") || raw[0].0.starts_with("__R"));
        assert_ne!(raw[0].0, expected);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn native_cpp_overloads_keep_distinct_raw_names_for_one_compact_display() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("cpp.o");
    let compilation = Command::new("g++")
        .args(["-c", "-O0"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/demangle.cpp"))
        .arg("-o")
        .arg(&output)
        .output()
        .expect("G++ is required for the original C++ symbol fixture");
    assert!(
        compilation.status.success(),
        "{}",
        String::from_utf8_lossy(&compilation.stderr)
    );
    let symbols = names(&output);
    assert_eq!(
        symbols
            .values()
            .filter(|name| name.as_str() == "demangle_fixture::overloaded")
            .count(),
        2
    );
    assert!(
        symbols
            .values()
            .any(|name| name == "demangle_fixture::identity<int>")
    );
}

#[cfg(windows)]
#[test]
fn native_msvc_object_names_cover_templates_operators_and_specials() {
    use std::os::windows::process::CommandExt;
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("msvc.obj");
    let installer = std::path::PathBuf::from(std::env::var_os("ProgramFiles(x86)").unwrap())
        .join("Microsoft Visual Studio/Installer/vswhere.exe");
    let installation = Command::new(installer)
        .args([
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ])
        .output()
        .expect("Visual Studio C++ tools are required for the original MSVC fixture");
    assert!(installation.status.success());
    let installation = String::from_utf8(installation.stdout).unwrap();
    let vcvars = Path::new(installation.trim()).join("VC/Auxiliary/Build/vcvars64.bat");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/demangle_msvc.cpp");
    let compilation = Command::new("cmd.exe")
        .args(["/d", "/s", "/c"])
        // cmd.exe has its own quote rules; these are trusted fixture/tool paths.
        .raw_arg(format!(
            "\"\"{}\" && cl /nologo /c /Od /EHsc /Fo\"{}\" \"{}\"\"",
            vcvars.display(),
            output.display(),
            source.display()
        ))
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        compilation.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&compilation.stdout),
        String::from_utf8_lossy(&compilation.stderr)
    );
    let symbols = names(&output);
    for expected in [
        "demangle_fixture::Widget::Widget",
        "demangle_fixture::Widget::~Widget",
        "demangle_fixture::Widget::operator+",
        "demangle_fixture::inner::identity<int>",
        "demangle_fixture::`anonymous namespace'::hidden",
        "demangle_fixture::Widget::`vftable'",
    ] {
        assert!(
            symbols.values().any(|name| name == expected),
            "Missing {expected}: {symbols:?}"
        );
    }
    assert_eq!(
        symbols
            .values()
            .filter(|name| name.as_str() == "demangle_fixture::overloaded")
            .count(),
        2
    );
}
