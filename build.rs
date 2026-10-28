use std::{env, fs, path::PathBuf};

fn main() {
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
