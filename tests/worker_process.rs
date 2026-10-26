//! Exercise the real disposable process, not just an in-process protocol mock.
#![cfg(target_os = "linux")]

mod linkage;

use ghidra_rust::model::{Request, Response, WorkerRequest, WorkerResponse};
use object::{Object, ObjectSymbol};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

struct Process {
    child: Child,
    input: ChildStdin,
    output: Receiver<WorkerResponse>,
    id: u64,
}

impl Process {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ghidra-rust"))
            .arg("--analysis-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, output) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let Ok(response) = serde_json::from_str(&line) else {
                    break;
                };
                if tx.send(response).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            output,
            id: 0,
        }
    }
    fn request(&mut self, request: Request) -> Response {
        self.id += 1;
        serde_json::to_writer(
            &mut self.input,
            &WorkerRequest {
                id: self.id,
                request,
            },
        )
        .unwrap();
        self.input.write_all(b"\n").unwrap();
        self.input.flush().unwrap();
        let response = self
            .output
            .recv_timeout(Duration::from_secs(30))
            .expect("real worker must reply within its deadline");
        assert_eq!(response.id, self.id);
        response.response
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn real_worker_publishes_declarations_from_its_immutable_snapshot() {
    use ghidra_rust::linkage::ExportTarget;
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("linkage.so");
    let output = Command::new("gcc")
        .args(["-O0", "-fPIC", "-shared"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/linkage.c"
        ))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut worker = Process::start();
    let Response::Opened { info, .. } = worker.request(Request::Open {
        path: binary.to_string_lossy().into_owned(),
    }) else {
        panic!("Open original shared library");
    };
    // Replace only this test's private file, before metadata is requested.
    // Declaration extraction must still use the already-analyzed snapshot.
    std::fs::write(&binary, b"replaced private fixture").unwrap();
    let table = linkage::read(|request| worker.request(request), &info);
    let puts = table
        .imports
        .iter()
        .find(|import| import.raw.as_deref() == Some("puts"))
        .unwrap();
    assert_eq!(
        table.libraries[puts.library.unwrap() as usize].name,
        "libc.so.6"
    );
    assert!(puts.version.as_deref().unwrap().starts_with("GLIBC_"));
    assert!(puts.slot.is_some());
    let weak = table
        .imports
        .iter()
        .find(|import| import.raw.as_deref() == Some("optional_hook"))
        .unwrap();
    assert!(weak.weak);
    assert_eq!(weak.library, None);
    let function = table
        .exports
        .iter()
        .find(|export| export.raw.as_deref() == Some("_ZN4demo3fooEv"))
        .unwrap();
    assert_eq!(function.display.as_deref(), Some("demo::foo"));
    assert!(matches!(function.target, ExportTarget::Code { .. }));
    assert!(
        table
            .exports
            .iter()
            .any(|export| export.raw.as_deref() == Some("exported_word")
                && matches!(export.target, ExportTarget::Data { .. }))
    );
    assert_eq!(
        table.digest,
        linkage::read(|request| worker.request(request), &info).digest
    );
}

#[test]
fn real_worker_reads_section_pages_and_clipped_zero_filled_tails() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("pages.c");
    let binary = directory.path().join("pages");
    std::fs::write(
        &source,
        b"const unsigned char page_data[5003] __attribute__((section(\".hex_data\"))) = {65, 66};\nunsigned char page_zero[9001];\nint main(void) { return page_data[0] + page_zero[0]; }\n",
    )
    .unwrap();
    let result = Command::new("gcc")
        .args(["-g", "-O0", "-fno-pie", "-no-pie"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original = std::fs::read(&binary).unwrap();
    let mut worker = Process::start();
    let Response::Opened { info, .. } = worker.request(Request::Open {
        path: binary.to_string_lossy().into_owned(),
    }) else {
        panic!("cannot open page fixture")
    };
    for name in [".hex_data", ".bss"] {
        let section = info
            .sections
            .iter()
            .find(|section| section.name == name)
            .unwrap();
        assert!(section.size > 4096);
        for offset in [0, (section.size - 1) / 4096 * 4096] {
            let address = section.address + offset;
            let length = (section.size - offset).min(4096) as usize;
            let Response::Bytes {
                address: actual,
                bytes,
            } = worker.request(Request::Bytes { address, length })
            else {
                panic!("cannot read section page")
            };
            assert_eq!(actual, address);
            assert_eq!(bytes.len(), length);
            let expected: Vec<_> = (offset..offset + length as u64)
                .map(|relative| {
                    if relative < section.file_size {
                        original[(section.file_offset + relative) as usize]
                    } else {
                        0
                    }
                })
                .collect();
            assert_eq!(bytes, expected, "{name} page at {address:#x}");
        }
    }
    assert!(matches!(
        worker.request(Request::Bytes {
            address: 0,
            length: 4096
        }),
        Response::Error { .. }
    ));
    assert_eq!(std::fs::read(&binary).unwrap(), original);
}

#[test]
fn real_worker_browses_decompiles_decodes_scans_and_recovers_from_bad_open() {
    let directory = std::env::temp_dir().join(format!("grust-process-test-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let binary = directory.join("fixture");
    let result = Command::new("gcc")
        .args(["-g", "-O0", "-fno-pie", "-no-pie", "-fno-inline"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.c"
        ))
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("Linux integration tests require GCC");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original_bytes = std::fs::read(&binary).unwrap();
    let image = object::File::parse(original_bytes.as_slice()).unwrap();
    let address = |name: &str| {
        image
            .symbols()
            .find(|s| s.name().ok() == Some(name))
            .unwrap()
            .address()
    };
    let branch = address("branch_loop");
    let base64 = address("base64_message");
    let aes = address("aes_sbox_prefix");
    let mut worker = Process::start();
    let Response::Opened { info, .. } = worker.request(Request::Open {
        path: binary.to_string_lossy().into_owned(),
    }) else {
        panic!("cannot open fixture")
    };
    assert_eq!(
        info.sha256,
        ghidra_rust::session::fingerprint(&binary).unwrap()
    );
    assert_eq!(
        info.source_identity,
        ghidra_rust::model::FileIdentity::from_metadata(&binary.metadata().unwrap())
    );
    let protection = ghidra_rust::session::BinaryProtection::open(&binary)
        .unwrap()
        .bind_snapshot(&info)
        .unwrap();
    assert!(info.functions.iter().any(|f| f.address == branch));
    let Response::Graph { view } = worker.request(Request::Graph { address: branch }) else {
        panic!("cannot build CFG")
    };
    assert!(view.blocks.len() >= 3);
    assert!(
        view.edges
            .iter()
            .any(|edge| edge.target.is_some_and(|target| target <= edge.source)),
        "loop must retain a backedge"
    );
    let Response::Decompiled { text, mappings, .. } =
        worker.request(Request::Decompile { address: branch })
    else {
        panic!("cannot decompile")
    };
    assert!(text.contains("branch_loop"));
    assert!(
        !mappings.is_empty(),
        "Real decompilation must carry semantic locations"
    );
    assert!(mappings.iter().all(|mapping| {
        mapping.start < mapping.end
            && text.is_char_boundary(mapping.start)
            && text.is_char_boundary(mapping.end)
            && mapping.addresses.iter().all(|address| {
                view.blocks.iter().any(|block| {
                    block
                        .instructions
                        .iter()
                        .any(|instruction| instruction.address == *address)
                })
            })
    }));
    let Response::Bytes { bytes, .. } = worker.request(Request::Bytes {
        address: base64,
        length: 20,
    }) else {
        panic!("cannot read virtual bytes")
    };
    assert_eq!(
        ghidra_rust::decode::decode(&bytes, ghidra_rust::decode::Operation::Base64, &[]).unwrap(),
        b"hello reverser"
    );
    let Response::Strings { strings, .. } = worker.request(Request::Strings) else {
        panic!("cannot find strings")
    };
    assert!(strings.iter().any(|s| s.address == base64));
    let Response::Crypto { matches, .. } = worker.request(Request::Crypto) else {
        panic!("cannot find cryptographic constant")
    };
    assert!(
        matches
            .iter()
            .any(|m| m.address == aes && m.algorithm.contains("AES"))
    );
    assert!(matches!(
        worker.request(Request::Rename {
            address: branch,
            name: "renamed_loop".into()
        }),
        Response::Renamed { .. }
    ));
    let Response::Decompiled { text, mappings, .. } =
        worker.request(Request::Decompile { address: branch })
    else {
        panic!("cannot re-decompile")
    };
    assert!(text.contains("renamed_loop"));
    // Persist actual engine results, then reopen the embedded input through the
    // real worker. Live file identities change; binary/mapping provenance must not.
    let mut session = ghidra_rust::session::Session::new(info.sha256.clone());
    session.annotations.insert(
        branch,
        ghidra_rust::session::Annotation {
            label: "renamed_loop".into(),
            comment: "project round-trip".into(),
            decoded: vec![],
        },
    );
    let project = ghidra_rust::project::ProjectData {
        semantics: Default::default(),
        info,
        session,
        view: Some(view),
        decompiled: Some(text),
        mappings,
        strings,
        strings_truncated: false,
        crypto: matches,
        crypto_truncated: false,
        selected_address: Some(branch),
        discovery: None,
    };
    let project_path = directory.join("analysis.grproj");
    project.save(&project_path, &protection, true).unwrap();
    let loaded = ghidra_rust::project::ProjectData::load(&project_path).unwrap();
    assert!(!loaded.data.mappings.is_empty());
    assert_eq!(
        loaded.data.session.annotations[&branch].comment,
        "project round-trip"
    );
    let Response::Opened { info: reopened, .. } = worker.request(Request::Open {
        path: loaded
            .binary
            .as_ref()
            .unwrap()
            .path()
            .to_string_lossy()
            .into_owned(),
    }) else {
        panic!("cannot reopen embedded project input")
    };
    loaded.data.validate_against(&reopened).unwrap();
    assert!(
        loaded
            .data
            .decompiled
            .as_ref()
            .unwrap()
            .contains("renamed_loop")
    );
    drop(loaded);
    let invalid = directory.join("invalid");
    std::fs::write(&invalid, b"not an executable").unwrap();
    assert!(matches!(
        worker.request(Request::Open {
            path: invalid.to_string_lossy().into_owned()
        }),
        Response::Error { .. }
    ));
    assert!(matches!(
        worker.request(Request::Bytes {
            address: base64,
            length: 20
        }),
        Response::Error { .. }
    ));
    worker.child.kill().unwrap();
    assert!(!worker.child.wait().unwrap().success());
    assert_eq!(std::fs::read(&binary).unwrap(), original_bytes);
    drop(worker);
    std::fs::remove_dir_all(directory).unwrap();
}
