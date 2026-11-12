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

/// File offsets come from the published sections; the oracles here do not:
/// the ELF program headers, and the raw positions of unique fixture bytes.
#[test]
fn real_worker_sections_map_file_offsets_like_the_program_headers() {
    use ghidra_rust::file_offsets::{FileAddress, Unmapped, address_at, offset_of};
    use object::read::elf::{ElfFile64, FileHeader, ProgramHeader, SectionHeader};
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("fixture");
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
    let raw = std::fs::read(&binary).unwrap();
    let elf = ElfFile64::<object::Endianness>::parse(raw.as_slice()).unwrap();
    let endian = elf.endian();
    let symbol = |name: &str| {
        elf.symbols()
            .find(|s| s.name().ok() == Some(name))
            .unwrap()
            .address()
    };
    // `p_offset + (address - p_vaddr)` within a PT_LOAD's file bytes.
    let loads: Vec<_> = elf
        .elf_header()
        .program_headers(endian, raw.as_slice())
        .unwrap()
        .iter()
        .filter(|header| header.p_type(endian) == object::elf::PT_LOAD)
        .map(|header| {
            (
                header.p_vaddr(endian),
                header.p_filesz(endian),
                header.p_offset(endian),
            )
        })
        .collect();
    let segment_offset = |address: u64| {
        let mut hits = loads.iter().filter_map(|&(vaddr, filesz, offset)| {
            let relative = address.checked_sub(vaddr)?;
            (relative < filesz).then_some(offset + relative)
        });
        let hit = hits.next();
        assert!(hits.next().is_none(), "{address:#x} in two segments");
        hit
    };
    let mut worker = Process::start();
    let Response::Opened { info, .. } = worker.request(Request::Open {
        path: binary.to_string_lossy().into_owned(),
    }) else {
        panic!("cannot open fixture")
    };
    assert_eq!(info.file_len, raw.len() as u64);
    let read = |worker: &mut Process, address, length| {
        let Response::Bytes { bytes, .. } = worker.request(Request::Bytes { address, length })
        else {
            panic!("cannot read {address:#x}")
        };
        bytes
    };

    // Raw positions of unique bytes map to the address the worker reads
    // them back from.
    let marker = [0xd3, 0x71, 0x53, 0x72, 0x63, 0x48, 0x34, 0x41];
    for needle in [&b"aGVsbG8gcmV2ZXJzZXI="[..], &marker[..]] {
        let mut positions = raw.windows(needle.len()).enumerate();
        let (position, _) = positions.find(|(_, w)| *w == needle).unwrap();
        assert!(positions.all(|(_, w)| w != needle), "unique fixture bytes");
        let FileAddress::One(address) = address_at(&info.sections, info.file_len, position as u64)
        else {
            panic!("{position:#x} has no address")
        };
        assert_eq!(read(&mut worker, address, needle.len()), needle);
        assert_eq!(segment_offset(address), Some(position as u64));
    }
    assert_eq!(
        address_at(
            &info.sections,
            info.file_len,
            offset_of(&info.sections, symbol("base64_message")).unwrap()
        ),
        FileAddress::One(symbol("base64_message"))
    );

    // Code: `main` and `branch_loop` entries agree with the program headers,
    // and their raw bytes are what the worker reads.
    for name in ["main", "branch_loop"] {
        let address = symbol(name);
        let offset = offset_of(&info.sections, address).unwrap();
        assert_eq!(Some(offset), segment_offset(address), "{name}");
        let at = offset as usize;
        assert_eq!(read(&mut worker, address, 4), raw[at..at + 4], "{name}");
    }
    // Every published section's first and last backed byte agrees too.
    for section in info.sections.iter().filter(|s| s.file_size > 0) {
        for address in [section.address, section.address + section.file_size - 1] {
            let offset = offset_of(&info.sections, address).unwrap();
            assert_eq!(Some(offset), segment_offset(address), "{}", section.name);
            assert_eq!(
                address_at(&info.sections, info.file_len, offset),
                FileAddress::One(address)
            );
        }
    }

    // Zero-fill has no offset, and no offset reaches `.bss`; headers and the
    // end of the file have no address.
    let bss = elf.section_by_name(".bss").unwrap();
    let bss_offset = bss.elf_section_header().sh_offset(endian);
    assert_eq!(offset_of(&info.sections, symbol("fixture_sink")), None);
    assert!(matches!(
        address_at(&info.sections, info.file_len, bss_offset),
        FileAddress::Unmapped(_)
    ));
    assert_eq!(
        address_at(&info.sections, info.file_len, 0),
        FileAddress::Unmapped(Unmapped::BeforeSections)
    );
    assert_eq!(
        address_at(&info.sections, info.file_len, info.file_len),
        FileAddress::Unmapped(Unmapped::PastEnd)
    );
    assert_eq!(std::fs::read(&binary).unwrap(), raw);
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

// Exact original arrays and independently specified offsets; the production
// matcher/domain are never used to calculate the expected answers.
fn verify_search_fixture(
    info: &ghidra_rust::model::BinaryInfo,
    original: &[u8],
    mut invoke: impl FnMut(Request) -> Response,
) {
    use ghidra_rust::search::{MemoryPattern, MemorySearchSession, MemorySearchSpec, SearchState};
    use object::{Object, ObjectSection};
    let image = object::File::parse(original).unwrap();
    let marker_address = |marker: &[u8]| {
        let mut addresses = Vec::new();
        for section in image.sections() {
            if let Ok(bytes) = section.data() {
                for (offset, _) in bytes
                    .windows(marker.len())
                    .enumerate()
                    .filter(|(_, bytes)| *bytes == marker)
                {
                    addresses.push(section.address() + offset as u64);
                }
            }
        }
        assert_eq!(addresses.len(), 1, "original marker must occur once");
        addresses[0]
    };
    let ascii = marker_address(&[
        0xd3, 0x71, 0x53, 0x72, 0x63, 0x48, 0x34, 0x41, 0x42, 0x41, 0x42, 0x41, 0xf2,
    ]);
    let utf16 = marker_address(&[
        0xf1, 0x51, 0, 0x34, 0, 0x3e, 0xd8, 0x80, 0xdd, 0, 0x51, 0, 0x34, 0, 0x3e, 0xd8, 0x80,
        0xdd, 0xfe,
    ]);
    let wildcard = marker_address(&[
        0xe3, 0xd9, 0x6e, 0xa5, 0x16, 0xb7, 0xc8, 0x71, 0xd9, 0x6e, 0xa5, 0x80, 0xb7, 0xc8, 0xae,
    ]);
    let dense = marker_address(&[0xa6; 600]);
    for (spec, expected) in [
        (
            MemorySearchSpec {
                pattern: MemoryPattern::Ascii {
                    text: "srch4aba".into(),
                },
                match_case: false,
            },
            vec![ascii + 2],
        ),
        (
            MemorySearchSpec {
                pattern: MemoryPattern::Utf16Le {
                    text: "Q4🦀".into(),
                },
                match_case: true,
            },
            vec![utf16 + 1, utf16 + 10],
        ),
        (
            MemorySearchSpec::hex("D9 6E A5 ?? B7 C8").unwrap(),
            vec![wildcard + 1, wildcard + 8],
        ),
        (
            MemorySearchSpec::hex("A6 A6 A6 A6 A6 A6 A6 A6").unwrap(),
            (0..593).map(|offset| dense + offset).collect(),
        ),
    ] {
        let mut results = ghidra_rust::function_results::FunctionResults::default();
        let reservation = results
            .reserve_transient(ghidra_rust::search::MEMORY_SEARCH_RESERVATION_BYTES, &[])
            .unwrap();
        let mut search = MemorySearchSession::new(info, 7, 9, spec, reservation).unwrap();
        while let Some(query) = search.next_request(1).unwrap() {
            let Response::MemorySearch(page) = invoke(query) else {
                panic!("memory search page");
            };
            search.accept(page).unwrap();
        }
        assert_eq!(search.state(), SearchState::Complete);
        assert_eq!(
            search
                .hits()
                .iter()
                .map(|hit| hit.address)
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[test]
fn real_worker_searches_only_the_opened_snapshot_and_resumes_pages() {
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("search-fixture");
    assert!(
        Command::new("gcc")
            .args(["-O2", "-g", "-fno-pie", "-no-pie"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/sample.c"
            ))
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    let original = std::fs::read(&binary).unwrap();
    let mut worker = Process::start();
    let Response::Opened { info, .. } = worker.request(Request::Open {
        path: binary.to_string_lossy().into_owned(),
    }) else {
        panic!("open");
    };
    std::fs::write(&binary, b"changed only this private fixture after Open").unwrap();
    verify_search_fixture(&info, &original, |query| worker.request(query));
}
