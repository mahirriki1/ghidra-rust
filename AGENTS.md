# Project guidance

This file applies to the whole repository. Read `README.md`, `Cargo.toml`, and
the relevant source modules before changing behavior. Follow more specific
`AGENTS.md` files if any are added beneath this directory.

## Purpose and scope

- Build a responsive, memory-conscious native Rust reverse-engineering desktop
  with a familiar Ghidra layout and function-graph navigation.
- The current implementation supports linked x86/x86-64 and little-endian
  AArch64 (64-bit ABI) ELF, PE, and baseline arm64 Mach-O images. It is an
  experimental subset, not a complete Ghidra or IDA replacement.
- Keep the core desktop independent of Java and Python runtimes. Plugins,
  scripting, debugger integration, type/variable editing, and a user-facing CLI
  are future work unless explicitly requested.
- Measure performance and memory before claiming improvements over Ghidra.
  Account for worker memory and duplicated image bytes, not just the GUI process.

## Architecture

- `src/main.rs`: native eframe startup and the internal worker entry point.
- `src/app.rs`: GUI state, navigation, annotations, asynchronous jobs, and result
  adoption. `theme.rs` owns the shared dark appearance and the fixed-height
  row/table helpers; `file_dialog.rs` owns the in-app chooser.
- `src/window_chrome.rs`: Windows menu-row window controls and resize borders;
  other platforms retain native decorations.
- `src/client.rs`, `worker.rs`, `model.rs`: disposable worker lifecycle, bounded
  JSON transport, request/response types, and shared result limits.
- `src/architecture.rs`: supported architecture/ABI selection and validation.
- `src/analysis/`: loading, immutable image snapshots, function discovery, and
  analysis requests (`mod.rs`); the resumable bounded instruction walk and CFG
  (`cfg.rs`); the function-start pattern phase (`patterns.rs`); string scanning
  (`strings.rs`).
- `src/elf_startup.rs`, `switch_analysis.rs`, `function_patterns.rs`,
  `no_return.rs`: stripped-ELF `main` recovery, engine jump-table recovery, and
  vendored Ghidra function-start/no-return data (`data/`, see `NOTICE`).
- `src/call_analysis.rs`, `data_analysis.rs`: bounded reference validation/indexes
  and instruction-local direct memory-access evidence.
- `src/packing.rs`: conservative packed-image diagnostics; detected conventional
  UPX PE stubs skip expensive decompilation/discovery while retaining inspection.
- `src/decompile.rs`: semantic emission through public engine APIs, including
  restoration of the original printer/action after errors or panics.
- `src/selection.rs`, `highlight.rs`, `graph.rs`: validated instruction/pseudocode
  mappings, lexical syntax highlighting, and graph rendering/interaction.
- `src/project.rs`, `session.rs`: SQLite `.grproj` snapshots, JSON annotations,
  binary identity, fingerprint verification, and protected atomic saves.
- `src/decode.rs`, `decoder_ui.rs`, `crypto.rs`: bounded decoding and independently
  maintained cryptographic constant signatures.
- `src/limits.rs`, `windows.rs`: platform resource controls and Windows APIs.
- `tests/fixtures/sample.c`: original source fixture. Integration tests exercise
  real worker processes; most module/UI tests live alongside the implementation.

The engine is a pinned `ghidra-decompiler` Git dependency. Use its public APIs;
do not edit Cargo's dependency cache or restore an unused Ghidra checkout into
this repository. Intentional engine updates must also consider project cache
fingerprints, correctness tests, and upstream attribution in `NOTICE`.

## GUI and interaction

- Preserve the classic dark layout: symbol/program trees and functions on the
  left, listing/CFG and analysis tabs in the middle, full-height decompiler on the
  right. Keep panes resizable and use shared theme helpers.
- Preserve syntax colors while overlaying semantic selection highlights.
  Selection links must come from genuine engine addresses. Many instructions
  can map to one expression; optimized-away instructions may remain unmapped.
  Do not infer links from matching text, row numbers, or nearest addresses.
- Keep call double-click navigation and back/forward history working alongside
  single-click selection synchronization.
- Maintain the existing bindings: `L`, `G`, `;`, `X`, `F1`, `Space`, `Alt+Left/Right`, and
  `Ctrl+S/Z`. Respect text-field focus, modal dialogs, repeat keys, and file jobs.
- Keep expensive analysis, decoding, directory reads, and project I/O off the
  GUI thread. Use bounded work, virtualized lists, cached geometry/highlighting,
  and one-shot counterpart scrolling rather than resetting scroll every frame.
- Bind asynchronous results to their request, binary generation, selection, and
  annotation revision. Clear stale function views and mappings on navigation.

## Data and process boundaries

- Treat binaries, project files, symbols, and worker replies as untrusted data.
  Keep byte/count/depth budgets and checked address arithmetic. Consult the
  constants in `model.rs`, `analysis/`, `project.rs`, and `session.rs` rather
  than duplicating limits that can drift.
- Validate mapping bounds, UTF-8 boundaries, ordering, address counts, and
  executable file-backed membership before displaying them. Avoid multiplying
  independent collection limits; use indexed interval lookups for repeated PCs.
- Preserve immutable analyzed snapshots and retained opened-file identity.
  Never write to an input binary, including through renamed paths or aliases.
- Save complete new files with destination checks before creation and immediately
  before atomic publication. Carry every protected-file guard through the save.
- Keep `.grproj` versioning, exact schema checks, bounded deserialization,
  private extraction paths, SHA-256 binding, and engine cache fingerprints.
  Source hints are display-only; external binaries require explicit selection.
- A matching binary hash does not authenticate cached analysis. Keep saved-result
  provenance visible until each result class is recomputed. Preserve JSON
  annotation compatibility; treat format changes as migrations, not silent edits.
- Retain extracted-image ownership through worker termination and reaping.
  Preserve Linux bubblewrap isolation and resource limits. Windows jobs/watchdogs
  limit resources but provide no filesystem/network sandbox; do not describe
  Windows as safe for hostile inputs. Project SQLite parsing is also not isolated
  in a worker. Keep these actual limitations documented.
- Keep platform-specific code behind the appropriate `cfg` gates and document
  every `unsafe` block's invariants. Fail closed when identity/containment setup
  fails rather than silently weakening protection.

## Build and validation

Use the toolchain pinned in `.github/workflows/ci.yml` (currently Rust 1.98.1,
edition 2024), a native C/C++ toolchain, and an OpenGL-capable desktop. Linux GUI
analysis also requires bubblewrap and working unprivileged user namespaces.
Native Windows builds use x64 MSVC tools and a Windows SDK; see [the Windows guide](docs/windows.md).

```sh
cargo run --release --locked
cargo fmt --all --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

For Rust behavior changes, add focused regression coverage where useful and run
the applicable checks above. Tests run locally only: GitHub Actions builds, lints,
and packages without running them (`--skip-tests`/`-SkipTests`), so run the
tests before every push and report which platforms actually ran them. Do not add tests that merely mirror implementation.
For documentation-only edits, check paths and factual accuracy without rebuilding
the application. Do not discard or regenerate `Cargo.lock` unnecessarily.

Linux worker integration tests compile the C fixture using GCC.
`scripts/build-windows.ps1` compiles it into PE and sets `GHIDRA_RUST_TEST_PE` for
`tests/windows_worker.rs`; without that variable the PE integration test skips. Cross-compilation
checks are not evidence that the native Windows GUI or worker was run.

For GUI changes, exercise the native desktop with the safe fixture when a display
is available. Include navigation, selection syncing, and project save/reopen when
those paths change. Headless egui tests are useful but do not replace native
runtime validation. On affected WSL/Mesa hosts, the documented fallback is:

```sh
env -u WAYLAND_DISPLAY LIBGL_ALWAYS_SOFTWARE=1 cargo run --release --locked
```

Software rendering is a compatibility workaround, not a speed improvement.
Report which checks actually ran and any platform validation that remains pending.

## Repository hygiene

- Create or switch to a dedicated feature/fix branch before implementation edits;
  do not commit implementation work directly to `main`.
- Keep source, fixture source, tests, CI, current documentation, `LICENSE`,
  `NOTICE`, and the lockfile. Preserve independent signature provenance in
  `docs/crypto-signatures.md`.
- Put generated executables, build caches, and local test projects outside the
  tracked source tree or under ignored `target/` paths. Do not commit real sample
  binaries or analyst project data.
- Do not add private review reports, agent transcripts, session handoff files,
  or obsolete planning mockups to the repository.
- Preserve unrelated user changes. Keep edits scoped to the requested task and
  update public documentation when supported behavior or limitations change.
- Add a new `docs/release-notes/*.md` entry for each PR or direct change to main.
  Use detailed bullets for user-visible features, fixes, and limitations; follow
  `docs/release-notes/README.md`. Keep published entries and use new files for
  later changes so each release can collect its complete changes.
