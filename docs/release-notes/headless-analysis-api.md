- Add `ghidra-rust-headless`, a console-subsystem executable that analyzes a
  selected binary or reopens a project without creating a desktop window.
- Expose versioned JSON-line commands and a Rust controller for function
  analysis, bounded discovery, strings, cryptographic constants, mapped bytes,
  imports/exports pagination, preserved annotations, and project checkpoints.
- Reuse the existing contained worker, shared request deadline, validated result
  mappings, context invalidation, saved-analysis provenance, and protected saves.
  Checkpoint destinations and input files are selected at startup, not by commands.
- Support library cancellation and stop failed/timed-out workers while retaining
  extracted-image ownership through process reaping. Frame and output budgets
  prevent partial oversized JSON replies or reinterpretation of oversized input.
- Include the console tool and its guide in native archives. Keep normal
  `cargo run` launching the desktop; no project or annotation format changes.
  The desktop updater continues replacing only the desktop executable; update
  the headless tool from a fresh archive.
- This is a local JSON/console API; HTTP hosting, authentication, cloud sync,
  editing operations, and a core-only Cargo configuration remain future work.
