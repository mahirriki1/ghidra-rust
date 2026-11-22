# Desktop images

Regenerate the native window icon from the SVG in this directory.

```sh
rsvg-convert --width 256 --height 256 docs/images/ghidra-rust-logo.svg -o docs/images/ghidra-rust-icon.png
```

`ghidra-rust-icon.ico` is the Windows EXE icon. It holds 16, 24, 32, 48, 64,
and 256 pixel PNG images drawn from the SVG. `build.rs` embeds it in MSVC
builds. Regenerate it with:

```sh
python3 scripts/make-windows-icon.py
```

The Linux desktop entry and its icon also use `ghidra-rust-icon.png`.
[Menu entry and icon](../linux.md#menu-entry-and-icon)

To refresh the Listing and selection-sync screenshots:

1. Build the C fixture and run `cargo build --release --locked --features capture`.
   [Fixture build](../../tests/fixtures/README.md#desktop-smoke-test)
2. Find the fixture's `branch_loop` entry with `nm`. In the Decompiler, pick
   an instruction address with an actual pseudocode mapping.
3. Launch the built desktop with the fixture path. Set
   `GHIDRA_RUST_CAPTURE_TO=/tmp/new.ppm`, `GHIDRA_RUST_CAPTURE_SIZE=1600x1000`,
   `GHIDRA_RUST_CAPTURE_GOTO` to the function's hex address, and
   `GHIDRA_RUST_CAPTURE_SELECT` to the instruction's hex address.
   Set `GHIDRA_RUST_CAPTURE_TAB=graph` for the graph. Omit it for Listing.
4. Convert with `magick /tmp/new.ppm /tmp/new.png`. Check text legibility,
   selection highlighting, and the status bar before replacing an image.

The capture feature writes one frame and exits. See the source for available
environment variables. [Capture options](../../src/capture.rs)
