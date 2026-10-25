# Desktop images

The rust-orange dragon's vector source is [ghidra-rust-logo.svg](ghidra-rust-logo.svg).
From the repository root, regenerate the transparent native window icon with:

```sh
rsvg-convert --width 256 --height 256 docs/images/ghidra-rust-logo.svg -o docs/images/ghidra-rust-icon.png
```

The window icon is separate from Windows executable-file icon resources.

The native desktop's optional `capture` feature writes one frame and exits;
[capture.rs](../../src/capture.rs) documents its environment variables.
To refresh [selection sync](desktop-selection-sync.png) and [Listing](desktop-dark-listing.png):

1. Compile `tests/fixtures/sample.c` with GCC as shown in the
   [fixture guide](../../tests/fixtures/README.md), outside tracked source. Never execute it.
2. Build `cargo build --release --locked --features capture`. Use `nm` to find
   this fixture's `branch_loop` and a worker decompilation reply to choose an
   instruction with a genuine engine pseudocode mapping; do not reuse old addresses.
3. Launch the built desktop with the fixture path and
   `GHIDRA_RUST_CAPTURE_TO=/tmp/NEW.ppm`, `GHIDRA_RUST_CAPTURE_GOTO=FUNCTION_HEX`,
   `GHIDRA_RUST_CAPTURE_SELECT=INSTRUCTION_HEX`, and
   `GHIDRA_RUST_CAPTURE_SIZE=1600x1000`. Set `GHIDRA_RUST_CAPTURE_TAB=graph` for
   selection sync; omit it for Listing. The first-open analysis prompt is dismissed.
4. If graphics fail or the compositor constrains the capture, prefix the launch
   with `env -u WAYLAND_DISPLAY LIBGL_ALWAYS_SOFTWARE=1` (compatibility only).
5. Convert losslessly with `magick /tmp/NEW.ppm /tmp/NEW.png`. Inspect the PNG:
   native text must be legible, mapped selection visible, and status bar single-line.
   Replace the tracked images only after inspection; remove temporary PPMs and binaries.

The scripted interface has no Help-dialog selector. Do not add capture code just
for documentation screenshots.
