- The Ghidra Rust logo is now the app icon on Linux and Windows.
- On Linux, the desktop sets the window app id `io.github.mahirriki1.GhidraRust`
  and adds itself to your application menu when it starts. It writes a menu
  entry and a 256-pixel icon in your own data folder (`$XDG_DATA_HOME`,
  usually `~/.local/share`), so KDE Plasma on Wayland shows the logo in the
  taskbar instead of a generic icon.
- The Linux entry is rewritten only when it is out of date, for example after
  you move the app. It skips symlinked folders, never needs root, and creates
  a missing data folder only inside a folder you own. Failures are silent.
  The headless tool, analysis workers, and `cargo run` builds write nothing.
- The app only updates an entry it wrote itself and nobody has changed. An
  entry you edit, for example in a menu editor, or empty is left alone from
  then on, which also lets you opt out. See the Linux guide for the paths.
- If a system package already installs the entry under `/usr/share`, the app
  removes the user entry and icon it wrote earlier so the packaged entry is
  used. An edited user entry stays.
- The Linux archive now includes the entry and icon under `share/` for
  packagers.
- On Windows, `ghidra-rust.exe` and `ghidra-rust-headless.exe` now include a
  16 to 256 pixel icon, so Explorer, Start, Alt+Tab, and pinned taskbar
  entries show the logo. Only MSVC builds embed it.
