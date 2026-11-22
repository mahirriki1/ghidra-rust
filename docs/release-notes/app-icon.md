- The Ghidra Rust logo is now the app icon on Linux and Windows.
- On Linux, the desktop sets the window app id `io.github.mahirriki1.GhidraRust`
  and adds itself to your application menu when it starts. It writes a menu
  entry and a 256-pixel icon in your own data folder (`$XDG_DATA_HOME`,
  usually `~/.local/share`), so KDE Plasma on Wayland shows the logo in the
  taskbar instead of a generic icon.
- The Linux entry is rewritten only when it is out of date, for example after
  you move the app. It skips symlinked folders and never needs root. Failures
  are silent. The headless tool and analysis workers write nothing. Delete
  the two files to remove the entry; see the Linux guide for their paths.
- If a system package already installs the entry under `/usr/share`, the app
  leaves your data folder alone.
- The Linux archive now includes the entry and icon under `share/` for
  packagers.
- On Windows, `ghidra-rust.exe` and `ghidra-rust-headless.exe` now include a
  16 to 256 pixel icon, so Explorer, Start, Alt+Tab, and pinned taskbar
  entries show the logo. Only MSVC builds embed it.
