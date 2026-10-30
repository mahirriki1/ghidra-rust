- Browse files in a themed in-app chooser with clickable breadcrumbs, an
  editable path (Ctrl+L), Back/Forward/Up navigation, Places, and recent
  folders from the current session.
- Sort the virtualized file table by name, size, or age; move through rows with
  the arrow keys, Home/End and Page Up/Down, open with Enter, go up with
  Backspace, and filter names without leaving the chooser.
- Binary dialogs show all files by default, including extensionless ELF and
  Mach-O images, with an optional PE filter; project and annotation dialogs
  default to `.grproj` and `.json` filters with an All files option.
- File listing, metadata, Places and overwrite checks run off the UI thread
  through one shared reader; canceled or superseded reads cannot change the
  current folder or selection. Listings stop at 4,096 entries and are marked
  Partial. A stalled filesystem call still holds the reader until it returns,
  but Cancel stays responsive.
- Saving checks whether a typed name is a folder before adding the default
  `.grproj` extension, and replacing an existing file still needs an explicit
  Replace. Names with control characters or invalid UTF-8 are shown escaped
  while the exact file is used.
- Recent folders reset on exit. Windows Places lists existing USERPROFILE
  folders and local drives, so redirected known folders may need a typed path;
  network (UNC) paths remain unsupported.
