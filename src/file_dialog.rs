//! In-app file chooser. Directory I/O stays on background threads and does not
//! depend on a running desktop portal or an additional GUI toolkit.
use eframe::egui::{self, ScrollArea, TextEdit};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileDialogKind {
    OpenBinary,
    OpenProject,
    LocateProjectBinary,
    SaveProject,
    OpenAnnotations,
    SaveAnnotations,
}

impl FileDialogKind {
    fn is_save(self) -> bool {
        matches!(self, Self::SaveAnnotations | Self::SaveProject)
    }
}

pub struct FileDialogRequest {
    kind: FileDialogKind,
    initial_dir: Option<PathBuf>,
    result: SyncSender<Option<PathBuf>>,
}

/// Call only from a file-task thread: the modal sends back an explicit choice.
pub fn request_file(
    sender: &Sender<FileDialogRequest>,
    kind: FileDialogKind,
    initial_dir: Option<PathBuf>,
) -> Option<PathBuf> {
    let (result, receiver) = mpsc::sync_channel(1);
    sender
        .send(FileDialogRequest {
            kind,
            initial_dir,
            result,
        })
        .ok()?;
    receiver.recv().ok().flatten()
}

pub struct FileDialogs {
    requests: Sender<FileDialogRequest>,
    receiver: Receiver<FileDialogRequest>,
    active: Option<(Picker, SyncSender<Option<PathBuf>>)>,
    directory_busy: Arc<AtomicBool>,
}

impl Default for FileDialogs {
    fn default() -> Self {
        let (requests, receiver) = mpsc::channel();
        Self {
            requests,
            receiver,
            active: None,
            directory_busy: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl FileDialogs {
    pub fn sender(&self) -> Sender<FileDialogRequest> {
        self.requests.clone()
    }

    pub fn show(&mut self, context: &egui::Context) {
        if self.active.is_none()
            && let Ok(request) = self.receiver.try_recv()
        {
            self.active = Some((
                Picker::new(
                    request.kind,
                    request.initial_dir,
                    self.directory_busy.clone(),
                ),
                request.result,
            ));
        }
        let Some((picker, _)) = &mut self.active else {
            return;
        };
        if let Some(choice) = picker.show(context) {
            if let Some((_, result)) = self.active.take() {
                let _ = result.send(choice);
            }
            context.request_repaint();
        }
    }
}

struct Entry {
    path: PathBuf,
    label: String,
    directory: bool,
}

struct Listing {
    entries: Vec<Entry>,
    truncated: bool,
}

struct Picker {
    kind: FileDialogKind,
    directory: PathBuf,
    location: String,
    filename: String,
    filter: String,
    listing: Listing,
    loading: Option<Receiver<Result<Listing, String>>>,
    error: Option<String>,
    replace: Option<PathBuf>,
    directory_busy: Arc<AtomicBool>,
}

impl Picker {
    fn new(
        kind: FileDialogKind,
        initial_dir: Option<PathBuf>,
        directory_busy: Arc<AtomicBool>,
    ) -> Self {
        let directory = initial_dir
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        let mut picker = Self {
            kind,
            location: directory.to_string_lossy().into_owned(),
            directory,
            filename: match kind {
                FileDialogKind::SaveAnnotations => "annotations.json".into(),
                FileDialogKind::SaveProject => "analysis.grproj".into(),
                _ => String::new(),
            },
            filter: String::new(),
            listing: Listing {
                entries: Vec::new(),
                truncated: false,
            },
            loading: None,
            error: None,
            replace: None,
            directory_busy,
        };
        picker.load();
        picker
    }

    fn load(&mut self) {
        if self.loading.is_some() {
            return;
        }
        // A cancelled chooser cannot interrupt a stalled filesystem syscall.
        // Keep a single reader across chooser instances, so repeated cancels
        // cannot accumulate blocked threads. Manual paths remain available.
        if self
            .directory_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.error =
                Some("A directory read is still pending. Enter a file path directly.".into());
            return;
        }
        self.error = None;
        self.listing.entries.clear();
        let path = self.directory.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        self.loading = Some(receiver);
        let permit = DirectoryPermit(self.directory_busy.clone());
        if let Err(error) = std::thread::Builder::new()
            .name("directory-listing".into())
            .spawn(move || {
                let _permit = permit;
                let _ = sender.send(read_directory(path));
            })
        {
            self.loading = None;
            self.error = Some(format!("Cannot read directory: {error}"));
        }
    }

    fn change_directory(&mut self, directory: PathBuf) {
        if self.loading.is_some() {
            return;
        }
        self.directory = directory;
        self.location = self.directory.to_string_lossy().into_owned();
        self.filter.clear();
        self.load();
    }

    fn show(&mut self, context: &egui::Context) -> Option<Option<PathBuf>> {
        if let Some(result) = self
            .loading
            .as_ref()
            .and_then(|loading| loading.try_recv().ok())
        {
            self.loading = None;
            match result {
                Ok(listing) => self.listing = listing,
                Err(error) => self.error = Some(error),
            }
        }
        if self.loading.is_some() {
            context.request_repaint_after(std::time::Duration::from_millis(100));
        }
        let mut choice = None;
        let title = match self.kind {
            FileDialogKind::OpenBinary => "Open binary",
            FileDialogKind::OpenProject => "Open project (.grproj)",
            FileDialogKind::LocateProjectBinary => {
                "Locate the project's original binary (SHA-256 must match)"
            }
            FileDialogKind::SaveProject => "Save project (.grproj)",
            FileDialogKind::OpenAnnotations => "Open annotations",
            FileDialogKind::SaveAnnotations => "Save annotations",
        };
        let modal = egui::Modal::new(egui::Id::unique("file-chooser")).show(context, |ui| {
            ui.set_width(
                640.0_f32
                    .min(context.content_rect().width() - 64.0)
                    .max(320.0),
            );
            ui.heading(title);
            if let Some(path) = self.replace.clone() {
                ui.label(format!("Replace the existing file {}?", path.display()));
                ui.horizontal(|ui| {
                    if ui.button("Replace").clicked() {
                        choice = Some(Some(path.clone()));
                    }
                    if ui.button("Keep existing file").clicked() {
                        self.replace = None;
                    }
                });
                return;
            }
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(self.loading.is_none(), egui::Button::new("Up"))
                    .clicked()
                    && let Some(parent) = self.directory.parent()
                {
                    self.change_directory(parent.to_owned());
                }
                let location = ui.add(
                    TextEdit::singleline(&mut self.location)
                        .desired_width(440.0)
                        .char_limit(4096),
                );
                if (ui.button("Go").clicked()
                    || (location.lost_focus()
                        && ui.input(|input| input.key_pressed(egui::Key::Enter))))
                    && self.loading.is_none()
                {
                    self.change_directory(PathBuf::from(&self.location));
                }
            });
            ui.add(
                TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter files")
                    .char_limit(256),
            );
            if let Some(error) = &self.error {
                ui.colored_label(crate::theme::ERROR, error);
            }
            if self.loading.is_some() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Reading directory...");
                });
            }
            let filter = self.filter.to_lowercase();
            let visible: Vec<_> = self
                .listing
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| {
                    filter.is_empty() || entry.label.to_lowercase().contains(&filter)
                })
                .map(|(index, _)| index)
                .collect();
            let mut directory = None;
            let mut open = false;
            ScrollArea::vertical()
                .id_salt("file-chooser-list")
                .min_scrolled_height(200.0)
                .max_height(320.0_f32.min(context.content_rect().height() * 0.4))
                .show_rows(ui, 20.0, visible.len(), |ui, rows| {
                    ui.set_min_width(ui.available_width());
                    for row in rows {
                        let entry = &self.listing.entries[visible[row]];
                        let response = ui.selectable_label(
                            !entry.directory
                                && self.filename
                                    == entry.path.file_name().unwrap_or_default().to_string_lossy(),
                            &entry.label,
                        );
                        if response.clicked() && !entry.directory {
                            self.filename = entry
                                .path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .into_owned();
                        }
                        if response.double_clicked() {
                            if entry.directory {
                                directory = Some(entry.path.clone());
                            } else {
                                open = true;
                            }
                        }
                    }
                });
            if let Some(directory) = directory {
                self.change_directory(directory);
            }
            if self.listing.truncated {
                ui.weak("Showing at most 4,096 entries. Enter a path to navigate directly.");
            }
            ui.horizontal(|ui| {
                ui.label("File name");
                let filename = ui.add(
                    TextEdit::singleline(&mut self.filename)
                        .desired_width(f32::INFINITY)
                        .char_limit(4096),
                );
                open |=
                    filename.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            });
            ui.horizontal(|ui| {
                let verb = if self.kind.is_save() { "Save" } else { "Open" };
                open |= ui
                    .add_enabled(!self.filename.trim().is_empty(), egui::Button::new(verb))
                    .clicked();
                if ui.button("Cancel").clicked() {
                    choice = Some(None);
                }
            });
            if open && !self.filename.trim().is_empty() {
                let mut path = self.directory.join(self.filename.trim());
                if self.kind == FileDialogKind::SaveProject && path.extension().is_none() {
                    path.set_extension("grproj");
                }
                if self.kind.is_save() && path.exists() {
                    self.replace = Some(path);
                } else {
                    choice = Some(Some(path));
                }
            }
        });
        if modal.should_close() {
            choice = Some(None);
        }
        choice
    }
}

struct DirectoryPermit(Arc<AtomicBool>);

impl Drop for DirectoryPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn read_directory(path: PathBuf) -> Result<Listing, String> {
    let mut entries = Vec::new();
    let mut truncated = false;
    for result in
        std::fs::read_dir(path).map_err(|error| format!("Cannot read directory: {error}"))?
    {
        let entry = result.map_err(|error| error.to_string())?;
        if entries.len() == 4096 {
            truncated = true;
            break;
        }
        let directory = entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir();
        let name: String = entry
            .file_name()
            .to_string_lossy()
            .chars()
            .take(160)
            .collect();
        entries.push(Entry {
            path: entry.path(),
            directory,
            label: format!("{}{}", if directory { "[dir] " } else { "      " }, name),
        });
    }
    entries.sort_by(|left, right| {
        right
            .directory
            .cmp(&left.directory)
            .then_with(|| left.label.cmp(&right.label))
    });
    Ok(Listing { entries, truncated })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_directory_read_cannot_accumulate_threads_across_cancelled_choosers() {
        let busy = Arc::new(AtomicBool::new(true));
        for _ in 0..8 {
            let picker = Picker::new(
                FileDialogKind::OpenBinary,
                Some(PathBuf::from("/tmp")),
                busy.clone(),
            );
            assert!(picker.loading.is_none());
            assert!(picker.error.as_deref().unwrap().contains("still pending"));
        }
        drop(DirectoryPermit(busy.clone()));
        assert!(!busy.load(Ordering::Acquire));
    }

    #[test]
    fn chooser_returns_only_the_explicit_selection() {
        let dialogs = FileDialogs::default();
        let sender = dialogs.sender();
        let task =
            std::thread::spawn(move || request_file(&sender, FileDialogKind::OpenBinary, None));
        let request = dialogs
            .receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(request.kind, FileDialogKind::OpenBinary);
        request.result.send(Some(PathBuf::from("fixture"))).unwrap();
        assert_eq!(task.join().unwrap(), Some(PathBuf::from("fixture")));
        assert!(dialogs.active.is_none());
    }

    #[test]
    fn cancelled_dialog_releases_the_waiting_file_job() {
        let dialogs = FileDialogs::default();
        let sender = dialogs.sender();
        let task = std::thread::spawn(move || {
            request_file(&sender, FileDialogKind::SaveAnnotations, None)
        });
        let request = dialogs
            .receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        request.result.send(None).unwrap();
        assert!(task.join().unwrap().is_none());
    }

    #[test]
    fn chooser_renders_without_a_desktop_portal() {
        let mut picker = Picker::new(
            FileDialogKind::OpenBinary,
            Some(PathBuf::from("/tmp")),
            Arc::new(AtomicBool::new(false)),
        );
        let context = egui::Context::default();
        let mut output = context.run_ui(egui::RawInput::default(), |_ui| {
            assert!(picker.show(&context).is_none());
        });
        assert!(!output.shapes.is_empty());
        output.textures_delta.clear();
    }
}
