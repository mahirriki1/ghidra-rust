//! Update dialog; all network, hashing, copying, and worker reaping are jobs.
use std::sync::Arc;

use eframe::egui::{self, ScrollArea};

use crate::updater::{self, Available, Installed, Job, Prepared};

#[derive(Default)]
enum State {
    #[default]
    Idle,
    Checking(Job<Option<Available>>),
    Current,
    Available(Box<Available>),
    Downloading(Job<Arc<Prepared>>),
    Ready(Arc<Prepared>),
    Installing(Job<Installed>),
    Failed(String),
}

#[derive(Default)]
pub(crate) struct UpdatePanel {
    pub open: bool,
    state: State,
}

impl UpdatePanel {
    pub fn installing(&self) -> bool {
        matches!(self.state, State::Installing(_))
    }

    pub fn ready(&self) -> Option<Arc<Prepared>> {
        if let State::Ready(prepared) = &self.state {
            Some(Arc::clone(prepared))
        } else {
            None
        }
    }

    pub fn install(&mut self, job: Job<Installed>) {
        self.state = State::Installing(job);
        self.open = true;
    }

    pub fn poll(&mut self, context: &egui::Context) -> Option<Installed> {
        let result = match &self.state {
            State::Checking(job) => job.poll().map(|result| {
                result.map(|available| {
                    available.map_or(State::Current, |release| {
                        State::Available(Box::new(release))
                    })
                })
            }),
            State::Downloading(job) => job.poll().map(|result| result.map(State::Ready)),
            State::Installing(job) => {
                if let Some(result) = job.poll() {
                    match result {
                        Ok(installed) => {
                            self.state = State::Idle;
                            return Some(installed);
                        }
                        Err(error) => self.state = State::Failed(error),
                    }
                }
                None
            }
            _ => None,
        };
        if let Some(result) = result {
            self.state = result.unwrap_or_else(State::Failed);
        }
        if matches!(
            self.state,
            State::Checking(_) | State::Downloading(_) | State::Installing(_)
        ) {
            context.request_repaint_after(std::time::Duration::from_millis(100));
        }
        None
    }

    /// Returns true for an explicit install request. The desktop then uses its
    /// normal save/discard/cancel flow before it starts installation.
    pub fn show(&mut self, context: &egui::Context) -> bool {
        if !self.open {
            return false;
        }
        let mut check = false;
        let mut download = None;
        let mut install = false;
        let mut close = false;
        let modal = egui::Modal::new(egui::Id::unique("updates")).show(context, |ui| {
            ui.set_width(500.0);
            ui.heading("Ghidra Rust updates");
            ui.label(concat!("Installed version: ", env!("CARGO_PKG_VERSION")));
            if env!("CARGO_PKG_VERSION").starts_with("0.") {
                ui.weak("Alpha builds include newer published alpha releases.");
            }
            ui.separator();
            match &self.state {
                State::Idle => {
                    ui.label("Check GitHub Releases for a newer version of this portable app.");
                    ui.weak("Checks run only when requested. Installation requires a verified release signature.");
                }
                State::Checking(_) => { ui.spinner(); ui.label("Checking releases and verifying update information…"); }
                State::Current => { ui.label("You’re up to date."); }
                State::Available(release) => {
                    ui.label(format!("Version {} is available", release.version));
                    ui.weak("Release signature verified");
                    ScrollArea::vertical().max_height(240.0).show(ui, |ui| { ui.label(&release.notes); });
                    ui.hyperlink_to("Full release notes", &release.release_url);
                    ui.label("Download the update, then save your work and restart to install it.");
                    if ui.button("Download update").clicked() { download = Some((**release).clone()); }
                }
                State::Downloading(job) => {
                    let received = job.received();
                    let fraction = received as f32 / job.total.max(1) as f32;
                    ui.add(egui::ProgressBar::new(fraction.min(1.0)).show_percentage());
                    ui.label(format!("Downloading and verifying: {:.1} / {:.1} MiB", received as f64 / 1048576.0, job.total as f64 / 1048576.0));
                }
                State::Ready(prepared) => {
                    ui.label(format!("Version {} is downloaded and verified.", prepared.release.version));
                    ui.label("Installation restarts the app. You’ll be prompted to save unsaved work. The previous executable is retained beside the app for recovery.");
                    if ui.button("Install and restart").clicked() { install = true; }
                }
                State::Installing(_) => {
                    ui.spinner();
                    ui.label("Stopping analysis, retaining the previous version, and installing…");
                }
                State::Failed(error) => {
                    ui.label("The update could not be completed.");
                    ui.label(error);
                    ui.hyperlink_to("GitHub Releases", "https://github.com/mahirriki1/ghidra-rust/releases");
                }
            }
            ui.separator();
            ui.horizontal(|ui| {
                if matches!(self.state, State::Idle | State::Current | State::Failed(_))
                    && ui.add_enabled(updater::supported(), egui::Button::new("Check for updates")).clicked()
                { check = true; }
                if !updater::supported() { ui.label("In-app updates require Linux x64 or Windows x64."); }
                if !self.installing() && ui.button(if matches!(self.state, State::Checking(_) | State::Downloading(_)) { "Cancel" } else { "Close" }).clicked() {
                    close = true;
                }
            });
        });
        if check {
            self.state = State::Checking(updater::check(context));
        }
        if let Some(release) = download {
            self.state = State::Downloading(updater::download(context, release));
        }
        if !self.installing() && (close || modal.should_close() || install) {
            self.open = false;
            if matches!(self.state, State::Checking(_) | State::Downloading(_)) {
                self.state = State::Idle;
            }
        }
        install
    }
}
