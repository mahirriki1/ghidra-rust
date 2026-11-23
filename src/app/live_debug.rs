//! The desktop's live debug session: run control, breakpoints and PC follow.
//!
//! Every debugger request runs on the session controller's own thread; the
//! GUI only sends commands and drains events. A session is bound to the binary
//! generation and SHA-256 it launched, and ends as soon as either changes.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use eframe::egui::{self, RichText};

use super::{DesktopApp, crop, info_without_functions};
use crate::debugger::controller::{
    BreakpointStatus, Command, Controller, Event, Launch, Snapshot, StepKind,
};
use crate::debugger::{MAX_BREAKPOINTS, SUPPORTED};
use crate::search_jobs::Destination;
use crate::theme;

/// One live session's command and event channels.
trait SessionPort {
    /// Returns `false` once the session thread has ended.
    fn send(&self, command: Command) -> bool;
    fn try_recv(&self) -> Option<Event>;
    /// Ends the session, waiting at most `timeout`.
    fn shutdown(self: Box<Self>, timeout: Duration);
}

impl SessionPort for Controller {
    fn send(&self, command: Command) -> bool {
        Controller::send(self, command)
    }

    fn try_recv(&self) -> Option<Event> {
        Controller::try_recv(self)
    }

    fn shutdown(self: Box<Self>, timeout: Duration) {
        Controller::shutdown(*self, timeout);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    /// Started; `run` launches resume past the loader stop on their own.
    Launching {
        run: bool,
    },
    Running,
    Pausing,
    Stopped,
    /// A resume or step was sent while stopped.
    Stepping,
    Stopping,
}

struct LiveSession {
    generation: u64,
    sha256: String,
    port: Box<dyn SessionPort>,
    phase: Phase,
}

/// A pending "Run program" confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LaunchPrompt {
    generation: u64,
    run: bool,
}

#[derive(Default)]
pub(super) struct LiveDebug {
    /// Desired breakpoints of binary generation `generation`: static
    /// addresses of decoded instruction starts only.
    breakpoints: BTreeSet<u64>,
    /// The function whose decoded listing each breakpoint was set in.
    owners: BTreeMap<u64, u64>,
    breakpoint_revision: u64,
    /// The last live answer for `breakpoint_revision`; absent while unapplied.
    breakpoint_status: BTreeMap<u64, BreakpointStatus>,
    generation: u64,
    /// The binary generation and SHA-256 the user confirmed running.
    trusted: Option<(u64, String)>,
    prompt: Option<LaunchPrompt>,
    session: Option<LiveSession>,
    /// The latest stop of the current session.
    stop: Option<Box<Snapshot>>,
    /// How the last session's target ended, until a new session or binary.
    exit: Option<String>,
}

impl LiveDebug {
    /// Ends any session and forgets everything bound to the previous binary.
    /// Returns whether a live session was ended.
    pub(super) fn end(&mut self, generation: u64) -> bool {
        let ended = self.session.is_some();
        *self = Self {
            generation,
            ..Self::default()
        };
        ended
    }

    /// Keeps state only for the same binary generation and contents.
    /// Returns whether a live session was ended.
    pub(super) fn bind(&mut self, generation: u64, sha256: &str) -> bool {
        if self.generation != generation
            || self.session.as_ref().is_some_and(|s| s.sha256 != sha256)
            || self.trusted.as_ref().is_some_and(|(_, s)| s != sha256)
        {
            return self.end(generation);
        }
        false
    }

    pub(super) fn prompt_open(&self) -> bool {
        self.prompt.is_some()
    }

    /// Ends the session on quit, waiting at most `timeout`.
    pub(super) fn shutdown(&mut self, timeout: Duration) {
        if let Some(session) = self.session.take() {
            session.port.shutdown(timeout);
        }
    }

    fn phase(&self) -> Option<Phase> {
        self.session.as_ref().map(|session| session.phase)
    }

    fn stopped(&self) -> Option<&Snapshot> {
        (self.phase() == Some(Phase::Stopped))
            .then_some(self.stop.as_deref())
            .flatten()
    }

    /// The stopped PC in the static image, if it is one.
    pub(super) fn pc(&self) -> Option<u64> {
        self.stopped()?.stop.location.static_address
    }

    fn send(&mut self, command: Command, phase: Phase) {
        if let Some(session) = &mut self.session {
            // A closed thread reports `Ended` through `try_recv`.
            session.port.send(command);
            session.phase = phase;
        }
    }

    fn mark(&self, address: u64) -> Option<theme::BreakpointMark> {
        let status = self.breakpoint_status.get(&address);
        if !self.breakpoints.contains(&address) {
            // An undesired address whose removal failed is still armed, and
            // one removed since the applied revision stays armed until the
            // removal applies at the next stop.
            return match status {
                Some(BreakpointStatus::Failed(_)) => Some(theme::BreakpointMark::Failed),
                Some(BreakpointStatus::Set) if self.session.is_some() => {
                    Some(theme::BreakpointMark::Pending)
                }
                _ => None,
            };
        }
        if self.session.is_none() {
            return Some(theme::BreakpointMark::Set);
        }
        Some(match status {
            Some(BreakpointStatus::Set) => theme::BreakpointMark::Set,
            Some(BreakpointStatus::Failed(_)) => theme::BreakpointMark::Failed,
            None => theme::BreakpointMark::Pending,
        })
    }

    /// Terse hover lines for a Listing row at `address`.
    fn hover(&self, address: u64) -> Option<String> {
        let mut lines = Vec::new();
        match (self.mark(address), self.breakpoint_status.get(&address)) {
            (Some(_), Some(BreakpointStatus::Failed(message))) => {
                lines.push(crop(message, 200));
            }
            (Some(theme::BreakpointMark::Pending), _) => {
                lines.push("Breakpoint (next stop)".into())
            }
            (Some(_), _) => lines.push("Breakpoint".into()),
            (None, _) => {}
        }
        if self.pc() == Some(address) {
            lines.push("PC".into());
        }
        (!lines.is_empty()).then(|| lines.join("\n"))
    }

    /// The status-bar token, its hover, and whether it reports a fault.
    fn token(&self) -> Option<(String, Option<String>, bool)> {
        let Some(session) = &self.session else {
            let exit = self.exit.clone()?;
            let fault = exit.starts_with("Killed");
            return Some((exit, None, fault));
        };
        let text = match session.phase {
            Phase::Launching { .. } => "Launching",
            Phase::Running | Phase::Pausing | Phase::Stepping => "Running",
            Phase::Stopping => "Stopping",
            Phase::Stopped => {
                let snapshot = self.stop.as_deref()?;
                let stop = &snapshot.stop;
                let fault = stop.signal.as_deref().filter(|signal| *signal != "SIGINT");
                let head = crop(fault.unwrap_or("Stopped"), 24);
                let text = match stop.location.static_address {
                    Some(address) => format!("{head} @ {address:x}"),
                    None => format!("{head} {:#x}", stop.location.runtime),
                };
                let hover = format!(
                    "Thread {}\n{:#x}\n{}",
                    stop.thread,
                    stop.location.runtime,
                    crop(&stop.reason, 120)
                );
                return Some((text, Some(hover), fault.is_some()));
            }
        };
        Some((text.into(), None, false))
    }
}

fn exit_text(code: Option<u32>, signal: Option<String>) -> String {
    match (code, signal) {
        (_, Some(signal)) => format!("Killed by {}", crop(&signal, 24)),
        (Some(code), None) => format!("Exited {code}"),
        (None, None) => "Exited".into(),
    }
}

impl DesktopApp {
    /// Static reasons this binary cannot be debugged; stable while it is open.
    fn live_binary(&self) -> Result<(), &'static str> {
        if !SUPPORTED {
            return Err("Requires Linux x86-64");
        }
        let info = self.info.as_ref().ok_or("Open a binary")?;
        if info.format != "ELF" || info.architecture != "x86-64" {
            return Err("Requires an x86-64 ELF executable");
        }
        if !crate::call_analysis::code_address(info, info.entry) {
            return Err("No executable entry point");
        }
        if self.project_binary.is_some() || self.binary_path.is_none() {
            return Err("Open the executable directly");
        }
        Ok(())
    }

    pub(super) fn live_session_active(&self) -> bool {
        self.live.session.is_some()
    }

    pub(super) fn live_debuggable(&self) -> Result<(), &'static str> {
        self.live_binary()?;
        if self.opening.is_some() {
            return Err("Wait for the binary to open");
        }
        Ok(())
    }

    /// Whether Listing rows reserve the breakpoint gutter. It does not change
    /// when a session starts or ends, so columns stay put.
    pub(super) fn live_gutter(&self) -> bool {
        self.live_binary().is_ok()
    }

    /// The breakpoint and PC marks of the Listing row at `address`.
    pub(super) fn live_marks(&self, address: u64) -> (Option<theme::BreakpointMark>, bool) {
        (self.live.mark(address), self.live.pc() == Some(address))
    }

    pub(super) fn live_hover(&self, address: u64) -> Option<String> {
        self.live.hover(address)
    }

    pub(super) fn live_breakpoint_set(&self, address: u64) -> bool {
        self.live.breakpoints.contains(&address)
    }

    /// Paints a Listing row's live marks after its selection fill.
    pub(super) fn paint_live_row(
        &self,
        ui: &egui::Ui,
        rect: egui::Rect,
        columns: &theme::ListingColumns,
        address: u64,
        selected: bool,
        related: bool,
    ) {
        let Some(gutter) = columns.gutter else {
            return;
        };
        let (mark, pc) = self.live_marks(address);
        if pc {
            theme::paint_live_pc_row(ui, rect, selected || related);
        }
        theme::paint_live_gutter(ui, rect, gutter, mark, pc);
    }

    /// The exact decoded instruction start at the selection, with the
    /// function whose listing decoded it. Never a nearby address.
    pub(super) fn breakpoint_target(&self) -> Option<(u64, u64)> {
        if self.program_scope() {
            let layout = self.program_layout()?;
            let crate::program_listing::Row::Instruction { owner, start, .. } =
                self.program_cursor(&layout)?
            else {
                return None;
            };
            let (_, listing) = self.row_view(owner)?;
            let index = listing.position(start)?;
            return (listing.get(index)?.address == start).then_some((start, owner));
        }
        let selected = self.selected?;
        let view = self.view()?;
        let listing = self.listing();
        let index = listing.position(selected)?;
        (listing.get(index)?.address == selected).then_some((selected, view.address))
    }

    pub(super) fn live_toggle_breakpoint(&mut self) {
        if self.live_debuggable().is_err() {
            return;
        }
        match self.breakpoint_target() {
            Some((address, owner)) => self.toggle_breakpoint_at(address, owner),
            None => self.status = "Select an instruction".into(),
        }
    }

    /// Toggles a breakpoint at `address`, a decoded instruction of `owner`.
    pub(super) fn toggle_breakpoint_at(&mut self, address: u64, owner: u64) {
        if self.live_debuggable().is_err() {
            return;
        }
        let live = &mut self.live;
        if !live.breakpoints.remove(&address) {
            if live.breakpoints.len() >= MAX_BREAKPOINTS {
                self.status = "Breakpoint limit reached".into();
                return;
            }
            live.breakpoints.insert(address);
            live.owners.insert(address, owner);
        } else {
            live.owners.remove(&address);
        }
        self.sync_breakpoints();
    }

    pub(super) fn live_clear_breakpoints(&mut self) {
        if self.live.breakpoints.is_empty() {
            return;
        }
        self.live.breakpoints.clear();
        self.live.owners.clear();
        self.sync_breakpoints();
    }

    fn sync_breakpoints(&mut self) {
        let live = &mut self.live;
        live.breakpoint_revision = live.breakpoint_revision.wrapping_add(1);
        if let Some(session) = &live.session
            && session.phase != Phase::Stopping
        {
            session.port.send(Command::Breakpoints {
                revision: live.breakpoint_revision,
                addresses: live.breakpoints.clone(),
            });
        }
    }

    /// F5: start and run when idle, continue when stopped.
    pub(super) fn live_run(&mut self, context: &egui::Context) {
        match self.live.phase() {
            None => self.live_start(true, context),
            Some(Phase::Stopped) => self.live.send(Command::Resume, Phase::Stepping),
            Some(_) => {}
        }
    }

    pub(super) fn live_step(&mut self) {
        if self.live.phase() == Some(Phase::Stopped) {
            self.live
                .send(Command::Step(StepKind::Instruction), Phase::Stepping);
        }
    }

    pub(super) fn live_pause(&mut self) {
        if self.live.phase() == Some(Phase::Running) {
            self.live.send(Command::Pause, Phase::Pausing);
        }
    }

    pub(super) fn live_stop(&mut self) {
        if self
            .live
            .phase()
            .is_some_and(|phase| phase != Phase::Stopping)
        {
            self.live.send(Command::Stop, Phase::Stopping);
        }
    }

    /// Starts a session, first asking once per binary generation to run it.
    pub(super) fn live_start(&mut self, run: bool, context: &egui::Context) {
        if self.live.session.is_some() || self.live_debuggable().is_err() {
            return;
        }
        let Some(info) = &self.info else { return };
        if self.live.trusted.as_ref() != Some(&(self.generation, info.sha256.clone())) {
            self.live.prompt = Some(LaunchPrompt {
                generation: self.generation,
                run,
            });
            return;
        }
        self.live_launch(run, context);
    }

    fn live_launch(&mut self, run: bool, context: &egui::Context) {
        let (Some(info), Some(path)) = (&self.info, &self.binary_path) else {
            return;
        };
        let notify = {
            let context = context.clone();
            Arc::new(move || context.request_repaint())
        };
        let mut launch = Launch::new(path.clone(), info_without_functions(info), notify);
        launch.breakpoints = (self.live.breakpoint_revision, self.live.breakpoints.clone());
        launch.run = run;
        let sha256 = info.sha256.clone();
        match Controller::launch(launch) {
            Ok(controller) => self.adopt_live_port(Box::new(controller), sha256, run),
            Err(error) => self.status = crop(&error.to_string(), 1024),
        }
    }

    fn adopt_live_port(&mut self, port: Box<dyn SessionPort>, sha256: String, run: bool) {
        let live = &mut self.live;
        live.generation = self.generation;
        live.breakpoint_status.clear();
        live.stop = None;
        live.exit = None;
        live.session = Some(LiveSession {
            generation: self.generation,
            sha256,
            port,
            phase: Phase::Launching { run },
        });
    }

    /// Drains the session's events. Only the last stop of the batch is
    /// followed; a session of another binary generation is dropped unread.
    pub(super) fn poll_live_debug(&mut self, context: &egui::Context) {
        let Some(session) = &self.live.session else {
            return;
        };
        let sha_changed = self
            .info
            .as_ref()
            .is_none_or(|info| info.sha256 != session.sha256);
        if session.generation != self.generation
            || self.live.generation != self.generation
            || sha_changed
        {
            if self.live.end(self.generation) {
                self.status = "Debug session ended".into();
            }
            return;
        }
        let mut follow = false;
        while let Some(event) = self
            .live
            .session
            .as_ref()
            .and_then(|session| session.port.try_recv())
        {
            follow |= self.adopt_live_event(event);
        }
        // An open in flight would take the navigation as its own follow-up,
        // and moving the selection would replace an annotation draft. The
        // marks still update; the next stop or Go to PC follows.
        if follow
            && self.opening.is_none()
            && !context.egui_wants_keyboard_input()
            && !self.annotation_draft_pending()
            && self.live.stop.is_some()
            && let Some(pc) = self.live.pc()
        {
            self.follow_pc(pc, context);
        }
    }

    /// Whether the Annotations editor holds an edit that a selection change
    /// would discard.
    fn annotation_draft_pending(&self) -> bool {
        let Some(address) = self.editor_address.filter(|_| self.annotations_open) else {
            return false;
        };
        let comment = self
            .session
            .as_ref()
            .and_then(|session| session.annotations.get(&address))
            .map_or("", |annotation| annotation.comment.as_str());
        let name = self
            .view()
            .and_then(|view| {
                crate::model::function_at(&self.info.as_ref()?.functions, view.address)
            })
            .map_or("", |function| function.name.as_str());
        self.comment_edit != comment || self.name_edit != name
    }

    /// Applies one event; returns whether it was a stop to follow.
    fn adopt_live_event(&mut self, event: Event) -> bool {
        let live = &mut self.live;
        let Some(session) = &mut live.session else {
            return false;
        };
        match event {
            Event::Stopped(snapshot) => {
                // A run launch resumes past its loader stop by itself.
                let loader = matches!(session.phase, Phase::Launching { run: true })
                    && snapshot.stop_seq == 1;
                if !loader && session.phase != Phase::Stopping {
                    session.phase = Phase::Stopped;
                }
                live.stop = Some(snapshot);
                !loader
            }
            Event::Running => {
                if session.phase != Phase::Stopping {
                    session.phase = Phase::Running;
                }
                live.stop = None;
                false
            }
            Event::Breakpoints { revision, status } => {
                if revision == live.breakpoint_revision {
                    live.breakpoint_status = status;
                }
                false
            }
            Event::Memory { .. } => false,
            // A pause that crossed a stop is moot, not an error.
            Event::Refused { .. } if session.phase == Phase::Stopped => false,
            Event::Refused { message } => {
                session.phase = match session.phase {
                    Phase::Stepping => Phase::Stopped,
                    Phase::Pausing => Phase::Running,
                    Phase::Launching { .. } if live.stop.is_some() => Phase::Stopped,
                    phase => phase,
                };
                self.status = crop(&message, 1024);
                false
            }
            Event::Exited { code, signal } => {
                let text = exit_text(code, signal);
                self.status = text.clone();
                live.exit = Some(text);
                live.stop = None;
                session.phase = Phase::Stopping;
                false
            }
            Event::Ended { error } => {
                live.session = None;
                live.stop = None;
                live.breakpoint_status.clear();
                match error {
                    Some(error) => self.status = crop(&error, 1024),
                    None if live.exit.is_none() => self.status = "Debug session ended".into(),
                    None => {}
                }
                false
            }
        }
    }

    /// The function whose decoded listing exactly contains `pc`, from the
    /// same evidence Go To uses plus the listings breakpoints were set in.
    fn live_owner(&self, pc: u64) -> Option<u64> {
        let info = self.info.as_ref()?;
        let observed = |pc| {
            self.observed_owner(pc)
                .or_else(|| self.live.owners.get(&pc).copied())
        };
        match crate::search_jobs::resolve(info, pc, 1, observed)? {
            Destination::Code { owner, .. } => Some(owner),
            Destination::Data { .. } => None,
        }
    }

    /// Moves the selection to a stop's PC without recording history. A PC
    /// no known function decoded leaves the selection where it is.
    fn follow_pc(&mut self, pc: u64, context: &egui::Context) {
        // Unrecorded navigation keeps Listing and Graph; other tabs switch
        // to the Listing.
        if let Some(owner) = self.live_owner(pc) {
            self.navigate_location(pc, Some(owner), false, context);
        }
    }

    /// "Go to PC": navigates to the stopped PC and records history.
    pub(super) fn live_go_to_pc(&mut self, context: &egui::Context) {
        let Some(pc) = self.live.pc() else { return };
        match self.live_owner(pc) {
            Some(owner) => self.navigate_location(pc, Some(owner), true, context),
            None => self.status = "No known function contains the PC".into(),
        }
    }

    /// The status-bar token. Returns whether it was clicked.
    pub(super) fn live_status_token(&self, ui: &mut egui::Ui) -> bool {
        let Some((text, hover, fault)) = self.live.token() else {
            return false;
        };
        let color = if fault { theme::ERROR } else { theme::MUTED };
        let response = theme::status_button_token(ui, &text, color);
        let response = match hover {
            Some(hover) => response.on_hover_text(hover),
            None => response,
        };
        response.clicked() && self.live.pc().is_some()
    }

    /// The trust confirmation before the first run of a binary generation.
    pub(super) fn live_prompt_window(&mut self, context: &egui::Context) {
        let Some(prompt) = self.live.prompt else {
            return;
        };
        if prompt.generation != self.generation
            || self.live.session.is_some()
            || self.live_debuggable().is_err()
        {
            self.live.prompt = None;
            return;
        }
        let Some(path) = self.binary_path.clone() else {
            self.live.prompt = None;
            return;
        };
        let name = path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned();
        let mut run = false;
        let mut cancel = false;
        let modal = egui::Modal::new(egui::Id::unique("live-debug-trust")).show(context, |ui| {
            ui.set_max_width(520.0);
            ui.heading("Run program");
            ui.add(egui::Label::new(RichText::new(crop(&name, 120)).monospace()).truncate())
                .on_hover_text(path.to_string_lossy());
            ui.horizontal(|ui| {
                run = ui.button("Run").clicked();
                cancel = ui.button("Cancel").clicked();
            });
        });
        if cancel || modal.should_close() {
            self.live.prompt = None;
            return;
        }
        if run {
            self.live.prompt = None;
            if let Some(info) = &self.info {
                self.live.trusted = Some((self.generation, info.sha256.clone()));
            }
            self.live_launch(prompt.run, context);
        }
    }

    /// The Debug menu body.
    pub(super) fn live_menu(&mut self, ui: &mut egui::Ui, context: &egui::Context) {
        let available = self.live_debuggable();
        let reason = available.err().unwrap_or("");
        let phase = self.live.phase();
        let idle = phase.is_none() && available.is_ok();
        let stopped = phase == Some(Phase::Stopped);
        let label = if phase.is_some() { "Continue" } else { "Start" };
        let busy = if phase.is_some() { "Running" } else { reason };
        if ui
            .add_enabled(
                idle || stopped,
                egui::Button::new(label).shortcut_text("F5"),
            )
            .on_disabled_hover_text(busy)
            .clicked()
        {
            self.live_run(context);
            ui.close();
        }
        if ui
            .add_enabled(idle, egui::Button::new("Start paused"))
            .on_disabled_hover_text(if phase.is_some() {
                "Session active"
            } else {
                reason
            })
            .clicked()
        {
            self.live_start(false, context);
            ui.close();
        }
        if ui
            .add_enabled(
                phase == Some(Phase::Running),
                egui::Button::new("Pause").shortcut_text("F6"),
            )
            .on_disabled_hover_text("Not running")
            .clicked()
        {
            self.live_pause();
            ui.close();
        }
        if ui
            .add_enabled(
                stopped,
                egui::Button::new("Step instruction").shortcut_text("F11"),
            )
            .on_disabled_hover_text("Not stopped")
            .clicked()
        {
            self.live_step();
            ui.close();
        }
        if ui
            .add_enabled(
                phase.is_some_and(|phase| phase != Phase::Stopping),
                egui::Button::new("Stop").shortcut_text("Shift+F5"),
            )
            .on_disabled_hover_text("No session")
            .clicked()
        {
            self.live_stop();
            ui.close();
        }
        ui.separator();
        let target = available.is_ok() && self.breakpoint_target().is_some();
        if ui
            .add_enabled(
                target,
                egui::Button::new("Toggle breakpoint").shortcut_text("F9"),
            )
            .on_disabled_hover_text(if available.is_ok() {
                "Select an instruction"
            } else {
                reason
            })
            .clicked()
        {
            self.live_toggle_breakpoint();
            ui.close();
        }
        if ui
            .add_enabled(
                !self.live.breakpoints.is_empty(),
                egui::Button::new("Clear breakpoints"),
            )
            .on_disabled_hover_text("No breakpoints")
            .clicked()
        {
            self.live_clear_breakpoints();
            ui.close();
        }
        if ui
            .add_enabled(self.live.pc().is_some(), egui::Button::new("Go to PC"))
            .on_disabled_hover_text("Not stopped in the image")
            .clicked()
        {
            self.live_go_to_pc(context);
            ui.close();
        }
    }

    /// The toolbar run-control group, only for debuggable binaries.
    pub(super) fn live_toolbar(&mut self, ui: &mut egui::Ui, context: &egui::Context) {
        if !SUPPORTED || self.live_binary().is_err() {
            return;
        }
        ui.separator();
        let available = self.live_debuggable().is_ok();
        let phase = self.live.phase();
        let spacing = ui.spacing().item_spacing.x;
        ui.spacing_mut().item_spacing.x = 0.0;
        let run_label = if phase.is_some() {
            "Continue (F5)"
        } else {
            "Start (F5)"
        };
        let run_enabled = (phase.is_none() && available) || phase == Some(Phase::Stopped);
        if theme::run_control_button(ui, theme::RunIcon::Run, run_enabled, run_label).clicked() {
            self.live_run(context);
        }
        if theme::run_control_button(
            ui,
            theme::RunIcon::Pause,
            phase == Some(Phase::Running),
            "Pause (F6)",
        )
        .clicked()
        {
            self.live_pause();
        }
        if theme::run_control_button(
            ui,
            theme::RunIcon::Step,
            phase == Some(Phase::Stopped),
            "Step instruction (F11)",
        )
        .clicked()
        {
            self.live_step();
        }
        if theme::run_control_button(
            ui,
            theme::RunIcon::Stop,
            phase.is_some_and(|phase| phase != Phase::Stopping),
            "Stop (Shift+F5)",
        )
        .clicked()
        {
            self.live_stop();
        }
        ui.spacing_mut().item_spacing.x = spacing;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::super::tests as fixture;
    use super::super::{Shortcut, shortcut};
    use super::*;
    use crate::debugger::{Location, Register, Stop};
    use crate::model::{BasicBlock, FunctionView, Instruction};

    /// A session port the test drives in place of the GDB thread.
    struct Fake {
        commands: mpsc::Sender<Command>,
        events: mpsc::Receiver<Event>,
    }

    impl SessionPort for Fake {
        fn send(&self, command: Command) -> bool {
            self.commands.send(command).is_ok()
        }

        fn try_recv(&self) -> Option<Event> {
            self.events.try_recv().ok()
        }

        fn shutdown(self: Box<Self>, _timeout: Duration) {}
    }

    struct Wire {
        commands: mpsc::Receiver<Command>,
        events: mpsc::Sender<Event>,
    }

    impl Wire {
        fn sent(&self) -> Vec<Command> {
            self.commands.try_iter().collect()
        }

        fn emit(&self, event: Event) {
            self.events.send(event).unwrap();
        }
    }

    fn fake_session(app: &mut DesktopApp, phase: Phase) -> Wire {
        let (commands, command_receiver) = mpsc::channel();
        let (event_sender, events) = mpsc::channel();
        let sha256 = app.info.as_ref().unwrap().sha256.clone();
        app.adopt_live_port(Box::new(Fake { commands, events }), sha256, false);
        app.live.session.as_mut().unwrap().phase = phase;
        Wire {
            commands: command_receiver,
            events: event_sender,
        }
    }

    const RUNTIME: u64 = 0x5555_5555_0000;

    fn stopped(stop_seq: u64, static_address: Option<u64>, signal: Option<&str>) -> Event {
        let runtime = static_address.map_or(0x7fff_f7fd_0100, |address| RUNTIME + address);
        Event::Stopped(Box::new(Snapshot {
            stop_seq,
            stop: Stop {
                reason: "breakpoint-hit".into(),
                thread: 1,
                location: Location {
                    runtime,
                    static_address,
                },
                signal: signal.map(Into::into),
            },
            registers: Ok(vec![Register {
                name: "rip".into(),
                value: runtime,
            }]),
            frames: Ok(vec![]),
            register_locations: vec![],
        }))
    }

    fn instruction(address: u64, length: usize) -> Instruction {
        Instruction {
            address,
            bytes: vec![0x90; length],
            mnemonic: "nop".into(),
            operands: String::new(),
        }
    }

    /// The fixture's function at 0x1000 with a 5-byte instruction at 0x1001,
    /// opened from an explicitly selected executable path.
    fn debuggable() -> DesktopApp {
        let mut app = fixture::keyboard_app();
        app.binary_path = Some("/nonexistent/ghidra-rust-live/fixture".into());
        fixture::show_view(
            &mut app,
            FunctionView {
                address: 0x1000,
                blocks: vec![BasicBlock {
                    address: 0x1000,
                    instructions: vec![
                        instruction(0x1000, 1),
                        instruction(0x1001, 5),
                        instruction(0x1006, 1),
                    ],
                }],
                edges: vec![],
                calls: vec![],
                warnings: vec![],
            },
        );
        app
    }

    fn key(key: egui::Key, modifiers: egui::Modifiers, repeat: bool) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: Some(key),
            pressed: true,
            repeat,
            modifiers,
        }
    }

    fn release(key: egui::Key) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: Some(key),
            pressed: false,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }
    }

    fn frame(
        context: &egui::Context,
        app: &mut DesktopApp,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        let time = context.input(|input| input.time) + 0.1;
        let mut output = context.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1400.0, 800.0),
                )),
                time: Some(time),
                events,
                ..Default::default()
            },
            |ui| app.draw(ui),
        );
        output.textures_delta.clear();
        output
    }

    fn scaled_context() -> egui::Context {
        let context = egui::Context::default();
        theme::install(&context);
        context.set_pixels_per_point(1.25);
        context.all_styles_mut(|style| style.animation_time = 0.0);
        context
    }

    #[test]
    fn debug_keys_map_only_on_supported_builds_and_ignore_repeats_and_text_focus() {
        let none = egui::Modifiers::NONE;
        let mapped = |event: egui::Event| shortcut(&event).map(|s| s as u8);
        assert_eq!(
            mapped(key(egui::Key::F5, none, false)),
            SUPPORTED.then_some(Shortcut::DebugRun as u8)
        );
        assert_eq!(
            mapped(key(egui::Key::F5, egui::Modifiers::SHIFT, false)),
            SUPPORTED.then_some(Shortcut::DebugStop as u8)
        );
        for pressed in [egui::Key::F5, egui::Key::F9, egui::Key::F11] {
            assert_eq!(mapped(key(pressed, none, true)), None);
        }
        // Ctrl+F5 and Alt+F9 stay unbound.
        assert_eq!(
            mapped(key(egui::Key::F5, egui::Modifiers::CTRL, false)),
            None
        );
        assert_eq!(
            mapped(key(egui::Key::F9, egui::Modifiers::ALT, false)),
            None
        );

        let context = scaled_context();
        let mut app = debuggable();
        frame(&context, &mut app, vec![]);
        // egui reports a held key's further presses as repeats.
        frame(&context, &mut app, vec![key(egui::Key::F9, none, false)]);
        frame(&context, &mut app, vec![key(egui::Key::F9, none, false)]);
        frame(&context, &mut app, vec![key(egui::Key::F9, none, false)]);
        assert_eq!(
            app.live.breakpoints.iter().copied().collect::<Vec<_>>(),
            if SUPPORTED { vec![0x1000] } else { vec![] },
            "held F9 toggles once"
        );
        frame(&context, &mut app, vec![release(egui::Key::F9)]);

        // Typing in the toolbar's Go field or the Go To dialog runs nothing.
        context.memory_mut(|memory| memory.request_focus(egui::Id::unique("toolbar-go-to")));
        frame(&context, &mut app, vec![]);
        assert!(context.egui_wants_keyboard_input());
        frame(&context, &mut app, vec![key(egui::Key::F5, none, false)]);
        frame(&context, &mut app, vec![release(egui::Key::F5)]);
        frame(&context, &mut app, vec![key(egui::Key::F9, none, false)]);
        frame(&context, &mut app, vec![release(egui::Key::F9)]);
        assert!(app.live.prompt.is_none() && app.live.session.is_none());
        assert_eq!(app.live.breakpoints.len(), usize::from(SUPPORTED));
        context.memory_mut(|memory| memory.surrender_focus(egui::Id::unique("toolbar-go-to")));
        app.begin_go_to();
        frame(&context, &mut app, vec![]);
        frame(&context, &mut app, vec![key(egui::Key::F5, none, false)]);
        frame(&context, &mut app, vec![release(egui::Key::F5)]);
        assert!(app.browser_dialog.is_some());
        assert!(app.live.prompt.is_none() && app.live.session.is_none());
        app.browser_dialog = None;
        frame(&context, &mut app, vec![]);
        frame(&context, &mut app, vec![key(egui::Key::F5, none, false)]);
        assert_eq!(
            app.live.prompt.is_some(),
            SUPPORTED,
            "F5 asks before running"
        );
    }

    #[test]
    fn debugging_is_available_only_for_directly_opened_x86_64_elf_executables() {
        let mut app = DesktopApp::empty(None);
        assert!(app.live_debuggable().is_err() && !app.live_gutter());
        let mut app_debuggable = debuggable();
        if !SUPPORTED {
            assert_eq!(
                app_debuggable.live_debuggable(),
                Err("Requires Linux x86-64")
            );
            return;
        }
        assert_eq!(app_debuggable.live_debuggable(), Ok(()));
        assert!(app_debuggable.live_gutter());
        app_debuggable.binary_path = None;
        assert_eq!(
            app_debuggable.live_debuggable(),
            Err("Open the executable directly")
        );
        for (format, architecture) in [("PE", "x86-64"), ("ELF", "AArch64"), ("Mach-O", "AArch64")]
        {
            app = debuggable();
            let info = app.info.as_mut().unwrap();
            info.format = format.into();
            info.architecture = architecture.into();
            assert_eq!(
                app.live_debuggable(),
                Err("Requires an x86-64 ELF executable")
            );
            assert!(!app.live_gutter());
        }
        app = debuggable();
        app.info.as_mut().unwrap().entry = 0x9000;
        assert_eq!(app.live_debuggable(), Err("No executable entry point"));
        // A reopen keeps the gutter, so columns do not jump.
        app = debuggable();
        app.opening = Some(super::super::Opening {
            path: "x".into(),
            preserve: true,
            follow: None,
            revision: 0,
            follow_origin: app.request_origin(),
        });
        assert_eq!(app.live_debuggable(), Err("Wait for the binary to open"));
        assert!(app.live_gutter());
        app.opening = None;
        // Neither a session nor its end changes the gutter.
        let wire = fake_session(&mut app, Phase::Running);
        assert!(app.live_gutter());
        wire.emit(Event::Ended { error: None });
        app.poll_live_debug(&egui::Context::default());
        assert!(app.live.session.is_none() && app.live_gutter());
    }

    #[test]
    fn breakpoints_toggle_only_on_decoded_instruction_starts() {
        if !SUPPORTED {
            return;
        }
        let mut app = debuggable();
        // Inside the 5-byte instruction, and outside any decoded listing.
        for address in [0x1002, 0x1080] {
            app.selected = Some(address);
            app.live_toggle_breakpoint();
            assert!(app.live.breakpoints.is_empty());
            assert_eq!(app.status, "Select an instruction");
        }
        app.selected = Some(0x1001);
        app.live_toggle_breakpoint();
        assert_eq!(
            app.live.breakpoints.iter().copied().collect::<Vec<_>>(),
            [0x1001]
        );
        assert_eq!(app.live.owners.get(&0x1001), Some(&0x1000));
        app.live_toggle_breakpoint();
        assert!(app.live.breakpoints.is_empty() && app.live.owners.is_empty());
        // Program scope uses the cursor row only, and has none here.
        app.set_listing_scope(super::super::program_listing::ListingScope::Program);
        app.selected = Some(0x1001);
        assert_eq!(app.breakpoint_target(), None);
        app.set_listing_scope(super::super::program_listing::ListingScope::Function);

        app.live.breakpoints = (0..MAX_BREAKPOINTS as u64).map(|i| 0x2000 + i).collect();
        let revision = app.live.breakpoint_revision;
        app.selected = Some(0x1006);
        app.live_toggle_breakpoint();
        assert_eq!(app.status, "Breakpoint limit reached");
        assert!(!app.live.breakpoints.contains(&0x1006));
        assert_eq!(app.live.breakpoint_revision, revision);
        // Removing still works at the limit.
        app.toggle_breakpoint_at(0x2000, 0x1000);
        assert_eq!(app.live.breakpoints.len(), MAX_BREAKPOINTS - 1);
    }

    #[test]
    fn breakpoint_edits_sync_to_the_session_and_stale_status_revisions_are_ignored() {
        if !SUPPORTED {
            return;
        }
        let context = egui::Context::default();
        let mut app = debuggable();
        let wire = fake_session(&mut app, Phase::Running);
        app.toggle_breakpoint_at(0x1000, 0x1000);
        app.toggle_breakpoint_at(0x1006, 0x1000);
        let sent = wire.sent();
        let revisions: Vec<_> = sent
            .iter()
            .map(|command| match command {
                Command::Breakpoints {
                    revision,
                    addresses,
                } => (*revision, addresses.len()),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(revisions, [(1, 1), (2, 2)]);
        // Unapplied while running: both show the pending ring.
        assert_eq!(
            app.live_marks(0x1000).0,
            Some(theme::BreakpointMark::Pending)
        );
        wire.emit(Event::Breakpoints {
            revision: 1,
            status: BTreeMap::from([(0x1000, BreakpointStatus::Set)]),
        });
        app.poll_live_debug(&context);
        assert!(app.live.breakpoint_status.is_empty(), "revision 1 is stale");
        wire.emit(Event::Breakpoints {
            revision: 2,
            status: BTreeMap::from([
                (0x1000, BreakpointStatus::Set),
                (0x1006, BreakpointStatus::Failed("Cannot insert".into())),
                (
                    0x1001,
                    BreakpointStatus::Failed("Could not remove: x".into()),
                ),
            ]),
        });
        app.poll_live_debug(&context);
        assert_eq!(app.live_marks(0x1000).0, Some(theme::BreakpointMark::Set));
        assert_eq!(
            app.live_marks(0x1006).0,
            Some(theme::BreakpointMark::Failed)
        );
        assert_eq!(app.live_hover(0x1006).as_deref(), Some("Cannot insert"));
        // An undesired address that is still armed keeps a failed mark.
        assert_eq!(
            app.live_marks(0x1001).0,
            Some(theme::BreakpointMark::Failed)
        );
        // Ending the session returns the marks to the plain desired set.
        wire.emit(Event::Ended { error: None });
        app.poll_live_debug(&context);
        assert_eq!(app.live_marks(0x1006).0, Some(theme::BreakpointMark::Set));
        assert_eq!(app.live_marks(0x1001).0, None);
    }

    #[test]
    fn a_stop_moves_the_selection_to_the_pc_without_recording_history() {
        if !SUPPORTED {
            return;
        }
        let context = egui::Context::default();
        // Mapping `return …;` covers 0x1004 and 0x1008; 0x1000 has none.
        let mut app = fixture::semantic_app();
        app.binary_path = Some("/nonexistent/ghidra-rust-live/fixture".into());
        let history = (app.history.clone(), app.history_index);
        let wire = fake_session(&mut app, Phase::Running);
        wire.emit(stopped(2, Some(0x1004), None));
        app.poll_live_debug(&context);
        assert_eq!(app.selected, Some(0x1004));
        assert_eq!((app.history.clone(), app.history_index), history);
        let mapping = app
            .semantic
            .mappings
            .iter()
            .filter(|mapping| mapping.addresses.contains(&0x1004))
            .map(|mapping| mapping.start..mapping.end)
            .collect::<Vec<_>>();
        assert!(!mapping.is_empty());
        assert_eq!(app.semantic.ranges, mapping);
        assert_eq!(app.live_marks(0x1004), (None, true));
        assert_eq!(
            app.live.token().map(|(text, _, fault)| (text, fault)),
            Some(("Stopped @ 1004".into(), false))
        );
        // A step to an instruction with no engine mapping highlights nothing.
        app.live_step();
        assert_eq!(wire.sent(), [Command::Step(StepKind::Instruction)]);
        assert_eq!(app.live.phase(), Some(Phase::Stepping));
        assert_eq!(app.live.pc(), None, "no PC while the step runs");
        wire.emit(Event::Running);
        wire.emit(stopped(3, Some(0x1000), Some("SIGSEGV")));
        app.poll_live_debug(&context);
        assert_eq!(app.selected, Some(0x1000));
        assert!(app.semantic.ranges.is_empty());
        assert_eq!(
            app.live.token().map(|(text, _, fault)| (text, fault)),
            Some(("SIGSEGV @ 1000".into(), true))
        );
        assert_eq!((app.history.clone(), app.history_index), history);
        // Go to PC is the one that records history.
        app.selected = Some(0x1008);
        app.live_go_to_pc(&context);
        assert_eq!(app.selected, Some(0x1000));
        assert_ne!((app.history.clone(), app.history_index), history);
    }

    #[test]
    fn only_the_last_stop_of_a_drained_batch_is_followed() {
        if !SUPPORTED {
            return;
        }
        let context = egui::Context::default();
        let mut app = fixture::semantic_app();
        app.binary_path = Some("/nonexistent/ghidra-rust-live/fixture".into());
        let wire = fake_session(&mut app, Phase::Running);
        wire.emit(stopped(2, Some(0x1004), None));
        wire.emit(Event::Running);
        wire.emit(stopped(3, Some(0x1008), None));
        app.poll_live_debug(&context);
        assert_eq!(app.selected, Some(0x1008));
        assert_eq!(app.live.stop.as_ref().unwrap().stop_seq, 3);
        // A stop already superseded by Running is not followed.
        app.live.session.as_mut().unwrap().phase = Phase::Stepping;
        wire.emit(stopped(4, Some(0x1004), None));
        wire.emit(Event::Running);
        app.poll_live_debug(&context);
        assert_eq!(app.selected, Some(0x1008));
        assert_eq!(app.live.phase(), Some(Phase::Running));
        assert_eq!(app.live.pc(), None);
    }

    #[test]
    fn stops_outside_the_image_leave_the_selection_alone() {
        if !SUPPORTED {
            return;
        }
        let context = egui::Context::default();
        let mut app = debuggable();
        app.selected = Some(0x1001);
        let wire = fake_session(&mut app, Phase::Running);
        // In the loader: no static address.
        wire.emit(stopped(2, None, Some("SIGINT")));
        app.poll_live_debug(&context);
        assert_eq!(app.selected, Some(0x1001));
        assert_eq!(app.live.phase(), Some(Phase::Stopped));
        assert_eq!(
            app.live.token().map(|(text, _, _)| text),
            Some("Stopped 0x7ffff7fd0100".into())
        );
        // Image code no known function decoded is never given a guessed owner.
        app.live_run(&context);
        wire.emit(Event::Running);
        wire.emit(stopped(3, Some(0x1080), None));
        app.poll_live_debug(&context);
        assert_eq!(app.selected, Some(0x1001));
        assert_eq!(app.view().map(|view| view.address), Some(0x1000));
        assert!(app.queue.is_empty() && app.pending.is_none());
        // A breakpoint's decoded listing is evidence of its owner.
        app.live.owners.insert(0x1006, 0x1000);
        app.live_run(&context);
        wire.emit(Event::Running);
        wire.emit(stopped(4, Some(0x1006), None));
        app.poll_live_debug(&context);
        assert_eq!(app.selected, Some(0x1006));
    }

    #[test]
    fn run_control_follows_the_session_phase_and_sends_one_command_at_a_time() {
        if !SUPPORTED {
            return;
        }
        let context = egui::Context::default();
        let mut app = debuggable();
        let wire = fake_session(&mut app, Phase::Launching { run: true });
        // A run launch's loader stop is not a stop to act on.
        wire.emit(stopped(1, None, None));
        app.poll_live_debug(&context);
        assert_eq!(app.live.phase(), Some(Phase::Launching { run: true }));
        app.live_run(&context);
        app.live_step();
        app.live_pause();
        assert!(wire.sent().is_empty());
        wire.emit(Event::Running);
        app.poll_live_debug(&context);
        app.live_pause();
        app.live_pause();
        assert_eq!(wire.sent(), [Command::Pause]);
        assert_eq!(app.live.phase(), Some(Phase::Pausing));
        wire.emit(stopped(2, None, Some("SIGINT")));
        app.poll_live_debug(&context);
        app.live_run(&context);
        app.live_run(&context);
        assert_eq!(wire.sent(), [Command::Resume]);
        // A refused resume returns to the stop.
        wire.emit(Event::Refused {
            message: "nope".into(),
        });
        app.poll_live_debug(&context);
        assert_eq!(app.live.phase(), Some(Phase::Stopped));
        assert_eq!(app.status, "nope");
        app.live_stop();
        app.live_stop();
        assert_eq!(wire.sent(), [Command::Stop]);
        wire.emit(Event::Exited {
            code: Some(19),
            signal: None,
        });
        wire.emit(Event::Ended { error: None });
        app.poll_live_debug(&context);
        assert!(app.live.session.is_none() && app.live.stop.is_none());
        assert_eq!(app.status, "Exited 19");
        assert_eq!(
            app.live.token().map(|(text, _, _)| text),
            Some("Exited 19".into())
        );
        // A session that ended with an error reports it.
        let wire = fake_session(&mut app, Phase::Launching { run: false });
        assert_eq!(
            app.live.token().map(|(text, _, _)| text),
            Some("Launching".into())
        );
        wire.emit(Event::Ended {
            error: Some("GDB is required at /usr/bin/gdb".into()),
        });
        app.poll_live_debug(&context);
        assert_eq!(app.status, "GDB is required at /usr/bin/gdb");
        assert_eq!(app.live.token(), None);
    }

    #[test]
    fn closing_or_opening_a_binary_ends_the_session_and_clears_breakpoints() {
        if !SUPPORTED {
            return;
        }
        let context = egui::Context::default();
        let mut app = debuggable();
        app.toggle_breakpoint_at(0x1000, 0x1000);
        let sha = app.info.as_ref().unwrap().sha256.clone();
        let wire = fake_session(&mut app, Phase::Stopped);
        wire.emit(stopped(2, Some(0x1000), None));
        app.poll_live_debug(&context);
        // A preserving reopen of the same contents keeps everything.
        app.live.bind(app.generation, &sha);
        assert!(app.live.session.is_some() && app.live.breakpoints.contains(&0x1000));
        // Different contents end the session.
        app.live.bind(app.generation, &"b".repeat(64));
        assert!(app.live.session.is_none() && app.live.breakpoints.is_empty());
        assert!(
            wire.commands.recv().is_err(),
            "the port was dropped, which ends the session thread"
        );

        // A fresh open is a new generation: the next poll drops the session
        // without reading its events.
        app.toggle_breakpoint_at(0x1000, 0x1000);
        let wire = fake_session(&mut app, Phase::Running);
        wire.emit(stopped(2, Some(0x1006), None));
        app.generation += 1;
        app.poll_live_debug(&context);
        assert!(app.live.session.is_none() && app.live.breakpoints.is_empty());
        assert_eq!(app.selected, Some(0x1000));
        assert_eq!(app.live.generation, app.generation);

        // Close.
        let wire = fake_session(&mut app, Phase::Stopped);
        app.live.trusted = Some((app.generation, sha.clone()));
        app.clear_binary();
        assert!(app.live.session.is_none() && app.live.trusted.is_none());
        assert!(wire.commands.recv().is_err());
        assert_eq!(app.live.token(), None);
        assert!(app.live_debuggable().is_err());
    }

    #[test]
    fn launch_prompt_is_required_once_per_generation_and_discarded_on_change() {
        if !SUPPORTED {
            return;
        }
        let context = scaled_context();
        let mut app = debuggable();
        frame(&context, &mut app, vec![]);
        app.live_start(true, &context);
        assert_eq!(
            app.live.prompt,
            Some(LaunchPrompt {
                generation: app.generation,
                run: true
            })
        );
        // A modal paints from its second frame, after sizing.
        frame(&context, &mut app, vec![]);
        let output = frame(&context, &mut app, vec![]);
        let text = fixture::rendered_text(&output);
        assert!(text.iter().any(|t| t == "Run program"), "{text:?}");
        assert!(text.iter().any(|t| t == "fixture"));
        // Other shortcuts stay inert behind it, and Enter does not confirm.
        frame(
            &context,
            &mut app,
            vec![
                key(egui::Key::F9, egui::Modifiers::NONE, false),
                key(egui::Key::Enter, egui::Modifiers::NONE, false),
            ],
        );
        frame(
            &context,
            &mut app,
            vec![release(egui::Key::F9), release(egui::Key::Enter)],
        );
        assert!(app.live.prompt.is_some() && app.live.session.is_none());
        assert!(app.live.breakpoints.is_empty());
        // Escape cancels.
        frame(
            &context,
            &mut app,
            vec![key(egui::Key::Escape, egui::Modifiers::NONE, false)],
        );
        assert!(app.live.prompt.is_none() && app.live.trusted.is_none());
        // A prompt of an earlier generation is discarded unshown.
        app.live_start(true, &context);
        app.generation += 1;
        app.live.end(app.generation);
        app.live.prompt = Some(LaunchPrompt {
            generation: app.generation - 1,
            run: true,
        });
        let output = frame(&context, &mut app, vec![]);
        assert!(app.live.prompt.is_none());
        assert!(
            !fixture::rendered_text(&output)
                .iter()
                .any(|t| t == "Run program")
        );

        // Run trusts this generation and launches. The path does not exist,
        // so the session ends before GDB starts.
        app.live_start(true, &context);
        frame(&context, &mut app, vec![]);
        let output = frame(&context, &mut app, vec![]);
        // The button, not the "Run program" heading.
        let run = output
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::Shape::Text(text) if text.galley.text() == "Run" => {
                    Some(text.galley.rect.translate(text.pos.to_vec2()).center())
                }
                _ => None,
            })
            .expect("Run button");
        frame(&context, &mut app, fixture::pointer_events(run));
        assert!(app.live.prompt.is_none());
        let sha = app.info.as_ref().unwrap().sha256.clone();
        assert_eq!(app.live.trusted, Some((app.generation, sha)));
        assert!(app.live.session.is_some());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while app.live.session.is_some() {
            assert!(std::time::Instant::now() < deadline);
            app.poll_live_debug(&context);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_ne!(
            app.status, "Debug session ended",
            "the launch error is shown"
        );
        // No second prompt for the same generation.
        app.live_start(false, &context);
        assert!(app.live.prompt.is_none() && app.live.session.is_some());
        app.live.end(app.generation);
        // A new generation asks again.
        app.generation += 1;
        app.live.bind(app.generation, &"a".repeat(64));
        app.live_start(true, &context);
        assert!(app.live.prompt.is_some());
    }

    #[test]
    fn debug_menu_toolbar_and_gutter_marks_render_at_fractional_scale() {
        let context = scaled_context();
        let mut app = DesktopApp::empty(None);
        let output = frame(&context, &mut app, vec![]);
        assert_eq!(
            fixture::rendered_text(&output).iter().any(|t| t == "Debug"),
            SUPPORTED
        );
        let mut app = debuggable();
        app.toggle_breakpoint_at(0x1001, 0x1000);
        let wire = fake_session(&mut app, Phase::Running);
        wire.emit(stopped(2, Some(0x1006), None));
        let output = frame(&context, &mut app, vec![]);
        if !SUPPORTED {
            return;
        }
        let circles: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Circle(circle) => Some(circle.center),
                _ => None,
            })
            .collect();
        let address = |needle: &str| {
            output.shapes.iter().find_map(|shape| match &shape.shape {
                egui::Shape::Text(text) if text.galley.text() == needle => {
                    Some(text.pos + text.galley.rect.min.to_vec2())
                }
                _ => None,
            })
        };
        let row = address("00001001").expect("listing row");
        // The pending ring sits in the gutter, left of the address cell.
        assert!(
            circles
                .iter()
                .any(|c| (c.y - (row.y + 6.0)).abs() < 12.0 && c.x < row.x),
            "{circles:?} {row:?}"
        );
        // The PC arrow is painted on the stopped row.
        let pc = address("00001006").expect("pc row");
        assert!(output.shapes.iter().any(|shape| matches!(
            &shape.shape,
            egui::Shape::Path(path) if path.fill == theme::EDGE_TRUE
                && path.points.iter().all(|p| p.x < pc.x && (p.y - pc.y).abs() < 20.0)
        )));
        assert!(
            fixture::rendered_text(&output)
                .iter()
                .any(|t| t == "Stopped @ 1006")
        );
    }

    fn opening(app: &DesktopApp, preserve: bool) -> super::super::Opening {
        super::super::Opening {
            path: "/nonexistent/ghidra-rust-live/other".into(),
            preserve,
            follow: None,
            revision: app.revision,
            follow_origin: app.request_origin(),
        }
    }

    #[test]
    fn a_stop_during_an_open_neither_moves_the_selection_nor_becomes_its_follow_up() {
        if !SUPPORTED {
            return;
        }
        let context = egui::Context::default();
        for preserve in [false, true] {
            let mut app = debuggable();
            app.selected = Some(0x1001);
            // Only the breakpoint's listing knows 0x1080's owner, which is
            // not the displayed function: following would request its graph.
            app.live.owners.insert(0x1080, 0x1060);
            let wire = fake_session(&mut app, Phase::Running);
            app.opening = Some(opening(&app, preserve));
            wire.emit(stopped(2, Some(0x1080), None));
            app.poll_live_debug(&context);
            assert_eq!(app.live.pc(), Some(0x1080), "the stop itself is adopted");
            let open = app.opening.as_ref().unwrap();
            assert!(open.follow.is_none(), "preserve={preserve}");
            assert_eq!(app.selected, Some(0x1001));
            assert!(app.queue.is_empty() && app.pending.is_none());
        }
    }

    #[test]
    fn a_stop_keeps_an_unsaved_annotation_draft() {
        if !SUPPORTED {
            return;
        }
        let context = egui::Context::default();
        let mut app = debuggable();
        app.selected = Some(0x1001);
        app.annotations_open = true;
        app.editor_address = Some(0x1001);
        app.name_edit = "entry".into();
        app.comment_edit = "half-typed".into();
        let wire = fake_session(&mut app, Phase::Running);
        wire.emit(stopped(2, Some(0x1006), None));
        app.poll_live_debug(&context);
        assert_eq!(app.selected, Some(0x1001));
        assert_eq!(app.comment_edit, "half-typed");
        assert_eq!(app.live_marks(0x1006), (None, true));
        // Without a draft the next stop follows.
        app.comment_edit.clear();
        app.live_run(&context);
        wire.emit(Event::Running);
        wire.emit(stopped(3, Some(0x1006), None));
        app.poll_live_debug(&context);
        assert_eq!(app.selected, Some(0x1006));
    }

    #[test]
    fn a_breakpoint_removed_while_running_stays_marked_until_the_removal_applies() {
        if !SUPPORTED {
            return;
        }
        let context = egui::Context::default();
        let mut app = debuggable();
        app.toggle_breakpoint_at(0x1000, 0x1000);
        let wire = fake_session(&mut app, Phase::Running);
        wire.emit(Event::Breakpoints {
            revision: app.live.breakpoint_revision,
            status: BTreeMap::from([(0x1000, BreakpointStatus::Set)]),
        });
        app.poll_live_debug(&context);
        app.toggle_breakpoint_at(0x1000, 0x1000);
        assert_eq!(
            app.live_marks(0x1000).0,
            Some(theme::BreakpointMark::Pending)
        );
        wire.emit(Event::Breakpoints {
            revision: app.live.breakpoint_revision,
            status: BTreeMap::new(),
        });
        app.poll_live_debug(&context);
        assert_eq!(app.live_marks(0x1000).0, None);
    }

    #[test]
    fn pause_and_stop_keys_work_while_a_binary_reopens() {
        if !SUPPORTED {
            return;
        }
        let context = scaled_context();
        let none = egui::Modifiers::NONE;
        let mut app = debuggable();
        let wire = fake_session(&mut app, Phase::Running);
        app.opening = Some(opening(&app, true));
        frame(&context, &mut app, vec![]);
        for event in [
            key(egui::Key::F9, none, false),
            release(egui::Key::F9),
            key(egui::Key::G, none, false),
            release(egui::Key::G),
        ] {
            frame(&context, &mut app, vec![event]);
        }
        assert!(app.live.breakpoints.is_empty() && app.browser_dialog.is_none());
        frame(&context, &mut app, vec![key(egui::Key::F6, none, false)]);
        assert_eq!(wire.sent(), [Command::Pause]);
        frame(&context, &mut app, vec![release(egui::Key::F6)]);
        frame(
            &context,
            &mut app,
            vec![key(egui::Key::F5, egui::Modifiers::SHIFT, false)],
        );
        assert_eq!(wire.sent(), [Command::Stop]);
        // Without a session the reopen still blocks every key.
        let mut app = debuggable();
        app.opening = Some(opening(&app, true));
        frame(&context, &mut app, vec![key(egui::Key::F5, none, false)]);
        assert!(app.live.prompt.is_none());
    }

    #[test]
    fn ending_a_session_with_its_binary_says_so_and_a_moot_pause_is_not_an_error() {
        if !SUPPORTED {
            return;
        }
        let context = egui::Context::default();
        let mut app = debuggable();
        let wire = fake_session(&mut app, Phase::Running);
        app.status = "Ready".into();
        app.live_pause();
        // The target stopped at a breakpoint before the pause reached it.
        wire.emit(stopped(2, Some(0x1006), None));
        wire.emit(Event::Refused {
            message: "The target is not running".into(),
        });
        app.poll_live_debug(&context);
        assert_eq!(app.live.phase(), Some(Phase::Stopped));
        assert_eq!(app.status, "Ready");
        app.clear_binary();
        assert_eq!(app.status, "Binary closed · Debug session ended");
        app.clear_binary();
        assert_eq!(app.status, "Binary closed");
    }

    /// Real GDB: a listing breakpoint stops the fixture and selects the PC.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn desktop_session_stops_at_a_listing_breakpoint_and_follows_the_pc() {
        use super::super::{Opening, test_worker};
        use crate::client::WorkerClient;
        use crate::model::Request;
        use std::time::Instant;
        if !std::path::Path::new(crate::debugger::GDB_PATH).exists() {
            eprintln!("skipping: {} is not installed", crate::debugger::GDB_PATH);
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("fixture");
        assert!(
            std::process::Command::new("cc")
                .args([
                    "-O0",
                    "-g",
                    "-fPIE",
                    "-pie",
                    "tests/fixtures/debugger.c",
                    "-o"
                ])
                .arg(&binary)
                .status()
                .unwrap()
                .success()
        );
        let executable = test_worker().unwrap_or_else(|error| panic!("{error}"));
        let context = egui::Context::default();
        let mut app = DesktopApp::empty(None);
        app.program.scope = super::super::program_listing::ListingScope::Function;
        let client =
            WorkerClient::start_using_executable(context.clone(), &binary, &executable).unwrap();
        app.client = Some(client);
        app.worker_epoch += 1;
        app.opening = Some(Opening {
            path: binary.clone(),
            preserve: false,
            follow: None,
            revision: app.revision,
            follow_origin: app.request_origin(),
        });
        app.send_direct(Request::Open {
            debug: Default::default(),
            path: binary.to_string_lossy().into_owned(),
        });
        let settle = |app: &mut DesktopApp, step: &str, done: &dyn Fn(&DesktopApp) -> bool| {
            let deadline = Instant::now() + Duration::from_secs(60);
            while !done(app) {
                assert!(
                    Instant::now() < deadline,
                    "{step} did not settle: {} view={:?} pending={} phase={:?}",
                    app.status,
                    app.view().map(|view| view.address),
                    app.pending.is_some(),
                    app.live.phase()
                );
                app.poll_graph_preparation(&context);
                app.poll_worker(&context);
                app.poll_live_debug(&context);
                std::thread::sleep(Duration::from_millis(2));
            }
        };
        settle(&mut app, "open", &|app| {
            app.info.is_some() && app.opening.is_none()
        });
        app.analyze_prompt = None;
        let point = app
            .info
            .as_ref()
            .unwrap()
            .functions
            .iter()
            .find(|function| function.name == "debug_point")
            .expect("debug_point symbol")
            .address;
        app.navigate(point, true, &context);
        settle(&mut app, "navigate", &|app| {
            app.view().is_some_and(|view| view.address == point)
        });
        app.selected = Some(point);
        // Press and release, so the next press is not a held-key repeat.
        let keys = |app: &mut DesktopApp, event: egui::Event| {
            let egui::Event::Key { key, .. } = event else {
                unreachable!()
            };
            let mut output = context.run_ui(
                egui::RawInput {
                    events: vec![event, release(key)],
                    ..Default::default()
                },
                |ui| app.handle_shortcuts(ui.ctx()),
            );
            output.textures_delta.clear();
        };
        keys(&mut app, key(egui::Key::F9, egui::Modifiers::NONE, false));
        assert!(app.live.breakpoints.contains(&point), "{}", app.status);
        // Away from the breakpoint, so the stop must move the selection.
        app.selected = app.listing().get(1).map(|instruction| instruction.address);
        let history = app.history.len();
        app.live.trusted = Some((app.generation, app.info.as_ref().unwrap().sha256.clone()));
        keys(&mut app, key(egui::Key::F5, egui::Modifiers::NONE, false));
        assert!(app.live.session.is_some(), "{}", app.status);
        settle(&mut app, "stop", &|app| {
            app.live.phase() == Some(Phase::Stopped) || app.live.session.is_none()
        });
        assert_eq!(app.live.phase(), Some(Phase::Stopped), "{}", app.status);
        assert_eq!(app.live.pc(), Some(point));
        assert_eq!(app.selected, Some(point));
        assert_eq!(app.history.len(), history);
        assert_eq!(
            app.live.breakpoint_status.get(&point),
            Some(&BreakpointStatus::Set)
        );
        let snapshot = app.live.stop.as_deref().unwrap();
        let registers = snapshot.registers.as_ref().unwrap();
        let register = |name: &str| {
            registers
                .iter()
                .find(|register| register.name == name)
                .unwrap()
                .value
        };
        assert_eq!(register("rip"), snapshot.stop.location.runtime);
        let pid = register("rdi");
        let process = std::path::PathBuf::from(format!("/proc/{pid}"));
        assert!(process.exists());
        keys(&mut app, key(egui::Key::F5, egui::Modifiers::SHIFT, false));
        settle(&mut app, "end", &|app| app.live.session.is_none());
        assert!(
            !process.exists()
                || std::fs::read_to_string(process.join("status"))
                    .is_ok_and(|status| status.contains("State:\tZ")),
            "the target is gone"
        );
        assert_eq!(app.live.token(), None);
    }
}
