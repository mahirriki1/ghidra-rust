//! Native decoder controls. Work is bounded and runs away from the render thread;
//! edits invalidate both result generations and any manually changed provenance.

use std::sync::mpsc::{self, Receiver, TryRecvError};

use eframe::egui::{self, RichText, ScrollArea, TextEdit};

use crate::decode::{self, Candidate, MAX_INPUT, Operation};
use crate::session::DecodedAnnotation;

const PREVIEW_CHARACTERS: usize = 8192;

pub enum DecoderAction {
    Read { address: u64, length: usize },
    Annotate { annotation: DecodedAnnotation },
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum InputMode {
    Text,
    #[default]
    Hex,
}

struct Source {
    address: u64,
    bytes: Vec<u8>,
}

struct Decoded {
    bytes: Vec<u8>,
    operation: String,
    parameters: String,
    /// Display preview, computed once rather than on every frame.
    preview: std::cell::OnceCell<(String, &'static str)>,
}

enum JobResult {
    Decoded(Decoded),
    Candidates(Vec<Candidate>),
}

struct Pending {
    generation: u64,
    receiver: Receiver<Result<JobResult, String>>,
}

pub struct DecoderPanel {
    address: String,
    length: usize,
    mode: InputMode,
    input: String,
    operation: Operation,
    key: String,
    source: Option<Source>,
    generation: u64,
    pending: Option<Pending>,
    output: Option<Decoded>,
    candidates: Vec<Candidate>,
    error: Option<String>,
}

impl Default for DecoderPanel {
    fn default() -> Self {
        Self {
            address: "0".into(),
            length: 128,
            mode: InputMode::Hex,
            input: String::new(),
            operation: Operation::Utf8,
            key: "hex:2a".into(),
            source: None,
            generation: 0,
            pending: None,
            output: None,
            candidates: Vec::new(),
            error: None,
        }
    }
}

impl DecoderPanel {
    /// Associate only actual loaded bytes with an address. Pasted text cannot
    /// manufacture source provenance, even if an address field has been entered.
    pub fn set_source(&mut self, address: u64, bytes: Vec<u8>) {
        self.invalidate(false);
        self.source = None;
        if bytes.len() > MAX_INPUT {
            self.error = Some("Source exceeds 64 KiB; select a smaller range".into());
            return;
        }
        if address.checked_add(bytes.len() as u64).is_none() {
            self.error = Some("Source range overflows the address space".into());
            return;
        }
        self.address = format!("{address:x}");
        self.length = bytes.len().max(1);
        self.mode = InputMode::Hex;
        self.input = hex_bytes(&bytes);
        self.source = Some(Source { address, bytes });
    }

    pub fn show(&mut self, ui: &mut egui::Ui) -> Option<DecoderAction> {
        self.poll();
        let mut action = None;
        ui.horizontal_wrapped(|ui| {
            ui.label("Address");
            ui.add(
                TextEdit::singleline(&mut self.address)
                    .desired_width(150.0)
                    .char_limit(18),
            );
            ui.label("Bytes");
            ui.add(egui::DragValue::new(&mut self.length).range(1..=MAX_INPUT));
            if ui.button("Read bytes").clicked() {
                match self.read_request() {
                    Ok(request) => {
                        // A pending read must not leave an old result annotatable.
                        self.invalidate(true);
                        action = Some(request);
                    }
                    Err(error) => self.error = Some(error),
                }
            }
        });
        let mut input_changed = false;
        ui.horizontal(|ui| {
            ui.label("Input bytes");
            input_changed |= ui
                .selectable_value(&mut self.mode, InputMode::Text, "Text (UTF-8 bytes)")
                .changed();
            input_changed |= ui
                .selectable_value(&mut self.mode, InputMode::Hex, "Hex bytes")
                .changed();
            if let Some(source) = &self.source {
                ui.label(format!(
                    "Source: {:#x}, {} bytes",
                    source.address,
                    source.bytes.len()
                ));
            } else {
                ui.weak("Pasted input")
                    .on_hover_text("Read memory to attach decoded annotations to an address.");
            }
        });
        let max_characters = match self.mode {
            InputMode::Text => MAX_INPUT,
            InputMode::Hex => MAX_INPUT * 3,
        };
        ScrollArea::vertical()
            .id_salt("decoder-input")
            .max_height(140.0)
            .show(ui, |ui| {
                input_changed |= ui
                    .add(
                        TextEdit::multiline(&mut self.input)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(4)
                            .char_limit(max_characters),
                    )
                    .changed();
            });
        if input_changed {
            self.invalidate(true);
        }
        let mut parameters_changed = false;
        ui.horizontal_wrapped(|ui| {
            ui.label("Operation")
                .on_hover_text("Hex/Base64 decode encoded text; input mode supplies raw bytes.");
            egui::ComboBox::from_id_salt("decoder-operation")
                .selected_text(operation_name(self.operation))
                .show_ui(ui, |ui| {
                    for operation in [
                        Operation::Utf8,
                        Operation::Utf16Le,
                        Operation::Utf16Be,
                        Operation::Hex,
                        Operation::Base64,
                        Operation::Xor,
                    ] {
                        parameters_changed |= ui
                            .selectable_value(
                                &mut self.operation,
                                operation,
                                operation_name(operation),
                            )
                            .changed();
                    }
                });
            if self.operation == Operation::Xor {
                ui.label("Key");
                parameters_changed |= ui
                    .add(
                        TextEdit::singleline(&mut self.key)
                            .desired_width(200.0)
                            .char_limit(MAX_INPUT),
                    )
                    .on_hover_text("hex:4142 or text:AB")
                    .changed();
            }
        });
        if parameters_changed {
            self.invalidate(false);
        }
        ui.horizontal(|ui| {
            let ready = self.pending.is_none();
            if ui
                .add_enabled(ready, egui::Button::new("Decode"))
                .on_hover_text("Decoding never modifies the source bytes")
                .clicked()
            {
                self.start_job(false, ui.ctx());
            }
            if ui
                .add_enabled(ready, egui::Button::new("Try common decodings"))
                .clicked()
            {
                self.start_job(true, ui.ctx());
            }
            if !ready {
                ui.spinner();
                ui.label("Working…");
            }
        });
        if let Some(error) = &self.error {
            ui.colored_label(crate::theme::ERROR, error);
        }
        if !self.candidates.is_empty() {
            ui.separator();
            ui.colored_label(crate::theme::WARNING, "Unverified suggestions")
                .on_hover_text("Readable output may still be incorrect.");
            let mut selected = None;
            for (index, candidate) in self.candidates.iter().enumerate() {
                if ui.button(&candidate.label).clicked() {
                    selected = Some(index);
                }
            }
            if let Some(index) = selected {
                let candidate = &self.candidates[index];
                self.output = Some(Decoded {
                    bytes: candidate.bytes.clone(),
                    operation: candidate.label.clone(),
                    parameters: format!(
                        "selected suggestion: {}; result unverified",
                        candidate.label
                    ),
                    preview: Default::default(),
                });
            }
        }
        if let Some(output) = &self.output {
            ui.separator();
            ui.label(RichText::new(&output.operation).strong());
            let (preview, encoding) = output
                .preview
                .get_or_init(|| output_preview(&output.bytes, PREVIEW_CHARACTERS));
            ui.weak(format!("{} output bytes · {encoding}", output.bytes.len()));
            ScrollArea::vertical()
                .id_salt("decoder-output")
                .max_height(230.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(preview.as_str()).monospace())
                            .selectable(true)
                            .wrap(),
                    );
                });
            let mut save_annotation = false;
            ui.horizontal(|ui| {
                if ui.button("Copy full output").clicked() {
                    ui.ctx().copy_text(output_text(&output.bytes).0);
                }
                if ui
                    .add_enabled(
                        self.source.is_some(),
                        egui::Button::new("Save decoded annotation"),
                    )
                    .clicked()
                {
                    save_annotation = true;
                }
            });
            if save_annotation {
                match self.annotation() {
                    Ok(annotation) => action = Some(DecoderAction::Annotate { annotation }),
                    Err(error) => self.error = Some(error),
                }
            }
        }
        action
    }

    fn read_request(&self) -> Result<DecoderAction, String> {
        let address = self.address.trim();
        let address = u64::from_str_radix(
            address
                .strip_prefix("0x")
                .or_else(|| address.strip_prefix("0X"))
                .unwrap_or(address),
            16,
        )
        .map_err(|_| "Enter a valid hexadecimal memory address".to_owned())?;
        if self.length == 0 || self.length > MAX_INPUT {
            return Err("Read length must be between 1 byte and 64 KiB".into());
        }
        address
            .checked_add(self.length as u64)
            .ok_or("Requested range overflows the address space")?;
        Ok(DecoderAction::Read {
            address,
            length: self.length,
        })
    }

    fn invalidate(&mut self, clear_source: bool) {
        self.generation = self.generation.wrapping_add(1);
        self.output = None;
        self.candidates.clear();
        self.error = None;
        if clear_source {
            self.source = None;
        }
    }

    fn input_bytes(&self) -> Result<Vec<u8>, String> {
        match self.mode {
            InputMode::Text => {
                if self.input.len() > MAX_INPUT {
                    return Err("UTF-8 input exceeds 64 KiB; select fewer bytes".into());
                }
                Ok(self.input.as_bytes().to_vec())
            }
            InputMode::Hex => {
                if self.input.len() > MAX_INPUT * 3 {
                    return Err("Hex input exceeds the 64 KiB byte-selection limit".into());
                }
                let compact: Vec<u8> = self
                    .input
                    .bytes()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .collect();
                if compact.len() > MAX_INPUT * 2 {
                    return Err("Hex input represents more than 64 KiB".into());
                }
                // Each even-sized chunk remains inside the core parser's textual
                // input bound, while a full 64 KiB memory selection still works.
                let mut bytes = Vec::with_capacity(compact.len() / 2);
                for chunk in compact.chunks(MAX_INPUT) {
                    let text = std::str::from_utf8(chunk)
                        .map_err(|_| "Hex input must contain ASCII digits")?;
                    bytes.extend(decode::parse_hex(text)?);
                }
                Ok(bytes)
            }
        }
    }

    fn start_job(&mut self, suggestions: bool, context: &egui::Context) {
        if self.pending.is_some() {
            return;
        }
        let input = match self.input_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        let key = if !suggestions && self.operation == Operation::Xor {
            match decode::parse_key(&self.key) {
                Ok(key) => key,
                Err(error) => {
                    self.error = Some(error);
                    return;
                }
            }
        } else {
            Vec::new()
        };
        self.invalidate(false);
        let operation = self.operation;
        let parameters = if operation == Operation::Xor {
            format!("key={}", self.key)
        } else {
            "explicit byte order; strict validation".into()
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        let context = context.clone();
        match std::thread::Builder::new()
            .name("string-decoder".into())
            .spawn(move || {
                let result = if suggestions {
                    Ok(JobResult::Candidates(decode::common_candidates(&input)))
                } else {
                    decode::decode(&input, operation, &key).map(|bytes| {
                        JobResult::Decoded(Decoded {
                            bytes,
                            operation: operation_name(operation).into(),
                            parameters,
                            preview: Default::default(),
                        })
                    })
                };
                let _ = sender.send(result);
                context.request_repaint();
            }) {
            Ok(_) => {
                self.pending = Some(Pending {
                    generation: self.generation,
                    receiver,
                })
            }
            Err(error) => self.error = Some(format!("Cannot start decoder: {error}")),
        }
    }

    fn poll(&mut self) {
        let Some(pending) = &self.pending else {
            return;
        };
        let generation = pending.generation;
        let result = match pending.receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                Err("Decoder task stopped before returning a result".into())
            }
        };
        self.pending = None;
        self.accept_result(generation, result);
    }

    fn accept_result(&mut self, generation: u64, result: Result<JobResult, String>) {
        if generation != self.generation {
            return;
        }
        match result {
            Ok(JobResult::Decoded(output)) => self.output = Some(output),
            Ok(JobResult::Candidates(candidates)) => {
                if candidates.is_empty() {
                    self.error = Some("No common decoding suggestions found".into());
                }
                self.candidates = candidates;
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn annotation(&self) -> Result<DecodedAnnotation, String> {
        let source = self
            .source
            .as_ref()
            .ok_or("Read bytes from the binary before annotating")?;
        let output = self
            .output
            .as_ref()
            .ok_or("Decode bytes before annotating")?;
        if self.input_bytes()? != source.bytes {
            return Err("Input no longer matches the loaded source bytes; read them again".into());
        }
        let (text, encoding) = output_text(&output.bytes);
        Ok(DecodedAnnotation {
            operation: output.operation.clone(),
            source_address: source.address,
            source_length: source.bytes.len(),
            parameters: format!("{}; output={encoding}", output.parameters),
            text,
        })
    }
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Utf8 => "UTF-8",
        Operation::Utf16Le => "UTF-16 little-endian",
        Operation::Utf16Be => "UTF-16 big-endian",
        Operation::Hex => "Hex decode",
        Operation::Base64 => "Base64 decode",
        Operation::Xor => "Repeating-key XOR",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            text.push(' ');
        }
        let _ = write!(&mut text, "{byte:02x}");
    }
    text
}

fn output_text(bytes: &[u8]) -> (String, &'static str) {
    if let Some(text) = decode::text_preview(bytes) {
        (text, "UTF-8")
    } else {
        (hex_bytes(bytes), "hex bytes (invalid UTF-8)")
    }
}

fn output_preview(bytes: &[u8], limit: usize) -> (String, &'static str) {
    let (mut preview, encoding, truncated) = if let Ok(text) = std::str::from_utf8(bytes) {
        (
            text.chars().take(limit).collect::<String>(),
            "UTF-8",
            text.chars().nth(limit).is_some(),
        )
    } else {
        let displayed = bytes.len().min(limit / 3);
        (
            hex_bytes(&bytes[..displayed]),
            "hex bytes (invalid UTF-8)",
            displayed < bytes.len(),
        )
    };
    if truncated {
        preview.push_str(
            "\n… Preview truncated; Copy full output preserves all bytes as text or hex.",
        );
    }
    (preview, encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(bytes: &[u8]) -> Result<JobResult, String> {
        Ok(JobResult::Decoded(Decoded {
            bytes: bytes.to_vec(),
            operation: "Base64 decode".into(),
            parameters: "strict validation".into(),
            preview: Default::default(),
        }))
    }

    #[test]
    fn stale_jobs_cannot_attach_results_to_a_different_source() {
        let mut panel = DecoderPanel::default();
        panel.set_source(0x1000, b"SGVsbG8=".to_vec());
        let original_generation = panel.generation;
        panel.set_source(0x2000, b"V29ybGQ=".to_vec());
        panel.accept_result(original_generation, result(b"Hello"));
        assert!(panel.output.is_none());
        assert!(panel.annotation().is_err());
        panel.accept_result(panel.generation, result(b"World"));
        let annotation = panel.annotation().unwrap();
        assert_eq!(annotation.source_address, 0x2000);
        assert_eq!(annotation.source_length, 8);
        assert_eq!(annotation.text, "World");
    }

    #[test]
    fn pasted_or_edited_input_cannot_claim_memory_provenance() {
        let mut panel = DecoderPanel {
            input: "SGVsbG8=".into(),
            mode: InputMode::Text,
            ..Default::default()
        };
        panel.accept_result(panel.generation, result(b"Hello"));
        assert!(panel.annotation().is_err());
        panel.set_source(0x3000, b"SGVsbG8=".to_vec());
        panel.input = "41".into();
        panel.accept_result(panel.generation, result(b"A"));
        assert!(
            panel
                .annotation()
                .unwrap_err()
                .contains("no longer matches")
        );
        panel.invalidate(true);
        assert!(panel.source.is_none());
        assert!(panel.output.is_none());
    }

    #[test]
    fn full_size_source_hex_is_accepted_without_truncation() {
        let mut panel = DecoderPanel::default();
        let source = vec![0xa5; MAX_INPUT];
        panel.set_source(0x4000, source.clone());
        assert_eq!(panel.input_bytes().unwrap(), source);
        panel.input.push_str(" a5");
        assert!(panel.input_bytes().is_err());
        panel.set_source(0, vec![0; MAX_INPUT + 1]);
        assert!(panel.source.is_none());
        assert!(panel.error.is_some());
        panel.mode = InputMode::Text;
        panel.input = "🦀".repeat(MAX_INPUT / 2);
        assert!(panel.input_bytes().is_err());
    }

    #[test]
    fn rejects_overflowing_sources_and_read_requests() {
        let mut panel = DecoderPanel::default();
        panel.set_source(u64::MAX, vec![1]);
        assert!(panel.source.is_none());
        panel.address = "ffffffffffffffff".into();
        panel.length = 1;
        assert!(panel.read_request().is_err());
        panel.address = "0x401000".into();
        panel.length = 128;
        assert!(matches!(
            panel.read_request().unwrap(),
            DecoderAction::Read {
                address: 0x401000,
                length: 128
            }
        ));
    }

    #[test]
    fn binary_output_is_copied_and_annotated_as_explicit_hex() {
        let mut panel = DecoderPanel::default();
        panel.set_source(0x1000, b"/w==".to_vec());
        panel.accept_result(panel.generation, result(&[0xff]));
        let annotation = panel.annotation().unwrap();
        assert_eq!(annotation.text, "ff");
        assert!(annotation.parameters.contains("hex bytes (invalid UTF-8)"));
        let (preview, encoding) = output_preview("🦀abc".as_bytes(), 1);
        assert!(preview.starts_with('🦀'));
        assert!(preview.contains("truncated"));
        assert_eq!(encoding, "UTF-8");
    }

    #[test]
    fn decoder_panel_renders_with_and_without_loaded_output() {
        let context = egui::Context::default();
        let mut panel = DecoderPanel::default();
        for loaded in [false, true] {
            if loaded {
                panel.set_source(0x1000, b"SGVsbG8=".to_vec());
                panel.accept_result(panel.generation, result(b"Hello"));
            }
            let mut output = context.run_ui(egui::RawInput::default(), |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    assert!(panel.show(ui).is_none());
                });
            });
            output.textures_delta.clear();
        }
    }
}
