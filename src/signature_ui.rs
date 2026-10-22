//! Structured prototype drafts. Unsupported inferred types require an explicit choice.
use crate::signatures::{
    self, FunctionSignature, SignatureBase, SignatureParameter, SignatureType,
};
use eframe::egui::{self, ComboBox, RichText, ScrollArea, TextEdit};

pub(crate) struct SignatureEditor {
    pub function: u64,
    pub generation: u64,
    pub revision: u64,
    pub selection: u64,
    pub name: String,
    pub abi: String,
    pub return_type: Option<SignatureType>,
    pub parameters: Vec<DraftParameter>,
    pub notes: Vec<String>,
    pub error: Option<String>,
    pub has_override: bool,
}
pub(crate) struct DraftParameter {
    pub name: String,
    pub ty: Option<SignatureType>,
}
pub(crate) enum SignatureAction {
    Apply(FunctionSignature),
    Remove,
    Cancel,
}
impl SignatureEditor {
    pub fn show(&mut self, ctx: &egui::Context) -> Option<SignatureAction> {
        let mut action = None;
        let modal =
            egui::Modal::new(egui::Id::unique("function-signature-editor")).show(ctx, |ui| {
                ui.set_width(580.0);
                ui.heading("Edit function signature");
                ui.label(
                    RichText::new(format!("{} · {:#x}", self.name, self.function)).monospace(),
                );
                ui.label(format!(
                    "ABI: {} (current image default)",
                    abi_label(&self.abi)
                ));
                ui.weak("Integer and pointer types only. Parameter order determines ABI storage.");
                if !self.notes.is_empty() {
                    ScrollArea::vertical()
                        .id_salt("signature-notes")
                        .max_height(100.0)
                        .show(ui, |ui| {
                            for note in &self.notes {
                                ui.colored_label(crate::theme::WARNING, note);
                            }
                        });
                }
                ui.horizontal(|ui| {
                    ui.label("Return");
                    type_selector(ui, "signature-return", &mut self.return_type);
                });
                ui.separator();
                let mut remove = None;
                let mut swap = None;
                ScrollArea::vertical().max_height(330.0).show(ui, |ui| {
                    if self.parameters.is_empty() {
                        ui.label("No parameters (void)");
                    }
                    let count = self.parameters.len();
                    for (index, parameter) in self.parameters.iter_mut().enumerate() {
                        ui.push_id(index, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(format!("{}", index + 1));
                                ui.add(
                                    TextEdit::singleline(&mut parameter.name)
                                        .desired_width(125.0)
                                        .char_limit(64),
                                );
                                type_selector(ui, "parameter-type", &mut parameter.ty);
                                if ui.add_enabled(index > 0, egui::Button::new("↑")).clicked() {
                                    swap = Some((index, index - 1));
                                }
                                if ui
                                    .add_enabled(index + 1 < count, egui::Button::new("↓"))
                                    .clicked()
                                {
                                    swap = Some((index, index + 1));
                                }
                                if ui
                                    .small_button("×")
                                    .on_hover_text("Remove parameter")
                                    .clicked()
                                {
                                    remove = Some(index);
                                }
                            });
                        });
                    }
                });
                if let Some(index) = remove {
                    self.parameters.remove(index);
                }
                if let Some((a, b)) = swap {
                    self.parameters.swap(a, b);
                }
                if ui
                    .add_enabled(
                        self.parameters.len() < signatures::MAX_PARAMETERS,
                        egui::Button::new("Add parameter"),
                    )
                    .clicked()
                {
                    let mut index = self.parameters.len() + 1;
                    while self
                        .parameters
                        .iter()
                        .any(|p| p.name == format!("param_{index}"))
                    {
                        index += 1;
                    }
                    self.parameters.push(DraftParameter {
                        name: format!("param_{index}"),
                        ty: None,
                    });
                }
                if let Some(error) = &self.error {
                    ui.colored_label(crate::theme::WARNING, error);
                }
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Apply").clicked() {
                        match self.signature() {
                            Ok(signature) => action = Some(SignatureAction::Apply(signature)),
                            Err(error) => self.error = Some(error),
                        }
                    }
                    if self.has_override && ui.button("Remove override").clicked() {
                        action = Some(SignatureAction::Remove);
                    }
                    if ui.button("Cancel").clicked() {
                        action = Some(SignatureAction::Cancel);
                    }
                });
            });
        if modal.should_close() {
            action = Some(SignatureAction::Cancel);
        }
        action
    }
    fn signature(&self) -> Result<FunctionSignature, String> {
        let signature = FunctionSignature {
            function: self.function,
            engine: signatures::SIGNATURE_FINGERPRINT.into(),
            abi: self.abi.clone(),
            return_type: self.return_type.ok_or("Choose a supported return type")?,
            parameters: self
                .parameters
                .iter()
                .map(|p| {
                    Ok(SignatureParameter {
                        name: p.name.clone(),
                        ty: p.ty.ok_or("Choose a supported type for every parameter")?,
                    })
                })
                .collect::<Result<_, String>>()?,
        };
        signatures::validate_signatures(std::slice::from_ref(&signature))?;
        Ok(signature)
    }
}
fn type_selector(ui: &mut egui::Ui, id: &str, ty: &mut Option<SignatureType>) {
    let mut base = ty.as_ref().map(|t| t.base);
    ComboBox::from_id_salt(id)
        .selected_text(base.as_ref().map_or("Choose type…", base_label))
        .width(95.0)
        .show_ui(ui, |ui| {
            for value in [
                SignatureBase::Void,
                SignatureBase::I8,
                SignatureBase::U8,
                SignatureBase::I16,
                SignatureBase::U16,
                SignatureBase::I32,
                SignatureBase::U32,
                SignatureBase::I64,
                SignatureBase::U64,
            ] {
                ui.selectable_value(&mut base, Some(value), base_label(&value));
            }
        });
    let mut depth = ty.as_ref().map_or(0, |t| t.pointer_depth);
    ComboBox::from_id_salt((id, "pointer"))
        .selected_text(if depth == 0 {
            "value".into()
        } else {
            "*".repeat(depth as usize)
        })
        .width(55.0)
        .show_ui(ui, |ui| {
            for value in 0..=signatures::MAX_POINTER_DEPTH {
                ui.selectable_value(
                    &mut depth,
                    value,
                    if value == 0 {
                        "value".into()
                    } else {
                        "*".repeat(value as usize)
                    },
                );
            }
        });
    *ty = base.map(|base| SignatureType {
        base,
        pointer_depth: depth,
    });
}
fn base_label(base: &SignatureBase) -> &'static str {
    match base {
        SignatureBase::Void => "void",
        SignatureBase::I8 => "int8_t",
        SignatureBase::U8 => "uint8_t",
        SignatureBase::I16 => "int16_t",
        SignatureBase::U16 => "uint16_t",
        SignatureBase::I32 => "int32_t",
        SignatureBase::U32 => "uint32_t",
        SignatureBase::I64 => "int64_t",
        SignatureBase::U64 => "uint64_t",
    }
}
fn abi_label(abi: &str) -> &str {
    match abi {
        "x86:LE:64:default:gcc" => "x86-64 System V",
        "x86:LE:64:default:windows" => "Windows x64",
        "x86:LE:32:default:gcc" => "x86 GCC default",
        "x86:LE:32:default:windows" => "Windows x86 default",
        "AARCH64:LE:64:v8A:windows" => "Windows ARM64",
        "AARCH64:LE:64:AppleSilicon:default" => "Apple arm64",
        "AARCH64:LE:64:v8A:default" => "AArch64 default",
        _ => abi,
    }
}
