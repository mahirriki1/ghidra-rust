//! Shared Ghidra Rust branding. The SVG in docs/images is the source artwork;
//! its transparent PNG export is embedded for native icons and menu rendering.
use eframe::egui;
use std::sync::{Arc, OnceLock};

/// Window app id (Wayland `app_id`, X11 `WM_CLASS`) and the matching desktop
/// entry and icon name. Reverse-DNS of the project's home on GitHub, in the
/// form desktop-entry IDs and D-Bus names both accept.
pub const APP_ID: &str = "io.github.mahirriki1.GhidraRust";

/// The 256x256 PNG export of docs/images/ghidra-rust-logo.svg.
pub const ICON_PNG: &[u8] = include_bytes!("../docs/images/ghidra-rust-icon.png");

/// The bundled icon is decoded once and shared by native viewports.
pub fn icon() -> Arc<egui::IconData> {
    static ICON: OnceLock<Arc<egui::IconData>> = OnceLock::new();
    Arc::clone(ICON.get_or_init(|| {
        Arc::new(
            eframe::icon_data::from_png_bytes(ICON_PNG)
                .expect("bundled Ghidra Rust icon must be a valid PNG"),
        )
    }))
}

/// Passive branding within the existing menu row; never takes keyboard focus.
pub fn menu_mark(ui: &mut egui::Ui) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(18.0, 16.0), egui::Sense::hover());
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Image, true, "Ghidra Rust"));
    if ui.is_rect_visible(rect) {
        let id = egui::Id::unique("ghidra-rust-brand-texture");
        let cached = ui
            .ctx()
            .data(|data| data.get_temp::<egui::TextureHandle>(id));
        let texture = cached.unwrap_or_else(|| {
            let icon = icon();
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [icon.width as usize, icon.height as usize],
                &icon.rgba,
            );
            // Loading a texture also accesses context data, so do this outside
            // the temporary-data lock and retain the handle per context.
            let texture =
                ui.ctx()
                    .load_texture("Ghidra Rust logo", image, egui::TextureOptions::LINEAR);
            ui.ctx()
                .data_mut(|data| data.insert_temp(id, texture.clone()));
            texture
        });
        ui.painter().image(
            texture.id(),
            egui::Rect::from_center_size(rect.center(), egui::vec2(16.0, 16.0)),
            egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
            egui::Color32::WHITE,
        );
    }
    response.on_hover_text("Ghidra Rust")
}
