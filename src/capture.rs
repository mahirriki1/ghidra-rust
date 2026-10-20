//! Developer-only native screenshots, compiled with `--features capture`.
//!
//! `GHIDRA_RUST_CAPTURE_TO=<file.ppm>` writes one frame after the desktop has
//! been idle for `GHIDRA_RUST_CAPTURE_DELAY` seconds (default 6) and exits.
//! `GHIDRA_RUST_CAPTURE_GOTO=<hex>` navigates once the binary is open,
//! `GHIDRA_RUST_CAPTURE_TAB=graph` shows the function graph, and
//! `GHIDRA_RUST_CAPTURE_SELECT=<hex>` then selects one of its instructions.
//! The first-open analysis prompt is dismissed without analyzing.
use eframe::egui;
use std::io::Write;
use std::time::{Duration, Instant};

pub struct Capture {
    path: std::path::PathBuf,
    delay: Duration,
    pub goto: Option<u64>,
    pub select: Option<u64>,
    pub graph: bool,
    idle_since: Option<Instant>,
    requested: bool,
}

impl Capture {
    pub fn from_env() -> Option<Self> {
        let path = std::env::var_os("GHIDRA_RUST_CAPTURE_TO")?.into();
        let delay = std::env::var("GHIDRA_RUST_CAPTURE_DELAY")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(6.0);
        let address = |name| {
            std::env::var(name)
                .ok()
                .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
        };
        let graph = std::env::var("GHIDRA_RUST_CAPTURE_TAB").is_ok_and(|tab| tab == "graph");
        Some(Self {
            path,
            delay: Duration::from_secs_f32(delay),
            goto: address("GHIDRA_RUST_CAPTURE_GOTO"),
            select: address("GHIDRA_RUST_CAPTURE_SELECT"),
            graph,
            idle_since: None,
            requested: false,
        })
    }

    /// Requests a frame once the app has stayed idle, then saves it and exits.
    pub fn tick(&mut self, context: &egui::Context, idle: bool) {
        context.request_repaint_after(Duration::from_millis(100));
        if !idle {
            self.idle_since = None;
            return;
        }
        let since = *self.idle_since.get_or_insert_with(Instant::now);
        if !self.requested && since.elapsed() >= self.delay {
            self.requested = true;
            let path = self.path.clone();
            context.send_viewport_cmd(egui::ViewportCommand::Screenshot(
                egui::ScreenshotCallback::new(move |image| {
                    if let Err(error) = write_ppm(&path, &image) {
                        eprintln!("capture failed: {error}");
                    }
                    std::process::exit(0);
                }),
            ));
        }
    }
}

fn write_ppm(path: &std::path::Path, image: &egui::ColorImage) -> std::io::Result<()> {
    let [width, height] = image.size;
    let mut file = std::io::BufWriter::new(std::fs::File::create(path)?);
    write!(file, "P6\n{width} {height}\n255\n")?;
    for pixel in &image.pixels {
        file.write_all(&[pixel.r(), pixel.g(), pixel.b()])?;
    }
    file.flush()
}
