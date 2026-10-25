//! Developer-only native screenshots, compiled with `--features capture`.
//!
//! `GHIDRA_RUST_CAPTURE_TO=<file.ppm>` writes one frame after the desktop has
//! been idle for `GHIDRA_RUST_CAPTURE_DELAY` seconds (default 6) and exits.
//! `GHIDRA_RUST_CAPTURE_GOTO=<hex>` navigates once the binary is open,
//! `GHIDRA_RUST_CAPTURE_TAB=<graph|strings|crypto|decode|hex|references>`
//! `GHIDRA_RUST_CAPTURE_CACHE_CHECK=A,B` exercises cache/history/selection/Refresh;
//! `GHIDRA_RUST_CAPTURE_PROJECT=<new.grproj>` also saves and reopens a project.
//! The cache check uses hexadecimal function entries and asserts its results.
//! shows that view, and `GHIDRA_RUST_CAPTURE_SELECT=<hex>` then selects one of
//! its instructions. `GHIDRA_RUST_CAPTURE_ANALYZE=1` runs every automatic
//! analysis first; otherwise the first-open prompt is dismissed without
//! analyzing. `GHIDRA_RUST_CAPTURE_SIZE=<width>x<height>` resizes the window.
//! `GHIDRA_RUST_CAPTURE_UPDATES=1` opens the update dialog after analysis/checks.
use eframe::egui;
use std::io::Write;
use std::time::{Duration, Instant};

pub struct Capture {
    path: std::path::PathBuf,
    pub cache_check: Option<CacheCheck>,
    delay: Duration,
    pub goto: Option<u64>,
    pub select: Option<u64>,
    pub tab: Option<String>,
    pub analyze: bool,
    pub updates: bool,
    pub size: Option<egui::Vec2>,
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
        let size = std::env::var("GHIDRA_RUST_CAPTURE_SIZE")
            .ok()
            .and_then(|size| {
                let (width, height) = size.split_once('x')?;
                Some(egui::vec2(width.parse().ok()?, height.parse().ok()?))
            });
        Some(Self {
            path,
            cache_check: std::env::var("GHIDRA_RUST_CAPTURE_CACHE_CHECK")
                .ok()
                .map(|value| {
                    let (a, b) = value
                        .split_once(',')
                        .expect("Cache check needs A,B hexadecimal function addresses");
                    CacheCheck {
                        a: u64::from_str_radix(a.trim_start_matches("0x"), 16).expect("A"),
                        b: u64::from_str_radix(b.trim_start_matches("0x"), 16).expect("B"),
                        step: 0,
                        epoch: 0,
                        pc: 0,
                        graph: None,
                        code: None,
                        project: std::env::var_os("GHIDRA_RUST_CAPTURE_PROJECT").map(Into::into),
                    }
                }),
            delay: Duration::from_secs_f32(delay),
            goto: address("GHIDRA_RUST_CAPTURE_GOTO"),
            select: address("GHIDRA_RUST_CAPTURE_SELECT"),
            tab: std::env::var("GHIDRA_RUST_CAPTURE_TAB").ok(),
            analyze: std::env::var_os("GHIDRA_RUST_CAPTURE_ANALYZE").is_some(),
            updates: std::env::var_os("GHIDRA_RUST_CAPTURE_UPDATES").is_some(),
            size,
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
                    crate::performance::event("capture_exit", 0);
                    if let Err(error) = crate::performance::flush() {
                        eprintln!("{error}");
                        std::process::exit(1);
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

/// Developer-only native scenario. Assertions are exercised through the actual
/// desktop's worker/event/render loop, without a user-visible automation flow.
pub struct CacheCheck {
    pub a: u64,
    pub b: u64,
    pub step: usize,
    pub epoch: u64,
    pub pc: u64,
    pub graph: Option<crate::result_store::Shared<crate::function_presentation::PreparedGraph>>,
    pub code:
        Option<crate::result_store::Shared<crate::function_presentation::PreparedDecompilation>>,
    pub project: Option<std::path::PathBuf>,
}
