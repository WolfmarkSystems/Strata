//! Strata — Portable Forensic Analysis Workbench
//! Entry point: configures eframe window and launches the egui event loop.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod artifacts;
mod carve;
mod case;
mod cli;
mod evidence;
mod hash;
mod license_state;
mod plugin_host;
mod raid;
mod search;
mod state;
mod state_csam;
mod theme;
mod ui;

const STRATA_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    init_tracing();
    match cli::dispatch_from_env() {
        cli::CliAction::RunGui => {
            if let Err(err) = run_gui() {
                eprintln!("{}", err);
                std::process::exit(1);
            }
        }
        cli::CliAction::Exit(code) => std::process::exit(code),
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .compact()
        .try_init();
}

fn run_gui() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(format!(
                "Strata v{} — Forensic Analysis Workbench",
                STRATA_VERSION
            ))
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([800.0, 600.0])
            .with_maximized(true)
            .with_visible(false) // Start hidden — shown after theme+fonts load
            .with_icon(load_icon()),
        default_theme: eframe::Theme::Dark,
        ..Default::default()
    };

    eframe::run_native(
        "strata",
        native_options,
        Box::new(|cc| Ok(Box::new(app::StrataTreeApp::new(cc)))),
    )
}

fn load_icon() -> egui::IconData {
    // Programmatic 32x32 wolf-mark icon in Iron Wolf palette.
    // Simple geometric approximation for window/taskbar use.
    let size: u32 = 32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let bg = [0x0cu8, 0x0f, 0x16, 0xff];
    let silver = [0xdc, 0xe6, 0xf0, 0xff];
    let steel = [0x8f, 0xa8, 0xc0, 0xff];
    let dark = [0x11, 0x1e, 0x2e, 0xff];
    let eye = [0xff, 0xff, 0xff, 0xe0];

    // Fill background
    for pixel in rgba.chunks_exact_mut(4) {
        pixel.copy_from_slice(&bg);
    }

    // Helper: set pixel
    let mut set = |x: i32, y: i32, color: &[u8; 4]| {
        if x >= 0 && x < size as i32 && y >= 0 && y < size as i32 {
            let idx = ((y as u32 * size + x as u32) * 4) as usize;
            rgba[idx..idx + 4].copy_from_slice(color);
        }
    };

    // Draw a filled triangle using scanlines
    let fill_tri =
        |set: &mut dyn FnMut(i32, i32, &[u8; 4]), pts: [(f32, f32); 3], color: &[u8; 4]| {
            let min_y = pts.iter().map(|p| p.1 as i32).min().unwrap().max(0);
            let max_y = pts
                .iter()
                .map(|p| p.1 as i32)
                .max()
                .unwrap()
                .min(size as i32 - 1);
            for y in min_y..=max_y {
                let yf = y as f32 + 0.5;
                let mut xs = Vec::new();
                for i in 0..3 {
                    let (x0, y0) = pts[i];
                    let (x1, y1) = pts[(i + 1) % 3];
                    if (y0 <= yf && y1 > yf) || (y1 <= yf && y0 > yf) {
                        let t = (yf - y0) / (y1 - y0);
                        xs.push((x0 + t * (x1 - x0)) as i32);
                    }
                }
                if xs.len() >= 2 {
                    xs.sort();
                    for x in xs[0]..=*xs.last().unwrap() {
                        set(x, y, color);
                    }
                }
            }
        };

    // Scale factor: 28 -> 32, offset 2
    let si = |v: f32| v * 32.0 / 28.0;

    // Left ear
    fill_tri(
        &mut set,
        [
            (si(4.0), si(14.0)),
            (si(7.0), si(3.0)),
            (si(11.0), si(11.0)),
        ],
        &silver,
    );
    fill_tri(
        &mut set,
        [
            (si(5.0), si(13.0)),
            (si(7.0), si(5.0)),
            (si(10.0), si(11.0)),
        ],
        &bg,
    );
    // Right ear
    fill_tri(
        &mut set,
        [
            (si(24.0), si(14.0)),
            (si(21.0), si(3.0)),
            (si(17.0), si(11.0)),
        ],
        &silver,
    );
    fill_tri(
        &mut set,
        [
            (si(23.0), si(13.0)),
            (si(21.0), si(5.0)),
            (si(18.0), si(11.0)),
        ],
        &bg,
    );

    // Head (simplified: fill a large diamond area)
    fill_tri(
        &mut set,
        [
            (si(14.0), si(2.0)),
            (si(24.0), si(15.0)),
            (si(14.0), si(26.0)),
        ],
        &dark,
    );
    fill_tri(
        &mut set,
        [
            (si(14.0), si(2.0)),
            (si(4.0), si(15.0)),
            (si(14.0), si(26.0)),
        ],
        &dark,
    );

    // Forehead plate
    fill_tri(
        &mut set,
        [
            (si(14.0), si(4.0)),
            (si(18.0), si(8.0)),
            (si(10.0), si(8.0)),
        ],
        &steel,
    );
    fill_tri(
        &mut set,
        [
            (si(10.0), si(8.0)),
            (si(18.0), si(8.0)),
            (si(14.0), si(11.0)),
        ],
        &steel,
    );

    // Eyes (bright white spots)
    fill_tri(
        &mut set,
        [
            (si(9.0), si(11.0)),
            (si(11.0), si(10.5)),
            (si(10.0), si(13.0)),
        ],
        &eye,
    );
    fill_tri(
        &mut set,
        [
            (si(19.0), si(11.0)),
            (si(17.0), si(10.5)),
            (si(18.0), si(13.0)),
        ],
        &eye,
    );

    // Nose
    fill_tri(
        &mut set,
        [
            (si(13.5), si(15.0)),
            (si(14.5), si(15.0)),
            (si(14.0), si(17.0)),
        ],
        &steel,
    );

    egui::IconData {
        rgba,
        width: size,
        height: size,
    }
}
