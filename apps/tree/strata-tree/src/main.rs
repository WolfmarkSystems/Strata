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
    // Minimal 1x1 transparent icon — replace with actual icon bytes for production.
    egui::IconData {
        rgba: vec![0, 0, 0, 0],
        width: 1,
        height: 1,
    }
}
