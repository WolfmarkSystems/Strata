pub use strata_core::acquisition;
pub use strata_core::analysis;
pub use strata_core::capabilities;
pub use strata_core::carving;
pub use strata_core::case;
pub use strata_core::catalog;
pub use strata_core::classification;
pub use strata_core::context;
pub use strata_core::disk;
pub use strata_core::encryption;
pub use strata_core::events;
pub use strata_core::evidence;
pub use strata_core::filesystem;
pub use strata_core::hashing;
pub use strata_core::hashset;
pub use strata_core::memory;
pub use strata_core::model;
pub use strata_core::network;
pub use strata_core::parser;
pub use strata_core::parsers;
pub use strata_core::plugin;
pub use strata_core::report;
pub use strata_core::scripting;
pub use strata_core::strings;
pub use strata_core::timeline;
pub use strata_core::validation;

pub use strata_core::audit;
pub use strata_core::container;
pub use strata_core::errors;
pub use strata_core::hashing_utils;
pub use strata_core::virtualization;

use std::panic;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

pub fn init_tracing_and_panic_hook() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);

    panic::set_hook(Box::new(|panic_info| {
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());

        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };

        error!(
            target: "panic",
            location = %location,
            message = %message,
            "Application panicked!"
        );

        eprintln!("===========================================");
        eprintln!("PANIC at {}", location);
        eprintln!("Message: {}", message);
        eprintln!("===========================================");
    }));

    info!("Tracing and panic hook initialized");
}

#[cfg(test)]
pub mod tests;
