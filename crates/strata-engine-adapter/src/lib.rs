//! strata-engine-adapter
//!
//! A thin, JSON-friendly bridge between the heavy `strata-fs` / `strata-core`
//! / `strata-plugin-*` crates and the Tauri desktop UI. Lives inside the root
//! Strata workspace so it can resolve `{ workspace = true }` dependency
//! inheritance, then exposes a clean path-dep surface to the standalone
//! `strata-desktop` Tauri crate.
//!
//! All commands are synchronous (the Tauri command layer wraps them in
//! `tokio::task::spawn_blocking` if needed).

pub mod csam;
pub mod evidence;
pub mod files;
pub mod hashing;
pub mod plugins;
pub mod store;
pub mod types;
pub mod vfs_materialize;

// ── Public API surface ──────────────────────────────────────────────────────

pub use types::{
    format_size, AdapterError, AdapterResult, ArtifactCategoryInfo, EngineStats, EvidenceInfo,
    FileEntry, HashResult, HexData, HexLine, PluginArtifact, TreeNode,
};

pub use evidence::{
    close_evidence, get_files, get_stats, get_tree_children, get_tree_root, parse_evidence,
};

pub use files::{get_file_hex, get_file_metadata, get_file_text};

pub use hashing::{hash_all_files, hash_file, hashed_count};

pub use plugins::{
    get_artifact_categories, get_artifacts_by_category, get_plugin_artifacts, list_plugins,
    run_all_on_path, run_all_on_vfs, run_all_with_persistence,
    run_all_with_persistence_vfs, run_plugin,
};

pub use vfs_materialize::{materialize_targets, MaterializeReport};

pub use csam::{
    csam_confirm_hit, csam_create_session, csam_dismiss_hit, csam_drop_session,
    csam_export_audit_log, csam_generate_report, csam_import_hash_set, csam_list_hits,
    csam_review_hit, csam_run_scan, csam_session_summary, CsamHitInfo, CsamScanOptions,
    CsamScanSummary, CsamSessionSummary, HashSetImportResult,
};
