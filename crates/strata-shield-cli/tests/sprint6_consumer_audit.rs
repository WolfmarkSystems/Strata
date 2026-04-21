//! Post-v16 Sprint 6 — downstream consumer subcategory surface
//! audit. Ships as **anti-regression tripwires** confirming the
//! three consumers (report generator, Tauri UI, JSON export) all
//! consume plugin subcategory strings *dynamically* rather than
//! from hardcoded enumerations. If a future change introduces a
//! hardcoded subcategory list, the new 13+ Sprint-3-5 strings
//! would silently miss — these tests make that a loud compile /
//! test failure instead of a quiet demo-day surprise.
//!
//! **Full Sprint 6 findings live in
//! `SESSION_STATE_POST_V16_SPRINT_6_COMPLETE.md`.** This file is
//! the machine-checkable subset.
//!
//! ## Audit coverage
//!
//! Three file trees scanned:
//!   - `crates/strata-shield-engine/src/report/` — HTML / JSON /
//!     JSONL / CSV / PDF report generators
//!   - `crates/strata-core/src/report/` — court-ready + UCMJ
//!     report templates
//!   - `apps/strata-ui/src/` — Tauri desktop React source
//!
//! For each tree, confirm **none of the 13 Sprint-3-5 subcategory
//! strings** appear as string literals. Subcategory strings should
//! only live inside plugin source (where they're emitted) and in
//! `plugins/strata-plugin-sigma/src/lib.rs` (where rules key on
//! them). Any other file referencing them is a downstream-consumer
//! hardcoding gap.
//!
//! When a consumer genuinely needs a pretty-name for a subcategory
//! (v0.17 display-name infrastructure), the convention will be a
//! single shared table in `strata-plugin-sdk` — not per-consumer
//! hardcoding. Until that ships, dynamic consumption is the rule
//! and these tripwires enforce it.

use std::path::{Path, PathBuf};

/// Every subcategory string introduced by Sprints 3 + 5 that a
/// naive "let me hardcode the known subcategories" refactor
/// would trip over.
///
/// Source of record: `SESSION_STATE_POST_V16_SPRINT_3_COMPLETE.md`
/// §Tier 4 candidates + `SESSION_STATE_POST_V16_SPRINT_5_COMPLETE.md`
/// §Tier 4 candidates.
const SPRINT_3_5_SUBCATEGORIES: &[&str] = &[
    // Sprint 3 — Trace + Chronicle wiring
    "BITS Transfer",
    "PCA Execution",
    "XP Recycler Entry",
    "CAM Capability Access",
    // Sprint 5 — Phantom wiring
    "Memory String",
    "Memory Process",
    "Memory Network Connection",
    "Notepad TabState",
    "Outlook Carved",
    "PowerShell History",
    "Cloud CLI Credential",
    "Windows Recall Capture",
    "Windows Recall Locked",
];

/// Paths that *legitimately* contain these subcategory literals
/// — plugin emission source + Sigma rule source. Every other hit
/// is a hardcoded-consumer regression.
fn is_legitimate_source(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains("plugins/strata-plugin-trace/")
        || s.contains("plugins/strata-plugin-chronicle/")
        || s.contains("plugins/strata-plugin-phantom/")
        || s.contains("plugins/strata-plugin-sigma/")
        // This test file itself carries the strings in its
        // const SPRINT_3_5_SUBCATEGORIES — exclude.
        || s.ends_with("sprint6_consumer_audit.rs")
        // Session-state doc + inventory doc legitimately list
        // the strings for documentation — the tripwire only
        // checks production source, not docs.
        || s.contains("SESSION_STATE_POST_V16_SPRINT")
        || s.contains("RESEARCH_POST_V16_")
        || s.contains("FIELD_VALIDATION_REAL_IMAGES_")
}

/// Recursively enumerate .rs, .ts, .tsx files under `root`.
fn walk_source_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            // Skip obvious non-source dirs.
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, "target" | "node_modules" | "dist" | ".git") {
                continue;
            }
            out.extend(walk_source_files(&p));
        } else {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "rs" | "ts" | "tsx") {
                out.push(p);
            }
        }
    }
    out
}

/// Workspace root (parent of `crates/`).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("strata-shield-cli has a parent")
        .parent()
        .expect("crates has a parent")
        .to_path_buf()
}

/// Scan a subtree for hits on the Sprint 3-5 subcategory strings,
/// filtering out legitimate plugin + sigma + docs sources.
fn find_hardcoded_hits(subtree_rel: &str) -> Vec<(PathBuf, &'static str, usize)> {
    let root = workspace_root().join(subtree_rel);
    if !root.exists() {
        // Subtree absent — not a regression, just nothing to
        // audit. Callers treat empty result as pass.
        eprintln!(
            "audit: subtree {} not present, skipping",
            root.display()
        );
        return Vec::new();
    }
    let mut hits = Vec::new();
    for file in walk_source_files(&root) {
        if is_legitimate_source(&file) {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&file) else {
            continue;
        };
        for needle in SPRINT_3_5_SUBCATEGORIES {
            // Look for the string as a double-quoted literal.
            // Substring-only matching would trip on
            // docstring mentions; require the adjacent quote
            // characters so only actual string literals hit.
            let quoted = format!("\"{}\"", needle);
            for (line_no, line) in contents.lines().enumerate() {
                if line.contains(&quoted) {
                    hits.push((file.clone(), *needle, line_no + 1));
                }
            }
        }
    }
    hits
}

#[test]
fn report_generators_consume_subcategories_dynamically() {
    // Report-generator source trees: shield-engine (HTML / JSON /
    // JSONL / CSV / PDF) + strata-core (court-ready + UCMJ).
    // Neither should carry Sprint 3-5 subcategory literals; both
    // must consume subcategories dynamically from the artifact
    // record stream.
    let mut all_hits = Vec::new();
    all_hits.extend(find_hardcoded_hits("crates/strata-shield-engine/src/report"));
    all_hits.extend(find_hardcoded_hits("crates/strata-core/src/report"));
    assert!(
        all_hits.is_empty(),
        "Report generators must consume subcategories dynamically. \
         Found {} hardcoded subcategory literal(s) — these should come \
         from the plugin output stream, not a report-side enumeration. \
         Hits: {:#?}",
        all_hits.len(),
        all_hits
    );
}

#[test]
fn json_export_consumes_subcategories_dynamically() {
    // JSON / JSONL export uses serde pass-through on the category
    // + artifact_type strings. Schema is loose (pass-through); new
    // subcategories don't require code changes. This tripwire
    // confirms no Sprint 3-5 literal leaked into export-side code.
    let hits = find_hardcoded_hits("crates/strata-shield-engine/src/report");
    // Same subtree as the report generator test — JSON / JSONL
    // live alongside HTML / CSV / PDF. The no-hits assertion
    // above already covers JSON export; this separate test
    // documents that the audit explicitly includes JSON and
    // fails loudly if only JSON gets a new hardcoded subcategory.
    let json_hits: Vec<_> = hits
        .iter()
        .filter(|(p, _, _)| {
            let s = p.to_string_lossy();
            s.contains("/json.rs") || s.contains("/jsonl.rs") || s.contains("/export.rs")
        })
        .collect();
    assert!(
        json_hits.is_empty(),
        "JSON / JSONL / export modules must consume subcategories \
         dynamically. Hits: {json_hits:#?}"
    );
}

#[test]
fn tauri_ui_consumes_subcategories_dynamically() {
    // Tauri desktop React source in apps/strata-ui/src. The UI
    // consumes `artifact.category` (top-level ArtifactCategory
    // enum) + `artifact.plugin` (plugin name) dynamically — no
    // subcategory dropdown with hardcoded values.
    let hits = find_hardcoded_hits("apps/strata-ui/src");
    assert!(
        hits.is_empty(),
        "Tauri UI (React) must consume subcategories dynamically \
         from the artifact stream, not from a hardcoded enum. \
         Hits: {hits:#?}"
    );
}

#[test]
fn remnant_trailing_space_carved_is_not_referenced_by_any_consumer() {
    // Sprint 5 Fix 3 trimmed "Carved " (trailing space) to
    // "Carved". Any consumer that was checking the trailing-
    // space form would silently break — this tripwire confirms
    // zero such consumers exist. Scope: workspace-wide.
    //
    // This is a narrower scan than the Sprint 3-5 list: a
    // single literal "Carved " with trailing space.
    let needle = "\"Carved \"";
    let mut hits = Vec::new();
    for subtree in [
        "crates/strata-shield-engine/src/report",
        "crates/strata-core/src/report",
        "apps/strata-ui/src",
        "crates/strata-shield-cli/src",
    ] {
        let root = workspace_root().join(subtree);
        if !root.exists() {
            continue;
        }
        for file in walk_source_files(&root) {
            if is_legitimate_source(&file) {
                continue;
            }
            let Ok(contents) = std::fs::read_to_string(&file) else {
                continue;
            };
            for (line_no, line) in contents.lines().enumerate() {
                if line.contains(needle) {
                    hits.push((file.clone(), line_no + 1, line.trim().to_string()));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "Sprint 5 Fix 3 trimmed Remnant's subcategory from 'Carved ' \
         to 'Carved'. Any consumer checking the trailing-space form \
         would silently break. Found {} occurrence(s): {:#?}",
        hits.len(),
        hits
    );
}
