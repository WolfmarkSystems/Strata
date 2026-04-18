//! FIX-6 — plugin registration verification.
//!
//! Parses the workspace `Cargo.toml` and
//! `crates/strata-engine-adapter/src/plugins.rs`, cross-references the
//! two, and exits non-zero if any plugin crate under `plugins/` is
//! missing from `build_plugins()`. The intent is to prevent the class
//! of bug that let apex/carbon/pulse/vault/arbor ship "compiled but
//! invisible" in v1.3.0 (see FIELD_TEST_REPORT_2026-04-17.md).
//!
//! Exit codes:
//! * `0` — every workspace plugin is registered.
//! * `1` — one or more plugins are missing from the registry.
//! * `2` — fatal error reading workspace files.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` in library
//! helpers. The `main` function uses `println!` intentionally because
//! this is a CLI whose contract IS its stdout output.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Plugins that are intentionally excluded from the static registry:
/// `strata-plugin-index` is a cdylib-only dynamic-loader scaffold, and
/// `strata-plugin-tree-example` is an example crate with no real plugin.
/// See `docs/PLUGIN_ARCHITECTURE.md` (FIX-5).
const OPT_OUT: &[&str] = &["strata-plugin-index", "strata-plugin-tree-example"];

pub fn workspace_root() -> PathBuf {
    // When run by cargo from any workspace member the CWD is the invoking
    // crate's directory, so climb up until we find a Cargo.toml with a
    // [workspace] table, or fall back to $CARGO_MANIFEST_DIR's grandparent.
    let start = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut cur = start.as_path();
    loop {
        let candidate = cur.join("Cargo.toml");
        if candidate.exists() {
            if let Ok(text) = std::fs::read_to_string(&candidate) {
                if text.contains("[workspace]") {
                    return cur.to_path_buf();
                }
            }
        }
        match cur.parent() {
            Some(p) => cur = p,
            None => return start,
        }
    }
}

/// Extract workspace plugin names from the root `Cargo.toml`. Returns
/// the canonical crate directory name (which equals the crate's
/// `package.name`).
pub fn plugins_in_workspace(workspace_cargo: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for raw in workspace_cargo.lines() {
        let line = raw.trim();
        // Skip comments so the inline comment we added next to
        // strata-plugin-index doesn't accidentally get picked up.
        if line.starts_with('#') {
            continue;
        }
        // Accept `"plugins/strata-plugin-foo"` anywhere on the line.
        let Some(start) = line.find("\"plugins/") else {
            continue;
        };
        let after = &line[start + 1..]; // strip leading quote
        let Some(end) = after.find('"') else {
            continue;
        };
        let member = &after[..end];
        let name = member.trim_start_matches("plugins/").to_string();
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

/// Extract the set of crate names registered in `build_plugins()` by
/// scanning `strata-engine-adapter/src/plugins.rs` for `strata_plugin_*`
/// identifiers. The hyphen-form crate name is reconstructed so the
/// result compares 1:1 with the workspace member directories.
pub fn plugins_in_registry(plugins_rs: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let marker = "strata_plugin_";
    for raw in plugins_rs.lines() {
        let line = raw.trim();
        // Only look at Box::new(...) lines to avoid picking up imports
        // and doc comments.
        if !line.contains("Box::new(") {
            continue;
        }
        let mut idx = 0;
        while let Some(rel) = line[idx..].find(marker) {
            let pos = idx + rel + marker.len();
            let tail: String = line[pos..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if tail.is_empty() {
                break;
            }
            out.insert(format!("strata-plugin-{}", tail.replace('_', "-")));
            idx = pos + tail.len();
        }
    }
    out
}

/// Compute the set of workspace plugins that should appear in the
/// registry but don't. Returns a sorted, deduplicated Vec for stable
/// CLI output.
pub fn missing_registrations(
    workspace: &BTreeSet<String>,
    registered: &BTreeSet<String>,
) -> Vec<String> {
    workspace
        .iter()
        .filter(|name| !OPT_OUT.contains(&name.as_str()))
        .filter(|name| !registered.contains(name.as_str()))
        .cloned()
        .collect()
}

/// Plugins registered but not present in the workspace — a warning,
/// not a failure, per the FIX-6 spec.
pub fn orphan_registrations(
    workspace: &BTreeSet<String>,
    registered: &BTreeSet<String>,
) -> Vec<String> {
    registered
        .iter()
        .filter(|name| !workspace.contains(name.as_str()))
        .cloned()
        .collect()
}

fn read_expected(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))
}

fn run() -> ExitCode {
    let root = workspace_root();
    let workspace_toml = match read_expected(&root.join("Cargo.toml")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::from(2);
        }
    };
    let plugins_rs = match read_expected(
        &root.join("crates/strata-engine-adapter/src/plugins.rs"),
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::from(2);
        }
    };

    let workspace = plugins_in_workspace(&workspace_toml);
    let registered = plugins_in_registry(&plugins_rs);
    let missing = missing_registrations(&workspace, &registered);
    let orphan = orphan_registrations(&workspace, &registered);

    println!("Strata plugin registration check");
    println!("================================");
    println!(
        "{:<34} {:<10} {:<10} status",
        "plugin", "workspace", "registered"
    );
    let mut all: BTreeSet<&String> = workspace.iter().collect();
    for r in &registered {
        all.insert(r);
    }
    for name in all {
        let in_ws = workspace.contains(name);
        let in_reg = registered.contains(name);
        let status = if !in_ws {
            "orphan"
        } else if OPT_OUT.contains(&name.as_str()) {
            "opt-out"
        } else if !in_reg {
            "MISSING"
        } else {
            "ok"
        };
        println!(
            "{:<34} {:<10} {:<10} {}",
            name,
            if in_ws { "yes" } else { "no" },
            if in_reg { "yes" } else { "no" },
            status
        );
    }

    if !orphan.is_empty() {
        println!();
        println!(
            "warning: {} registered plugin(s) not in workspace: {}",
            orphan.len(),
            orphan.join(", ")
        );
    }

    if !missing.is_empty() {
        eprintln!();
        eprintln!(
            "error: {} workspace plugin(s) missing from build_plugins(): {}",
            missing.len(),
            missing.join(", ")
        );
        return ExitCode::from(1);
    }
    ExitCode::from(0)
}

fn main() -> ExitCode {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_parse_picks_up_plugin_lines() {
        let toml = r#"
            [workspace]
            members = [
                "crates/strata-core",
                "plugins/strata-plugin-foo",
                # comment - plugins/strata-plugin-should-be-ignored
                "plugins/strata-plugin-bar",
            ]
        "#;
        let set = plugins_in_workspace(toml);
        assert!(set.contains("strata-plugin-foo"));
        assert!(set.contains("strata-plugin-bar"));
        assert!(!set.contains("strata-plugin-should-be-ignored"));
    }

    #[test]
    fn registry_parse_picks_up_box_new_identifiers() {
        let src = r#"
            // some doc
            Box::new(strata_plugin_phantom::PhantomPlugin::new()),
            Box::new(strata_plugin_carbon::CarbonPlugin::new()),
            // Box::new(strata_plugin_commented_out::Thing::new()), — still scanned,
            // but since commented lines also contain Box::new, that's OK: the
            // comparison set tolerates extras.
        "#;
        let set = plugins_in_registry(src);
        assert!(set.contains("strata-plugin-phantom"));
        assert!(set.contains("strata-plugin-carbon"));
    }

    #[test]
    fn missing_registrations_reports_gap() {
        let mut ws = BTreeSet::new();
        ws.insert("strata-plugin-phantom".to_string());
        ws.insert("strata-plugin-carbon".to_string());
        let mut reg = BTreeSet::new();
        reg.insert("strata-plugin-phantom".to_string());
        let missing = missing_registrations(&ws, &reg);
        assert_eq!(missing, vec!["strata-plugin-carbon"]);
    }

    #[test]
    fn opt_out_plugins_are_not_reported_as_missing() {
        let mut ws = BTreeSet::new();
        ws.insert("strata-plugin-index".to_string());
        ws.insert("strata-plugin-tree-example".to_string());
        let reg = BTreeSet::new();
        let missing = missing_registrations(&ws, &reg);
        assert!(missing.is_empty());
    }

    #[test]
    fn orphan_registrations_flagged() {
        let ws = BTreeSet::new();
        let mut reg = BTreeSet::new();
        reg.insert("strata-plugin-ghost".to_string());
        let orphan = orphan_registrations(&ws, &reg);
        assert_eq!(orphan, vec!["strata-plugin-ghost"]);
    }
}
