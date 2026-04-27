//! CI integration for the AST-aware quality gate (H3-AST-QUALITY-GATE).
//!
//! Builds and runs the `strata-verify-quality` binary and asserts it
//! exits 0. The binary reads `tools/strata-verify-quality/waivers.toml`
//! for per-category baselines; a commit that introduces new
//! library-code `.unwrap()` / `unsafe{}` / `println!` fails the gate
//! unless the corresponding baseline is reduced (not increased).
//!
//! Skip-guarded when the workspace root is not reachable from the
//! current working directory (i.e. when the test is run from a
//! location that doesn't contain `tools/strata-verify-quality/`).

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> Option<PathBuf> {
    // Walk upward from CARGO_MANIFEST_DIR until we find the workspace
    // root (the directory containing tools/strata-verify-quality).
    let start = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    let mut cur = Some(start.as_path());
    while let Some(dir) = cur {
        if dir.join("tools/strata-verify-quality").exists() {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    None
}

#[test]
fn ast_quality_gate_passes() {
    let Some(root) = workspace_root() else {
        eprintln!("SKIP: workspace root not locatable");
        return;
    };
    let output = Command::new(env!("CARGO"))
        .args(["run", "--quiet", "-p", "strata-verify-quality", "--"])
        .current_dir(&root)
        .output();
    let output = match output {
        Ok(o) => o,
        Err(e) => {
            eprintln!("SKIP: failed to spawn cargo ({e})");
            return;
        }
    };
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "Quality gate FAILED (exit {}).\n\nstdout:\n{stdout}\n\nstderr:\n{stderr}\n\n\
             To remediate: reduce the offending baseline in \
             tools/strata-verify-quality/waivers.toml by fixing real \
             violations (not by raising the waiver).",
            output.status
        );
    }
}

#[test]
fn waiver_file_exists_and_is_valid_toml() {
    let Some(root) = workspace_root() else {
        return;
    };
    let waivers = root.join("tools/strata-verify-quality/waivers.toml");
    assert!(waivers.exists(), "waivers.toml must exist");
    let text = std::fs::read_to_string(&waivers).expect("read waivers");
    let _parsed: toml::Value = toml::from_str(&text).expect("valid TOML");
}
