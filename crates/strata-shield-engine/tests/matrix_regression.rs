//! REGRESS-GUARD-1 — permanent regression guard for the v12 universal
//! VFS bridge scorecard. Shells out to the `strata` CLI binary and
//! parses its JSON summary, which is the stable, user-facing surface
//! exercised by the v11/v12 field validation. Skip-guarded on:
//!   * Test Material root presence
//!   * `strata` binary presence (`target/release/strata`)
//!
//! CI environments without either skip cleanly. Developer environments
//! with both run the guards automatically.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md
//! (library/parser crate — CLI is the layer that speaks to humans;
//! this test uses `eprintln!` for progress, which is a test-harness
//! concern, not production stdout).

#![allow(clippy::needless_return)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const TEST_MATERIAL: &str = "/Users/randolph/Wolfmark/Test Material";

fn test_material_root() -> Option<PathBuf> {
    let p = PathBuf::from(TEST_MATERIAL);
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

fn strata_binary() -> Option<PathBuf> {
    // Prefer release, fall back to debug.
    let candidates = [
        PathBuf::from("target/release/strata"),
        PathBuf::from("target/debug/strata"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

struct RegressionCase {
    name: &'static str,
    /// Path under `Test Material/` to the source (file or directory).
    image_subpath: &'static str,
    /// Hard floor for total artifacts produced by the run.
    min_total_artifacts: usize,
    /// Per-plugin floor for artifacts. Only listed here for the plugins
    /// most likely to regress on this image.
    min_per_plugin: &'static [(&'static str, usize)],
    /// Human-readable hint surfaced to the examiner when the case fails.
    reason_if_low: &'static str,
}

// Minimums encoded from actual v12 observed counts minus ~5% margin.
// These are regression guards, not aspirational targets. A legitimate
// improvement that increases counts is fine; a drop below these floors
// is a bug.
const V12_BASELINE_CASES: &[RegressionCase] = &[
    RegressionCase {
        name: "charlie-2009-11-12",
        image_subpath: "charlie-2009-11-12.E01",
        min_total_artifacts: 3_200, // v12 observed 3,400
        min_per_plugin: &[
            ("Strata Phantom", 500),
            ("Strata Vector", 2_300), // v12 observed 2,465
            ("Strata Chronicle", 100),
            ("Strata Trace", 50),
        ],
        reason_if_low: "EWF reader, NTFS walker, vfs_materialize bridge, or plugin regression",
    },
    RegressionCase {
        name: "jo-2009-11-16",
        image_subpath: "jo-2009-11-16.E01",
        min_total_artifacts: 3_300, // v12 observed 3,537
        min_per_plugin: &[("Strata Phantom", 500), ("Strata Vector", 2_300)],
        reason_if_low: "same as charlie — shared codepath",
    },
    // Acquisition-trim cases: floor of 1 catches total breakage while
    // allowing the documented 4-artifact trim behavior.
    RegressionCase {
        name: "terry-2009-12-03",
        image_subpath: "terry-2009-12-03.E01",
        min_total_artifacts: 1,
        min_per_plugin: &[],
        reason_if_low: "image is acquisition-trimmed before MFT; 4 artifacts is baseline",
    },
    RegressionCase {
        name: "nps-2008-jean",
        image_subpath: "nps-2008-jean.E01",
        min_total_artifacts: 1,
        min_per_plugin: &[],
        reason_if_low: "image is acquisition-trimmed before MFT; 4 artifacts is baseline",
    },
    RegressionCase {
        name: "takeout",
        image_subpath: "Takeout",
        min_total_artifacts: 1,
        min_per_plugin: &[],
        reason_if_low: "HostVfs regression or specialty-plugin breakage",
    },
];

enum CaseResult {
    Skipped(&'static str),
    Ran {
        total: usize,
        per_plugin: HashMap<String, usize>,
    },
    Errored(String),
}

fn run_case(binary: &Path, root: &Path, case: &RegressionCase) -> CaseResult {
    let source = root.join(case.image_subpath);
    if !source.exists() {
        return CaseResult::Skipped("image not present");
    }

    let case_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => return CaseResult::Errored(format!("tempdir: {e}")),
    };
    let summary_path = case_dir.path().join("summary.json");

    let status = Command::new(binary)
        .args(["ingest", "run", "--source"])
        .arg(&source)
        .args(["--case-dir"])
        .arg(case_dir.path())
        .args([
            "--case-name",
            case.name,
            "--examiner",
            "regression-guard",
            "--output-format",
            "json",
            "--auto",
            "--quiet",
            "--json-result",
        ])
        .arg(&summary_path)
        .output();

    let output = match status {
        Ok(o) => o,
        Err(e) => return CaseResult::Errored(format!("spawn strata: {e}")),
    };
    if !output.status.success() {
        // Capture last bit of stderr for diagnostic context.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: String = stderr.lines().rev().take(20).collect::<Vec<_>>().join("\n");
        return CaseResult::Errored(format!(
            "strata ingest run failed (exit {}): …{tail}",
            output.status
        ));
    }

    let json_bytes = match std::fs::read(&summary_path) {
        Ok(b) => b,
        Err(e) => {
            return CaseResult::Errored(format!("read summary {}: {e}", summary_path.display()))
        }
    };
    let v: serde_json::Value = match serde_json::from_slice(&json_bytes) {
        Ok(v) => v,
        Err(e) => return CaseResult::Errored(format!("parse summary: {e}")),
    };

    let total = v
        .get("artifacts_total")
        .and_then(|n| n.as_u64())
        .unwrap_or(0) as usize;

    let mut per_plugin: HashMap<String, usize> = HashMap::new();
    if let Some(arr) = v.get("per_plugin").and_then(|a| a.as_array()) {
        for entry in arr {
            let name = entry
                .get("plugin")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let count = entry
                .get("artifact_count")
                .and_then(|n| n.as_u64())
                .unwrap_or(0) as usize;
            if !name.is_empty() {
                per_plugin.insert(name, count);
            }
        }
    }

    CaseResult::Ran { total, per_plugin }
}

#[test]
fn v12_regression_guard() {
    let Some(root) = test_material_root() else {
        eprintln!("SKIP: Test Material not present at {TEST_MATERIAL}");
        return;
    };
    let Some(binary) = strata_binary() else {
        eprintln!("SKIP: `strata` binary not built (expected target/release/strata)");
        return;
    };

    eprintln!(
        "v12 regression guard: {} cases, binary = {}",
        V12_BASELINE_CASES.len(),
        binary.display()
    );

    let mut failures: Vec<String> = Vec::new();
    let mut skipped = 0usize;
    let mut passed = 0usize;

    for case in V12_BASELINE_CASES {
        match run_case(&binary, &root, case) {
            CaseResult::Skipped(why) => {
                eprintln!("SKIP: {} ({why})", case.name);
                skipped += 1;
            }
            CaseResult::Errored(e) => {
                failures.push(format!("{}: execution error — {e}", case.name));
            }
            CaseResult::Ran { total, per_plugin } => {
                let mut case_failed = false;
                if total < case.min_total_artifacts {
                    failures.push(format!(
                        "{}: total artifacts {} < minimum {} (reason: {})",
                        case.name, total, case.min_total_artifacts, case.reason_if_low
                    ));
                    case_failed = true;
                }
                for (plugin, min) in case.min_per_plugin {
                    let actual = per_plugin.get(*plugin).copied().unwrap_or(0);
                    if actual < *min {
                        failures.push(format!(
                            "{}: plugin {} artifacts {} < minimum {}",
                            case.name, plugin, actual, min
                        ));
                        case_failed = true;
                    }
                }
                if !case_failed {
                    eprintln!("PASS: {} — {} artifacts", case.name, total);
                    passed += 1;
                }
            }
        }
    }

    eprintln!(
        "\nRegression guard summary: {passed} passed, {skipped} skipped, {} failed",
        failures.len()
    );
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {f}");
        }
        panic!(
            "v12 regression guard: {} case(s) regressed — investigate listed failures",
            failures.len()
        );
    }
}

// ── Internal unit tests (always run, regardless of Test Material) ──────

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn v12_baseline_cases_are_well_formed() {
        assert!(!V12_BASELINE_CASES.is_empty());
        for case in V12_BASELINE_CASES {
            assert!(!case.name.is_empty(), "case missing name");
            assert!(!case.image_subpath.is_empty(), "case missing path");
            assert!(
                !case.reason_if_low.is_empty(),
                "{}: reason_if_low must not be empty",
                case.name
            );
            assert!(
                case.min_total_artifacts > 0,
                "{}: min_total_artifacts must be > 0 (floor of 1 catches total breakage)",
                case.name
            );
        }
    }

    #[test]
    fn charlie_and_jo_have_per_plugin_guards() {
        let must_have_guards = ["charlie-2009-11-12", "jo-2009-11-16"];
        for name in must_have_guards {
            let case = V12_BASELINE_CASES
                .iter()
                .find(|c| c.name == name)
                .expect("baseline case present");
            assert!(
                !case.min_per_plugin.is_empty(),
                "{name}: Windows baseline images must have per-plugin floors"
            );
            let has_phantom = case
                .min_per_plugin
                .iter()
                .any(|(p, _)| *p == "Strata Phantom");
            let has_vector = case
                .min_per_plugin
                .iter()
                .any(|(p, _)| *p == "Strata Vector");
            assert!(has_phantom, "{name}: must guard Phantom");
            assert!(has_vector, "{name}: must guard Vector");
        }
    }

    #[test]
    fn case_result_variants_discriminate() {
        // Compile-time + match-coverage sanity check.
        let r = CaseResult::Skipped("x");
        let r2 = CaseResult::Ran {
            total: 42,
            per_plugin: HashMap::new(),
        };
        let r3 = CaseResult::Errored("e".into());
        for r in [r, r2, r3] {
            match r {
                CaseResult::Skipped(_) | CaseResult::Ran { .. } | CaseResult::Errored(_) => {}
            }
        }
    }

    #[test]
    fn test_material_lookup_is_consistent() {
        // Whichever answer this returns, it must be idempotent across
        // calls (no flapping cache issues).
        let a = test_material_root();
        let b = test_material_root();
        assert_eq!(a, b);
    }
}
