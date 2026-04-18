//! TRUTH-1/2 — ground-truth regression tests for real forensic images.
//!
//! Each test skips cleanly when its image is not present under
//! `~/Wolfmark/Test Material/`. When images are present AND the v10
//! FS walkers have landed, these tests enforce minimum artifact
//! counts so future regressions that reduce extraction fail CI.
//!
//! v9 caveat: the FS walkers (NTFS/APFS/ext4/FAT/HFS+) that
//! transform an E01 into a walkable tree were deferred to v10 per
//! SESSION_STATE_v9_BLOCKER.md. Until any one FS walker lands, the
//! assertions on E01 images are documented minimums but the tests
//! skip instead of asserting — so they don't fail CI while the work
//! is in flight. When FS walkers arrive, flip `WALKERS_LANDED` to
//! `true` to turn the assertions on.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::path::{Path, PathBuf};

const TEST_MATERIAL: &str = "/Users/randolph/Wolfmark/Test Material";

/// Flip this once a v10 FS walker ships and `strata ingest run
/// <E01>` produces artifacts. Until then, skip assertions.
const WALKERS_LANDED: bool = false;

struct Expected {
    image: &'static str,
    os: &'static str,
    min_total_artifacts: u64,
    min_per_plugin: &'static [(&'static str, u64)],
}

/// Ground-truth minimums. Numbers calibrated to the regression
/// expectations in SPRINTS_v9 (NPS Jean ≥100 total, Phantom ≥20;
/// Windows 7+ thousands; macOS/iOS/Android hundreds). Conservative —
/// 10% safety margin already applied.
const TRUTH: &[Expected] = &[
    Expected {
        image: "nps-2008-jean.E01",
        os: "WindowsXP",
        min_total_artifacts: 90,
        min_per_plugin: &[
            ("Strata Phantom", 18),
            ("Strata Chronicle", 13),
            ("Strata Trace", 9),
        ],
    },
    Expected {
        image: "charlie-2009-11-12.E01",
        os: "WindowsVista",
        min_total_artifacts: 90,
        min_per_plugin: &[("Strata Phantom", 15), ("Strata Chronicle", 10)],
    },
    Expected {
        image: "terry-2009-12-03.E01",
        os: "WindowsVista",
        min_total_artifacts: 90,
        min_per_plugin: &[("Strata Phantom", 15)],
    },
    Expected {
        image: "windows-ftkimager-first.E01",
        os: "Windows",
        min_total_artifacts: 45,
        min_per_plugin: &[("Strata Phantom", 9)],
    },
];

fn image_path(name: &str) -> PathBuf {
    Path::new(TEST_MATERIAL).join(name)
}

fn skip_if_missing(name: &str) -> bool {
    let p = image_path(name);
    if !p.exists() {
        eprintln!("SKIP: {} not present at {}", name, p.display());
        return true;
    }
    false
}

#[test]
fn nps_jean_ground_truth_minimums_documented() {
    // Calibration phase: assert the expectations are plausible
    // regardless of whether the image is present or the walkers are
    // ready. This test always runs and protects the TRUTH array
    // from silent corruption.
    let jean = TRUTH
        .iter()
        .find(|e| e.image == "nps-2008-jean.E01")
        .expect("NPS Jean entry in TRUTH");
    assert_eq!(jean.os, "WindowsXP");
    assert!(jean.min_total_artifacts >= 90);
    // Phantom must be in the per-plugin list with a non-trivial floor.
    let phantom = jean
        .min_per_plugin
        .iter()
        .find(|(n, _)| *n == "Strata Phantom")
        .expect("Phantom floor");
    assert!(phantom.1 >= 10);
}

#[test]
fn nps_jean_real_ingestion_when_walkers_land() {
    if skip_if_missing("nps-2008-jean.E01") {
        return;
    }
    if !WALKERS_LANDED {
        eprintln!(
            "SKIP: v10 FS walkers have not landed; E01 ingestion still yields 0 artifacts"
        );
        return;
    }
    let (total, by_plugin) = run_and_count("nps-2008-jean.E01");
    let expected = TRUTH
        .iter()
        .find(|e| e.image == "nps-2008-jean.E01")
        .expect("entry");
    assert!(
        total >= expected.min_total_artifacts,
        "NPS Jean produced {} artifacts; expected >= {}",
        total,
        expected.min_total_artifacts
    );
    for (plugin, min) in expected.min_per_plugin {
        let actual = by_plugin.get(*plugin).copied().unwrap_or(0);
        assert!(
            actual >= *min,
            "{} produced {} artifacts, expected >= {}",
            plugin,
            actual,
            min
        );
    }
}

#[test]
fn charlie_ground_truth_when_walkers_land() {
    if skip_if_missing("charlie-2009-11-12.E01") || !WALKERS_LANDED {
        return;
    }
    let (total, _) = run_and_count("charlie-2009-11-12.E01");
    let expected = TRUTH
        .iter()
        .find(|e| e.image == "charlie-2009-11-12.E01")
        .expect("entry");
    assert!(total >= expected.min_total_artifacts);
}

#[test]
fn terry_ground_truth_when_walkers_land() {
    if skip_if_missing("terry-2009-12-03.E01") || !WALKERS_LANDED {
        return;
    }
    let (total, _) = run_and_count("terry-2009-12-03.E01");
    let expected = TRUTH
        .iter()
        .find(|e| e.image == "terry-2009-12-03.E01")
        .expect("entry");
    assert!(total >= expected.min_total_artifacts);
}

#[test]
fn windows_ftkimager_ground_truth_when_walkers_land() {
    if skip_if_missing("windows-ftkimager-first.E01") || !WALKERS_LANDED {
        return;
    }
    let (total, _) = run_and_count("windows-ftkimager-first.E01");
    let expected = TRUTH
        .iter()
        .find(|e| e.image == "windows-ftkimager-first.E01")
        .expect("entry");
    assert!(total >= expected.min_total_artifacts);
}

fn run_and_count(_image_name: &str) -> (u64, std::collections::HashMap<String, u64>) {
    // Placeholder until FS walkers land. When walkers ship:
    //  1. `let image = strata_evidence::open_evidence(&image_path(image_name))?;`
    //  2. walk partitions, mount filesystems, build CompositeVfs
    //  3. call run_all_with_persistence with that VFS as root
    //  4. query the artifacts.sqlite count + count_by_plugin
    // For now we return zeros so the skip-guarded tests never run
    // past their early-return; the `_documented` test above keeps
    // the TRUTH array honest.
    (0, std::collections::HashMap::new())
}
