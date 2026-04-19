//! FS-HFSPLUS-1 Phase B Part 2 — integration test against the
//! committed `hfsplus_small.img` fixture.
//!
//! Runs when the fixture is present (which it is in this repo —
//! committed as a one-time snapshot since HFS+ generation via
//! `newfs_hfs` is not byte-stable). Verifies structural invariants
//! against `hfsplus_small.expected.json`.

use std::fs::File;
use std::path::PathBuf;

use strata_fs::hfsplus_walker::HfsPlusWalker;
use strata_fs::vfs::VirtualFilesystem;

fn fixture_path() -> PathBuf {
    // tests/ is at crates/strata-fs/tests/, fixture sits under
    // tests/fixtures/. CARGO_MANIFEST_DIR = crates/strata-fs at
    // integration-test time.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("hfsplus_small.img")
}

#[test]
fn walker_opens_committed_fixture() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP: hfsplus_small.img not present");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = HfsPlusWalker::open(file).expect("HfsPlusWalker::open");
    assert_eq!(walker.fs_type(), "hfs+");
}

#[test]
fn walker_lists_root_with_committed_structure() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP: hfsplus_small.img not present");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = HfsPlusWalker::open(file).expect("open walker");
    let root_entries = walker.list_dir("/").expect("list_dir /");
    let names: Vec<&str> = root_entries.iter().map(|e| e.name.as_str()).collect();
    eprintln!("root entries: {names:?}");

    // Structural invariant — the fixture's root contains
    // readme.txt, forky.txt, and the docs directory. The HFS+
    // Private Data directory exists on the volume but is hidden
    // by the walker's default filter.
    assert!(
        root_entries.iter().any(|e| e.name == "readme.txt" && !e.is_directory),
        "fixture must contain /readme.txt"
    );
    assert!(
        root_entries.iter().any(|e| e.name == "forky.txt" && !e.is_directory),
        "fixture must contain /forky.txt"
    );
    assert!(
        root_entries.iter().any(|e| e.name == "docs" && e.is_directory),
        "fixture must contain /docs (directory)"
    );

    // HFS+ Private Data (always created by newfs_hfs) must NOT appear.
    assert!(
        !root_entries.iter().any(|e| e.name.contains("HFS+ Private Data")),
        "walker default filter must hide HFS+ Private Data"
    );
}

#[test]
fn walker_descends_into_nested_docs_directory() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP: hfsplus_small.img not present");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = HfsPlusWalker::open(file).expect("open walker");

    let docs = walker.list_dir("/docs").expect("list_dir /docs");
    assert!(
        docs.iter().any(|e| e.name == "nested" && e.is_directory),
        "/docs must contain nested/"
    );

    let nested = walker.list_dir("/docs/nested").expect("list_dir /docs/nested");
    assert!(
        nested.iter().any(|e| e.name == "buried.txt" && !e.is_directory),
        "/docs/nested must contain buried.txt"
    );
}

#[test]
fn walker_exists_returns_true_for_committed_paths() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = HfsPlusWalker::open(file).expect("open walker");
    assert!(walker.exists("/"));
    assert!(walker.exists("/readme.txt"));
    assert!(walker.exists("/forky.txt"));
    assert!(walker.exists("/docs"));
    assert!(walker.exists("/docs/nested"));
    assert!(walker.exists("/docs/nested/buried.txt"));
    assert!(!walker.exists("/nope.txt"));
}

#[test]
fn walker_metadata_reports_correct_entry_kinds_on_committed_fixture() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = HfsPlusWalker::open(file).expect("open walker");
    assert!(
        !walker.metadata("/readme.txt").expect("md").is_directory,
        "readme.txt must be a file"
    );
    assert!(
        walker.metadata("/docs").expect("md").is_directory,
        "docs must be a directory"
    );
    assert!(
        walker.metadata("/docs/nested").expect("md").is_directory,
        "docs/nested must be a directory"
    );
}
