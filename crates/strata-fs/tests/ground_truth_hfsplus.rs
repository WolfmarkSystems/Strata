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

// ── v16 Session 3 Sprint 2: FS-HFSPLUS-READFILE integration ────

#[test]
fn walker_reads_readme_txt_matches_populated_bytes() {
    // The mkhfsplus.sh script writes 'hello hfs+\n' (11 bytes)
    // into /readme.txt. Confirm the walker surfaces that exact
    // payload via the data-fork extent reader. First real-fixture
    // read_file test since the v15 Session D tripwire was flipped.
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = HfsPlusWalker::open(file).expect("open walker");
    let content = walker.read_file("/readme.txt").expect("read_file");
    assert_eq!(
        content,
        b"hello hfs+\n",
        "data fork content must match the bytes mkhfsplus.sh wrote"
    );
}

#[test]
fn walker_reads_nested_deep_file() {
    // /docs/nested/buried.txt — 3-level nested path, 'deep content\n'
    // (13 bytes). Exercises resolve_path_to_cnid walking three
    // directory levels + fork extent reading at the leaf.
    let path = fixture_path();
    if !path.exists() {
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = HfsPlusWalker::open(file).expect("open walker");
    let content = walker
        .read_file("/docs/nested/buried.txt")
        .expect("read deep");
    assert_eq!(content, b"deep content\n");
}

#[test]
fn walker_surfaces_resource_fork_as_rsrc_alternate_stream() {
    // /forky.txt has a 9-byte resource fork ("RSRC_DATA") per
    // mkhfsplus.sh: `printf 'RSRC_DATA' > "$MNT/forky.txt/..namedfork/rsrc"`.
    // Walker's alternate_streams("/forky.txt") must return
    // `["rsrc"]` and read_alternate_stream must return the bytes.
    let path = fixture_path();
    if !path.exists() {
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = HfsPlusWalker::open(file).expect("open walker");
    let streams = walker
        .alternate_streams("/forky.txt")
        .expect("alternate_streams");
    assert!(
        streams.iter().any(|s| s == "rsrc"),
        "expected 'rsrc' alternate stream on forky.txt, got {streams:?}"
    );
    let rsrc = walker
        .read_alternate_stream("/forky.txt", "rsrc")
        .expect("read rsrc");
    assert_eq!(
        rsrc, b"RSRC_DATA",
        "resource fork content must match mkhfsplus.sh's 9 bytes"
    );
}

#[test]
fn walker_reports_no_alternate_streams_for_non_fork_file() {
    // /readme.txt has a data fork but no resource fork.
    // alternate_streams must return an empty vec — not `["rsrc"]`,
    // not an error. Forensic correctness: walker must distinguish
    // present-empty resource forks from absent ones, and surface
    // only the ones the file actually has.
    let path = fixture_path();
    if !path.exists() {
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = HfsPlusWalker::open(file).expect("open walker");
    let streams = walker
        .alternate_streams("/readme.txt")
        .expect("alternate_streams");
    assert!(
        streams.is_empty(),
        "readme.txt has no resource fork; expected empty, got {streams:?}"
    );
    let rsrc = walker.read_alternate_stream("/readme.txt", "rsrc");
    match rsrc {
        Err(_) => {}
        Ok(bytes) => panic!(
            "read_alternate_stream(rsrc) on a file without a resource fork \
             must Err; got {} bytes",
            bytes.len()
        ),
    }
}

#[test]
fn walker_reads_forky_data_fork_matches_populated_bytes() {
    // Also verify the data fork on /forky.txt is surfaced
    // correctly — it's 'file with fork' in mkhfsplus.sh's
    // populate step (14 bytes).
    let path = fixture_path();
    if !path.exists() {
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = HfsPlusWalker::open(file).expect("open walker");
    let content = walker.read_file("/forky.txt").expect("read forky");
    // Committed fixture contains "file with fork\n" — 15 bytes
    // including trailing newline. The mkhfsplus.sh header comment
    // says 15 bytes; the `printf 'file with fork'` command in the
    // script doesn't append a newline, but the committed fixture
    // was populated with a trailing newline on the macOS run that
    // produced it. Real fixture bytes win over script comments
    // (per v15 Lesson 2) — this assertion pins the actual
    // committed content.
    assert_eq!(
        content, b"file with fork\n",
        "forky.txt data fork must match committed fixture bytes (15 bytes with trailing newline)"
    );
}
