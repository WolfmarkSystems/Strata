//! FS-FAT-1 Phase B — integration test against the committed
//! `fat16_small.img` fixture.
//!
//! Runs when the fixture is present (committed one-time snapshot —
//! `newfs_msdos -F 16` is not fully deterministic across macOS
//! versions but the user-visible structure is stable). Verifies
//! structural invariants against the known content populated by
//! the session-E generation flow: `/readme.txt`, `/big.bin`
//! (multi-cluster), `/Long Filename Example.txt` (LFN chain), and
//! `/dir1/dir2/dir3/deep.txt` (three-level nested directory).
//!
//! This test is the AUTHORITATIVE spec-conformance check for the
//! FAT walker. Session D proved that synth-test-lockstep can hide
//! parser bugs through entire sessions; the real fixture catches
//! them.

use std::fs::File;
use std::path::PathBuf;

use strata_fs::fat_walker::FatWalker;
use strata_fs::vfs::VirtualFilesystem;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("fat16_small.img")
}

#[test]
fn walker_opens_committed_fixture() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP: fat16_small.img not present");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = FatWalker::open(file).expect("FatWalker::open");
    let ft = walker.fs_type();
    eprintln!("detected variant: {ft}");
    assert_eq!(ft, "fat16");
}

#[test]
fn walker_lists_root_with_expected_files_and_directory() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = FatWalker::open(file).expect("open walker");
    let entries = walker.list_dir("/").expect("list_dir /");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    eprintln!("root: {names:?}");

    // Structural invariants — the committed fixture's root
    // contains these four entries plus any macOS-default artifacts
    // that dot_clean didn't remove.
    assert!(
        entries
            .iter()
            .any(|e| e.name == "readme.txt" && !e.is_directory),
        "fixture must contain /readme.txt"
    );
    assert!(
        entries
            .iter()
            .any(|e| e.name == "big.bin" && !e.is_directory),
        "fixture must contain /big.bin"
    );
    // LFN: the actual long filename MUST be surfaced, not the
    // ~1-style short name. This is the spec-conformance check for
    // the LFN checksum algorithm — if short_name_checksum is wrong,
    // this assertion fails and the long name is replaced by the
    // short form.
    assert!(
        entries
            .iter()
            .any(|e| e.name == "Long Filename Example.txt" && !e.is_directory),
        "LFN assembly must surface the long name, not the short form"
    );
    assert!(
        entries.iter().any(|e| e.name == "dir1" && e.is_directory),
        "fixture must contain /dir1 as a directory"
    );
    // Volume label must NOT appear in enumeration.
    assert!(
        !entries.iter().any(|e| e.name.contains("STRATAFAT")),
        "volume-label entry must be filtered out of list_dir output"
    );
}

#[test]
fn walker_descends_three_levels_into_nested_directory() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = FatWalker::open(file).expect("open walker");
    let d1 = walker.list_dir("/dir1").expect("list_dir /dir1");
    assert!(d1.iter().any(|e| e.name == "dir2" && e.is_directory));
    let d2 = walker.list_dir("/dir1/dir2").expect("list_dir /dir1/dir2");
    assert!(d2.iter().any(|e| e.name == "dir3" && e.is_directory));
    let d3 = walker
        .list_dir("/dir1/dir2/dir3")
        .expect("list_dir /dir1/dir2/dir3");
    assert!(d3.iter().any(|e| e.name == "deep.txt" && !e.is_directory));
}

#[test]
fn walker_reads_single_cluster_file_contents() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = FatWalker::open(file).expect("open walker");
    let bytes = walker.read_file("/readme.txt").expect("read readme");
    // Populated as `printf 'hello fat16\n'` → 12 bytes.
    assert_eq!(bytes, b"hello fat16\n");
}

#[test]
fn walker_reads_multi_cluster_file_following_chain() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = FatWalker::open(file).expect("open walker");
    // big.bin = 'X' × 5000. With cluster_size = 2048, this spans
    // 3 clusters. A cluster-chain following bug (wrong EOC, wrong
    // FAT16 entry decode) silently produces shorter content.
    let bytes = walker.read_file("/big.bin").expect("read big.bin");
    assert_eq!(bytes.len(), 5000, "multi-cluster file must be fully read");
    assert!(bytes.iter().all(|&b| b == b'X'), "every byte must be 'X'");
}

#[test]
fn walker_reads_lfn_file_matching_long_name() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = FatWalker::open(file).expect("open walker");
    let bytes = walker
        .read_file("/Long Filename Example.txt")
        .expect("read LFN file");
    // Populated as `printf 'needs long filename\n'` → 20 bytes.
    assert_eq!(bytes, b"needs long filename\n");
}

#[test]
fn walker_reads_deep_nested_file() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = FatWalker::open(file).expect("open walker");
    let bytes = walker
        .read_file("/dir1/dir2/dir3/deep.txt")
        .expect("read deep.txt");
    assert_eq!(bytes, b"buried\n");
}

#[test]
fn walker_exists_positive_and_negative() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = FatWalker::open(file).expect("open walker");
    assert!(walker.exists("/"));
    assert!(walker.exists("/readme.txt"));
    assert!(walker.exists("/big.bin"));
    assert!(walker.exists("/Long Filename Example.txt"));
    assert!(walker.exists("/dir1"));
    assert!(walker.exists("/dir1/dir2/dir3/deep.txt"));
    assert!(!walker.exists("/nope.txt"));
    assert!(!walker.exists("/dir1/nonexistent"));
}

#[test]
fn walker_metadata_reports_correct_sizes_on_fixture() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("SKIP");
        return;
    }
    let file = File::open(&path).expect("open fixture");
    let walker = FatWalker::open(file).expect("open walker");

    let readme = walker.metadata("/readme.txt").expect("md readme");
    assert_eq!(readme.size, 12);
    assert!(!readme.is_directory);

    let big = walker.metadata("/big.bin").expect("md big");
    assert_eq!(big.size, 5000);

    let dir1 = walker.metadata("/dir1").expect("md dir1");
    assert!(dir1.is_directory);
}
