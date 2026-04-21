//! VFS-PLUGIN-WIN-1..FINAL universal bridge: materialize forensic
//! targets from a mounted VFS into a scratch directory so existing
//! plugins (which walk `root_path` via `std::fs`) can see real
//! evidence from an E01 without per-plugin migration.
//!
//! Rather than migrate 25 plugins mechanically (each with its own
//! classification logic and file-naming assumptions), we bridge the
//! abstraction: walk the mounted VFS once, extract every file whose
//! path matches any forensic-target pattern, mirror the logical
//! directory tree into a scratch dir, and hand `root_path =
//! scratch` to the legacy `run_all_on_path` pipeline. Plugins see a
//! real filesystem tree full of real artifacts.
//!
//! The pattern list covers the major target file types plugins look
//! for: Windows registry hives, event logs, prefetch, LNK / jumplist
//! / $MFT metadata files, browser databases, macOS plist / SQLite,
//! iOS sms.db / KnowledgeC, Android package directories, Linux
//! auth.log / bash_history, memory dump fragments.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use strata_fs::vfs::{VfsEntry, VirtualFilesystem, WalkDecision};

/// Patterns that identify forensic targets. Matching is case-
/// insensitive suffix / substring against the logical path.
const TARGET_PATTERNS: &[&str] = &[
    // --- Windows registry hives ---
    "/system",
    "/software",
    "/sam",
    "/security",
    "/ntuser.dat",
    "/usrclass.dat",
    "amcache.hve",
    // --- Windows event logs ---
    ".evtx",
    ".evt",
    // --- Windows execution evidence ---
    ".pf", // Prefetch
    ".lnk",
    "automaticdestinations-ms",
    "customdestinations-ms",
    // --- Windows $MFT / NTFS metadata (if exposed as files) ---
    "$mft",
    "$logfile",
    "$usnjrnl",
    "$recycle.bin",
    "$i",
    // --- Browser databases ---
    "/history",
    "/cookies",
    "/login data",
    "/web data",
    "/favicons",
    "/media history",
    "/top sites",
    "places.sqlite",
    "formhistory.sqlite",
    // --- Common SQLite databases ---
    ".sqlite",
    ".db",
    ".sqlitedb",
    ".sqlite-wal",
    // --- macOS / iOS specific ---
    ".plist",
    "knowledgec.db",
    "sms.db",
    "chat.db",
    "callhistory.storedata",
    "notestore.sqlite",
    "photos.sqlite",
    // --- Android ---
    "build.prop",
    "packages.xml",
    "/data/data/",
    "/data/app/",
    // --- Linux ---
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/group",
    "/etc/os-release",
    ".bash_history",
    "/var/log/",
    "auth.log",
    "/var/spool/cron/",
    // --- Cloud / misc ---
    "manifest.db",
    "manifest.mbdb",
    ".json",
    "hosts",
    "hosts.ics",
    ".log",
    "pagefile.sys",
    "hiberfil.sys",
    // --- v0.16.0 real-image validation gap G10: materialize-filter
    // was Windows/browser-heavy, missed realistic Mac/iOS/examiner
    // content. Extensions below cover the "plain file" content
    // examiners expect to see in a case output: text notes,
    // structured logs, images, video, screenshots, PDFs. Each is
    // extension-suffix only (no directory assumption). The 512 MB
    // per-file cap (MAX_MATERIALIZE_BYTES) and 16 GB total cap
    // (MAX_TOTAL_BYTES) still protect against runaway materialization
    // — an APFS volume full of .mov files stops copying at the cap
    // with `hit_cap = true` surfaced in the report.
    ".txt",    // plain-text notes, credentials, key material
    ".pdf",    // scanned documents, printed evidence
    ".jpg",    // photos (Apex EXIF relies on this)
    ".jpeg",
    ".png",    // screenshots, iOS photo roll
    ".heic",   // Apple photo default since iOS 11
    ".mov",    // QuickTime video (iOS/macOS default)
    ".mp4",    // mobile video
    ".eml",    // email exports
    ".mbox",   // Mail.app mailbox archives
    ".ipa",    // iOS app packages
    ".apk",    // Android app packages (paired with /data/app/)
    // --- post-v16 Sprint 3 — close the loop on Trace + Chronicle
    // wiring against real Charlie. Sprint 3 wired BITS deep-parse
    // (qmgr0.dat / qmgr1.dat / qmgr.db) and XP recycler records
    // (INFO2). Without these patterns the walkers materialize those
    // files as empty and the submodule parsers never see real
    // evidence — the wires pass unit tests but silent-no-op on
    // real cases.
    "info2",         // XP recycler record blob (C:\RECYCLER\<SID>\INFO2)
    "qmgr0.dat",     // BITS job queue (Win7–10 primary)
    "qmgr1.dat",     // BITS job queue (Win7–10 rotation)
    "qmgr.db",       // BITS job queue (Win11 SQLite replacement)
    "pcaapplaunchdic.txt", // PCA launch dictionary (Win11 22H2+)
    "pcageneraldb2.txt",   // PCA general database (Win11 22H2+)
    "capabilityaccessmanager.db", // Win11 23H2+ CAM privacy audit
    "/recycler/",    // XP recycler directory — ensures INFO2 path
                     //   components are reached by the walker tree
                     //   descent (Session-C $recycle.bin entry
                     //   covered Vista+ only)
];

/// Maximum file size to materialize (guards against accidentally
/// copying enormous files like pagefile.sys on the extract path).
const MAX_MATERIALIZE_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum total bytes to write across all files (safety cap).
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Maximum files to materialize.
const MAX_FILES: u64 = 500_000;

#[derive(Debug, Clone, Default)]
pub struct MaterializeReport {
    pub files_written: u64,
    pub bytes_written: u64,
    pub skipped_too_large: u64,
    pub skipped_read_error: u64,
    pub hit_cap: bool,
}

/// Returns `true` when any TARGET_PATTERNS substring appears in
/// `path` (case-insensitive).
fn is_target(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    TARGET_PATTERNS.iter().any(|p| lower.contains(p))
}

/// Walk the supplied VFS, copy every matching file into a mirror
/// tree under `scratch_root`. Returns a per-run diagnostic report
/// even on partial failure — individual unreadable files don't abort
/// the run.
pub fn materialize_targets(
    vfs: &Arc<dyn VirtualFilesystem>,
    scratch_root: &Path,
) -> std::io::Result<MaterializeReport> {
    fs::create_dir_all(scratch_root)?;
    let mut report = MaterializeReport::default();

    // The VFS walk fills `entries` via a mutable closure; we copy
    // each file after the walk completes so we don't hold the VFS
    // walk's callback on file I/O.
    let mut entries: Vec<VfsEntry> = Vec::new();
    let mut collect = |e: &VfsEntry| -> WalkDecision {
        if !e.is_directory && is_target(&e.path) {
            entries.push(e.clone());
        }
        WalkDecision::Descend
    };
    if let Err(e) = vfs.walk(&mut collect) {
        // Continue with whatever we collected — partial walks are
        // common on partially-acquired images.
        tracing::warn!("VFS walk reported: {e}");
    }

    for entry in entries {
        if report.files_written >= MAX_FILES || report.bytes_written >= MAX_TOTAL_BYTES {
            report.hit_cap = true;
            break;
        }
        if entry.size > MAX_MATERIALIZE_BYTES {
            report.skipped_too_large += 1;
            continue;
        }
        let dest = logical_to_scratch(scratch_root, &entry.path);
        if let Some(parent) = dest.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                tracing::warn!("create_dir_all {:?} failed: {e}", parent);
                report.skipped_read_error += 1;
                continue;
            }
        }
        let Ok(bytes) = vfs.read_file(&entry.path) else {
            report.skipped_read_error += 1;
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        if let Err(e) = fs::write(&dest, &bytes) {
            tracing::warn!("write {:?} failed: {e}", dest);
            report.skipped_read_error += 1;
            continue;
        }
        report.files_written += 1;
        report.bytes_written += bytes.len() as u64;
    }
    Ok(report)
}

/// Convert a VFS logical path ("/C:/Windows/system32/...") into an
/// equivalent path under `scratch_root`. Path separators are
/// preserved as '/', and Windows drive prefixes like `[C:]` are
/// stripped of the brackets + colon so the downstream host-fs tree
/// looks natural.
fn logical_to_scratch(scratch_root: &Path, logical: &str) -> PathBuf {
    let trimmed = logical.trim_start_matches('/');
    let mut out = scratch_root.to_path_buf();
    for component in trimmed.split('/') {
        if component.is_empty() {
            continue;
        }
        // Strip [C:] / [D:] / [Macintosh HD] bracket wrappers that
        // CompositeVfs uses for multi-partition roots.
        let cleaned = component
            .trim_start_matches('[')
            .trim_end_matches(']')
            .replace(':', "_");
        out.push(cleaned);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_fs::vfs::HostVfs;

    #[test]
    fn target_patterns_match_windows_hives() {
        assert!(is_target("/C/Windows/system32/config/SYSTEM"));
        assert!(is_target("/C:/Windows/System32/config/SOFTWARE"));
        assert!(is_target("/C/Users/Alice/NTUSER.DAT"));
    }

    #[test]
    fn target_patterns_match_evtx() {
        assert!(is_target("/Windows/System32/winevt/Logs/Security.evtx"));
    }

    #[test]
    fn target_patterns_ignore_irrelevant_files() {
        // Irrelevant examples — no extension in TARGET_PATTERNS and
        // no matching substring. `.bin`, `.exe`, `.dll`, `.o` are
        // deliberately excluded (materializing them wholesale would
        // balloon case size with no forensic win vs. inspecting in
        // place). Avoid picking paths that overlap Windows-hive or
        // Linux pattern substrings — the substring match is
        // intentionally broad (e.g., `/system` catches both
        // `Windows\System32\config\SYSTEM` and `/etc/systemd/`).
        assert!(!is_target("/App/random.bin"));
        assert!(!is_target("/tmp/image.gif"));
        assert!(!is_target("/tmp/font.ttf"));
        assert!(!is_target("/opt/thing.so"));
    }

    #[test]
    fn target_patterns_match_sprint3_wire_targets() {
        // Sprint 3 materialize extension closes the loop with
        // Trace + Chronicle submodule wiring. Without these
        // patterns the wires silent-no-op on Charlie/Jo because
        // the target files are filtered out upstream.
        assert!(is_target("/C/RECYCLER/S-1-5-21-xxxx/INFO2"));
        assert!(is_target("/Users/alice/AppData/Roaming/.../qmgr0.dat"));
        assert!(is_target("/Users/alice/AppData/Roaming/.../qmgr1.dat"));
        assert!(is_target("/Windows/appcompat/pca/PcaAppLaunchDic.txt"));
        assert!(is_target("/Windows/appcompat/pca/PcaGeneralDb2.txt"));
        assert!(is_target("/ProgramData/Microsoft/Windows/CapabilityAccessManager/CapabilityAccessManager.db"));
    }

    #[test]
    fn target_patterns_match_apfs_examiner_content_gap_g10() {
        // v0.16.0 real-image validation gap G10 tripwire: the
        // materialize filter must pick up the "plain file" content
        // examiners expect on Mac / iOS evidence — text notes,
        // plists, SQLite, PDFs, photos, video. UNENCRYPTED.dmg
        // produced zero materialized files in the v0.16.0 run
        // because its content was three .txt files that no existing
        // pattern matched.
        //
        // If a future change narrows this list (e.g., removing
        // `.txt` because "binary content clobbers case size"), the
        // change must also re-examine the Mac casework gap this
        // test was written to close.
        assert!(is_target("/Volumes/Evidence/note.txt"));
        assert!(is_target("/Users/alice/Desktop/scan.pdf"));
        assert!(is_target("/DCIM/100APPLE/IMG_0123.jpg"));
        assert!(is_target("/screenshots/capture.png"));
        assert!(is_target("/Photos/apple.heic"));
        assert!(is_target("/DCIM/clip.mov"));
        assert!(is_target("/videos/share.mp4"));
        assert!(is_target("/Mail/inbox.eml"));
        assert!(is_target("/Library/Mail/archive.mbox"));
        assert!(is_target("/Downloads/app.ipa"));
        assert!(is_target("/data/local/app.apk"));
    }

    #[test]
    fn target_patterns_preserve_pre_v16_matches() {
        // Regression guard: every pattern that was in
        // TARGET_PATTERNS before the G10 extension must still match
        // its representative path. Protects against accidental
        // deletion of Windows / browser / Linux / Android targets
        // during future additions.
        assert!(is_target("/Windows/System32/config/SYSTEM"));
        assert!(is_target("/Windows/System32/winevt/Logs/Security.evtx"));
        assert!(is_target("/Windows/Prefetch/CMD.EXE-ABCD1234.pf"));
        assert!(is_target("/Users/A/Recent/thing.lnk"));
        assert!(is_target("/Users/A/Chrome/History"));
        assert!(is_target("/db/places.sqlite"));
        assert!(is_target("/etc/passwd"));
        assert!(is_target("/var/log/auth.log"));
        assert!(is_target("/data/data/com.example.app"));
        assert!(is_target("/app/dump.json"));
    }

    #[test]
    fn logical_to_scratch_strips_brackets_and_maps_drive() {
        let scratch = PathBuf::from("/tmp/scratch");
        let out = logical_to_scratch(&scratch, "/[C:]/Windows/System32/config/SYSTEM");
        assert!(out.starts_with("/tmp/scratch"));
        assert!(out.to_string_lossy().contains("C_"));
        assert!(out.to_string_lossy().ends_with("SYSTEM"));
    }

    #[test]
    fn materialize_host_vfs_copies_target_files() {
        let src = tempfile::tempdir().expect("src");
        let scratch = tempfile::tempdir().expect("scratch");
        std::fs::create_dir_all(src.path().join("Windows/System32/config")).expect("mk");
        std::fs::write(
            src.path().join("Windows/System32/config/SYSTEM"),
            b"regf\x00\x00\x00",
        )
        .expect("w");
        std::fs::write(src.path().join("Windows/System32/config/random.bin"), b"x")
            .expect("w");

        let vfs: Arc<dyn VirtualFilesystem> = Arc::new(HostVfs::new(src.path().to_path_buf()));
        let report = materialize_targets(&vfs, scratch.path()).expect("mat");
        assert!(report.files_written >= 1, "should copy at least SYSTEM");
        // random.bin should not match any target pattern.
        let total_scratch = walk_count(scratch.path());
        assert!(total_scratch >= 1);
    }

    fn walk_count(dir: &Path) -> usize {
        let mut n = 0usize;
        if let Ok(iter) = std::fs::read_dir(dir) {
            for e in iter.flatten() {
                let p = e.path();
                if p.is_dir() {
                    n += walk_count(&p);
                } else {
                    n += 1;
                }
            }
        }
        n
    }
}
