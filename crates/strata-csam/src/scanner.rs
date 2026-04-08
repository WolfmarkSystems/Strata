//! CSAM scanner.
//!
//! The scanner walks an [`EvidenceSource`] via its
//! [`VirtualFileSystem`](strata_fs::virtualization::VirtualFileSystem),
//! computes file hashes, and produces [`CsamHit`]s without ever
//! rendering image content.
//!
//! ## Threading model
//!
//! Cryptographic hashing of every file is parallelised with rayon.
//! For multi-hundred-GB evidence, hashes are computed in 1 MB streaming
//! chunks via `read_file_range` so memory usage stays bounded.
//!
//! Image bytes are only loaded in full when perceptual scanning is
//! enabled AND the file matches the configured image-extension list.
//! Image files are typically <50 MB so this stays within memory limits.
//!
//! ## Tie-breaking on perceptual hash matches
//!
//! [`PerceptualHashDb::find_match`] returns the **strictly closest**
//! match within the configured threshold. If two stored hashes have
//! the same Hamming distance to the query, **the first-added hash
//! wins** (insertion order from import). The scanner records the
//! exact match in `CsamHit::match_source` and `perceptual_distance`,
//! so the audit trail and the examiner can always see which source
//! identifier won the tie.

use anyhow::{anyhow, Result};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;

use strata_fs::container::EvidenceSource;
use strata_fs::virtualization::{VfsEntry, VirtualFileSystem};

use crate::hash_db::CsamHashDb;
use crate::perceptual::{self, PerceptualHashDb};
use crate::{Confidence, CsamHit, MatchType};

/// Chunk size for streaming-hash reads (1 MB).
const HASH_CHUNK: u64 = 1024 * 1024;

pub struct CsamScanner {
    pub(crate) hash_dbs: Vec<CsamHashDb>,
    pub(crate) perceptual_db: Option<PerceptualHashDb>,
    pub(crate) scan_id: uuid::Uuid,
    pub(crate) examiner: String,
    pub(crate) case_number: String,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Always true — exact-hash scanning is the baseline.
    pub run_exact_hash: bool,
    /// Opt-in: perceptual scanning is more expensive and decode-bound.
    pub run_perceptual: bool,
    /// Hamming-distance cutoff for perceptual matches (default 10).
    pub perceptual_threshold: u32,
    pub image_extensions: Vec<String>,
    /// If true, scan every file regardless of extension.
    pub scan_all_files: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            run_exact_hash: true,
            run_perceptual: false,
            perceptual_threshold: 10,
            image_extensions: vec![
                "jpg".into(),
                "jpeg".into(),
                "png".into(),
                "bmp".into(),
                "gif".into(),
                "tiff".into(),
                "webp".into(),
            ],
            scan_all_files: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub files_scanned: usize,
    pub files_total: usize,
    pub hits_found: usize,
    pub current_file: String,
}

impl CsamScanner {
    pub fn new(examiner: &str, case_number: &str) -> Self {
        Self {
            hash_dbs: Vec::new(),
            perceptual_db: None,
            scan_id: uuid::Uuid::new_v4(),
            examiner: examiner.to_string(),
            case_number: case_number.to_string(),
        }
    }

    pub fn add_hash_db(&mut self, db: CsamHashDb) {
        self.hash_dbs.push(db);
    }

    pub fn set_perceptual_db(&mut self, db: PerceptualHashDb) {
        self.perceptual_db = Some(db);
    }

    pub fn scan_id(&self) -> uuid::Uuid {
        self.scan_id
    }

    pub fn examiner(&self) -> &str {
        &self.examiner
    }

    pub fn case_number(&self) -> &str {
        &self.case_number
    }

    pub fn hash_dbs(&self) -> &[CsamHashDb] {
        &self.hash_dbs
    }

    /// Scan a single in-memory file. Used by tests and by callers
    /// that already have file bytes (e.g. plugins operating on
    /// pre-extracted artefacts).
    ///
    /// `path` is recorded verbatim in the resulting [`CsamHit`].
    pub fn scan_file(
        &self,
        path: &str,
        file_bytes: &[u8],
        config: &ScanConfig,
    ) -> Result<Option<CsamHit>> {
        let file_size = file_bytes.len() as u64;
        let (md5, sha1, sha256) = hash_bytes(file_bytes);

        let want_perceptual = config.run_perceptual
            && self.perceptual_db.is_some()
            && (config.scan_all_files
                || is_image_extension(Path::new(path), &config.image_extensions));
        let dhash = if want_perceptual {
            perceptual::compute_dhash(file_bytes)
        } else {
            None
        };

        Ok(self.match_hashes(path.to_string(), file_size, md5, sha1, sha256, dhash, config))
    }

    /// Scan every reachable file in `source` and return all hits.
    ///
    /// Walking is serial (single-threaded directory enumeration);
    /// hashing and matching are parallelised across rayon's pool.
    /// `progress_tx` receives one update per scanned file.
    pub fn scan_evidence(
        &self,
        source: &EvidenceSource,
        config: &ScanConfig,
        progress_tx: Sender<ScanProgress>,
    ) -> Result<Vec<CsamHit>> {
        let vfs = source
            .vfs_ref()
            .ok_or_else(|| anyhow!("evidence source has no VFS"))?;

        // Phase 1 — walk to collect candidate files. Serial; parallelism
        // here would just thrash on directory enumeration.
        let mut all_files = Vec::new();
        walk_vfs(vfs, &mut all_files);

        // Phase 2 — apply extension filter.
        let candidates: Vec<VfsEntry> = if config.scan_all_files {
            all_files
        } else {
            all_files
                .into_iter()
                .filter(|f| is_image_extension(&f.path, &config.image_extensions))
                .collect()
        };

        let total = candidates.len();
        let scanned = AtomicUsize::new(0);
        let hit_count = AtomicUsize::new(0);

        // Phase 3 — parallel hash + match. `map_with` clones the
        // sender once per worker thread; rayon's mpsc-style fan-in
        // is then handled by std's mpsc receiver on the parent side.
        let hits: Vec<CsamHit> = candidates
            .par_iter()
            .map_with(progress_tx, |tx, entry| {
                let display_path = entry.path.to_string_lossy().into_owned();

                let result = self.scan_vfs_file(vfs, entry, config);
                let n = scanned.fetch_add(1, Ordering::Relaxed) + 1;

                let hit_opt = match result {
                    Ok(opt) => opt,
                    Err(e) => {
                        tracing::warn!(
                            "[csam] scan failed for {}: {:#}",
                            display_path,
                            e
                        );
                        None
                    }
                };

                let hits_so_far = if hit_opt.is_some() {
                    hit_count.fetch_add(1, Ordering::Relaxed) + 1
                } else {
                    hit_count.load(Ordering::Relaxed)
                };

                let _ = tx.send(ScanProgress {
                    files_scanned: n,
                    files_total: total,
                    hits_found: hits_so_far,
                    current_file: display_path,
                });

                hit_opt
            })
            .filter_map(|x| x)
            .collect();

        Ok(hits)
    }

    /// Hash + match a single VFS entry, choosing streaming or
    /// full-buffer access based on whether perceptual scanning is
    /// requested for this file.
    fn scan_vfs_file(
        &self,
        vfs: &dyn VirtualFileSystem,
        entry: &VfsEntry,
        config: &ScanConfig,
    ) -> Result<Option<CsamHit>> {
        let path = &entry.path;
        let file_size = entry.size;

        let is_image = is_image_extension(path, &config.image_extensions);
        let want_perceptual =
            config.run_perceptual && is_image && self.perceptual_db.is_some();

        let (md5, sha1, sha256, dhash) = if want_perceptual {
            // Image file with perceptual scanning enabled — load whole
            // file once, hash and decode from the same buffer.
            let bytes = vfs
                .open_file(path)
                .map_err(|e| anyhow!("vfs open_file({}): {:?}", path.display(), e))?;
            let (m, s1, s256) = hash_bytes(&bytes);
            let dh = perceptual::compute_dhash(&bytes);
            (m, s1, s256, dh)
        } else {
            // Stream-hash from the VFS in 1 MB chunks. No buffering of
            // the file contents — works for arbitrary file sizes.
            let (m, s1, s256) = hash_streaming(vfs, path, file_size)?;
            (m, s1, s256, None)
        };

        Ok(self.match_hashes(
            path.to_string_lossy().into_owned(),
            file_size,
            md5,
            sha1,
            sha256,
            dhash,
            config,
        ))
    }

    /// Decide whether the given (md5, sha1, sha256, optional dhash)
    /// quartet matches any loaded hash database, and synthesise a
    /// [`CsamHit`] if so.
    ///
    /// Match priority:
    /// 1. Exact crypto-hash match across all `hash_dbs` (strongest first
    ///    via `CsamHashDb::lookup_any`)
    /// 2. Perceptual match against `perceptual_db`, if enabled
    ///
    /// On perceptual ties (same Hamming distance to multiple stored
    /// hashes), `PerceptualHashDb::find_match` returns the first-added
    /// hash. The selected source is recorded in `match_source` so the
    /// audit trail reflects exactly which entry was matched.
    #[allow(clippy::too_many_arguments)]
    fn match_hashes(
        &self,
        file_path: String,
        file_size: u64,
        md5: String,
        sha1: String,
        sha256: String,
        dhash: Option<u64>,
        config: &ScanConfig,
    ) -> Option<CsamHit> {
        if config.run_exact_hash {
            for db in &self.hash_dbs {
                if let Some(match_type) = db.lookup_any(&md5, &sha1, &sha256) {
                    return Some(CsamHit {
                        hit_id: uuid::Uuid::new_v4(),
                        file_path,
                        file_size,
                        md5,
                        sha1,
                        sha256,
                        match_type,
                        match_source: db.name.clone(),
                        perceptual_hash: dhash.map(perceptual::dhash_to_hex),
                        perceptual_distance: None,
                        confidence: Confidence::Confirmed,
                        timestamp_utc: chrono::Utc::now(),
                        examiner_reviewed: false,
                        examiner_confirmed: false,
                        examiner_notes: String::new(),
                    });
                }
            }
        }

        if let (Some(dh), Some(pdb)) = (dhash, &self.perceptual_db) {
            if let Some((distance, source)) = pdb.find_match(dh) {
                if let Some(confidence) = Confidence::from_perceptual_distance(distance) {
                    return Some(CsamHit {
                        hit_id: uuid::Uuid::new_v4(),
                        file_path,
                        file_size,
                        md5,
                        sha1,
                        sha256,
                        match_type: MatchType::Perceptual,
                        match_source: source.to_string(),
                        perceptual_hash: Some(perceptual::dhash_to_hex(dh)),
                        perceptual_distance: Some(distance),
                        confidence,
                        timestamp_utc: chrono::Utc::now(),
                        examiner_reviewed: false,
                        examiner_confirmed: false,
                        examiner_notes: String::new(),
                    });
                }
            }
        }

        None
    }
}

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

/// Compute MD5, SHA1, SHA256 of the given byte slice in one pass.
fn hash_bytes(bytes: &[u8]) -> (String, String, String) {
    let mut md5 = md5::Md5::new();
    let mut sha1 = sha1::Sha1::new();
    let mut sha256 = sha2::Sha256::new();
    md5.update(bytes);
    sha1.update(bytes);
    sha256.update(bytes);
    (
        format!("{:x}", md5.finalize()),
        format!("{:x}", sha1.finalize()),
        format!("{:x}", sha256.finalize()),
    )
}

/// Stream-hash a file from the VFS in fixed-size chunks. Memory usage
/// is bounded by `HASH_CHUNK` regardless of file size.
fn hash_streaming(
    vfs: &dyn VirtualFileSystem,
    path: &Path,
    file_size: u64,
) -> Result<(String, String, String)> {
    let mut md5 = md5::Md5::new();
    let mut sha1 = sha1::Sha1::new();
    let mut sha256 = sha2::Sha256::new();

    let mut offset: u64 = 0;
    while offset < file_size {
        let want = HASH_CHUNK.min(file_size - offset) as usize;
        let chunk = vfs
            .read_file_range(path, offset, want)
            .map_err(|e| anyhow!("read_file_range {} @ {}: {:?}", path.display(), offset, e))?;
        if chunk.is_empty() {
            break;
        }
        md5.update(&chunk);
        sha1.update(&chunk);
        sha256.update(&chunk);
        offset += chunk.len() as u64;
    }

    Ok((
        format!("{:x}", md5.finalize()),
        format!("{:x}", sha1.finalize()),
        format!("{:x}", sha256.finalize()),
    ))
}

/// Recursively enumerate every non-directory entry reachable from the
/// VFS root. Permission errors and unreadable subtrees are logged and
/// skipped — a single bad directory must not abort an evidence scan.
fn walk_vfs(vfs: &dyn VirtualFileSystem, out: &mut Vec<VfsEntry>) {
    let mut stack: Vec<PathBuf> = vec![PathBuf::from("/")];
    while let Some(dir) = stack.pop() {
        match vfs.read_dir(&dir) {
            Ok(entries) => {
                for entry in entries {
                    if entry.is_dir {
                        stack.push(entry.path.clone());
                    } else {
                        out.push(entry);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "[csam] read_dir failed for {}: {:?}",
                    dir.display(),
                    e
                );
            }
        }
    }
}

fn is_image_extension(path: &Path, exts: &[String]) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(e) => {
            let lower = e.to_ascii_lowercase();
            exts.iter().any(|x| x == &lower)
        }
        None => false,
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_db::CsamHashDb;
    use std::io::Write;
    use std::sync::mpsc::channel;
    use tempfile::{NamedTempFile, TempDir};

    /// Build an in-memory hash DB from a single SHA256 hex string.
    /// Goes through the public `import_from_file` path so the test
    /// exercises the same code path examiners use.
    fn db_with_sha256(hash: &str, name: &str) -> CsamHashDb {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "{}", hash).unwrap();
        f.flush().unwrap();
        CsamHashDb::import_from_file(f.path(), "test_examiner", name).unwrap()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = sha2::Sha256::new();
        h.update(bytes);
        format!("{:x}", h.finalize())
    }

    #[test]
    fn scan_file_returns_hit_on_exact_sha256_match() {
        let payload = b"this is the file content for csam scanner test";
        let target_sha256 = sha256_hex(payload);

        let mut scanner = CsamScanner::new("examiner_a", "CASE-001");
        scanner.add_hash_db(db_with_sha256(&target_sha256, "test_db"));

        let cfg = ScanConfig {
            scan_all_files: true,
            ..Default::default()
        };
        let hit = scanner
            .scan_file("evidence/payload.bin", payload, &cfg)
            .unwrap()
            .expect("expected a hit");

        assert_eq!(hit.match_type, MatchType::ExactSha256);
        assert_eq!(hit.confidence, Confidence::Confirmed);
        assert_eq!(hit.match_source, "test_db");
        assert_eq!(hit.sha256, target_sha256);
        assert_eq!(hit.file_path, "evidence/payload.bin");
        assert!(!hit.examiner_reviewed);
        assert!(!hit.examiner_confirmed);
    }

    #[test]
    fn scan_file_returns_none_when_no_match() {
        let mut scanner = CsamScanner::new("ex", "case");
        scanner.add_hash_db(db_with_sha256(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "empty_db",
        ));

        let cfg = ScanConfig {
            scan_all_files: true,
            ..Default::default()
        };
        let hit = scanner
            .scan_file("path.txt", b"different bytes", &cfg)
            .unwrap();
        assert!(hit.is_none());
    }

    #[test]
    fn scan_file_skips_non_image_when_extension_filter_active() {
        // Even if the bytes match, an exact-hash scan with the
        // extension filter active will still match because exact-hash
        // doesn't depend on extension. This test confirms perceptual
        // is gated correctly: non-image extension + perceptual config
        // → no perceptual computation, so perceptual_hash is None.
        let payload = b"plain text not an image";

        let mut scanner = CsamScanner::new("ex", "case");
        let mut pdb = PerceptualHashDb::new();
        pdb.add_hash(0, "ref"); // any value
        scanner.set_perceptual_db(pdb);

        let cfg = ScanConfig {
            run_perceptual: true,
            scan_all_files: false,
            ..Default::default()
        };

        // .txt is not in the image extension list — perceptual is
        // skipped, exact hashing still runs but no DB is loaded so
        // there's no exact-hash hit either.
        let hit = scanner
            .scan_file("readme.txt", payload, &cfg)
            .unwrap();
        assert!(hit.is_none());
    }

    #[test]
    fn scan_evidence_walks_directory_and_hits_one_file() {
        let dir = TempDir::new().unwrap();
        let target_path = dir.path().join("subdir").join("target.bin");
        std::fs::create_dir_all(target_path.parent().unwrap()).unwrap();

        let target_payload = b"some bytes that we will plant the hash of";
        std::fs::write(&target_path, target_payload).unwrap();
        // A second file that should NOT be matched.
        std::fs::write(dir.path().join("decoy.bin"), b"unrelated").unwrap();

        let target_sha256 = sha256_hex(target_payload);

        let source = EvidenceSource::open(dir.path()).unwrap();
        let mut scanner = CsamScanner::new("ex", "CASE-XYZ");
        scanner.add_hash_db(db_with_sha256(&target_sha256, "planted"));

        let (tx, rx) = channel();
        let cfg = ScanConfig {
            scan_all_files: true,
            ..Default::default()
        };
        let hits = scanner.scan_evidence(&source, &cfg, tx).unwrap();

        assert_eq!(hits.len(), 1, "expected exactly one hit, got {:?}", hits);
        assert_eq!(hits[0].sha256, target_sha256);
        assert_eq!(hits[0].match_type, MatchType::ExactSha256);
        assert!(hits[0].file_path.contains("target.bin"));

        // Progress channel must have produced at least 2 updates
        // (one per scanned file).
        let progress: Vec<_> = rx.try_iter().collect();
        assert!(progress.len() >= 2, "got {} progress updates", progress.len());
    }

    #[test]
    fn scan_evidence_extension_filter_skips_non_images() {
        let dir = TempDir::new().unwrap();
        // Plant a payload as .txt — extension filter should skip it.
        let payload = b"would-be evidence in a text file";
        std::fs::write(dir.path().join("evidence.txt"), payload).unwrap();

        let source = EvidenceSource::open(dir.path()).unwrap();
        let mut scanner = CsamScanner::new("ex", "case");
        scanner.add_hash_db(db_with_sha256(&sha256_hex(payload), "planted"));

        let (tx, _rx) = channel();
        let cfg = ScanConfig::default(); // scan_all_files = false
        let hits = scanner.scan_evidence(&source, &cfg, tx).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn scan_file_perceptual_match_records_distance_and_source() {
        // Build an image, compute its dhash, plant that dhash in
        // a perceptual db, then scan the SAME image — should hit
        // with distance 0 and Confidence::High.
        use image::{ImageFormat, Rgb, RgbImage};
        use std::io::Cursor;

        let mut img = RgbImage::new(64, 64);
        for y in 0..64 {
            for x in 0..64 {
                let v = ((x * 7 + y * 13) ^ (x * 3 + y * 11)) as u8;
                img.put_pixel(x, y, Rgb([v, v, v]));
            }
        }
        let mut bytes = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .unwrap();

        let dh = perceptual::compute_dhash(&bytes).unwrap();
        let mut pdb = PerceptualHashDb::new();
        pdb.add_hash(dh, "known_image_42.png");

        let mut scanner = CsamScanner::new("ex", "case");
        scanner.set_perceptual_db(pdb);

        let cfg = ScanConfig {
            run_perceptual: true,
            scan_all_files: false,
            ..Default::default()
        };
        let hit = scanner
            .scan_file("evidence/photo.png", &bytes, &cfg)
            .unwrap()
            .expect("expected a perceptual hit");

        assert_eq!(hit.match_type, MatchType::Perceptual);
        assert_eq!(hit.confidence, Confidence::High);
        assert_eq!(hit.perceptual_distance, Some(0));
        assert_eq!(hit.match_source, "known_image_42.png");
        assert!(hit.perceptual_hash.is_some());
    }

    #[test]
    fn scan_file_exact_hash_takes_priority_over_perceptual() {
        // If a file matches both an exact crypto hash AND a perceptual
        // hash, the exact match wins (Confidence::Confirmed).
        use image::{ImageFormat, Rgb, RgbImage};
        use std::io::Cursor;

        let mut img = RgbImage::new(32, 32);
        for y in 0..32 {
            for x in 0..32 {
                img.put_pixel(x, y, Rgb([(x * 8) as u8, (y * 8) as u8, 100]));
            }
        }
        let mut bytes = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .unwrap();

        let dh = perceptual::compute_dhash(&bytes).unwrap();
        let target_sha256 = sha256_hex(&bytes);

        let mut pdb = PerceptualHashDb::new();
        pdb.add_hash(dh, "perceptual_hit");

        let mut scanner = CsamScanner::new("ex", "case");
        scanner.add_hash_db(db_with_sha256(&target_sha256, "exact_hit_db"));
        scanner.set_perceptual_db(pdb);

        let cfg = ScanConfig {
            run_perceptual: true,
            scan_all_files: false,
            ..Default::default()
        };
        let hit = scanner
            .scan_file("evidence/photo.png", &bytes, &cfg)
            .unwrap()
            .expect("expected a hit");

        assert_eq!(hit.match_type, MatchType::ExactSha256);
        assert_eq!(hit.confidence, Confidence::Confirmed);
        assert_eq!(hit.match_source, "exact_hit_db");
    }
}
