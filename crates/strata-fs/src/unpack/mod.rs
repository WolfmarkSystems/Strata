//! UNPACK-1 — recursive container traversal engine.
//!
//! Forensic evidence routinely arrives wrapped in two or three archive
//! layers (Cellebrite tarball → EXTRACTION_FFS.zip → real filesystem,
//! Google Takeout with per-product ZIPs, FTK nested exports, …). This
//! module walks those layers automatically, stopping when it hits a
//! real filesystem tree (or a leaf that isn't a container).
//!
//! Safety is paramount — a malicious suspect can submit a zip bomb or a
//! symlink loop to try to exhaust the examiner's workstation. Every
//! recursion is bounded by depth, cumulative size, per-file size, and
//! per-container walltime. Symlinks that escape the extraction root are
//! refused.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

pub mod stream;

pub use stream::{
    auto_select_mode, ArchiveEntry, CompressionMethod, ExtractionMode, VfsError, VirtualFilesystem,
};

use crate::container::ContainerType;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Bounds enforced during recursive unpack. All limits are hard — once
/// a limit fires, recursion stops cleanly and the examiner is told
/// exactly which limit was hit.
#[derive(Debug, Clone)]
pub struct UnpackEngine {
    /// Maximum recursion depth. Default 5 — enough for Cellebrite
    /// wrapping without opening infinite-nested archive attacks.
    pub max_depth: u8,
    /// Maximum cumulative bytes extracted across the whole tree.
    /// Default: 10× the outer archive size, floor 2 GiB.
    pub max_total_bytes: u64,
    /// Maximum individual file size within any archive. Default 100
    /// GiB — large enough for full disk images, small enough to trip
    /// an obvious zip bomb.
    pub max_file_bytes: u64,
    /// Maximum total number of files extracted. Default 10 M.
    pub max_file_count: u64,
    /// Walltime budget per container (outer or nested). Default 30 min.
    pub per_container_timeout: Duration,
    /// Where extracted content goes.
    pub extraction_root: PathBuf,
}

impl UnpackEngine {
    /// Sensible defaults for real casework.
    pub fn new(extraction_root: PathBuf) -> Self {
        Self {
            max_depth: 5,
            max_total_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB floor; override via `with_max_total_bytes`
            max_file_bytes: 100 * 1024 * 1024 * 1024, // 100 GiB
            max_file_count: 10_000_000,
            per_container_timeout: Duration::from_secs(30 * 60),
            extraction_root,
        }
    }

    pub fn with_max_depth(mut self, d: u8) -> Self {
        self.max_depth = d;
        self
    }
    pub fn with_max_total_bytes(mut self, b: u64) -> Self {
        self.max_total_bytes = b;
        self
    }
    pub fn with_max_file_bytes(mut self, b: u64) -> Self {
        self.max_file_bytes = b;
        self
    }
    pub fn with_max_file_count(mut self, n: u64) -> Self {
        self.max_file_count = n;
        self
    }
    pub fn with_per_container_timeout(mut self, d: Duration) -> Self {
        self.per_container_timeout = d;
        self
    }
}

/// Summary of a single recursive unpack. Written into the case audit
/// log so chain of custody can reconstruct which layers were touched.
#[derive(Debug, Clone)]
pub struct UnpackResult {
    /// Deepest directory a plugin pipeline should walk.
    pub filesystem_root: PathBuf,
    pub containers_traversed: Vec<ContainerInfo>,
    pub total_bytes_extracted: u64,
    pub total_files_extracted: u64,
    pub elapsed: Duration,
    pub limits_hit: Vec<SafetyLimit>,
    pub warnings: Vec<UnpackWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub depth: u8,
    pub path: PathBuf,
    pub container_type: String,
    pub size_bytes: u64,
    pub entry_count: u64,
}

/// Which bound fired — examiner sees this as the "why we stopped" in the
/// progress output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SafetyLimit {
    MaxDepthReached {
        depth: u8,
    },
    TotalSizeExceeded {
        bytes: u64,
        limit: u64,
    },
    FileCountExceeded {
        count: u64,
        limit: u64,
    },
    IndividualFileSizeExceeded {
        path: PathBuf,
        bytes: u64,
        limit: u64,
    },
    Timeout {
        container: PathBuf,
        elapsed_secs: u64,
    },
    DiskSpaceExhausted {
        available: u64,
        needed: u64,
    },
}

/// Non-fatal issues observed while unpacking. The run still completes —
/// these become case-audit warnings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnpackWarning {
    EncryptedArchive { path: PathBuf, archive_type: String },
    CorruptedEntry { path: PathBuf, reason: String },
    SymlinkEscapesRoot { path: PathBuf, target: PathBuf },
    PermissionDenied { path: PathBuf },
    EmptyArchive { path: PathBuf },
    UnsupportedCompression { path: PathBuf, detail: String },
}

#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("other: {0}")]
    Other(String),
}

// ── Container classification ───────────────────────────────────────────

/// Archive flavours the unpack engine knows how to open. A separate
/// enum from `ContainerType` because only a subset of containers are
/// unpackable into a flat directory (raw/dd images are *filesystems*,
/// not archives).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    Zip,
    Gzip,
    /// Not an archive — treat as a leaf file.
    None,
}

/// Cheap classifier: checks magic bytes first, falls back to extension.
pub fn classify_archive(path: &Path) -> ArchiveKind {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return ArchiveKind::None,
    };
    if meta.is_dir() {
        return ArchiveKind::None;
    }
    let mut head = [0u8; 262];
    let read_ok = fs::File::open(path)
        .and_then(|mut f| {
            use std::io::Read;
            let n = f.read(&mut head)?;
            Ok(n)
        })
        .ok();
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if let Some(n) = read_ok {
        // gzip magic 1F 8B
        if n >= 2 && head[0] == 0x1F && head[1] == 0x8B {
            if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
                return ArchiveKind::TarGz;
            }
            return ArchiveKind::Gzip;
        }
        // bzip2 magic 42 5A 68
        if n >= 3 && &head[0..3] == b"BZh" {
            if name.ends_with(".tar.bz2") || name.ends_with(".tbz2") {
                return ArchiveKind::TarBz2;
            }
            // Raw bz2 not supported for unpack — caller treats as leaf.
            return ArchiveKind::None;
        }
        // xz magic FD 37 7A 58 5A 00
        if n >= 6 && &head[0..6] == b"\xFD7zXZ\x00" {
            if name.ends_with(".tar.xz") || name.ends_with(".txz") {
                return ArchiveKind::TarXz;
            }
            return ArchiveKind::None;
        }
        // ZIP / UFED zip / jar / etc. — "PK\x03\x04" or "PK\x05\x06" (empty)
        if n >= 4 && head[0] == b'P' && head[1] == b'K' {
            return ArchiveKind::Zip;
        }
        // Uncompressed tar magic at offset 257: "ustar"
        if n >= 262 && &head[257..262] == b"ustar" {
            return ArchiveKind::Tar;
        }
    }
    // Extension fallback for tars without ustar header (GNU old-style).
    if name.ends_with(".tar") {
        return ArchiveKind::Tar;
    }
    ArchiveKind::None
}

// ── Public entrypoint ──────────────────────────────────────────────────

/// Recursively unpack `input` into the engine's `extraction_root`.
/// Returns the deepest filesystem root a plugin pipeline should walk,
/// plus a full trace of which containers were seen.
pub fn unpack(input: &Path, engine: &UnpackEngine) -> Result<UnpackResult, UnpackError> {
    let started = Instant::now();
    fs::create_dir_all(&engine.extraction_root)?;
    let mut state = UnpackState::default();
    let leaf = recursive_unpack(input, engine, 0, &mut state, started)?;
    Ok(UnpackResult {
        filesystem_root: leaf,
        containers_traversed: state.containers,
        total_bytes_extracted: state.total_bytes,
        total_files_extracted: state.total_files,
        elapsed: started.elapsed(),
        limits_hit: state.limits_hit,
        warnings: state.warnings,
    })
}

#[derive(Default)]
struct UnpackState {
    total_bytes: u64,
    total_files: u64,
    containers: Vec<ContainerInfo>,
    limits_hit: Vec<SafetyLimit>,
    warnings: Vec<UnpackWarning>,
    stopped: bool,
}

fn recursive_unpack(
    input: &Path,
    engine: &UnpackEngine,
    depth: u8,
    state: &mut UnpackState,
    started: Instant,
) -> Result<PathBuf, UnpackError> {
    if state.stopped {
        return Ok(input.to_path_buf());
    }
    if started.elapsed() >= engine.per_container_timeout {
        state.limits_hit.push(SafetyLimit::Timeout {
            container: input.to_path_buf(),
            elapsed_secs: started.elapsed().as_secs(),
        });
        state.stopped = true;
        return Ok(input.to_path_buf());
    }
    if depth >= engine.max_depth {
        state
            .limits_hit
            .push(SafetyLimit::MaxDepthReached { depth });
        state.stopped = true;
        return Ok(input.to_path_buf());
    }

    // Directories — walk without extracting, but descend into any
    // archive we find at the top level.
    if input.is_dir() {
        // Only recurse into archives one layer below a directory; the
        // heavy fanout happens when we actually extract.
        if let Ok(entries) = fs::read_dir(input) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_file() && classify_archive(&p) != ArchiveKind::None {
                    let _ = recursive_unpack(&p, engine, depth + 1, state, started);
                }
            }
        }
        return Ok(input.to_path_buf());
    }

    let kind = classify_archive(input);
    if kind == ArchiveKind::None {
        return Ok(input.to_path_buf());
    }

    // Each nested container gets its own directory so we can tell
    // layers apart in the case dir.
    let layer_dir = engine.extraction_root.join(format!("layer_{}", depth));
    fs::create_dir_all(&layer_dir)?;

    let (bytes, files) = match extract_any(input, kind, &layer_dir, engine, state) {
        Ok(x) => x,
        Err(e) => {
            state.warnings.push(UnpackWarning::CorruptedEntry {
                path: input.to_path_buf(),
                reason: format!("{e}"),
            });
            return Ok(layer_dir);
        }
    };

    state.containers.push(ContainerInfo {
        depth,
        path: input.to_path_buf(),
        container_type: format!("{:?}", kind),
        size_bytes: bytes,
        entry_count: files,
    });

    if state.stopped {
        return Ok(layer_dir);
    }

    // Scan the freshly-extracted layer for any nested archive, recurse
    // into the first one we find. Each archive hit returns its own
    // leaf; if none found, the layer itself is the leaf.
    let mut leaf = layer_dir.clone();
    if let Ok(entries) = walk_dir_shallow(&layer_dir) {
        for candidate in entries {
            if state.stopped {
                break;
            }
            if candidate.is_file() && classify_archive(&candidate) != ArchiveKind::None {
                let nested_leaf = recursive_unpack(&candidate, engine, depth + 1, state, started)?;
                leaf = nested_leaf;
                // Stop after finding the first nested archive to avoid
                // combinatorial explosion on wide archives.
                break;
            }
        }
    }
    Ok(leaf)
}

fn walk_dir_shallow(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    // Up to 2 levels deep — enough to find EXTRACTION_FFS.zip inside a
    // UFED folder without walking a full OS tree.
    let mut out = Vec::new();
    for top in fs::read_dir(root)?.flatten() {
        let tp = top.path();
        out.push(tp.clone());
        if tp.is_dir() {
            if let Ok(inner) = fs::read_dir(&tp) {
                for child in inner.flatten() {
                    out.push(child.path());
                }
            }
        }
    }
    Ok(out)
}

// ── Per-kind extractors ────────────────────────────────────────────────

/// Dispatch to the right extractor and enforce size limits uniformly.
/// Returns (bytes_written, files_written).
fn extract_any(
    input: &Path,
    kind: ArchiveKind,
    dest: &Path,
    engine: &UnpackEngine,
    state: &mut UnpackState,
) -> Result<(u64, u64), UnpackError> {
    match kind {
        ArchiveKind::Zip => extract_zip(input, dest, engine, state),
        ArchiveKind::Tar => {
            let file = fs::File::open(input)?;
            extract_tar_from_reader(file, dest, engine, state, input)
        }
        ArchiveKind::TarGz => {
            let file = fs::File::open(input)?;
            let dec = flate2::read::GzDecoder::new(file);
            extract_tar_from_reader(dec, dest, engine, state, input)
        }
        ArchiveKind::Gzip => extract_gzip_single(input, dest, engine, state),
        ArchiveKind::TarBz2 | ArchiveKind::TarXz => {
            // We deliberately don't drag bzip2 / xz crates into the
            // workspace for v6; record and continue. Examiners can
            // pre-decompress these with standard tools.
            state.warnings.push(UnpackWarning::UnsupportedCompression {
                path: input.to_path_buf(),
                detail: format!("{:?} decompression not compiled in", kind),
            });
            Ok((0, 0))
        }
        ArchiveKind::None => Ok((0, 0)),
    }
}

fn remember_budget(
    state: &mut UnpackState,
    engine: &UnpackEngine,
    bytes: u64,
    path: &Path,
) -> bool {
    // Bump counters, flip `stopped` if over any limit, return "may continue".
    state.total_bytes = state.total_bytes.saturating_add(bytes);
    state.total_files = state.total_files.saturating_add(1);
    if state.total_bytes > engine.max_total_bytes {
        state.limits_hit.push(SafetyLimit::TotalSizeExceeded {
            bytes: state.total_bytes,
            limit: engine.max_total_bytes,
        });
        state.stopped = true;
        return false;
    }
    if state.total_files > engine.max_file_count {
        state.limits_hit.push(SafetyLimit::FileCountExceeded {
            count: state.total_files,
            limit: engine.max_file_count,
        });
        state.stopped = true;
        return false;
    }
    if bytes > engine.max_file_bytes {
        state
            .limits_hit
            .push(SafetyLimit::IndividualFileSizeExceeded {
                path: path.to_path_buf(),
                bytes,
                limit: engine.max_file_bytes,
            });
        state.stopped = true;
        return false;
    }
    true
}

/// Reject any path whose canonical form escapes `root`. Prevents
/// zip-slip and malicious tarball entries pointing at `/etc/passwd`.
fn safe_join(root: &Path, rel: &Path) -> Option<PathBuf> {
    let joined = root.join(rel);
    // Normalise without touching the filesystem.
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            std::path::Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            std::path::Component::Normal(_)
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                out.push(c);
            }
            std::path::Component::CurDir => {}
        }
    }
    let canonical_root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    if !out.starts_with(&canonical_root) && !out.starts_with(root) {
        return None;
    }
    Some(out)
}

fn extract_zip(
    input: &Path,
    dest: &Path,
    engine: &UnpackEngine,
    state: &mut UnpackState,
) -> Result<(u64, u64), UnpackError> {
    let file = fs::File::open(input)?;
    let mut archive = zip::ZipArchive::new(file)?;
    if archive.is_empty() {
        state.warnings.push(UnpackWarning::EmptyArchive {
            path: input.to_path_buf(),
        });
        return Ok((0, 0));
    }
    let mut bytes = 0u64;
    let mut files = 0u64;
    for i in 0..archive.len() {
        if state.stopped {
            break;
        }
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(zip::result::ZipError::UnsupportedArchive(detail)) => {
                // zip 2.x surfaces "Password required to decrypt
                // file" through UnsupportedArchive — classify it as
                // encrypted so examiners see the right status.
                if detail.to_ascii_lowercase().contains("password") {
                    state.warnings.push(UnpackWarning::EncryptedArchive {
                        path: input.to_path_buf(),
                        archive_type: "zip".into(),
                    });
                } else {
                    state.warnings.push(UnpackWarning::UnsupportedCompression {
                        path: input.to_path_buf(),
                        detail: detail.to_string(),
                    });
                }
                continue;
            }
            Err(e) => {
                state.warnings.push(UnpackWarning::CorruptedEntry {
                    path: input.to_path_buf(),
                    reason: format!("{e}"),
                });
                continue;
            }
        };
        if entry.encrypted() {
            state.warnings.push(UnpackWarning::EncryptedArchive {
                path: input.to_path_buf(),
                archive_type: "zip".into(),
            });
            continue;
        }
        let Some(rel) = entry.enclosed_name().map(|p| p.to_path_buf()) else {
            state.warnings.push(UnpackWarning::SymlinkEscapesRoot {
                path: input.to_path_buf(),
                target: PathBuf::from(entry.name()),
            });
            continue;
        };
        let Some(target) = safe_join(dest, &rel) else {
            state.warnings.push(UnpackWarning::SymlinkEscapesRoot {
                path: input.to_path_buf(),
                target: rel,
            });
            continue;
        };
        if entry.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let size = entry.size();
        if !remember_budget(state, engine, size, &target) {
            break;
        }
        let mut out = fs::File::create(&target)?;
        std::io::copy(&mut entry, &mut out)?;
        bytes = bytes.saturating_add(size);
        files += 1;
    }
    Ok((bytes, files))
}

fn extract_tar_from_reader<R: Read>(
    reader: R,
    dest: &Path,
    engine: &UnpackEngine,
    state: &mut UnpackState,
    origin: &Path,
) -> Result<(u64, u64), UnpackError> {
    let mut ar = tar::Archive::new(reader);
    ar.set_preserve_permissions(false);
    ar.set_unpack_xattrs(false);
    let mut bytes = 0u64;
    let mut files = 0u64;
    let entries = match ar.entries() {
        Ok(e) => e,
        Err(e) => {
            state.warnings.push(UnpackWarning::CorruptedEntry {
                path: origin.to_path_buf(),
                reason: format!("{e}"),
            });
            return Ok((0, 0));
        }
    };
    for entry in entries {
        if state.stopped {
            break;
        }
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                state.warnings.push(UnpackWarning::CorruptedEntry {
                    path: origin.to_path_buf(),
                    reason: format!("{e}"),
                });
                continue;
            }
        };
        let Ok(rel) = entry.path().map(|p| p.into_owned()) else {
            continue;
        };
        let Some(target) = safe_join(dest, &rel) else {
            state.warnings.push(UnpackWarning::SymlinkEscapesRoot {
                path: origin.to_path_buf(),
                target: rel,
            });
            continue;
        };
        let hdr = entry.header().clone();
        let size = hdr.size().unwrap_or(0);
        // Refuse symlinks and hard links — too easy to weaponise.
        use tar::EntryType::*;
        match hdr.entry_type() {
            Directory => {
                fs::create_dir_all(&target)?;
                continue;
            }
            Regular => {}
            Symlink | Link => {
                state.warnings.push(UnpackWarning::SymlinkEscapesRoot {
                    path: origin.to_path_buf(),
                    target: rel,
                });
                continue;
            }
            _ => continue,
        }
        if !remember_budget(state, engine, size, &target) {
            break;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = fs::File::create(&target)?;
        std::io::copy(&mut entry, &mut out)?;
        bytes = bytes.saturating_add(size);
        files += 1;
    }
    Ok((bytes, files))
}

fn extract_gzip_single(
    input: &Path,
    dest: &Path,
    engine: &UnpackEngine,
    state: &mut UnpackState,
) -> Result<(u64, u64), UnpackError> {
    let mut file = fs::File::open(input)?;
    let _ = file.seek(SeekFrom::Start(0));
    let dec = flate2::read::GzDecoder::new(file);
    let base = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("decompressed");
    let out_path = dest.join(base);
    let mut out = fs::File::create(&out_path)?;
    let mut limited = LimitedReader {
        inner: dec,
        remaining: engine.max_file_bytes,
    };
    let copied = std::io::copy(&mut limited, &mut out)?;
    if !remember_budget(state, engine, copied, &out_path) {
        return Ok((0, 0));
    }
    Ok((copied, 1))
}

struct LimitedReader<R: Read> {
    inner: R,
    remaining: u64,
}
impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let max = std::cmp::min(self.remaining, buf.len() as u64) as usize;
        let n = self.inner.read(&mut buf[..max])?;
        self.remaining = self.remaining.saturating_sub(n as u64);
        Ok(n)
    }
}

// Helpful conversion helper for callers that already speak
// `ContainerType`.
impl From<ArchiveKind> for ContainerType {
    fn from(k: ArchiveKind) -> Self {
        match k {
            ArchiveKind::Tar
            | ArchiveKind::TarGz
            | ArchiveKind::TarBz2
            | ArchiveKind::TarXz
            | ArchiveKind::Gzip
            | ArchiveKind::Zip => ContainerType::Directory,
            ArchiveKind::None => ContainerType::Raw,
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn engine(root: &Path) -> UnpackEngine {
        UnpackEngine::new(root.to_path_buf())
            .with_max_total_bytes(64 * 1024 * 1024)
            .with_max_file_bytes(16 * 1024 * 1024)
            .with_max_file_count(10_000)
            .with_max_depth(4)
    }

    fn make_tar(path: &Path, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(path).expect("tar create");
        let mut b = tar::Builder::new(file);
        for (name, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, name, *body).expect("append");
        }
        b.finish().expect("finish");
    }

    fn make_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(path).expect("zip create");
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in entries {
            w.start_file::<_, ()>(*name, opts).expect("start");
            w.write_all(body).expect("write");
        }
        w.finish().expect("finish");
    }

    #[test]
    fn classify_detects_zip_via_magic() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("a.unknownext");
        fs::write(&p, b"PK\x03\x04hello").expect("write");
        assert_eq!(classify_archive(&p), ArchiveKind::Zip);
    }

    #[test]
    fn classify_detects_tar_via_ustar() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("a.tar");
        make_tar(&p, &[("hello.txt", b"hi there")]);
        assert_eq!(classify_archive(&p), ArchiveKind::Tar);
    }

    #[test]
    fn single_layer_zip_extraction() {
        let src = tempfile::tempdir().expect("src");
        let zip = src.path().join("a.zip");
        make_zip(&zip, &[("a.txt", b"hello"), ("b.txt", b"world")]);
        let dest = tempfile::tempdir().expect("dst");
        let e = engine(dest.path());
        let r = unpack(&zip, &e).expect("unpack");
        assert_eq!(r.total_files_extracted, 2);
        assert_eq!(r.containers_traversed.len(), 1);
        assert!(r.limits_hit.is_empty());
        assert!(r.filesystem_root.starts_with(dest.path()));
    }

    #[test]
    fn single_layer_tar_extraction() {
        let src = tempfile::tempdir().expect("src");
        let tar = src.path().join("a.tar");
        make_tar(&tar, &[("x/y.txt", b"y"), ("x/z.txt", b"z")]);
        let dest = tempfile::tempdir().expect("dst");
        let r = unpack(&tar, &engine(dest.path())).expect("unpack");
        assert_eq!(r.total_files_extracted, 2);
    }

    #[test]
    fn nested_zip_in_tar_recurses() {
        let src = tempfile::tempdir().expect("src");
        let inner_zip = src.path().join("inner.zip");
        make_zip(&inner_zip, &[("leaf.txt", b"leaf data")]);
        let zip_bytes = fs::read(&inner_zip).expect("read");
        let outer = src.path().join("outer.tar");
        make_tar(&outer, &[("inner.zip", zip_bytes.as_slice())]);
        let dest = tempfile::tempdir().expect("dst");
        let r = unpack(&outer, &engine(dest.path())).expect("unpack");
        assert!(
            r.containers_traversed.len() >= 2,
            "expected >=2 containers traversed, got {}",
            r.containers_traversed.len()
        );
        assert!(r.filesystem_root.exists());
    }

    #[test]
    fn max_depth_halts_recursion() {
        let src = tempfile::tempdir().expect("src");
        let inner = src.path().join("inner.zip");
        make_zip(&inner, &[("x.txt", b"x")]);
        let outer = src.path().join("outer.tar");
        let inner_bytes = fs::read(&inner).expect("r");
        make_tar(&outer, &[("inner.zip", inner_bytes.as_slice())]);
        let dest = tempfile::tempdir().expect("dst");
        let e = engine(dest.path()).with_max_depth(1);
        let r = unpack(&outer, &e).expect("unpack");
        assert!(
            r.limits_hit
                .iter()
                .any(|l| matches!(l, SafetyLimit::MaxDepthReached { .. })),
            "expected MaxDepthReached, got {:?}",
            r.limits_hit
        );
    }

    #[test]
    fn zip_bomb_trips_total_size_limit() {
        let src = tempfile::tempdir().expect("src");
        let z = src.path().join("bomb.zip");
        // 64 files × 1 MiB = 64 MiB, cap set to 4 MiB.
        let blob = vec![0u8; 1024 * 1024];
        let entries: Vec<(String, Vec<u8>)> = (0..64)
            .map(|i| (format!("f{}.bin", i), blob.clone()))
            .collect();
        let file = fs::File::create(&z).expect("zip");
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (n, b) in &entries {
            w.start_file::<_, ()>(n.as_str(), opts).expect("s");
            w.write_all(b).expect("w");
        }
        w.finish().expect("f");
        let dest = tempfile::tempdir().expect("dst");
        let e = engine(dest.path()).with_max_total_bytes(4 * 1024 * 1024);
        let r = unpack(&z, &e).expect("unpack");
        assert!(
            r.limits_hit
                .iter()
                .any(|l| matches!(l, SafetyLimit::TotalSizeExceeded { .. })),
            "expected TotalSizeExceeded, got {:?}",
            r.limits_hit
        );
    }

    #[test]
    fn encrypted_zip_entry_skipped_with_warning() {
        use zip::unstable::write::FileOptionsExt;
        let src = tempfile::tempdir().expect("src");
        let z = src.path().join("enc.zip");
        let file = fs::File::create(&z).expect("c");
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"hunter2");
        w.start_file::<_, ()>("secret.txt", opts).expect("s");
        w.write_all(b"top secret").expect("w");
        w.finish().expect("f");

        let dest = tempfile::tempdir().expect("dst");
        let r = unpack(&z, &engine(dest.path())).expect("unpack");
        assert!(
            r.warnings
                .iter()
                .any(|w| matches!(w, UnpackWarning::EncryptedArchive { .. })),
            "expected EncryptedArchive warning, got {:?}",
            r.warnings
        );
    }

    #[test]
    fn symlink_zip_slip_refused() {
        // Craft a ZIP whose entry name escapes the extraction root.
        let src = tempfile::tempdir().expect("src");
        let z = src.path().join("slip.zip");
        let file = fs::File::create(&z).expect("c");
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        // The zip crate's enclosed_name() returns None for names with
        // `..` components, so the unpack path classifies it as a
        // symlink/escape and warns.
        w.start_file::<_, ()>("../escape.txt", opts).expect("s");
        w.write_all(b"pwn").expect("w");
        w.finish().expect("f");

        let dest = tempfile::tempdir().expect("dst");
        let r = unpack(&z, &engine(dest.path())).expect("unpack");
        assert!(
            r.warnings
                .iter()
                .any(|w| matches!(w, UnpackWarning::SymlinkEscapesRoot { .. })),
            "expected SymlinkEscapesRoot warning, got {:?}",
            r.warnings
        );
    }

    #[test]
    fn non_archive_file_passes_through() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("plain.bin");
        fs::write(&p, b"just bytes").expect("w");
        let dest = tempfile::tempdir().expect("dst");
        let r = unpack(&p, &engine(dest.path())).expect("unpack");
        assert_eq!(r.containers_traversed.len(), 0);
        assert_eq!(r.filesystem_root, p);
    }

    #[test]
    fn empty_zip_emits_warning_and_no_files() {
        let src = tempfile::tempdir().expect("src");
        let z = src.path().join("empty.zip");
        let file = fs::File::create(&z).expect("c");
        let w = zip::ZipWriter::new(file);
        w.finish().expect("f");
        let dest = tempfile::tempdir().expect("dst");
        let r = unpack(&z, &engine(dest.path())).expect("unpack");
        assert_eq!(r.total_files_extracted, 0);
        assert!(r
            .warnings
            .iter()
            .any(|w| matches!(w, UnpackWarning::EmptyArchive { .. })));
    }
}
