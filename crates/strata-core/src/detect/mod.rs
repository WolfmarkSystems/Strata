//! DETECT-1/2/3 — image-type classifier + plugin router.
//!
//! Given a filesystem root (possibly produced by UNPACK-1/2 auto-unpack),
//! walk the first few levels of the tree looking for OS-specific
//! markers. Every marker hit adds a weight to its target `ImageType`;
//! highest-scoring type wins, and its confidence is the ratio of the
//! winning score to the total weight observed.
//!
//! Recommendations map each image type to three plugin sets:
//! `recommended` (run by default), `optional` (skip unless
//! `--include`), and `unnecessary` (skip unless the examiner overrides
//! with `--plugins all` or `--skip-routing`).
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

pub mod apple_intelligence;
pub mod facetime26;
pub mod translation_gaps;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageType {
    WindowsWorkstation {
        version: Option<String>,
    },
    WindowsServer {
        version: Option<String>,
    },
    MacOS {
        version: Option<String>,
    },
    IOS {
        version: Option<String>,
    },
    IPadOS {
        version: Option<String>,
    },
    Android {
        version: Option<String>,
        oem: Option<String>,
    },
    ChromeOS,
    Linux {
        distribution: Option<String>,
    },
    Unix,
    MemoryDump {
        host_os: Option<String>,
    },
    NetworkCapture,
    CloudExport {
        provider: String,
    },
    CellebriteReport,
    UnknownFilesystem,
    Mixed(Vec<ImageType>),
}

impl ImageType {
    pub fn label(&self) -> String {
        match self {
            ImageType::WindowsWorkstation { version } => match version {
                Some(v) => format!("Windows Workstation ({v})"),
                None => "Windows Workstation".into(),
            },
            ImageType::WindowsServer { version } => match version {
                Some(v) => format!("Windows Server ({v})"),
                None => "Windows Server".into(),
            },
            ImageType::MacOS { version } => match version {
                Some(v) => format!("macOS ({v})"),
                None => "macOS".into(),
            },
            ImageType::IOS { version } => match version {
                Some(v) => format!("iOS ({v})"),
                None => "iOS".into(),
            },
            ImageType::IPadOS { version } => match version {
                Some(v) => format!("iPadOS ({v})"),
                None => "iPadOS".into(),
            },
            ImageType::Android { version, oem } => match (version, oem) {
                (Some(v), Some(o)) => format!("Android {v} ({o})"),
                (Some(v), None) => format!("Android {v}"),
                (None, Some(o)) => format!("Android ({o})"),
                _ => "Android".into(),
            },
            ImageType::ChromeOS => "ChromeOS".into(),
            ImageType::Linux { distribution } => match distribution {
                Some(d) => format!("Linux ({d})"),
                None => "Linux".into(),
            },
            ImageType::Unix => "Unix".into(),
            ImageType::MemoryDump { host_os } => match host_os {
                Some(os) => format!("Memory dump ({os})"),
                None => "Memory dump".into(),
            },
            ImageType::NetworkCapture => "Network capture".into(),
            ImageType::CloudExport { provider } => format!("Cloud export ({provider})"),
            ImageType::CellebriteReport => "Cellebrite report".into(),
            ImageType::UnknownFilesystem => "Unknown filesystem".into(),
            ImageType::Mixed(types) => {
                let mut parts: Vec<String> = types.iter().map(|t| t.label()).collect();
                parts.sort();
                format!("Mixed: {}", parts.join(", "))
            }
        }
    }

    /// Canonical identifier used in the recommendation table.
    pub fn kind(&self) -> ImageKind {
        match self {
            ImageType::WindowsWorkstation { .. } => ImageKind::WindowsWorkstation,
            ImageType::WindowsServer { .. } => ImageKind::WindowsServer,
            ImageType::MacOS { .. } => ImageKind::MacOS,
            ImageType::IOS { .. } => ImageKind::IOS,
            ImageType::IPadOS { .. } => ImageKind::IPadOS,
            ImageType::Android { .. } => ImageKind::Android,
            ImageType::ChromeOS => ImageKind::ChromeOS,
            ImageType::Linux { .. } | ImageType::Unix => ImageKind::Linux,
            ImageType::MemoryDump { .. } => ImageKind::MemoryDump,
            ImageType::NetworkCapture => ImageKind::NetworkCapture,
            ImageType::CloudExport { .. } => ImageKind::CloudExport,
            ImageType::CellebriteReport => ImageKind::CellebriteReport,
            ImageType::UnknownFilesystem | ImageType::Mixed(_) => ImageKind::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageKind {
    WindowsWorkstation,
    WindowsServer,
    MacOS,
    IOS,
    IPadOS,
    Android,
    ChromeOS,
    Linux,
    MemoryDump,
    NetworkCapture,
    CloudExport,
    CellebriteReport,
    Unknown,
}

/// Full classification output consumed by the CLI and the Tauri UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageClassification {
    pub primary_type: ImageType,
    pub confidence: f64,
    pub evidence: Vec<ClassificationEvidence>,
    pub recommended_plugins: Vec<String>,
    pub optional_plugins: Vec<String>,
    pub unnecessary_plugins: Vec<String>,
    pub mixed_types: Vec<ImageType>,
}

impl ImageClassification {
    /// Flatten the full evidence trace to a small examiner-friendly
    /// list of markers.
    pub fn evidence_markers(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .evidence
            .iter()
            .take(16)
            .map(|e| e.marker.clone())
            .collect();
        if self.evidence.len() > out.len() {
            out.push(format!(
                "(+{} more markers)",
                self.evidence.len() - out.len()
            ));
        }
        out
    }
    pub fn image_type_label(&self) -> String {
        self.primary_type.label()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationEvidence {
    pub marker: String,
    pub weight: f64,
    pub path: PathBuf,
}

// ── Marker dictionary ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct Marker {
    /// Substring that must appear in the observed path (forward-slash
    /// normalised, ASCII-lowercased).
    needle: &'static str,
    /// File-vs-dir hint: `Some(true)` means "must be a file",
    /// `Some(false)` means "must be a directory", `None` means either.
    is_file: Option<bool>,
    weight: f64,
    kind: ImageKind,
    note: &'static str,
}

/// Ordered list of markers. Weights roughly follow DETECT-1's spec
/// (high: 0.9, medium: 0.5, low: 0.2). Each marker contributes once
/// per matching path discovered during the scan.
const MARKERS: &[Marker] = &[
    // Windows
    Marker {
        needle: "/windows/system32/config/system",
        is_file: Some(true),
        weight: 0.9,
        kind: ImageKind::WindowsWorkstation,
        note: "SYSTEM hive",
    },
    Marker {
        needle: "/windows/system32/ntoskrnl.exe",
        is_file: Some(true),
        weight: 0.9,
        kind: ImageKind::WindowsWorkstation,
        note: "NT kernel",
    },
    Marker {
        needle: "/users/",
        is_file: Some(false),
        weight: 0.5,
        kind: ImageKind::WindowsWorkstation,
        note: "Users dir",
    },
    Marker {
        needle: "/pagefile.sys",
        is_file: Some(true),
        weight: 0.3,
        kind: ImageKind::WindowsWorkstation,
        note: "pagefile.sys",
    },
    Marker {
        needle: "/hiberfil.sys",
        is_file: Some(true),
        weight: 0.3,
        kind: ImageKind::WindowsWorkstation,
        note: "hiberfil.sys",
    },
    Marker {
        needle: "/program files/",
        is_file: Some(false),
        weight: 0.2,
        kind: ImageKind::WindowsWorkstation,
        note: "Program Files",
    },
    Marker {
        needle: "/windows/servicing/",
        is_file: None,
        weight: 0.2,
        kind: ImageKind::WindowsServer,
        note: "Windows Server servicing",
    },
    Marker {
        needle: "/windows/sysvol/",
        is_file: None,
        weight: 0.6,
        kind: ImageKind::WindowsServer,
        note: "AD SYSVOL",
    },
    // macOS
    Marker {
        needle: "/system/library/coreservices/systemversion.plist",
        is_file: Some(true),
        weight: 0.9,
        kind: ImageKind::MacOS,
        note: "SystemVersion.plist",
    },
    Marker {
        needle: "/library/preferences/",
        is_file: Some(false),
        weight: 0.5,
        kind: ImageKind::MacOS,
        note: "/Library/Preferences",
    },
    Marker {
        needle: "/private/var/db/",
        is_file: None,
        weight: 0.3,
        kind: ImageKind::MacOS,
        note: "macOS /private/var/db",
    },
    Marker {
        needle: "/.ds_store",
        is_file: Some(true),
        weight: 0.15,
        kind: ImageKind::MacOS,
        note: ".DS_Store",
    },
    // iOS
    Marker {
        needle: "/private/var/mobile/",
        is_file: None,
        weight: 0.9,
        kind: ImageKind::IOS,
        note: "iOS /private/var/mobile",
    },
    Marker {
        needle: "/containers/shared/appgroup/",
        is_file: None,
        weight: 0.4,
        kind: ImageKind::IOS,
        note: "iOS app groups",
    },
    Marker {
        needle: "/mobile/containers/data/application/",
        is_file: None,
        weight: 0.5,
        kind: ImageKind::IOS,
        note: "iOS application containers",
    },
    Marker {
        needle: "/library/sms/sms.db",
        is_file: Some(true),
        weight: 0.7,
        kind: ImageKind::IOS,
        note: "iOS SMS db",
    },
    // Android
    Marker {
        needle: "/data/data/",
        is_file: Some(false),
        weight: 0.9,
        kind: ImageKind::Android,
        note: "Android /data/data",
    },
    Marker {
        needle: "/data/app/",
        is_file: Some(false),
        weight: 0.7,
        kind: ImageKind::Android,
        note: "Android /data/app",
    },
    Marker {
        needle: "/system/build.prop",
        is_file: Some(true),
        weight: 0.8,
        kind: ImageKind::Android,
        note: "build.prop",
    },
    Marker {
        needle: "/sdcard/",
        is_file: None,
        weight: 0.3,
        kind: ImageKind::Android,
        note: "sdcard",
    },
    Marker {
        needle: "/data/misc/bootstat/",
        is_file: None,
        weight: 0.5,
        kind: ImageKind::Android,
        note: "bootstat",
    },
    // Linux
    Marker {
        needle: "/etc/os-release",
        is_file: Some(true),
        weight: 0.9,
        kind: ImageKind::Linux,
        note: "os-release",
    },
    Marker {
        needle: "/etc/passwd",
        is_file: Some(true),
        weight: 0.4,
        kind: ImageKind::Linux,
        note: "/etc/passwd",
    },
    Marker {
        needle: "/etc/shadow",
        is_file: Some(true),
        weight: 0.3,
        kind: ImageKind::Linux,
        note: "/etc/shadow",
    },
    Marker {
        needle: "/var/log/syslog",
        is_file: Some(true),
        weight: 0.4,
        kind: ImageKind::Linux,
        note: "syslog",
    },
    Marker {
        needle: "/home/",
        is_file: Some(false),
        weight: 0.3,
        kind: ImageKind::Linux,
        note: "/home",
    },
    // ChromeOS — multiple markers for recovery-image shape tolerance.
    // v0.16.0 validation caught a Chromebook tar misclassified as
    // Windows; root cause was the path-prefix pollution in absolute-
    // path matching (fixed in tally_markers_for) PLUS the
    // `/home/chronos/` (trailing-slash) marker not firing on recovery
    // images where chronos is empty and the `/etc/cros-machine-id`
    // file isn't present in the extracted tree. These three markers
    // give DETECT-1 three different paths to ChromeOS certainty.
    Marker {
        needle: "/opt/google/chrome/",
        is_file: None,
        weight: 0.5,
        kind: ImageKind::ChromeOS,
        note: "Chrome install root",
    },
    Marker {
        needle: "/etc/cros-machine-id",
        is_file: Some(true),
        weight: 0.9,
        kind: ImageKind::ChromeOS,
        note: "CrOS machine-id",
    },
    Marker {
        needle: "/home/chronos/",
        is_file: None,
        weight: 0.9,
        kind: ImageKind::ChromeOS,
        note: "CrOS chronos (with children)",
    },
    // Bare `chronos` directory entry — fires when chronos is empty
    // (common on recovery images post-logout) so ChromeOS isn't lost
    // just because there are no child files to scan.
    Marker {
        needle: "/home/chronos",
        is_file: Some(false),
        weight: 0.9,
        kind: ImageKind::ChromeOS,
        note: "CrOS chronos dir",
    },
    // `.shadow` cryptohome — ChromeOS-unique layout under /home
    // (cryptohome vaults per-user, distinct from regular Linux). Fires
    // on both the directory entry and its hash-dir children.
    Marker {
        needle: "/home/.shadow",
        is_file: None,
        weight: 0.8,
        kind: ImageKind::ChromeOS,
        note: "CrOS cryptohome .shadow",
    },
    // Cellebrite UFED / UFDR (treated as a container; plugins still run)
    Marker {
        needle: "extraction_ffs.zip",
        is_file: Some(true),
        weight: 0.9,
        kind: ImageKind::CellebriteReport,
        note: "Cellebrite EXTRACTION_FFS",
    },
    Marker {
        needle: ".ufdx",
        is_file: Some(true),
        weight: 0.9,
        kind: ImageKind::CellebriteReport,
        note: "UFDX metadata",
    },
    Marker {
        needle: "/report.xml",
        is_file: Some(true),
        weight: 0.5,
        kind: ImageKind::CellebriteReport,
        note: "UFDR report.xml",
    },
    // Network capture
    Marker {
        needle: ".pcap",
        is_file: Some(true),
        weight: 0.9,
        kind: ImageKind::NetworkCapture,
        note: "PCAP",
    },
    Marker {
        needle: ".pcapng",
        is_file: Some(true),
        weight: 0.9,
        kind: ImageKind::NetworkCapture,
        note: "PCAP-NG",
    },
    // Memory dumps
    Marker {
        needle: ".mem",
        is_file: Some(true),
        weight: 0.6,
        kind: ImageKind::MemoryDump,
        note: "Raw memory image",
    },
    Marker {
        needle: ".raw",
        is_file: Some(true),
        weight: 0.3,
        kind: ImageKind::MemoryDump,
        note: ".raw (may be disk)",
    },
    Marker {
        needle: ".dmp",
        is_file: Some(true),
        weight: 0.7,
        kind: ImageKind::MemoryDump,
        note: "Windows dump file",
    },
    // Cloud exports
    Marker {
        needle: "/takeout/",
        is_file: Some(false),
        weight: 0.9,
        kind: ImageKind::CloudExport,
        note: "Google Takeout root",
    },
    Marker {
        needle: "archive_browser.html",
        is_file: Some(true),
        weight: 0.5,
        kind: ImageKind::CloudExport,
        note: "Google Takeout browser",
    },
];

// ── Classification engine ──────────────────────────────────────────────

/// Classify a filesystem root or a single file. Directory scans go at
/// most 3 levels deep with a 2,000-file cap so classification of a
/// full disk image stays O(bounded) — this is a hint, not a full
/// catalogue.
pub fn classify(root: &Path) -> ImageClassification {
    let mut scores: std::collections::HashMap<ImageKind, f64> = std::collections::HashMap::new();
    let mut evidence: Vec<ClassificationEvidence> = Vec::new();
    let mut total_weight = 0f64;

    if root.is_file() {
        // For a single-file input, strip the parent so the match sees
        // `/capture.mem` not empty. Without this, stripping root==file
        // yields "" → evidence_relative_path returns "/" which matches
        // nothing. The parent suffices because single-file markers key
        // on filename/extension (e.g. `.mem`, `.pcap`).
        let parent = root.parent().unwrap_or(root);
        scan_single(root, parent, &mut scores, &mut evidence, &mut total_weight);
    } else if root.is_dir() {
        let mut ctx = ScanCtx {
            max_depth: 3,
            budget: 2000,
            scan_root: root,
            scores: &mut scores,
            evidence: &mut evidence,
            total: &mut total_weight,
        };
        scan_dir(root, 0, &mut ctx);
    }

    // Pick best scoring kind.
    let mut best_kind = ImageKind::Unknown;
    let mut best_score = 0.0f64;
    for (k, s) in &scores {
        if *s > best_score {
            best_score = *s;
            best_kind = *k;
        }
    }
    // Confidence: winner / total, zero if nothing matched.
    let confidence = if total_weight > 0.0 {
        (best_score / total_weight).clamp(0.0, 1.0)
    } else {
        0.0
    };

    let image_type = to_image_type(best_kind, root, &evidence);
    let recs = recommend_plugins(&image_type);
    ImageClassification {
        primary_type: image_type,
        confidence,
        evidence,
        recommended_plugins: recs.recommended,
        optional_plugins: recs.optional,
        unnecessary_plugins: recs.unnecessary,
        mixed_types: mixed_secondaries(&scores, best_kind),
    }
}

fn scan_single(
    path: &Path,
    scan_root: &Path,
    scores: &mut std::collections::HashMap<ImageKind, f64>,
    evidence: &mut Vec<ClassificationEvidence>,
    total: &mut f64,
) {
    tally_markers_for(path, scan_root, true, scores, evidence, total);
}

fn scan_dir(current: &Path, depth: u32, ctx: &mut ScanCtx) {
    if depth > ctx.max_depth {
        return;
    }
    let entries = match std::fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return,
    };
    for (seen, entry) in entries.flatten().enumerate() {
        if seen >= ctx.budget {
            break;
        }
        let path = entry.path();
        let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
        tally_markers_for(
            &path,
            ctx.scan_root,
            is_file,
            ctx.scores,
            ctx.evidence,
            ctx.total,
        );
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            scan_dir(&path, depth + 1, ctx);
        }
    }
}

/// Aggregate of the mutable state threaded through `scan_dir` — kept
/// in a struct so the recursive signature stays under the
/// `too_many_arguments` lint ceiling.
struct ScanCtx<'a> {
    max_depth: u32,
    budget: usize,
    /// Absolute path of the scan root. Every marker match compares
    /// against the tail relative to this root — prevents examiner-
    /// workstation path components (e.g. a macOS analyst running
    /// Strata out of `/Users/<examiner>/...`) from tripping Windows
    /// `/users/` marker matches that have nothing to do with the
    /// evidence content. Validated on the v0.16.0 Chromebook CTF
    /// tar: scans used to accumulate 0.91-confidence "Windows
    /// Workstation" on evidence that contains zero Windows artifacts,
    /// purely because the examiner's home dir was in the absolute
    /// path.
    scan_root: &'a Path,
    scores: &'a mut std::collections::HashMap<ImageKind, f64>,
    evidence: &'a mut Vec<ClassificationEvidence>,
    total: &'a mut f64,
}

/// Return the path normalized to a forward-slash lowercase string,
/// starting with `/` and stripped of everything up to and including
/// the scan root. For scan_root `/Users/alice/case/unpacked` and path
/// `/Users/alice/case/unpacked/layer_0/home/chronos`, returns
/// `/layer_0/home/chronos`. Falls back to the absolute path with a
/// leading `/` if stripping fails so classification still works on
/// unusual inputs — but that's the pre-fix behaviour and the one
/// that exposed the examiner-home pollution.
fn evidence_relative_path(path: &Path, scan_root: &Path) -> String {
    let rel = path.strip_prefix(scan_root).unwrap_or(path);
    let mut s = String::with_capacity(rel.as_os_str().len() + 1);
    s.push('/');
    s.push_str(&rel.to_string_lossy());
    s.replace('\\', "/").to_ascii_lowercase()
}

fn tally_markers_for(
    path: &Path,
    scan_root: &Path,
    is_file: bool,
    scores: &mut std::collections::HashMap<ImageKind, f64>,
    evidence: &mut Vec<ClassificationEvidence>,
    total: &mut f64,
) {
    let norm = evidence_relative_path(path, scan_root);
    for m in MARKERS {
        if !norm.contains(m.needle) {
            continue;
        }
        if let Some(want_file) = m.is_file {
            if want_file != is_file {
                continue;
            }
        }
        *scores.entry(m.kind).or_insert(0.0) += m.weight;
        *total += m.weight;
        evidence.push(ClassificationEvidence {
            marker: m.note.into(),
            weight: m.weight,
            path: path.to_path_buf(),
        });
    }
}

fn mixed_secondaries(
    scores: &std::collections::HashMap<ImageKind, f64>,
    winner: ImageKind,
) -> Vec<ImageType> {
    let mut out: Vec<ImageType> = Vec::new();
    // Any kind within 70 % of the winner's score is considered a
    // plausible secondary — worth the examiner knowing about.
    let winner_score = scores.get(&winner).copied().unwrap_or(0.0);
    let floor = winner_score * 0.7;
    let mut tuples: Vec<(&ImageKind, &f64)> = scores.iter().collect();
    tuples.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
    for (k, s) in tuples {
        if *k == winner {
            continue;
        }
        if *s < floor || *s == 0.0 {
            continue;
        }
        out.push(to_image_type(*k, Path::new(""), &[]));
    }
    out
}

fn to_image_type(kind: ImageKind, root: &Path, _evidence: &[ClassificationEvidence]) -> ImageType {
    match kind {
        ImageKind::WindowsWorkstation => ImageType::WindowsWorkstation { version: None },
        ImageKind::WindowsServer => ImageType::WindowsServer { version: None },
        ImageKind::MacOS => ImageType::MacOS { version: None },
        ImageKind::IOS => ImageType::IOS { version: None },
        ImageKind::IPadOS => ImageType::IPadOS { version: None },
        ImageKind::Android => ImageType::Android {
            version: None,
            oem: None,
        },
        ImageKind::ChromeOS => ImageType::ChromeOS,
        ImageKind::Linux => ImageType::Linux { distribution: None },
        ImageKind::MemoryDump => ImageType::MemoryDump { host_os: None },
        ImageKind::NetworkCapture => ImageType::NetworkCapture,
        ImageKind::CloudExport => ImageType::CloudExport {
            provider: if root
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("takeout")
            {
                "Google Takeout".into()
            } else {
                "unknown".into()
            },
        },
        ImageKind::CellebriteReport => ImageType::CellebriteReport,
        ImageKind::Unknown => ImageType::UnknownFilesystem,
    }
}

// ── Recommendation table (DETECT-1) ────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PluginRecommendation {
    pub recommended: Vec<String>,
    pub optional: Vec<String>,
    pub unnecessary: Vec<String>,
}

impl PluginRecommendation {
    /// Safety fallback — when we don't know what we're looking at,
    /// run every plugin.
    pub fn all_plugins() -> Self {
        let all: Vec<String> = ALL_PLUGINS.iter().map(|s| s.to_string()).collect();
        Self {
            recommended: all,
            optional: vec![],
            unnecessary: vec![],
        }
    }
}

/// Canonical list of static plugin names (display form from
/// `StrataPlugin::name()` — matches
/// strata-engine-adapter::list_plugins()).
const ALL_PLUGINS: &[&str] = &[
    "Strata Remnant",
    "Strata Chronicle",
    "Strata Cipher",
    "Strata Trace",
    "Strata Specter",
    "Strata Conduit",
    "Strata Nimbus",
    "Strata Wraith",
    "Strata Vector",
    "Strata Recon",
    "Strata Phantom",
    "Strata Guardian",
    "Strata NetFlow",
    "Strata MacTrace",
    "Strata Sentinel",
    "Strata CSAM Scanner",
    "Strata Apex",
    "Strata Carbon",
    "Strata Pulse",
    "Strata Vault",
    "Strata Arbor",
    "Strata Sigma",
];

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// Map an `ImageType` to a tri-partite plugin recommendation.
/// Keep every plugin name in sync with `ALL_PLUGINS` — the
/// `recommended ∪ optional ∪ unnecessary` union must equal `ALL_PLUGINS`.
pub fn recommend_plugins(image_type: &ImageType) -> PluginRecommendation {
    match image_type {
        ImageType::WindowsWorkstation { .. } | ImageType::WindowsServer { .. } => {
            PluginRecommendation {
                recommended: names(&[
                    "Strata Phantom",
                    "Strata Chronicle",
                    "Strata Sentinel",
                    "Strata Trace",
                    "Strata Remnant",
                    "Strata Guardian",
                    "Strata Cipher",
                    "Strata Nimbus",
                    "Strata Conduit",
                    "Strata Vector",
                    "Strata Wraith",
                    "Strata Recon",
                    "Strata Sigma",
                ]),
                optional: names(&["Strata Carbon", "Strata NetFlow", "Strata CSAM Scanner"]),
                unnecessary: names(&[
                    "Strata MacTrace",
                    "Strata Apex",
                    "Strata Pulse",
                    "Strata Arbor",
                    "Strata Specter",
                    "Strata Vault",
                ]),
            }
        }
        ImageType::MacOS { .. } => PluginRecommendation {
            recommended: names(&[
                "Strata MacTrace",
                "Strata Apex",
                "Strata Cipher",
                "Strata Nimbus",
                "Strata Conduit",
                "Strata Vector",
                "Strata Recon",
                "Strata Sigma",
            ]),
            optional: names(&["Strata Vault", "Strata NetFlow", "Strata CSAM Scanner"]),
            unnecessary: names(&[
                "Strata Phantom",
                "Strata Chronicle",
                "Strata Sentinel",
                "Strata Trace",
                "Strata Remnant",
                "Strata Guardian",
                "Strata Pulse",
                "Strata Arbor",
                "Strata Carbon",
                "Strata Specter",
                "Strata Wraith",
            ]),
        },
        ImageType::IOS { .. } | ImageType::IPadOS { .. } => PluginRecommendation {
            recommended: names(&[
                "Strata Pulse",
                "Strata Apex",
                "Strata Vault",
                "Strata Sigma",
            ]),
            optional: names(&["Strata Cipher", "Strata Nimbus", "Strata Recon"]),
            unnecessary: names(&[
                "Strata Phantom",
                "Strata Chronicle",
                "Strata Sentinel",
                "Strata Trace",
                "Strata Remnant",
                "Strata Guardian",
                "Strata MacTrace",
                "Strata Carbon",
                "Strata NetFlow",
                "Strata Conduit",
                "Strata Wraith",
                "Strata Arbor",
                "Strata Specter",
                "Strata Vector",
                "Strata CSAM Scanner",
            ]),
        },
        ImageType::Android { .. } => PluginRecommendation {
            recommended: names(&[
                "Strata Carbon",
                "Strata Pulse",
                "Strata Specter",
                "Strata Apex",
                "Strata Vault",
                "Strata Sigma",
            ]),
            optional: names(&["Strata Cipher", "Strata Recon", "Strata CSAM Scanner"]),
            unnecessary: names(&[
                "Strata Phantom",
                "Strata Chronicle",
                "Strata Sentinel",
                "Strata Trace",
                "Strata Remnant",
                "Strata Guardian",
                "Strata MacTrace",
                "Strata NetFlow",
                "Strata Conduit",
                "Strata Wraith",
                "Strata Arbor",
                "Strata Nimbus",
                "Strata Vector",
            ]),
        },
        ImageType::Linux { .. } | ImageType::Unix => PluginRecommendation {
            recommended: names(&[
                "Strata Arbor",
                "Strata NetFlow",
                "Strata Cipher",
                "Strata Recon",
                "Strata Vector",
                "Strata Sigma",
            ]),
            optional: names(&["Strata Nimbus", "Strata CSAM Scanner"]),
            unnecessary: names(&[
                "Strata Phantom",
                "Strata Chronicle",
                "Strata Sentinel",
                "Strata Trace",
                "Strata Remnant",
                "Strata Guardian",
                "Strata MacTrace",
                "Strata Apex",
                "Strata Carbon",
                "Strata Pulse",
                "Strata Specter",
                "Strata Conduit",
                "Strata Wraith",
                "Strata Vault",
            ]),
        },
        ImageType::ChromeOS => PluginRecommendation {
            recommended: names(&[
                "Strata Carbon",
                "Strata Nimbus",
                "Strata Recon",
                "Strata Sigma",
            ]),
            optional: names(&["Strata Cipher", "Strata Arbor", "Strata Vector"]),
            unnecessary: names(&[
                "Strata Phantom",
                "Strata Chronicle",
                "Strata Sentinel",
                "Strata Trace",
                "Strata Remnant",
                "Strata Guardian",
                "Strata MacTrace",
                "Strata Apex",
                "Strata Pulse",
                "Strata Specter",
                "Strata NetFlow",
                "Strata Conduit",
                "Strata Wraith",
                "Strata Vault",
                "Strata CSAM Scanner",
            ]),
        },
        ImageType::MemoryDump { .. } => PluginRecommendation {
            recommended: names(&[
                "Strata Phantom",
                "Strata Wraith",
                "Strata Vector",
                "Strata Recon",
                "Strata Sigma",
            ]),
            optional: names(&["Strata Cipher", "Strata Sentinel"]),
            unnecessary: names(&[
                "Strata Chronicle",
                "Strata Trace",
                "Strata Remnant",
                "Strata Guardian",
                "Strata MacTrace",
                "Strata Apex",
                "Strata Carbon",
                "Strata Pulse",
                "Strata Specter",
                "Strata NetFlow",
                "Strata Conduit",
                "Strata Nimbus",
                "Strata Arbor",
                "Strata Vault",
                "Strata CSAM Scanner",
            ]),
        },
        ImageType::NetworkCapture => PluginRecommendation {
            recommended: names(&["Strata NetFlow", "Strata Recon", "Strata Sigma"]),
            optional: names(&["Strata Vector"]),
            unnecessary: names(&[
                "Strata Phantom",
                "Strata Chronicle",
                "Strata Sentinel",
                "Strata Trace",
                "Strata Remnant",
                "Strata Guardian",
                "Strata Cipher",
                "Strata MacTrace",
                "Strata Apex",
                "Strata Carbon",
                "Strata Pulse",
                "Strata Specter",
                "Strata Conduit",
                "Strata Wraith",
                "Strata Nimbus",
                "Strata Arbor",
                "Strata Vault",
                "Strata CSAM Scanner",
            ]),
        },
        ImageType::CloudExport { .. } => PluginRecommendation {
            recommended: names(&[
                "Strata Nimbus",
                "Strata Recon",
                "Strata Carbon",
                "Strata Sigma",
            ]),
            optional: names(&["Strata Cipher", "Strata Vector"]),
            unnecessary: names(&[
                "Strata Phantom",
                "Strata Chronicle",
                "Strata Sentinel",
                "Strata Trace",
                "Strata Remnant",
                "Strata Guardian",
                "Strata MacTrace",
                "Strata Apex",
                "Strata Pulse",
                "Strata Specter",
                "Strata NetFlow",
                "Strata Conduit",
                "Strata Wraith",
                "Strata Arbor",
                "Strata Vault",
                "Strata CSAM Scanner",
            ]),
        },
        ImageType::CellebriteReport => PluginRecommendation {
            // Cellebrite wrapper: we don't yet know what OS is inside,
            // so the "recommended" bucket is mobile-heavy but not
            // exhaustive. The examiner can re-run against the unpacked
            // filesystem root for sharper routing.
            recommended: names(&[
                "Strata Pulse",
                "Strata Apex",
                "Strata Carbon",
                "Strata Specter",
                "Strata Vault",
                "Strata Sigma",
            ]),
            optional: names(&["Strata Cipher", "Strata Recon", "Strata Nimbus"]),
            unnecessary: names(&[
                "Strata Phantom",
                "Strata Chronicle",
                "Strata Sentinel",
                "Strata Trace",
                "Strata Remnant",
                "Strata Guardian",
                "Strata MacTrace",
                "Strata NetFlow",
                "Strata Conduit",
                "Strata Wraith",
                "Strata Arbor",
                "Strata Vector",
                "Strata CSAM Scanner",
            ]),
        },
        ImageType::Mixed(types) => combine_recommendations(types),
        ImageType::UnknownFilesystem => PluginRecommendation::all_plugins(),
    }
}

/// For Mixed(types) — union of every member's `recommended`, retain
/// `optional` only when it's optional in every member, mark
/// `unnecessary` only when ALL members agree.
fn combine_recommendations(types: &[ImageType]) -> PluginRecommendation {
    use std::collections::HashSet;
    let per: Vec<PluginRecommendation> = types.iter().map(recommend_plugins).collect();
    let all: HashSet<String> = ALL_PLUGINS.iter().map(|s| s.to_string()).collect();
    let recommended: HashSet<String> = per
        .iter()
        .flat_map(|r| r.recommended.iter().cloned())
        .collect();
    let unanimously_unnecessary: HashSet<String> = all
        .iter()
        .filter(|p| per.iter().all(|r| r.unnecessary.contains(p)))
        .cloned()
        .collect();
    let optional: HashSet<String> = all
        .iter()
        .filter(|p| !recommended.contains(*p) && !unanimously_unnecessary.contains(*p))
        .cloned()
        .collect();
    let mut out = PluginRecommendation {
        recommended: recommended.into_iter().collect(),
        optional: optional.into_iter().collect(),
        unnecessary: unanimously_unnecessary.into_iter().collect(),
    };
    out.recommended.sort();
    out.optional.sort();
    out.unnecessary.sort();
    out
}

// ── DETECT-3 — cross-evidence relationship inference ───────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRelationship {
    pub evidence_a: String,
    pub evidence_b: String,
    pub relationship_type: RelationshipType,
    pub confidence: f64,
    pub shared_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelationshipType {
    SameUser,
    MemoryOfDisk,
    BackupRelationship,
    CommunicationPartners,
    SameNetwork,
    Other(String),
}

/// Pairwise relationship inference over a set of classified evidence.
/// Current rules: (a) any mobile item + a desktop item that sees
/// mobile artifacts → BackupRelationship, (b) a MemoryDump + any
/// matching host_os → MemoryOfDisk, (c) any two items with an
/// overlapping cloud-export provider → SameUser.
pub fn infer_cross_evidence_relationships(
    evidence: &[(String, ImageClassification)],
) -> Vec<EvidenceRelationship> {
    let mut out = Vec::new();
    for (i, (name_a, a)) in evidence.iter().enumerate() {
        for (name_b, b) in evidence.iter().skip(i + 1) {
            if let Some(rel) = pair_relationship(a, b) {
                out.push(EvidenceRelationship {
                    evidence_a: name_a.clone(),
                    evidence_b: name_b.clone(),
                    relationship_type: rel.0,
                    confidence: rel.1,
                    shared_indicators: rel.2,
                });
            }
        }
    }
    out
}

fn pair_relationship(
    a: &ImageClassification,
    b: &ImageClassification,
) -> Option<(RelationshipType, f64, Vec<String>)> {
    // Memory dump + host OS match.
    if let (ImageType::MemoryDump { host_os: Some(os) }, other)
    | (other, ImageType::MemoryDump { host_os: Some(os) }) = (&a.primary_type, &b.primary_type)
    {
        if other
            .label()
            .to_ascii_lowercase()
            .contains(&os.to_ascii_lowercase())
        {
            return Some((
                RelationshipType::MemoryOfDisk,
                0.85,
                vec![format!("host_os={os}")],
            ));
        }
    }
    // BackupRelationship: one mobile, one desktop where desktop's
    // evidence markers mention mobile dirs.
    let (mobile, desktop) = match (&a.primary_type, &b.primary_type) {
        (
            ImageType::IOS { .. } | ImageType::Android { .. },
            ImageType::WindowsWorkstation { .. } | ImageType::MacOS { .. },
        ) => (a, b),
        (
            ImageType::WindowsWorkstation { .. } | ImageType::MacOS { .. },
            ImageType::IOS { .. } | ImageType::Android { .. },
        ) => (b, a),
        _ => return try_cloud_or_same_network(a, b),
    };
    // If the desktop side's markers mention iTunes / Android backup
    // paths, we flag the pair.
    let desktop_paths: Vec<String> = desktop
        .evidence
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect();
    let hit_mobile_backup = desktop_paths
        .iter()
        .any(|p| p.contains("MobileSync") || p.contains("Android Backup") || p.contains("itunes"));
    if hit_mobile_backup {
        return Some((
            RelationshipType::BackupRelationship,
            0.8,
            vec![mobile.primary_type.label()],
        ));
    }
    try_cloud_or_same_network(a, b)
}

fn try_cloud_or_same_network(
    a: &ImageClassification,
    b: &ImageClassification,
) -> Option<(RelationshipType, f64, Vec<String>)> {
    if let (ImageType::CloudExport { provider: pa }, ImageType::CloudExport { provider: pb }) =
        (&a.primary_type, &b.primary_type)
    {
        if pa.eq_ignore_ascii_case(pb) {
            return Some((
                RelationshipType::SameUser,
                0.7,
                vec![format!("cloud_provider={pa}")],
            ));
        }
    }
    None
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn windows_tree_is_classified_as_windows() {
        let d = tmp();
        fs::create_dir_all(d.path().join("Windows/System32/config")).expect("ok");
        fs::write(d.path().join("Windows/System32/config/SYSTEM"), b"hive").expect("ok");
        fs::write(d.path().join("Windows/System32/ntoskrnl.exe"), b"kernel").expect("ok");
        fs::create_dir_all(d.path().join("Users/alice")).expect("ok");
        let c = classify(d.path());
        assert!(matches!(
            c.primary_type,
            ImageType::WindowsWorkstation { .. }
        ));
        assert!(c.confidence > 0.3);
        assert!(c.recommended_plugins.iter().any(|p| p == "Strata Phantom"));
    }

    #[test]
    fn macos_tree_is_classified_as_macos() {
        let d = tmp();
        fs::create_dir_all(d.path().join("System/Library/CoreServices")).expect("ok");
        fs::write(
            d.path()
                .join("System/Library/CoreServices/SystemVersion.plist"),
            b"<plist/>",
        )
        .expect("ok");
        fs::create_dir_all(d.path().join("Library/Preferences")).expect("ok");
        fs::create_dir_all(d.path().join("private/var/db")).expect("ok");
        let c = classify(d.path());
        assert!(matches!(c.primary_type, ImageType::MacOS { .. }));
        assert!(c.recommended_plugins.iter().any(|p| p == "Strata MacTrace"));
    }

    #[test]
    fn ios_tree_is_classified_as_ios() {
        let d = tmp();
        fs::create_dir_all(d.path().join("private/var/mobile/Library/SMS")).expect("ok");
        fs::write(
            d.path().join("private/var/mobile/Library/SMS/sms.db"),
            b"SQLite format 3",
        )
        .expect("ok");
        let c = classify(d.path());
        assert!(matches!(c.primary_type, ImageType::IOS { .. }));
        assert!(c.recommended_plugins.iter().any(|p| p == "Strata Pulse"));
    }

    #[test]
    fn android_tree_is_classified_as_android() {
        let d = tmp();
        fs::create_dir_all(d.path().join("data/data/com.example.app")).expect("ok");
        fs::create_dir_all(d.path().join("data/app")).expect("ok");
        fs::create_dir_all(d.path().join("system")).expect("ok");
        fs::write(d.path().join("system/build.prop"), b"ro.build=1").expect("ok");
        let c = classify(d.path());
        assert!(matches!(c.primary_type, ImageType::Android { .. }));
        assert!(c.recommended_plugins.iter().any(|p| p == "Strata Carbon"));
    }

    #[test]
    fn linux_tree_is_classified_as_linux() {
        let d = tmp();
        fs::create_dir_all(d.path().join("etc")).expect("ok");
        fs::write(d.path().join("etc/os-release"), b"NAME=Ubuntu").expect("ok");
        fs::write(d.path().join("etc/passwd"), b"root:x:0:0::/root:/bin/bash").expect("ok");
        let c = classify(d.path());
        assert!(matches!(c.primary_type, ImageType::Linux { .. }));
        assert!(c.recommended_plugins.iter().any(|p| p == "Strata Arbor"));
    }

    #[test]
    fn chromebook_recovery_tree_is_classified_as_chromeos() {
        // v0.16.0 real-image validation gap G7 regression: the
        // Chromebook CTF tar misclassified as Windows Workstation
        // (0.91 confidence). Two defects combined:
        //
        //   (1) tally_markers_for lowercased the ABSOLUTE path, so
        //       running Strata from /Users/<examiner>/... on macOS
        //       tripped the Windows `/users/` marker on every
        //       evidence path regardless of content.
        //   (2) The `/home/chronos/` (trailing-slash) marker needed
        //       child entries to fire — on recovery images chronos
        //       is empty post-logout so ChromeOS never scored.
        //
        // This fixture reproduces the exact shape of the validation
        // Chromebook: empty chronos, `.shadow` cryptohome dir, user
        // and root hash dirs. Classification MUST be ChromeOS (or
        // at least NOT Windows Workstation) and must not depend on
        // the tempdir's absolute path containing "/Users/".
        let d = tmp();
        fs::create_dir_all(d.path().join("home/chronos")).expect("ok");
        fs::create_dir_all(d.path().join("home/.shadow/abc123hash")).expect("ok");
        fs::create_dir_all(d.path().join("home/user/abc123hash")).expect("ok");
        fs::create_dir_all(d.path().join("home/root/abc123hash")).expect("ok");
        let c = classify(d.path());
        assert_eq!(
            c.primary_type,
            ImageType::ChromeOS,
            "Chromebook recovery tree must classify as ChromeOS; \
             got {:?} with confidence {:.2}. If this fails with \
             WindowsWorkstation, the examiner-home path-prefix \
             pollution regression has returned — tally_markers_for \
             must compare against paths relative to the scan root.",
            c.primary_type,
            c.confidence,
        );
    }

    #[test]
    fn examiner_home_on_macos_does_not_trip_windows_users_marker() {
        // Tripwire for the exact pollution mode that caused the
        // Chromebook misclassification: a tempdir on macOS has an
        // absolute path like /var/folders/.../T/.tmpXYZ or
        // /Users/alice/... — the classifier must not count those
        // ambient components against the evidence content.
        //
        // Build a pure-Linux tree (no Windows markers at all) and
        // confirm classification does NOT pick WindowsWorkstation
        // merely because the tempdir lives under /Users/.
        let d = tmp();
        fs::create_dir_all(d.path().join("etc")).expect("ok");
        fs::write(d.path().join("etc/os-release"), b"ID=ubuntu").expect("ok");
        fs::create_dir_all(d.path().join("home/alice")).expect("ok");
        fs::create_dir_all(d.path().join("var/log")).expect("ok");
        fs::write(d.path().join("var/log/syslog"), b"").expect("ok");
        let c = classify(d.path());
        assert!(
            !matches!(c.primary_type, ImageType::WindowsWorkstation { .. }),
            "pure-Linux evidence must not be classified as Windows; \
             got {:?} — the scan root's absolute path must not leak \
             into marker matching",
            c.primary_type,
        );
    }

    #[test]
    fn memory_dump_file_classified_as_memory() {
        let d = tmp();
        let p = d.path().join("capture.mem");
        fs::write(&p, b"MDMPsomething").expect("ok");
        let c = classify(&p);
        assert!(matches!(c.primary_type, ImageType::MemoryDump { .. }));
    }

    #[test]
    fn cellebrite_layout_classified_as_cellebrite() {
        let d = tmp();
        fs::write(d.path().join("Evidence.ufdx"), b"<ufdx/>").expect("ok");
        fs::create_dir_all(d.path().join("EXTRACTION_FFS 01")).expect("ok");
        fs::write(
            d.path().join("EXTRACTION_FFS 01/EXTRACTION_FFS.zip"),
            b"PK\x03\x04",
        )
        .expect("ok");
        let c = classify(d.path());
        assert!(matches!(c.primary_type, ImageType::CellebriteReport));
    }

    #[test]
    fn empty_dir_falls_back_to_all_plugins() {
        let d = tmp();
        let c = classify(d.path());
        assert_eq!(c.confidence, 0.0);
        // UnknownFilesystem → all_plugins().
        assert_eq!(
            c.recommended_plugins.len(),
            ALL_PLUGINS.len(),
            "expected all plugins, got {:?}",
            c.recommended_plugins
        );
    }

    #[test]
    fn recommendation_names_match_engine_registry() {
        // Every plugin name referenced in every per-kind recommendation
        // must appear in the canonical ALL_PLUGINS table.
        for t in [
            ImageType::WindowsWorkstation { version: None },
            ImageType::MacOS { version: None },
            ImageType::IOS { version: None },
            ImageType::Android {
                version: None,
                oem: None,
            },
            ImageType::Linux { distribution: None },
            ImageType::MemoryDump { host_os: None },
            ImageType::NetworkCapture,
            ImageType::CloudExport {
                provider: "Google".into(),
            },
            ImageType::CellebriteReport,
            ImageType::ChromeOS,
        ] {
            let rec = recommend_plugins(&t);
            for p in rec
                .recommended
                .iter()
                .chain(rec.optional.iter())
                .chain(rec.unnecessary.iter())
            {
                assert!(
                    ALL_PLUGINS.iter().any(|a| a == p),
                    "plugin name {:?} not in ALL_PLUGINS for image {}",
                    p,
                    t.label()
                );
            }
        }
    }

    #[test]
    fn cross_evidence_relationship_empty_for_unrelated_items() {
        let a = classify(tmp().path()); // unknown
        let b = classify(tmp().path()); // unknown
        let rels = infer_cross_evidence_relationships(&[("a".into(), a), ("b".into(), b)]);
        assert!(rels.is_empty());
    }
}
