# SPRINTS_v6.md — STRATA AUTO-UNPACK + IMAGE TYPE DETECTION + SMART ROUTING
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md and SPRINTS_v6.md. Execute all incomplete sprints in order.
#         For each sprint: implement, test, commit, then move to the next."
# Last updated: 2026-04-17
# Prerequisite: SPRINTS.md, SPRINTS_v2.md, SPRINTS_v3.md, SPRINTS_v4.md, SPRINTS_v5.md complete
# Current state: 3,357 tests, 26 plugins registered, v5 field-validated
# Focus: Auto-unpack + image type detection + intelligent plugin routing
#
# Context: VALIDATE-1 ran 506 plugin×image executions with zero failures,
# but revealed that Strata doesn't automatically unpack nested container layers
# (Cellebrite tarball → EXTRACTION_FFS.zip → filesystem) and doesn't identify
# what kind of image it's looking at to route appropriate plugins.
#
# This sprint queue closes both gaps.

---

## HOW TO EXECUTE

Read CLAUDE.md first. Then execute each sprint below in order.
For each sprint:
1. Implement exactly as specified
2. Run `cargo test --workspace` — all 3,357+ tests must pass
3. Run `cargo clippy --workspace -- -D warnings` — must be clean
4. Verify zero `.unwrap()`, zero `unsafe{}`, zero `println!`
5. Commit with message: "feat: [sprint-id] [description]" or "fix: [sprint-id] [description]"
6. Move to next sprint immediately

If a sprint is marked COMPLETE — skip it.

---

## COMPLETED SPRINTS (skip these)

None yet — this is v6.

---

# ═══════════════════════════════════════════════════════
# PART 1 — AUTO-UNPACK ENGINE
# ═══════════════════════════════════════════════════════

## SPRINT UNPACK-1 — Recursive Container Traversal Engine

Create `crates/strata-fs/src/unpack/mod.rs` as the central unpack engine.

**Problem statement:**
Forensic images frequently contain nested container structures:
- Cellebrite tarball → `EXTRACTION_FFS.zip` → actual filesystem
- FTK export → folder structure → individual E01 segments → filesystem
- ZIP inside a TAR inside a UFED wrapper
- Google Takeout → multiple ZIP archives per product → individual data files

Currently Strata detects the outer container but doesn't recursively traverse
inner containers. This sprint builds the engine that makes this automatic.

**Implementation:**

Core engine:
```rust
pub struct UnpackEngine {
    /// Maximum recursion depth (prevents zip bomb exploitation)
    pub max_depth: u8,                    // Default: 5
    /// Maximum cumulative extraction size (prevents disk exhaustion)
    pub max_total_bytes: u64,             // Default: 10 * original_size
    /// Maximum individual file size within archive
    pub max_file_bytes: u64,              // Default: 100GB
    /// Maximum number of files to extract
    pub max_file_count: u64,              // Default: 10,000,000
    /// Timeout for unpacking any single container
    pub per_container_timeout: Duration,  // Default: 30 minutes
    /// Output directory for extracted content
    pub extraction_root: PathBuf,
}

pub struct UnpackResult {
    /// Root filesystem path (either original or unpacked)
    pub filesystem_root: PathBuf,
    /// Total containers traversed
    pub containers_traversed: Vec<ContainerInfo>,
    /// Total bytes extracted
    pub total_bytes_extracted: u64,
    /// Total files extracted
    pub total_files_extracted: u64,
    /// Time spent unpacking
    pub elapsed: Duration,
    /// Any safety limits that were hit
    pub limits_hit: Vec<SafetyLimit>,
    /// Warnings (corrupt entries, permission issues, etc.)
    pub warnings: Vec<UnpackWarning>,
}

pub struct ContainerInfo {
    pub depth: u8,
    pub path: PathBuf,
    pub container_type: ContainerType,
    pub size_bytes: u64,
    pub entry_count: u64,
}
```

**Recursive unpack algorithm:**

```
1. Detect outer container type (use existing ContainerType detection)
2. If NOT a container → return filesystem_root = input_path
3. If IS a container:
   a. Check depth < max_depth
   b. Check cumulative_bytes + estimated_size < max_total_bytes
   c. Extract to extraction_root/depth_N/
   d. Log ContainerInfo
   e. For each entry in extracted content:
      - If entry is itself a container type → recursive call
      - If entry is filesystem/raw data → stop, this is the leaf
   f. Return filesystem_root pointing to deepest meaningful layer
4. If any limit hit → log SafetyLimit, stop recursion, return current state
```

**Safety limits (critical — prevents malicious images from crashing Strata):**

```rust
pub enum SafetyLimit {
    MaxDepthReached { depth: u8 },
    TotalSizeExceeded { bytes: u64, limit: u64 },
    FileCountExceeded { count: u64, limit: u64 },
    IndividualFileSizeExceeded { path: PathBuf, bytes: u64, limit: u64 },
    Timeout { container: PathBuf, elapsed: Duration },
    DiskSpaceExhausted { available: u64, needed: u64 },
}
```

All limits MUST be enforced. A malicious forensic image submitted by a
suspect must not be able to crash or exhaust the examiner's workstation.

**Container types to unpack recursively:**
- TAR, TAR.GZ, TAR.BZ2, TAR.XZ
- ZIP (including encrypted — emit warning, skip extraction)
- 7z (including encrypted — emit warning, skip extraction)
- RAR (read-only — do not attempt if no unrar library)
- E01/EWF (multi-segment split images as single logical unit)
- UFED/UFDR (from FIX-2)
- Android Backup .ab (from AND-4)
- DD/RAW (no unpacking — this IS the filesystem)
- VMDK/VHD/VHDX (virtual disk images — extract filesystem)
- AFF4 (if library available)
- ZFF (from R-7)
- gzip, bzip2, xz on individual files (transparent decompression)

**Encrypted archive handling:**
When an encrypted archive is encountered:
1. Do NOT attempt extraction
2. Emit `Artifact::new("Encrypted Archive", path_str)` with:
   - `requires_password: true`
   - `archive_type: String`
   - `suspicious: true` (encryption may indicate hiding evidence)
   - Description noting examiner may need to provide password
3. Continue with rest of unpack — don't block on one encrypted file
4. If examiner provides password via config, retry extraction

**Zero-file / empty archive handling:**
Emit warning but don't fail. Continue processing.

**Corrupted archive handling:**
Attempt partial recovery. Log corrupted entries. Continue.

**Tests required:**
- Single-layer extraction (tarball of flat files)
- Multi-layer nested (ZIP inside TAR inside UFED)
- Maximum depth enforcement (6-deep archive stops at 5)
- Zip bomb protection (file that decompresses to > max_total_bytes stops cleanly)
- Encrypted archive detection and graceful skip
- Corrupted archive partial recovery
- Multi-segment E01 unification (E01+E02+E03 treated as single image)
- Symlink handling (do not follow symlinks outside extraction root)

Zero unwrap, zero unsafe, Clippy clean, eight tests minimum.

---

## SPRINT UNPACK-2 — Streaming Extraction and Memory Management

Enhance `crates/strata-fs/src/unpack/` with streaming extraction.

**Problem statement:**
UNPACK-1 extracts to disk which works but large images can produce 500GB+
of extracted content. Examiners with limited disk space need streaming
options that extract only what's needed, when it's needed.

**Implementation:**

Add streaming mode:
```rust
pub enum ExtractionMode {
    /// Extract everything to disk upfront (current behavior)
    ExtractToDisk,
    /// Extract lazily — only when plugin requests a specific path
    StreamOnDemand,
    /// Hybrid: extract metadata upfront, stream file content on request
    HybridStream,
}
```

**StreamOnDemand implementation:**
Instead of extracting the archive, create a virtual filesystem layer
that extracts individual files on demand when plugins request them.

```rust
pub struct VirtualFilesystem {
    /// Original archive path
    pub archive_path: PathBuf,
    /// Archive index (extracted once, cached)
    pub entries: HashMap<PathBuf, ArchiveEntry>,
    /// Extracted file cache (LRU, bounded)
    pub cache: LruCache<PathBuf, Bytes>,
    /// Cache size limit
    pub cache_size_bytes: u64,  // Default: 1GB
}

pub struct ArchiveEntry {
    pub path: PathBuf,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
    pub permissions: u32,
    pub offset_in_archive: u64,
    pub compression_method: CompressionMethod,
}

impl VirtualFilesystem {
    /// Read file content — extracts from archive if not cached
    pub fn read_file(&mut self, path: &Path) -> Result<Bytes, UnpackError>;
    
    /// Check if file exists without extracting
    pub fn exists(&self, path: &Path) -> bool;
    
    /// Get file metadata without extracting
    pub fn metadata(&self, path: &Path) -> Option<&ArchiveEntry>;
    
    /// List files in directory without extracting
    pub fn list_dir(&self, path: &Path) -> Vec<&ArchiveEntry>;
}
```

**Plugin integration:**
Plugins already use the file_index system to locate target files.
With StreamOnDemand, the file_index is built from VirtualFilesystem metadata
without extracting actual file content. When a plugin calls `read_file()`,
the content is extracted lazily.

Benefits:
- File index builds in seconds regardless of archive size
- Only files plugins actually parse get extracted
- Total disk usage stays low
- Can process 500GB archives on a 256GB SSD

**Automatic mode selection:**
```rust
impl UnpackEngine {
    pub fn auto_select_mode(archive_size: u64, available_disk: u64) -> ExtractionMode {
        if archive_size * 3 < available_disk {
            ExtractionMode::ExtractToDisk  // plenty of space
        } else if archive_size < available_disk {
            ExtractionMode::HybridStream   // tight but workable
        } else {
            ExtractionMode::StreamOnDemand // streaming mandatory
        }
    }
}
```

**Tests required:**
- StreamOnDemand correctness (reads match ExtractToDisk bytes)
- Cache eviction under memory pressure
- Concurrent reads from same archive (thread safety)
- Performance: streaming vs. extract-all on 10GB archive

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT UNPACK-3 — Auto-Unpack Integration with CLI and File Index

Wire UNPACK-1 and UNPACK-2 into the main ingestion pipeline.

**Implementation:**

Modify `strata-shield-cli/src/commands/ingest.rs` to:

```
1. Parse CLI args (source, case_dir, etc.)
2. Initialize case directory
3. Detect outer container type
4. Run UnpackEngine recursively until filesystem root reached
5. Build file_index against unpacked filesystem (or VirtualFilesystem)
6. Run NSRL + threat intel prefilter
7. Run plugins (now operating on unpacked filesystem)
8. Correlation + ranking + report
```

**Progress reporting:**

Show examiner what's happening during unpack:
```
[00:00:15] Detecting container format... UFED tarball
[00:00:23] Unpacking layer 1/3: UFED wrapper (4.2 GB)
[00:02:47] Unpacking layer 2/3: EXTRACTION_FFS.zip (3.8 GB)
[00:05:12] Unpacking layer 3/3: iOS filesystem image (3.7 GB)
[00:07:58] Unpack complete. 3 containers, 487,213 files, 3.7 GB.
[00:08:00] Starting file index...
```

**Case directory layout after unpack:**

```
~/cases/case-001/
├── case.json                     # Metadata
├── audit_log.jsonl              # Chain of custody
├── integrity_violations.sqlite  # (from FIX-3)
├── file_index.db                # (from v4 audit)
├── timeline.sqlite              # (from A-1)
├── original/                    # Symlink to original image
├── unpacked/                    # Extracted filesystem (if ExtractToDisk)
│   ├── layer_0/                 # Outer container extraction
│   ├── layer_1/                 # First nested container
│   └── layer_2/                 # Deepest layer (filesystem)
├── artifacts.sqlite             # Plugin artifacts
├── correlations.sqlite          # Cross-plugin correlations
└── reports/
    ├── examiner.html
    ├── expert_witness.html
    └── courtmartial.pdf
```

**Examiner transparency:**
The examiner should not need to know about container layers. From their
perspective, they point Strata at a Cellebrite tarball and get forensic
findings. The unpacking is invisible — but logged in detail in the audit
trail for chain of custody purposes.

**Audit log entries:**
Every container traversal logged:
```json
{
  "event": "ContainerUnpacked",
  "timestamp": "2026-04-17T23:15:22Z",
  "container_path": "original/case001.tar",
  "container_type": "UFED",
  "extraction_target": "unpacked/layer_0/",
  "bytes_extracted": 4281234567,
  "files_extracted": 487213,
  "sha256_original": "abc123...",
  "sha256_extracted": "def456..."
}
```

**Tests required:**
- End-to-end: Cellebrite tarball → artifacts emitted
- End-to-end: nested UFED + ZIP + filesystem
- Safety limit triggers (zip bomb test file)
- Audit log correctness

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 2 — IMAGE TYPE DETECTION + SMART PLUGIN ROUTING
# ═══════════════════════════════════════════════════════

## SPRINT DETECT-1 — Image Type Classification Engine

Create `crates/strata-core/src/detect/mod.rs` — the image classifier.

**Problem statement:**
Examiners currently must know which plugins to run against which image type.
For a Windows laptop image, they need Phantom, Chronicle, Sentinel, etc.
For an iOS image, they need Pulse, MOB-1/2/3, Apex.
For a Linux server, they need ARBOR.

This is tribal knowledge that slows new examiners and creates errors.
This sprint makes Strata figure it out automatically.

**Implementation:**

Image type enum:
```rust
pub enum ImageType {
    /// Windows (XP, 7, 8, 10, 11) — full filesystem
    WindowsWorkstation { version: Option<String> },
    /// Windows Server
    WindowsServer { version: Option<String> },
    /// macOS (10.x, 11.x, 12.x, 13.x, 14.x, 15.x)
    MacOS { version: Option<String> },
    /// iOS device (phone, tablet)
    IOS { version: Option<String>, device: Option<String> },
    /// iPadOS specifically
    IPadOS { version: Option<String> },
    /// Android device
    Android { version: Option<String>, oem: Option<String> },
    /// ChromeOS
    ChromeOS,
    /// Linux (any distribution)
    Linux { distribution: Option<String> },
    /// Generic Unix
    Unix,
    /// Memory dump (Windows, Linux, macOS)
    MemoryDump { host_os: Option<String> },
    /// Network packet capture
    NetworkCapture { format: PcapFormat },
    /// Cloud export (Google Takeout, Microsoft Graph export, etc.)
    CloudExport { provider: CloudProvider },
    /// Cellebrite report (already parsed)
    CellebriteReport,
    /// Generic filesystem we couldn't classify
    UnknownFilesystem,
    /// Mixed (multiple OSes or types detected)
    Mixed(Vec<ImageType>),
}

pub struct ImageClassification {
    pub primary_type: ImageType,
    pub confidence: f64,              // 0.0 to 1.0
    pub evidence: Vec<ClassificationEvidence>,
    pub recommended_plugins: Vec<String>,
    pub optional_plugins: Vec<String>,
    pub unnecessary_plugins: Vec<String>,
}

pub struct ClassificationEvidence {
    pub marker: String,        // "Found /System/Library/CoreServices/SystemVersion.plist"
    pub weight: f64,           // How strongly this indicates the type
    pub path: PathBuf,
}
```

**Detection strategy:**

Use filesystem markers with weighted scoring. Every marker found contributes
a weight to its associated image type. Highest score wins (with confidence
based on score delta).

**Windows markers:**
- `\Windows\System32\config\SYSTEM` (weight: 0.9)
- `\Windows\System32\ntoskrnl.exe` (weight: 0.9)
- `\Users\` directory with multiple user profiles (weight: 0.5)
- `\pagefile.sys` or `\hiberfil.sys` (weight: 0.3)
- `\Program Files\` (weight: 0.2)

Windows version detection:
- Parse SOFTWARE hive: `Microsoft\Windows NT\CurrentVersion` → ProductName, CurrentBuild
- Parse SYSTEM hive: `Setup` → InstallDate

Server vs Workstation:
- Parse `Microsoft\Windows NT\CurrentVersion\InstallationType` — "Server" or "Client"
- Presence of AD roles, DNS server data, etc.

**macOS markers:**
- `/System/Library/CoreServices/SystemVersion.plist` (weight: 0.9)
- `/Library/Preferences/` (weight: 0.5)
- `/Users/*/Library/Preferences/` (weight: 0.4)
- `/private/var/db/` (weight: 0.3)
- `.DS_Store` files throughout (weight: 0.2)

macOS version detection:
- Parse SystemVersion.plist → ProductVersion, BuildVersion

**iOS markers:**
- `/private/var/mobile/` (weight: 0.9)
- `/System/Library/Caches/com.apple.xpc.launchd/` (weight: 0.7)
- iOS-specific paths like Biome, KnowledgeC (weight: 0.5)
- Lack of `/Users/` (weight: 0.3 against macOS)

iOS version:
- Parse `/System/Library/CoreServices/SystemVersion.plist` → ProductVersion

**Android markers:**
- `/data/data/` (weight: 0.9)
- `/data/app/` (weight: 0.7)
- `/system/build.prop` (weight: 0.8)
- `/data/misc/bootstat/` (weight: 0.5)
- `/sdcard/` or `/mnt/sdcard/` (weight: 0.3)

Android version:
- Parse `/system/build.prop` → ro.build.version.release
- OEM detection: ro.product.manufacturer

**Linux markers:**
- `/etc/os-release` (weight: 0.9)
- `/etc/passwd` + `/etc/shadow` + `/etc/group` (weight: 0.7)
- `/var/log/syslog` or `/var/log/messages` (weight: 0.5)
- `/home/` with user dirs (weight: 0.4)

Distribution:
- Parse `/etc/os-release` → NAME, VERSION_ID

**Memory dump markers:**
- File size matches physical memory (multiple of 4GB typically)
- Not a filesystem (no partition table, no bootable structure)
- Windows crash dump magic bytes (MDMP, PAGEDUMP)
- LiME header (0xD4C3B2A1)

**Cloud export markers:**
- Google Takeout: `Takeout/` root folder, `archive_browser.html`
- Microsoft Graph: specific JSON export structure
- AWS CLI backup: `.aws/` directory structure

**Plugin routing rules:**

```rust
pub fn recommend_plugins(image_type: &ImageType) -> PluginRecommendation {
    match image_type {
        ImageType::WindowsWorkstation { .. } | ImageType::WindowsServer { .. } => {
            PluginRecommendation {
                recommended: vec![
                    "phantom", "chronicle", "sentinel", "trace", "remnant",
                    "guardian", "cipher", "nimbus", "conduit", "vector",
                    "wraith", "recon", "sigma",
                ],
                optional: vec!["carbon", "netflow"],
                unnecessary: vec!["mactrace", "apex", "pulse", "arbor"],
            }
        }
        ImageType::MacOS { .. } => {
            PluginRecommendation {
                recommended: vec![
                    "mactrace", "apex", "cipher", "nimbus",
                    "conduit", "vector", "recon", "sigma",
                ],
                optional: vec!["vault", "netflow"],
                unnecessary: vec!["phantom", "chronicle", "sentinel", "trace",
                                  "remnant", "guardian", "pulse", "arbor"],
            }
        }
        ImageType::IOS { .. } | ImageType::IPadOS { .. } => {
            PluginRecommendation {
                recommended: vec!["pulse", "apex", "vault", "sigma"],
                optional: vec!["cipher", "nimbus"],
                unnecessary: vec!["phantom", "chronicle", "sentinel", "trace",
                                  "remnant", "guardian", "mactrace", "carbon",
                                  "netflow", "conduit", "wraith", "arbor"],
            }
        }
        ImageType::Android { .. } => {
            PluginRecommendation {
                recommended: vec!["carbon", "pulse", "specter", "apex", "vault", "sigma"],
                optional: vec!["cipher"],
                unnecessary: vec!["phantom", "chronicle", "sentinel", "trace",
                                  "remnant", "guardian", "mactrace", "netflow",
                                  "conduit", "wraith", "arbor"],
            }
        }
        ImageType::Linux { .. } | ImageType::Unix => {
            PluginRecommendation {
                recommended: vec!["arbor", "netflow", "cipher", "recon", "vector", "sigma"],
                optional: vec!["nimbus"],
                unnecessary: vec!["phantom", "chronicle", "sentinel", "trace",
                                  "remnant", "guardian", "mactrace", "apex",
                                  "carbon", "pulse", "specter"],
            }
        }
        ImageType::MemoryDump { .. } => {
            PluginRecommendation {
                recommended: vec!["phantom", "wraith", "vector", "recon", "sigma"],
                optional: vec!["cipher"],
                unnecessary: vec!["chronicle", "sentinel", "trace", "remnant",
                                  "guardian", "mactrace", "apex", "carbon",
                                  "pulse", "specter", "netflow", "conduit",
                                  "nimbus", "arbor"],
            }
        }
        ImageType::CloudExport { .. } => {
            PluginRecommendation {
                recommended: vec!["nimbus", "recon", "sigma"],
                optional: vec!["cipher", "vector"],
                unnecessary: vec!["phantom", "chronicle", "sentinel", "trace",
                                  "remnant", "guardian", "mactrace", "apex",
                                  "carbon", "pulse", "specter", "netflow",
                                  "conduit", "wraith", "arbor", "vault"],
            }
        }
        ImageType::NetworkCapture { .. } => {
            PluginRecommendation {
                recommended: vec!["netflow", "recon", "sigma"],
                optional: vec!["vector"],
                unnecessary: vec!["phantom", "chronicle", "sentinel", "trace",
                                  "remnant", "guardian", "cipher", "mactrace",
                                  "apex", "carbon", "pulse", "specter",
                                  "conduit", "wraith", "nimbus", "arbor", "vault"],
            }
        }
        ImageType::Mixed(types) => {
            // Combine recommendations from all types
            // Take union of recommended
            // Only mark unnecessary if ALL constituent types agree
            combine_recommendations(types)
        }
        _ => PluginRecommendation::all_plugins(),
    }
}
```

**Zero-confidence fallback:**
If classification confidence < 0.3 (couldn't reliably determine type),
run all plugins. Better to over-run than miss evidence.

**Tests required:**
- Windows detection from SYSTEM/SOFTWARE hives
- macOS detection from SystemVersion.plist
- iOS detection from mobile directory structure
- Android detection from build.prop
- Linux detection from os-release
- Memory dump detection
- Mixed-type detection (USB drive containing Windows backup on macOS filesystem)
- Unknown type fallback to all plugins

Zero unwrap, zero unsafe, Clippy clean, eight tests minimum.

---

## SPRINT DETECT-2 — Interactive Plugin Routing UI (CLI + GUI)

Enhance CLI and GUI with interactive plugin routing.

**CLI behavior:**

After unpack completes but before plugins run:
```
╔══════════════════════════════════════════════════════════════╗
║  IMAGE CLASSIFICATION                                         ║
╠══════════════════════════════════════════════════════════════╣
║  Type:        Windows 11 Workstation                         ║
║  Version:     Windows 11 Pro 22H2 (Build 22621)              ║
║  Confidence:  94%                                             ║
║                                                               ║
║  Evidence:                                                    ║
║  • Found \Windows\System32\config\SYSTEM                     ║
║  • Found \Users\korbyn\NTUSER.DAT                           ║
║  • CurrentVersion → Windows 11 Pro                          ║
╠══════════════════════════════════════════════════════════════╣
║  RECOMMENDED PLUGINS (will run):                             ║
║  ✓ phantom    ✓ chronicle  ✓ sentinel   ✓ trace             ║
║  ✓ remnant    ✓ guardian   ✓ cipher     ✓ nimbus            ║
║  ✓ conduit    ✓ vector     ✓ wraith     ✓ recon             ║
║  ✓ sigma                                                      ║
║                                                               ║
║  OPTIONAL (skipped — use --include to enable):               ║
║  ○ carbon     ○ netflow                                      ║
║                                                               ║
║  UNNECESSARY (skipped — not applicable to this image):       ║
║  ✗ mactrace   ✗ apex       ✗ pulse      ✗ arbor             ║
║  ✗ specter    ✗ vault                                        ║
╠══════════════════════════════════════════════════════════════╣
║  Continue with recommended plugins? [Y/n/all/select]          ║
╚══════════════════════════════════════════════════════════════╝
```

Options:
- **Y** (default) — run recommended plugins
- **n** — abort
- **all** — run all plugins regardless of recommendation
- **select** — enter interactive plugin selection mode

**Non-interactive mode:**
Add CLI flag `--auto` which accepts defaults without prompting:
```bash
strata ingest run --source image.e01 --case-dir ./cases/001 --auto
```

Add CLI flag `--plugins` for explicit selection:
```bash
strata ingest run --source image.e01 --plugins phantom,chronicle,sigma
```

Add CLI flag `--include` to add optional plugins:
```bash
strata ingest run --source image.e01 --include carbon,netflow
```

**GUI behavior:**

After unpack, show classification modal:
- Large header: "Detected: Windows 11 Workstation (94% confidence)"
- Three columns: Recommended, Optional, Unnecessary
- Each plugin has toggle switch (recommended pre-enabled)
- Evidence panel explaining the classification
- Proceed button starts plugin execution

Examiner can override any classification before starting.

**Classification confidence display:**
- **> 90%** → Green indicator, "High confidence"
- **70-90%** → Yellow, "Medium confidence"
- **< 70%** → Red, "Low confidence — review carefully"
- **< 30%** → "Unable to classify — running all plugins"

**Override and manual mode:**
Examiner can always override to run all plugins or select specific ones.
Override logged in audit trail:
```json
{
  "event": "PluginSelectionOverride",
  "timestamp": "...",
  "classification": "WindowsWorkstation",
  "recommended_plugins": [...],
  "examiner_selected_plugins": [...],
  "reason": "examiner_choice"
}
```

**Tests required:**
- CLI interactive flow (with mocked stdin)
- CLI --auto flag
- CLI --plugins explicit selection
- Classification confidence rendering
- GUI classification modal state management

Zero unwrap, zero unsafe, Clippy clean, six tests minimum.

---

## SPRINT DETECT-3 — Multi-Image Correlation Hints

Enhance the existing multi-image correlation (WF-11) with classification-aware hints.

**Problem statement:**
When an examiner opens multiple evidence items for one case, Strata should
proactively identify relationships:
- "This appears to be a laptop belonging to the same user as this iPhone"
- "This memory dump was taken from the Windows image in this case"
- "These two Android devices appear to share a Google account"

**Implementation:**

Add to multi-image correlator:
```rust
pub fn infer_cross_evidence_relationships(
    evidence_classifications: &[(String, ImageClassification)],
) -> Vec<EvidenceRelationship> {
    // ...
}

pub struct EvidenceRelationship {
    pub evidence_a: String,
    pub evidence_b: String,
    pub relationship_type: RelationshipType,
    pub confidence: f64,
    pub shared_indicators: Vec<String>,
}

pub enum RelationshipType {
    /// Same user across devices
    SameUser,
    /// Memory dump matches source disk image
    MemoryOfDisk,
    /// Backup of another device
    BackupRelationship,
    /// Devices communicated with each other
    CommunicationPartners,
    /// Shared network environment
    SameNetwork,
    /// Related in some other way
    Other(String),
}
```

**Detection heuristics:**
- Shared username in user account lists → SameUser (high confidence)
- Shared Apple ID / Google account → SameUser (very high confidence)
- Memory dump + Windows image with matching hostname → MemoryOfDisk
- iTunes backup on Windows image + iOS image with matching device ID → BackupRelationship
- Shared WiFi network MAC addresses → SameNetwork
- Messages between phone numbers present on both devices → CommunicationPartners

**Output:**
Present relationships as a "Case Evidence Map" in the main report:

```
Evidence Map (3 items):

📱 iPhone 12 (iOS 17.2)           ──┐
   - Apple ID: korbyn@example.com   │
                                     ├── SAME USER (99%)
💻 MacBook Pro (macOS 14.3)       ──┘
   - Apple ID: korbyn@example.com

💻 MacBook Pro (macOS 14.3)       ──┐
                                     ├── MEMORY DUMP (95%)
💾 memory_dump.raw                 ──┘
   - Hostname matches: Korbyns-MacBook
```

**Tests required:**
- Shared username detection across Windows images
- Apple ID matching between iOS and macOS
- Memory dump to disk matching
- No false positives (unrelated evidence stays separate)

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 3 — VALIDATION + PERFORMANCE BENCHMARKS
# ═══════════════════════════════════════════════════════

## SPRINT VALIDATE-v6-1 — Re-run Full Image Matrix with Auto-Unpack + Routing

After UNPACK-1/2/3 and DETECT-1/2/3 ship, re-run the full Test Material
collection to confirm everything works end-to-end.

**Execution:**

For every image in `~/Wolfmark/Test Material/`:

1. Run Strata with auto-unpack enabled
2. Capture classification output (what did it detect?)
3. Capture plugin recommendation (which ran, which skipped?)
4. Capture final artifact count
5. Capture correlation findings
6. Capture total ingestion time

**Compare against VALIDATE-1 baseline:**
- Did classification accuracy match reality? (e.g., was the iOS image
  actually classified as iOS?)
- Did plugin routing improve performance (skipping irrelevant plugins)?
- Did auto-unpack surface artifacts that VALIDATE-1 missed because it
  couldn't get to nested layers?
- Did correlation find more cross-evidence relationships?

**Deliverable:**
`FIELD_VALIDATION_v6_REPORT.md` with:
- Classification accuracy table (image → detected type → actual type → match)
- Plugin routing efficiency (time saved vs. running all)
- New artifacts surfaced by auto-unpack (not found in v5 run)
- New correlations found

**Target outcomes:**
- 100% classification accuracy on clearly-typed images
- 80%+ time savings on single-platform images (no unnecessary plugin runs)
- 2-5x more artifacts surfaced on Cellebrite-wrapped iOS images (due to
  auto-unpack reaching inner filesystems)
- Cross-evidence correlations fire on multi-image cases

---

## SPRINT BENCH-1 — Performance Benchmarks Documentation

With auto-unpack live, produce the performance documentation deferred from v5.

**Benchmark matrix:**

Run Strata against test images in these tiers:

**Tier 1: Small (< 10GB)**
- iPhone full file system extraction
- Android phone image
- Small Windows laptop image
- Linux VM image

**Tier 2: Medium (10-100GB)**
- Windows workstation image
- macOS laptop image
- Large Android tablet
- Memory dump (64-128GB)

**Tier 3: Large (100GB-1TB)**
- Windows server image
- macOS workstation with FileVault
- Multi-TB NAS-like image

**Tier 4: Containerized/Nested**
- Cellebrite tarball (with auto-unpack)
- Multi-segment E01 split image
- Nested ZIP-in-TAR-in-UFED

**Metrics captured per image:**
- Container detection time
- Unpack time (and unpack throughput in MB/sec)
- File index build time
- File index throughput (files/sec)
- Per-plugin execution time
- Total ingestion time
- Peak memory usage
- Peak disk usage during unpack
- Output: artifact count, correlation count

**Output:**
`docs/PERFORMANCE_BENCHMARKS.md`

Format as publishable documentation — these numbers go on marketing
materials and procurement RFP responses. Be honest. Include hardware
specs. Include the image specs. Include cold-cache vs warm-cache numbers.

**Hardware baselines:**
- Apple Silicon M1 Max 64GB (Korbyn's workstation)
- Note which numbers would change on different hardware

**Comparison claims (use carefully):**
Only make comparison claims to Cellebrite/Magnet/X-Ways when based on
publicly available performance documentation or direct testing. Never
fabricate comparison numbers. Better to simply state Strata's numbers
and let examiners draw their own conclusions.

---

## SPRINT BENCH-2 — Memory and Resource Usage Profiling

Verify Strata runs well on field hardware, not just Korbyn's M1 Max.

**Test profiles:**

**Profile A: Field laptop (8GB RAM, SATA SSD, i5-10th gen)**
- Run ingestion on iPhone image
- Verify doesn't OOM
- Measure performance degradation vs workstation
- Confirm StreamOnDemand kicks in automatically

**Profile B: Mid-range workstation (32GB RAM, NVMe SSD, i7-13th gen)**
- Run full Cellebrite + auto-unpack
- Confirm performance matches expectations

**Profile C: Forensic server (128GB RAM, NVMe RAID, Xeon 32-core)**
- Run multiple images in parallel
- Verify scaling

**Deliverable:**
Add to `docs/PERFORMANCE_BENCHMARKS.md` a "System Requirements" section:
- Minimum: 8GB RAM, 100GB free disk, 4 CPU cores
- Recommended: 32GB RAM, 500GB free disk, 8 CPU cores
- Optimal: 64GB+ RAM, 1TB+ NVMe, 16+ CPU cores

Tests required on each profile:
- Full ingestion completes without OOM
- Progress reporting remains responsive
- Correlation engine completes
- Report generation succeeds

---

# ═══════════════════════════════════════════════════════
# COMPLETION CRITERIA
# ═══════════════════════════════════════════════════════

SPRINTS_v6.md is complete when:

**Auto-unpack (Part 1):**
- UNPACK-1 recursive engine shipped with all safety limits enforced
- UNPACK-2 streaming/virtual filesystem shipped
- UNPACK-3 CLI integration with progress reporting shipped
- Cellebrite tarballs auto-unpack to filesystem transparently
- All safety limits tested including zip bomb protection
- Audit logging captures every container traversal

**Image type detection (Part 2):**
- DETECT-1 classification engine identifies all major image types
- DETECT-2 interactive plugin routing in CLI and GUI
- DETECT-3 multi-image relationship inference surfacing cross-evidence hints
- Classification accuracy verified against all 23+ test images

**Validation + benchmarks (Part 3):**
- VALIDATE-v6-1 re-runs full matrix, documents improvements over v5
- BENCH-1 produces publishable performance benchmarks
- BENCH-2 documents system requirements across hardware tiers

**Quality gates:**
- Test count: 3,357+ (plus tests added in this queue)
- All tests passing
- Clippy clean workspace-wide
- Zero `.unwrap()`, zero `unsafe{}`, zero `println!` introduced
- All 9 load-bearing tests preserved
- Public API unchanged

**Ready to ship:**
- v1.5.0 release candidate locked
- Marketing numbers verified
- FIELD_VALIDATION_v6_REPORT.md publishable
- Performance documentation publishable
- Strata deployable to first pilot agency

---

*STRATA AUTONOMOUS BUILD QUEUE v6*
*Wolfmark Systems — 2026-04-17*
*Part 1: Auto-unpack engine — nested container transparency*
*Part 2: Image type detection + intelligent plugin routing*
*Part 3: Validation + benchmarks — publishable performance data*
*Mission: Zero-friction ingestion — examiner points, Strata figures it out*
*Execute all incomplete sprints in order. Ship everything.*
