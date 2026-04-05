# Strata Tree — Complete Product Roadmap
### From Current State to Court-Ready Forensic Workbench
**Version:** 0.2.0 → 1.0.0  
**Codebase:** `D:\Strata\apps\tree\strata-tree\`  
**Binary:** `D:\Strata\target\release\strata-tree.exe` (16.4MB, 6.46s build)  
**Date:** 2026-03-28  
**Status at start:** 10,038 LOC · 71 files · 48 pub structs · 120 pub fns · 0 unwrap() · 9 functional UI tabs

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current State Snapshot](#2-current-state-snapshot)
3. [The Primary Gap — VFS Byte-Level Access](#3-the-primary-gap--vfs-byte-level-access)
4. [Milestone Map](#4-milestone-map)
5. [Phase 1 — Foundation Hardening (Weeks 1–6)](#5-phase-1--foundation-hardening-weeks-16)
6. [Phase 2 — Artifact Parsers (Weeks 7–14)](#6-phase-2--artifact-parsers-weeks-714)
7. [Phase 3 — Performance & Scale (Weeks 15–20)](#7-phase-3--performance--scale-weeks-1520)
8. [Phase 4 — Intelligence Layer (Weeks 21–28)](#8-phase-4--intelligence-layer-weeks-2128)
9. [Phase 5 — Court-Ready Polish (Weeks 29–36)](#9-phase-5--court-ready-polish-weeks-2936)
10. [Phase 6 — Plugin Ecosystem (Weeks 37–44)](#10-phase-6--plugin-ecosystem-weeks-3744)
11. [Phase 7 — Release Hardening (Weeks 45–52)](#11-phase-7--release-hardening-weeks-4552)
12. [Cross-Cutting Concerns](#12-cross-cutting-concerns)
13. [Full Feature Checklist](#13-full-feature-checklist)
14. [Dependency Upgrade Path](#14-dependency-upgrade-path)
15. [Architecture Decisions](#15-architecture-decisions)
16. [Codex Session Templates](#16-codex-session-templates)

---

## 1. Executive Summary

Strata Tree is a Rust/egui forensic workbench targeting government, law enforcement, and national security examiners. The core architecture is sound — egui immediate-mode UI, SQLite-backed case files, channel-based background workers, and a strata-fs VFS layer for E01 container access. Nine UI tabs all render real content with zero `todo!()`, `unimplemented!()`, or `unwrap()` calls in production code.

The single most important gap holding the entire product back is **VFS byte-level access not being wired to the hex editor, gallery, preview panel, hasher, and carver**. Every one of these subsystems uses `std::fs::read()` which works perfectly for host filesystem files but fails silently for files inside E01/VHD forensic containers. Fixing this one integration gap unlocks the majority of the product's forensic value.

Beyond that primary gap, the following major subsystems exist in code but are not wired to the UI: carve engine (26 signatures), hash set manager (NSRL + custom), content indexer (tantivy), and full court-ready HTML report generator. The artifact parser layer (Prefetch, Shellbag, LNK, Browser, EVTX) has not been started. The audit log lacks cryptographic chain integrity. The examiner profile is not persisted between sessions. There is no auto-save.

This roadmap addresses all of the above across seven phases spanning approximately 52 weeks, structured so that each phase produces a shippable increment with real forensic value.

---

## 2. Current State Snapshot

### What Works End-to-End

| Feature | Status | Notes |
|---|---|---|
| Open E01 and show file count | PARTIAL | Succeeds when NTFS enumeration succeeds; fallback shows 1 container entry |
| Navigate directory tree | YES | Works for host dirs and VFS paths when NTFS succeeds |
| Hex editor | PARTIAL | Works for host files; fails for VFS container files |
| Text preview | PARTIAL | Same VFS limitation |
| Gallery thumbnails | PARTIAL | Background worker with LRU-500 cache; fails for VFS images |
| Registry viewer | YES | Full nt-hive integration, 16 forensic keys, search, bookmarking |
| Timeline | YES | File timestamps only; suspicious event detection; filters |
| File bookmarking | YES | 6 tags, examiner notes, VTP persistence |
| Registry bookmarking | YES | Key + value targeting from registry view |
| File hashing | PARTIAL | Works for host files; fails for VFS files |
| HASH ALL | YES | Background worker, progress in titlebar |
| Evidence comparison | YES | Full diff, timestomping detection, CSV + PDF export |
| PDF export | YES | Case info + bookmarks + recent files via printpdf |
| CSV export | YES | Files, bookmarks, timeline |
| Save/load .vtp | YES | SQLite — evidence sources, file index, bookmarks, audit log |
| Audit log | YES | 13 action types; in-memory + VTP; no chain integrity |
| Prefetch parser | NO | Not started |
| Shellbag parser | NO | Not started |
| LNK parser | NO | Not started |
| Browser history parser | NO | Not started |
| File carving | NO | Engine exists (26 sigs), not wired |
| Hash set / NSRL | NO | Manager exists, not wired to UI |
| Content search | NO | Tantivy indexer exists, not wired |
| Plugin execution | NO | Loader exists, execution not wired |
| Auto-save | NO | Manual save only |
| Examiner profile persistence | NO | Setup dialog shown every launch |
| Audit chain integrity | NO | Append-only, no hash chain |

### Integration Gaps (Summary)

The following pairs exist independently but do not communicate:

- **HexState** ↔ **strata-fs VFS** — hex editor reads `std::fs`, not VFS bytes
- **GalleryView** ↔ **strata-fs VFS** — thumbnails decode from `std::fs`, not VFS
- **PreviewPanel** ↔ **strata-fs VFS** — preview reads `std::fs`, not VFS
- **Hasher** ↔ **strata-fs VFS** — hashing reads `std::fs`, not VFS bytes
- **CarveEngine** ↔ **Toolbar** — button exists, engine is not invoked
- **ContentIndexer** ↔ **SearchView** — only metadata search is wired
- **HashSetManager** ↔ **UI** — no load/match UI
- **PluginLoader** ↔ **Plugin execution** — loading works, running does not
- **Timeline** ↔ **Registry** — registry events never generated
- **report/html.rs** ↔ **Export button** — HTML report not exposed in toolbar
- **ExaminerProfile** ↔ **Persistence** — profile lost between sessions

### Performance Bottlenecks (Summary)

Every one of the following runs on the UI thread every frame:

- `visible_files()` — iterates entire `file_index` Vec
- `file_table` — clones entire `Vec<FileEntry>` then sorts
- `collect_dirs()` — iterates all entries per evidence source
- `deleted_count()`, `carved_count()`, `hashed_count()`, `flagged_count()` — each iterates entire index
- `spawn_timeline_builder` — clones entire `file_index` into thread
- `render_image_preview` — `std::fs::read()` blocks render loop
- `HexState::load_file` — `std::fs::read()` blocks render loop

---

## 3. The Primary Gap — VFS Byte-Level Access

This is the single most impactful gap in the entire codebase. It blocks hex editing, gallery thumbnails, image preview, file hashing, and file carving for any file inside a forensic container. It must be solved first before anything else.

### Current Architecture

```
FileEntry {
    id: Uuid,
    full_path: String,      // e.g. "E:\case\evidence.E01/NTFS/Windows/System32/cmd.exe"
    evidence_id: String,    // links back to EvidenceSource
    ...
}

EvidenceSource {
    id: String,
    path: PathBuf,          // D:\evidence\stack001.E01
    vfs: Option<Arc<EwfVfs>>,
}

HexState::load_file(path: &str) {
    // BROKEN for VFS files:
    let bytes = std::fs::read(path)?;  // fails — path is virtual
}
```

### Required Solution

Implement a `VfsReadContext` that routes file reads through the correct source:

```rust
pub enum ReadSource {
    HostFilesystem(PathBuf),
    VfsContainer {
        evidence_id: String,
        virtual_path: String,
    },
}

pub struct VfsReadContext {
    sources: Arc<HashMap<String, Arc<EwfVfs>>>,
}

impl VfsReadContext {
    pub fn read_file(&self, entry: &FileEntry) -> Result<Vec<u8>, anyhow::Error>;
    pub fn read_range(&self, entry: &FileEntry, offset: u64, len: usize) -> Result<Vec<u8>, anyhow::Error>;
    pub fn stream_file(&self, entry: &FileEntry) -> Result<impl Read, anyhow::Error>;
}
```

This context is created once in `AppState`, held in an `Arc`, and passed to every subsystem that reads file bytes: hex editor, gallery worker, preview panel, hasher worker, carver. Once wired, all five subsystems work for both host files and VFS container files without further changes.

### Wire Points

| Subsystem | File | Change Required |
|---|---|---|
| HexState | `src/state.rs:143` | Replace `std::fs::read()` with `ctx.read_range()` |
| GalleryView | `src/ui/gallery_view.rs` | Pass `VfsReadContext` to thumbnail worker |
| PreviewPanel | `src/ui/preview_panel.rs` | Replace `File::open()` with `ctx.read_file()` |
| Hasher | `src/evidence/hasher.rs` | Replace `std::fs::File` with `ctx.stream_file()` |
| CarveEngine | `src/carve/engine.rs` | Pass `ctx.stream_file()` as data source |

---

## 4. Milestone Map

```
WEEK  1-2   M0: VFS Byte-Level Access — wire read context to all 5 subsystems
WEEK  3-4   M1: Carve Engine UI — wire CARVE button, carve dialog, $CARVED tree node
WEEK  5-6   M2: Hash Set Manager UI — load NSRL, match on hash, UI indicators

WEEK  7-8   M3: Prefetch Parser — parse .pf, timeline integration, viewer
WEEK  9-10  M4: Shellbag Parser — BagMRU walk, timeline integration, viewer
WEEK 11-12  M5: LNK Parser — shortcut analysis, deleted target detection
WEEK 13-14  M6: Browser History Parser — Chrome/Firefox/Edge SQLite parsing

WEEK 15-16  M7: Virtual Scrolling File Table — handle 1M+ file indexes
WEEK 17-18  M8: Hex Editor Virtual Rendering — demand paging, search
WEEK 19-20  M9: SQLite Query Architecture — replace in-memory filter with SQL

WEEK 21-22  M10: Content Indexer UI — wire tantivy, full-text search tab
WEEK 23-24  M11: EVTX Parser — Windows Event Log, security/system/application
WEEK 25-26  M12: Timeline Enrichment — registry + artifact events in timeline
WEEK 27-28  M13: Audit Chain Integrity — cryptographic hash chain, tamper detection

WEEK 29-30  M14: Court-Ready PDF Report — wire report/html.rs, full template
WEEK 31-32  M15: .VTP Completion — timeline/comparison/search persistence, auto-save
WEEK 33-34  M16: Examiner Profile — persist name/agency/badge, case assignment
WEEK 35-36  M17: UI Polish Pass — keyboard nav, column resize, theme, accessibility

WEEK 37-38  M18: Plugin Execution — wire C-ABI, run on evidence files
WEEK 39-40  M19: Plugin SDK — document protocol, provide strata-tree-sdk
WEEK 41-42  M20: Remnant/Chronicle/Cipher/Trace plugin integration
WEEK 43-44  M21: Plugin marketplace scaffold (local install)

WEEK 45-46  M22: Full Smoke Test Suite — 22-step automated verification
WEEK 47-48  M23: Performance Benchmarks — 1M file index, 50GB E01
WEEK 49-50  M24: Security Audit — evidence integrity, no write paths
WEEK 51-52  M25: v1.0 Release — installer, signing, documentation
```

---

## 5. Phase 1 — Foundation Hardening (Weeks 1–6)

### M0 — VFS Byte-Level Access (Weeks 1–2)

**Priority: CRITICAL — blocks all downstream work**

#### Task M0.1 — Implement VfsReadContext

File: `src/evidence/vfs_context.rs` (new file)

```rust
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use anyhow::Result;
use strata_fs::EwfVfs;
use crate::state::FileEntry;

/// Routes file reads to the correct source — host filesystem or VFS container.
pub struct VfsReadContext {
    /// Maps evidence_id → VFS instance
    pub vfs_map: Arc<HashMap<String, Arc<EwfVfs>>>,
}

impl VfsReadContext {
    pub fn new(vfs_map: Arc<HashMap<String, Arc<EwfVfs>>>) -> Self {
        Self { vfs_map }
    }

    /// Read entire file content. For files under 64MB only.
    pub fn read_file(&self, entry: &FileEntry) -> Result<Vec<u8>> {
        if entry.evidence_id.is_empty() {
            // Host filesystem file
            Ok(std::fs::read(&entry.full_path)?)
        } else {
            let vfs = self.vfs_map.get(&entry.evidence_id)
                .ok_or_else(|| anyhow::anyhow!("VFS not found for evidence {}", entry.evidence_id))?;
            Ok(vfs.read_file(&entry.vfs_path)?)
        }
    }

    /// Read a byte range. Use for hex editor and streaming.
    pub fn read_range(&self, entry: &FileEntry, offset: u64, len: usize) -> Result<Vec<u8>> {
        if entry.evidence_id.is_empty() {
            let mut f = std::fs::File::open(&entry.full_path)?;
            std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(offset))?;
            let mut buf = vec![0u8; len.min(entry.size as usize)];
            std::io::Read::read(&mut f, &mut buf)?;
            Ok(buf)
        } else {
            let vfs = self.vfs_map.get(&entry.evidence_id)
                .ok_or_else(|| anyhow::anyhow!("VFS not found"))?;
            Ok(vfs.read_at(&entry.vfs_path, offset, len)?)
        }
    }
}
```

Add `vfs_path: String` field to `FileEntry` in `src/state.rs`. This is the VFS-internal path separate from `full_path`. For host filesystem files it is empty. For VFS files it is the path within the container (e.g. `/Windows/System32/cmd.exe`).

Add `vfs_context: Option<Arc<VfsReadContext>>` to `AppState`.

Build `vfs_context` in `app.rs` when an evidence source is loaded:

```rust
// After VFS is attached to evidence source:
let mut vfs_map = HashMap::new();
for src in &state.evidence_sources {
    if let Some(vfs) = &src.vfs {
        vfs_map.insert(src.id.clone(), Arc::clone(vfs));
    }
}
state.vfs_context = Some(Arc::new(VfsReadContext::new(Arc::new(vfs_map))));
```

#### Task M0.2 — Wire Hex Editor

File: `src/state.rs` — `HexState::load_file()`

Replace:
```rust
pub fn load_file(&mut self, path: &str) {
    match std::fs::read(path) {
        Ok(bytes) => { self.bytes = bytes.into(); ... }
        Err(e) => { self.load_error = true; ... }
    }
}
```

With:
```rust
pub fn load_entry(&mut self, entry: &FileEntry, ctx: &VfsReadContext) {
    // Load first 64KB for initial view
    match ctx.read_range(entry, 0, 65536) {
        Ok(bytes) => {
            self.bytes = bytes;
            self.file_size = entry.size;
            self.file_entry_id = Some(entry.id);
            self.load_error = false;
            self.load_error_msg = String::new();
        }
        Err(e) => {
            self.load_error = true;
            self.load_error_msg = format!("Cannot read: {}", e);
        }
    }
}
```

Update all call sites in `app.rs` and `ui/hex_panel.rs` to pass `ctx`.

#### Task M0.3 — Wire Gallery Worker

File: `src/ui/gallery_view.rs`

The thumbnail worker closure currently captures only the file path. Extend it to accept a `VfsReadContext`:

```rust
// In spawn_thumbnail_worker():
let ctx = Arc::clone(ctx);
let entry = entry.clone();
std::thread::spawn(move || {
    match ctx.read_file(&entry) {
        Ok(bytes) => {
            match image::load_from_memory(&bytes) {
                Ok(img) => {
                    let thumb = img.thumbnail(128, 128);
                    tx.send(ThumbnailMessage::Ready { id: entry.id, thumb }).ok();
                }
                Err(e) => tx.send(ThumbnailMessage::Error { id: entry.id, msg: e.to_string() }).ok(),
            }
        }
        Err(e) => tx.send(ThumbnailMessage::Error { id: entry.id, msg: e.to_string() }).ok(),
    }
});
```

#### Task M0.4 — Wire Preview Panel

File: `src/ui/preview_panel.rs`

Replace all `std::fs::File::open(&entry.full_path)` and `std::fs::read(&entry.full_path)` with `ctx.read_file(&entry)`. The preview panel renders text, hex, image, EXIF — all need the context.

#### Task M0.5 — Wire Hasher

File: `src/evidence/hasher.rs`

The hasher currently opens `std::fs::File`. Extend the hash worker to accept `VfsReadContext` and stream bytes through `ctx.read_range()` in 64KB chunks regardless of whether the file is in a container.

#### Task M0.6 — Wire Carver Data Source

File: `src/carve/engine.rs`

Add a `scan_entry(entry: &FileEntry, ctx: &VfsReadContext)` function that reads the file in 1MB pages and runs the signature scanner over each page, handling cross-page boundaries for signatures that span chunk edges.

#### Verification

After M0, run this sequence and verify each works for a file INSIDE an E01 container:
- Select file → hex editor shows bytes ✓
- Select image → gallery shows thumbnail ✓
- Select file → preview shows text/hex/image ✓
- Hash single file → hash appears in file table ✓
- HASH ALL → processes VFS files ✓

---

### M1 — Carve Engine UI (Weeks 3–4)

**Prerequisite: M0 complete**

#### Task M1.1 — Wire CARVE Toolbar Button

File: `src/ui/toolbar.rs`

Replace stub message with launch of `CarveDialog`:

```rust
ToolbarAction::Carve => {
    state.show_carve_dialog = true;
}
```

#### Task M1.2 — Render CarveDialog

File: `src/ui/dialogs/carve_dialog.rs` (exists but not rendered)

Add to `src/ui/dialogs/mod.rs`:

```rust
if state.show_carve_dialog {
    carve_dialog::render(ctx, state, vfs_context);
}
```

The dialog must offer:
- Evidence source selector (which partition/volume to carve)
- Signature checkbox list (JPEG, PNG, PDF, ZIP, DOCX, SQLite, EVTX, LNK, PF, MP3, MP4, ...)
- Output location (in-memory virtual $CARVED node only — never write to evidence)
- Start/Cancel buttons
- Progress bar during carving (scanned MB / total MB)
- Results summary when complete: "234 files carved — JPEG: 180 | PDF: 32 | ZIP: 22"

#### Task M1.3 — Background Carve Worker

File: `src/carve/engine.rs`

Wire the existing `CarveEngine` to a background thread with progress reporting:

```rust
pub enum CarveMessage {
    Progress { scanned_bytes: u64, total_bytes: u64 },
    FileFound { entry: FileEntry },
    Complete { count: usize },
    Error { msg: String },
}

pub fn spawn_carve_worker(
    source: Arc<EwfVfs>,
    signatures: Vec<SignatureType>,
    tx: mpsc::Sender<CarveMessage>,
) -> JoinHandle<()>
```

Poll `carve_rx` in `app.rs::update()` alongside existing channel pollers.

#### Task M1.4 — $CARVED Virtual Directory

File: `src/ui/tree_panel.rs`

When carved entries arrive, add them to `state.file_index` with:

```rust
FileEntry {
    full_path: format!("$CARVED/{}/{}", sig_name, offset),
    parent_path: format!("$CARVED/{}", sig_name),
    name: format!("carved_{:016x}.{}", offset, ext),
    is_carved: true,
    evidence_id: source_id.clone(),
    ...
}
```

Add a `$CARVED` node to the evidence tree that expands to show `JPEG (180)`, `PDF (32)`, etc.

#### Task M1.5 — Carved File Preview

File: `src/ui/preview_panel.rs`

For carved image files: show thumbnail using `VfsReadContext.read_range(entry, entry.carve_offset, entry.size)`.

For non-image carved files: show carve details — source offset, size, confidence score (0–100%), signature detected, SHA-256.

Add an EXPORT FILE button that saves the carved bytes to a user-selected path via `rfd::FileDialog`.

---

### M2 — Hash Set Manager UI (Weeks 5–6)

The `hash/hashset.rs` `HashSetManager` is complete. It needs only a UI.

#### Task M2.1 — Hash Sets Tab

Add a HASH SETS tab to the tab bar between PLUGINS and AUDIT LOG.

File: `src/ui/hash_sets_view.rs` (new)

Layout:
```
[IMPORT HASH SET]  [CLEAR ALL]

Loaded Hash Sets:
┌─────────────────────────────────────────────────────┐
│ Name          │ Type      │ Entries  │ Source        │
├───────────────┼───────────┼──────────┼───────────────┤
│ NSRL v3.1     │ Known Good│ 145,234  │ NSRLFile.txt  │
│ Malware MD5s  │ Known Bad │  12,847  │ custom.txt    │
└─────────────────────────────────────────────────────┘

NSRL Download: https://www.nist.gov/itl/ssd/software-quality-group/...
Import formats: NSRL RDS (tab-separated), SHA-256 list, MD5 list, CSV
```

#### Task M2.2 — Import Dialog

On IMPORT HASH SET:
1. `rfd::FileDialog` → pick file
2. Auto-detect format: NSRL header → parse NSRLFile.txt; single-column → SHA-256 or MD5 list; `.csv` with header → parse columns
3. Show progress: "Importing... 12,847 / 145,234 entries"
4. On complete: add to `HashSetManager`, show count

#### Task M2.3 — Wire Hash Matching to File Table

After hashing completes for a file, call `hash_set_manager.lookup(sha256)`:

```rust
pub struct HashSetMatch {
    pub set_name: String,
    pub category: HashSetCategory, // KnownGood / KnownBad / Notable
    pub file_name: Option<String>,
}
```

Add `hash_match: Option<HashSetMatch>` to `FileEntry`.

File table rendering:
- `KnownGood` → dim row (opacity 50%), ✓ in hash column
- `KnownBad` → red left border, ⚠ in hash column, increment FLAGGED counter
- `Notable` → amber indicator in hash column

#### Task M2.4 — Hash Match in Preview Panel

In the IMAGE / INFO tab of preview panel, show hash set result:

```
KNOWN BAD — Malware.Generic.12345 (KnownBad set "Malware MD5s")
```
or
```
KNOWN GOOD — Windows System File (NSRL v3.1)
```

#### Task M2.5 — Hash Match in PDF Export

Include hash set match information in the PDF report for every bookmarked file:

```
Hash Status: KNOWN BAD — Malware.Generic.12345
Set: Custom Malware MD5s (imported 2026-03-28)
```

---

## 6. Phase 2 — Artifact Parsers (Weeks 7–14)

All parsers follow the same pattern:
1. Detection during NTFS indexing (set `category` field on `FileEntry`)
2. Binary parser that produces a typed struct
3. Timeline integration (events added to `TimelineEntry` vec)
4. Preview panel section (shown when file with that category is selected)
5. Suspicious flagging (flag events matching attacker TTPs)

### M3 — Windows Prefetch Parser (Weeks 7–8)

#### Task M3.1 — Prefetch Detection

File: `src/evidence/indexer.rs`

During NTFS walk, when path matches `*/Windows/Prefetch/*.pf`:
```rust
entry.category = Some(FileCategory::Prefetch);
```

#### Task M3.2 — Prefetch Binary Parser

New file: `src/parsers/prefetch.rs`

```rust
pub struct PrefetchFile {
    pub executable_name: String,       // e.g. "MIMIKATZ.EXE"
    pub prefetch_hash: u32,            // hash of executable path
    pub run_count: u32,                // number of executions recorded
    pub last_run_times: Vec<DateTime<Utc>>, // up to 8 entries
    pub volume_serial_numbers: Vec<u32>,
    pub volume_device_paths: Vec<String>,
    pub file_references: Vec<String>,  // files loaded during execution
    pub format_version: u8,            // 17=XP, 23=Vista/7, 26=Win8, 30=Win10+
}

pub fn parse_prefetch(data: &[u8]) -> Result<PrefetchFile, anyhow::Error>
```

Support format versions 17, 23, 26, and 30.

**MAM decompression (Win10):** Detect magic bytes `4D 41 4D 04` at offset 0. If present, decompress using the `lz4` or custom MAM algorithm before parsing. The Win10 Prefetch format uses a proprietary LZ variant. Use the `decomp` approach: read the 8-byte header, decompress the remaining body, then parse as version 30.

#### Task M3.3 — Prefetch Timeline Integration

File: `src/ui/timeline_view.rs`

For each `last_run_time` in a PrefetchFile, generate:
```rust
TimelineEntry {
    event_type: TimelineEventType::ProcessExecuted,
    timestamp: last_run_time,
    path: entry.full_path.clone(),
    detail: format!("{} executed (run {} of {})", 
        pf.executable_name, run_idx + 1, pf.run_count),
    is_suspicious: is_suspicious_execution(&pf),
}
```

Suspicious execution criteria:
- Path contains `\AppData\Local\Temp\`
- Path contains `\Downloads\`
- Path contains `\ProgramData\`
- Path contains `\Users\Public\`
- Executable name in known-bad list (mimikatz, psexec, wce, fgdump, pwdump, procdump, etc.)
- Executed from removable media path
- Execution time between 00:00 and 05:00 UTC

#### Task M3.4 — Prefetch Preview Viewer

File: `src/ui/preview_panel.rs`

When a `.pf` file is selected, show a PREFETCH tab:

```
Executable:   MIMIKATZ.EXE
Hash:         0xABCD1234
Run Count:    3
Format:       Windows 10+ (v30)

Execution Times:
  [1] 2023-03-22 14:55:01 UTC  ← most recent
  [2] 2023-03-21 09:12:44 UTC
  [3] 2023-03-20 18:33:12 UTC

Volumes Accessed:
  \DEVICE\HARDDISKVOLUME2

Files Referenced (first 20):
  \WINDOWS\SYSTEM32\NTDLL.DLL
  \WINDOWS\SYSTEM32\KERNEL32.DLL
  ... (247 total)

⚠ SUSPICIOUS: Known credential dumping tool
⚠ SUSPICIOUS: Executed from C:\Users\Suspect\Downloads\
```

---

### M4 — Windows Shellbag Parser (Weeks 9–10)

Shellbags prove a user navigated to a specific directory — even after the directory is deleted.

#### Task M4.1 — Shellbag Detection

During NTFS indexing, when a hive file is found at:
- `*/Users/*/NTUSER.DAT`
- `*/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat`

Set `entry.category = Some(FileCategory::RegistryHive)` and `entry.has_shellbags = true`.

#### Task M4.2 — Shellbag Parser

New file: `src/parsers/shellbag.rs`

```rust
pub struct ShellbagEntry {
    pub path: String,                           // reconstructed folder path
    pub last_interacted: Option<DateTime<Utc>>,
    pub first_interacted: Option<DateTime<Utc>>,
    pub bag_key: String,                        // registry key that contained this
    pub shell_type: ShellItemType,
    pub is_network_path: bool,
    pub is_removable: bool,
}

pub enum ShellItemType {
    Desktop,
    Drive(String),      // "C:\"
    Folder(String),     // folder name
    File(String),       // file name
    NetworkPath(String),
    Uri(String),
    Unknown(u8),        // type byte
}

pub fn parse_shellbags(
    hive: &nt_hive::Hive,
    source: ShellbagSource,
) -> Result<Vec<ShellbagEntry>, anyhow::Error>

pub enum ShellbagSource {
    NtUser,    // NTUSER.DAT — Software\Microsoft\Windows\Shell\BagMRU
    UsrClass,  // UsrClass.dat — Local Settings\Software\Microsoft\Windows\Shell\BagMRU
}
```

Walk the BagMRU tree recursively. Each node's value name is the MRU index. The value data is a ShellItem blob. Decode ShellItem type byte:
- `0x1F` — Desktop / special folder (GUID)
- `0x2F` — Drive letter
- `0x31`, `0x32` — Folder (short + long name)
- `0x40` — Network share
- `0x61` — URI

Timestamps are stored in FILETIME format in the ShellItem blob. Convert to `DateTime<Utc>`.

#### Task M4.3 — Shellbag Timeline Integration

```rust
TimelineEntry {
    event_type: TimelineEventType::UserActivity,
    timestamp: last_interacted,
    path: shellbag.path.clone(),
    detail: format!("User browsed: {}", shellbag.path),
    is_suspicious: is_suspicious_path(&shellbag.path),
}
```

Suspicious path criteria:
- Removable media (`\DEVICE\REMOVABLESTORAGE`, drive letter not C:/D:)
- Network paths (`\\`)
- Paths containing: `evidence`, `deleted`, `wiped`, `password`, `encrypt`
- Paths under `\Users\Public\`

#### Task M4.4 — Shellbag Viewer in Registry Panel

When NTUSER.DAT or UsrClass.dat is open in the registry viewer, add a SHELLBAGS section in the right panel below the value list:

```
SHELLBAGS (Click to parse)
[PARSE SHELLBAGS]

After parsing:
Desktop
└─ C:\
   └─ Users
      └─ Suspect
         ├─ Desktop       (accessed: 2023-03-22 14:55:01 UTC) ⚠
         ├─ Documents
         └─ Downloads     (accessed: 2023-03-22 14:50:12 UTC)
   └─ D:\                 (removable — USB?) ⚠
      └─ Evidence_Copy
```

---

### M5 — LNK File Parser (Weeks 11–12)

LNK files (Windows shortcuts) record access to files and folders even after the target is deleted. Extremely useful for proving file access.

#### Task M5.1 — LNK Detection

During indexing:
- Extension `.lnk` → check magic bytes `4C 00 00 00 01 14 02 00`
- Set `entry.category = Some(FileCategory::LnkShortcut)`

Common LNK locations to watch for:
- `*/Recent/*.lnk`
- `*/Microsoft/Windows/Recent/*.lnk`
- `*/Desktop/*.lnk`
- `*/AppData/Roaming/Microsoft/Office/Recent/*.lnk`

#### Task M5.2 — LNK Binary Parser

New file: `src/parsers/lnk.rs`

```rust
pub struct LnkFile {
    pub target_path: Option<String>,
    pub target_size: Option<u64>,
    pub target_created: Option<DateTime<Utc>>,
    pub target_modified: Option<DateTime<Utc>>,
    pub target_accessed: Option<DateTime<Utc>>,
    pub working_directory: Option<String>,
    pub arguments: Option<String>,          // command line arguments
    pub machine_id: Option<String>,         // NetBIOS hostname
    pub volume_label: Option<String>,
    pub volume_serial: Option<u32>,
    pub drive_type: DriveType,
    pub is_network_target: bool,
    pub network_share_name: Option<String>,
    pub lnk_created: Option<DateTime<Utc>>,
    pub lnk_modified: Option<DateTime<Utc>>,
    pub lnk_accessed: Option<DateTime<Utc>>,
    pub relative_path: Option<String>,
    pub icon_location: Option<String>,
    pub description: Option<String>,
    pub show_command: u32,
}

pub enum DriveType {
    Unknown, NoRootDir, Removable, Fixed, Remote, CdRom, RamDisk,
}

pub fn parse_lnk(data: &[u8]) -> Result<LnkFile, anyhow::Error>
```

Parse according to MS-SHLLINK specification:
1. Shell Link Header (76 bytes) — flags, timestamps, file size
2. Link Target ID List (if HasLinkTargetIDList flag)
3. Link Info (if HasLinkInfo flag) — volume type, serial, path
4. String Data — name, relative path, working dir, arguments, icon
5. Extra Data blocks — MachineName, Tracker, etc.

#### Task M5.3 — LNK Timeline Integration

```rust
// LNK creation time → user accessed or created the shortcut
TimelineEntry {
    event_type: TimelineEventType::UserActivity,
    timestamp: lnk.lnk_created,
    path: entry.full_path.clone(),
    detail: format!("Shortcut created to: {}", target_path),
    is_suspicious: check_lnk_suspicious(&lnk, &state.file_index),
}

// Target modified time → the actual target file was written
TimelineEntry {
    event_type: TimelineEventType::FileModified,
    timestamp: lnk.target_modified,
    path: target_path.clone(),
    detail: format!("Target file modified (via LNK: {})", lnk_name),
    is_suspicious: false,
}
```

Suspicious LNK criteria:
- Target path not found in `file_index` → target was deleted
- Drive type is Removable → target was on USB/external
- Target path is network share
- Target in Temp or Downloads
- `machine_id` differs from the evidence machine hostname (lateral movement indicator)

#### Task M5.4 — LNK Preview Viewer

Show in preview panel LNK tab:

```
Target Path:    C:\Users\Suspect\Desktop\stolen_data.zip
Target Created: 2023-03-22 14:55:01 UTC
Target Modified:2023-03-22 14:55:01 UTC
Target Size:    1,234,567 bytes
Working Dir:    C:\Users\Suspect\Desktop
Arguments:      (none)
Machine ID:     SUSPECT-PC
Volume Serial:  0xABCD1234
Drive Type:     Local Fixed Disk

LNK Created:    2023-03-22 14:55:01 UTC
LNK Modified:   2023-03-22 14:55:03 UTC

⚠ TARGET NOT FOUND IN EVIDENCE — file was deleted or on external media
⚠ MACHINE ID MISMATCH — LNK target was on a different machine
```

---

### M6 — Browser History Parser (Weeks 13–14)

Browser history is critical — it shows intent, research, and exfiltration.

#### Task M6.1 — Browser Database Detection

During indexing, detect by path pattern:

```rust
pub fn detect_browser_db(path: &str) -> Option<BrowserDbType> {
    if path.contains("Google/Chrome") && path.ends_with("/History") 
        { return Some(BrowserDbType::ChromeHistory); }
    if path.contains("Google/Chrome") && path.ends_with("/Downloads") 
        { return Some(BrowserDbType::ChromeDownloads); }
    if path.contains("Firefox/Profiles") && path.ends_with("places.sqlite") 
        { return Some(BrowserDbType::FirefoxHistory); }
    if path.contains("Microsoft/Edge") && path.ends_with("/History") 
        { return Some(BrowserDbType::EdgeHistory); }
    None
}
```

Set `entry.category = Some(FileCategory::BrowserDatabase)`.

#### Task M6.2 — Browser History Parser

New file: `src/parsers/browser.rs`

```rust
pub struct BrowserVisit {
    pub url: String,
    pub title: Option<String>,
    pub visit_time: DateTime<Utc>,
    pub visit_count: u32,
    pub typed_count: u32,          // manually typed into address bar
    pub transition_type: String,   // "typed", "link", "auto_bookmark", "reload"
    pub browser: String,
    pub profile: Option<String>,
}

pub struct BrowserDownload {
    pub url: String,
    pub referrer: Option<String>,
    pub target_path: String,
    pub file_name: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub total_bytes: i64,
    pub received_bytes: i64,
    pub state: DownloadState,
    pub mime_type: Option<String>,
    pub browser: String,
}

pub enum DownloadState {
    Complete, Interrupted, InProgress, Cancelled,
}

pub fn parse_chrome_history(data: &[u8]) -> Result<Vec<BrowserVisit>, anyhow::Error>
pub fn parse_chrome_downloads(data: &[u8]) -> Result<Vec<BrowserDownload>, anyhow::Error>
pub fn parse_firefox_places(data: &[u8]) -> Result<Vec<BrowserVisit>, anyhow::Error>
```

Open the SQLite database from in-memory bytes using `rusqlite::Connection::open_in_memory()` then `conn.restore()` from the raw bytes. This avoids needing a host filesystem path.

Chrome `History` schema queries:
```sql
SELECT url, title, visit_count, typed_count, last_visit_time FROM urls;
SELECT u.url, v.visit_time, v.transition FROM visits v JOIN urls u ON v.url = u.id;
```

Chrome times are microseconds since 1601-01-01. Convert: `chrono_offset = visit_time / 1_000_000 - 11644473600`.

Firefox `places.sqlite` schema:
```sql
SELECT url, title, visit_count, last_visit_date FROM moz_places;
SELECT p.url, h.visit_date FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id;
```

Firefox times are microseconds since 1970-01-01 (standard Unix micros).

#### Task M6.3 — Browser History Timeline Integration

```rust
TimelineEntry {
    event_type: TimelineEventType::WebVisit,
    timestamp: visit.visit_time,
    path: visit.url.clone(),
    detail: format!("{}: {}", visit.browser, visit.title.as_deref().unwrap_or(&visit.url)),
    is_suspicious: is_suspicious_url(&visit.url),
}
```

Suspicious URL criteria:
- `.onion` domains
- Paste sites: `pastebin.com`, `paste.ee`, `ghostbin.co`, `hastebin.com`, `rentry.co`
- File hosting: `mega.nz`, `wetransfer.com`, `gofile.io`, `anonfiles.com`, `filebin.net`
- VPN/proxy: `protonvpn.com`, `nordvpn.com`, `mullvad.net`, `torproject.org`
- Crypto: search for "bitcoin", "monero", "cryptocurrency exchange"
- Search queries containing: `"how to delete"`, `"cover tracks"`, `"wipe drive"`, `"hide files"`, `"disable logging"`
- URL contains known C2 indicators (crosscheck with hash set IOC list)

#### Task M6.4 — Browser History Viewer

When browser database selected or via BROWSER HISTORY context menu:

Show two-tab panel:

**HISTORY tab:**
```
Filter: [_____________________] [Chrome ▼] [Date range: _____ → _____]

Time                  │ URL                          │ Title           │ Visits│ Typed
──────────────────────┼──────────────────────────────┼─────────────────┼───────┼──────
2023-03-22 14:55:01  │ https://mega.nz/file/...     │ File Share      │  1    │  1   ⚠
2023-03-22 14:50:01  │ https://google.com/search... │ how to delete.. │  1    │  1   ⚠
2023-03-22 14:40:01  │ https://github.com/...       │ mimikatz        │  3    │  2   ⚠
```

**DOWNLOADS tab:**
```
Time                  │ URL                  │ Local Path               │ Size    │ Status
──────────────────────┼──────────────────────┼──────────────────────────┼─────────┼────────
2023-03-22 14:55:01  │ https://mega.nz/...  │ C:\Users\...\stolen.zip  │ 1.2 GB  │ COMPLETE
```

Export to CSV button on each tab.

---

## 7. Phase 3 — Performance & Scale (Weeks 15–20)

### M7 — Virtual Scrolling File Table (Weeks 15–16)

#### Task M7.1 — Virtual Scroll Architecture

File: `src/ui/file_table.rs`

The current implementation clones all visible files and renders all rows every frame. Replace with a virtual scrolling approach.

```rust
pub struct FileTableState {
    pub scroll_offset_px: f32,
    pub selected_id: Option<Uuid>,
    pub sort_col: SortCol,
    pub sort_asc: bool,
    pub filter: FileFilter,
    pub filtered_ids: Vec<usize>,     // indices into file_index — no cloning
    pub filter_dirty: bool,
    pub sort_dirty: bool,
    pub last_filter_text: String,
    pub column_widths: [f32; 7],
}

const ROW_HEIGHT_PX: f32 = 22.0;
const SCROLL_BUFFER_ROWS: usize = 50;
```

Render:
```rust
fn render_file_table(ui: &mut egui::Ui, state: &mut AppState) {
    let total_rows = state.file_table.filtered_ids.len();
    let total_height = total_rows as f32 * ROW_HEIGHT_PX;
    
    let viewport_height = ui.available_height();
    let first_visible = (state.file_table.scroll_offset_px / ROW_HEIGHT_PX) as usize;
    let visible_count = (viewport_height / ROW_HEIGHT_PX) as usize + 2;
    
    let render_start = first_visible.saturating_sub(SCROLL_BUFFER_ROWS);
    let render_end = (first_visible + visible_count + SCROLL_BUFFER_ROWS).min(total_rows);
    
    // Spacer for rows above render window
    let top_space = render_start as f32 * ROW_HEIGHT_PX;
    ui.add_space(top_space);
    
    // Render only visible + buffer rows
    for i in render_start..render_end {
        let file_idx = state.file_table.filtered_ids[i];
        let entry = &state.file_index[file_idx];
        render_row(ui, entry, state);
    }
    
    // Spacer for rows below render window
    let bottom_space = (total_rows - render_end) as f32 * ROW_HEIGHT_PX;
    ui.add_space(bottom_space);
}
```

#### Task M7.2 — Debounced Filter with Cached Result

```rust
// In app.rs update():
if state.file_table.filter_dirty {
    let filter = state.file_table.filter.clone();
    let last = &state.file_table.last_filter_text;
    if *last != filter.text {
        state.file_table.debounce_timer = Instant::now();
        state.file_table.last_filter_text = filter.text.clone();
    }
    if state.file_table.debounce_timer.elapsed() > Duration::from_millis(300) {
        // Rebuild filtered_ids
        state.file_table.filtered_ids = state.file_index.iter()
            .enumerate()
            .filter(|(_, e)| filter.matches(e))
            .map(|(i, _)| i)
            .collect();
        state.file_table.filter_dirty = false;
        state.file_table.sort_dirty = true;
    }
}
```

#### Task M7.3 — Parallel Sort

```rust
if state.file_table.sort_dirty {
    let col = state.file_table.sort_col;
    let asc = state.file_table.sort_asc;
    let index = &state.file_index;
    
    if state.file_table.filtered_ids.len() > 10_000 {
        state.file_table.filtered_ids.par_sort_unstable_by(|&a, &b| {
            compare_entries(&index[a], &index[b], col, asc)
        });
    } else {
        state.file_table.filtered_ids.sort_unstable_by(|&a, &b| {
            compare_entries(&index[a], &index[b], col, asc)
        });
    }
    state.file_table.sort_dirty = false;
}
```

#### Task M7.4 — Running Counters

Replace per-frame count iterations in `titlebar.rs`:

```rust
// In AppState, maintain these counters updated only when file_index changes:
pub struct IndexCounters {
    pub total: usize,
    pub deleted: usize,
    pub carved: usize,
    pub hashed: usize,
    pub flagged: usize,      // KnownBad hash set match
    pub suspicious: usize,   // timeline suspicious events
}
```

Update `counters` on `IndexBatch::Files` arrival and on hash completion — not per frame.

#### Task M7.5 — Column Resize

Add drag handles between column headers. Persist `column_widths: [f32; 7]` in `AppState` and save to VTP case metadata.

Default widths: `[280.0, 400.0, 90.0, 160.0, 80.0, 200.0, 80.0]` (Name, Path, Size, Modified, Type, Hash, Status).

---

### M8 — Hex Editor Virtual Rendering (Weeks 17–18)

#### Task M8.1 — Virtual Row Renderer

File: `src/ui/hex_panel.rs`

```rust
pub struct HexState {
    // Current:
    pub bytes: Vec<u8>,          // first 64KB loaded
    pub file_size: u64,
    // Add:
    pub scroll_byte_offset: u64, // first byte of current view
    pub page_cache: HashMap<u64, HexPage>, // keyed by page start offset
    pub pending_pages: HashSet<u64>,
    pub search_query: HexSearchQuery,
    pub search_hits: Vec<u64>,   // byte offsets of hits
    pub search_hit_idx: usize,
    pub goto_offset: String,     // "Go to offset" input
}

const HEX_ROW_BYTES: usize = 16;
const HEX_ROW_HEIGHT_PX: f32 = 18.0;
const HEX_PAGE_SIZE: usize = 65536;  // 64KB pages
const HEX_MAX_CACHED_PAGES: usize = 16;  // 1MB total in cache
```

Render only visible rows:
```rust
let total_rows = (state.hex.file_size + 15) / 16;
let viewport_rows = (ui.available_height() / HEX_ROW_HEIGHT_PX) as u64 + 2;
let first_row = state.hex.scroll_byte_offset / 16;
let last_row = (first_row + viewport_rows).min(total_rows);

// Top spacer
ui.add_space(first_row as f32 * HEX_ROW_HEIGHT_PX);

for row in first_row..last_row {
    let offset = row * 16;
    if let Some(page) = get_page(&state.hex, offset) {
        render_hex_row(ui, offset, &page, &state.hex.search_hits);
    } else {
        render_loading_row(ui, offset);
        request_page(offset, entry, vfs_ctx, &hex_page_tx);
    }
}

// Bottom spacer
let remaining = (total_rows - last_row) as f32 * HEX_ROW_HEIGHT_PX;
ui.add_space(remaining);
```

#### Task M8.2 — Background Page Loader

```rust
pub struct HexPage {
    pub start_offset: u64,
    pub data: Vec<u8>,
    pub loaded_at: Instant,
}

pub enum HexPageMessage {
    Loaded { offset: u64, data: Vec<u8> },
    Error { offset: u64, msg: String },
}

// In app.rs: poll hex_page_rx per frame
// When page arrives: insert into state.hex.page_cache
// Evict oldest page when cache exceeds HEX_MAX_CACHED_PAGES
```

Pre-fetch next page when within 2 rows of page boundary.

#### Task M8.3 — Hex Search

Add search bar above hex view:

```
[Mode: HEX ▼] [4D 5A 90 00                    ] [Search] ← Prev  → Next  (3 of 47)
```

Modes: HEX (byte sequence), ASCII (string), UNICODE (UTF-16LE string).

Search runs in background thread — scans the file in page-sized chunks, reports hits via `mpsc`. Show progress: "Searching... 24% (1.2 GB / 5.0 GB)".

Highlight matching bytes in the hex view with colored background. Navigation buttons jump to prev/next hit.

#### Task M8.4 — Offset Navigation

- Clicking offset column → copy to clipboard
- "Go to offset:" input box (top of hex panel) — accept decimal or `0x` hex
- Jump to offset on Enter key

---

### M9 — SQLite Query Architecture (Weeks 19–20)

Replace in-memory `Vec<FileEntry>` filtering with SQLite-backed queries for 1M+ file performance.

#### Task M9.1 — Verify Index Schema and Indexes

File: `src/case/project.rs`

Verify these indexes exist, create if missing:
```sql
CREATE INDEX IF NOT EXISTS idx_parent ON file_index(evidence_id, parent_path);
CREATE INDEX IF NOT EXISTS idx_name ON file_index(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_ext ON file_index(extension COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_deleted ON file_index(is_deleted);
CREATE INDEX IF NOT EXISTS idx_hash ON file_index(hash_sha256);
CREATE INDEX IF NOT EXISTS idx_size ON file_index(size);
CREATE INDEX IF NOT EXISTS idx_modified ON file_index(modified_utc);
CREATE INDEX IF NOT EXISTS idx_category ON file_index(category);
CREATE INDEX IF NOT EXISTS idx_carved ON file_index(is_carved);
CREATE INDEX IF NOT EXISTS idx_flagged ON file_index(is_flagged);
```

Run `PRAGMA integrity_check` and `PRAGMA optimize` after indexing completes.

#### Task M9.2 — SQLite-Backed Directory Listing

Replace `collect_dirs()` and `visible_files()` with parameterized SQL queries:

```rust
pub fn query_directory(
    conn: &Connection,
    evidence_id: &str,
    parent_path: &str,
    filter: &FileFilter,
    sort: SortCol,
    asc: bool,
    limit: usize,
    offset: usize,
) -> Result<Vec<FileEntry>, anyhow::Error>
```

Directory listing query:
```sql
SELECT * FROM file_index
WHERE evidence_id = ?1 AND parent_path = ?2
AND (name LIKE ?3 OR ?3 = '%')
AND (is_deleted = ?4 OR ?4 = -1)
ORDER BY {sort_col} {asc_desc}
LIMIT ?5 OFFSET ?6
```

Target: < 100ms for directories with up to 100,000 files.

#### Task M9.3 — Transaction Batching Verification

Verify the indexer inserts in batches of 1000:
```rust
conn.execute("BEGIN IMMEDIATE")?;
let mut batch_count = 0;
for entry in &entries {
    insert_file_entry(&stmt, entry)?;
    batch_count += 1;
    if batch_count >= 1000 {
        conn.execute("COMMIT")?;
        conn.execute("BEGIN IMMEDIATE")?;
        batch_count = 0;
    }
}
conn.execute("COMMIT")?;
```

If not batching: fix it. Measure insert time before and after.

#### Task M9.4 — Persistent DB Path

Verify that `strata_index.db` is stored in the case directory, not a temp path. On VTP save, store the DB path in `case_metadata`. On VTP load, re-open from stored path.

Schema for `case_metadata`:
```sql
CREATE TABLE IF NOT EXISTS case_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR REPLACE INTO case_metadata VALUES ('db_path', '/path/to/strata_index.db');
INSERT OR REPLACE INTO case_metadata VALUES ('schema_version', '2');
```

---

## 8. Phase 4 — Intelligence Layer (Weeks 21–28)

### M10 — Content Search UI (Weeks 21–22)

#### Task M10.1 — Wire INDEX Toolbar Button

File: `src/ui/toolbar.rs`

Replace stub:
```rust
ToolbarAction::Index => {
    if state.vfs_context.is_some() {
        state.show_index_progress = true;
        spawn_content_indexer(state, vfs_ctx);
    }
}
```

#### Task M10.2 — Wire ContentIndexer

File: `src/search/content.rs`

The tantivy-based `ContentIndexer` exists. Wire it:

1. During or after file indexing, spawn `ContentIndexer::index_all(entries, vfs_ctx)` in background
2. Progress: "Indexing content... 12,847 / 47,293 files"
3. On complete: `state.content_index_ready = true`

#### Task M10.3 — Full-Text Search UI

File: `src/ui/search_view.rs`

Extend SEARCH tab to support content search:

```
[Search Type: METADATA / CONTENT]  
[Query: ___________________________] [Search]

CONTENT mode:
  Query: "stolen" OR "exfiltrate" OR "password"
  Results: 47 files containing matching text

  File                              │ Match Context
  ──────────────────────────────────┼────────────────────────────────────
  /Users/Suspect/Documents/plan.txt │ ...send the stolen files to...
  /Users/Suspect/Desktop/note.txt   │ ...exfiltrate before midnight...
```

Click result → navigate to file in explorer + show match context in preview.

---

### M11 — EVTX Parser (Weeks 23–24)

Windows Event Logs (`.evtx`) are critical for authentication, process creation, network connections, and security events.

#### Task M11.1 — EVTX Detection

During indexing, files ending in `.evtx` → `category = Some(FileCategory::EventLog)`. Common paths:
- `*/Windows/System32/winevt/Logs/*.evtx`

High-value logs to prioritize:
- `Security.evtx` — logon events (4624, 4625, 4648), process creation (4688), privilege use
- `System.evtx` — service control manager (7045 — new service), USB (20001)
- `Application.evtx` — application errors, crash reports
- `Microsoft-Windows-PowerShell*.evtx` — PS execution (4103, 4104, 4105, 4106)
- `Microsoft-Windows-TaskScheduler*.evtx` — scheduled task creation
- `Microsoft-Windows-TerminalServices*.evtx` — RDP sessions

#### Task M11.2 — EVTX Parser

The `evtx` crate is already declared as a dependency. Wire it:

```rust
// src/parsers/evtx.rs

pub struct EventLogEntry {
    pub event_id: u32,
    pub level: EventLevel,          // Critical, Error, Warning, Information
    pub time_created: DateTime<Utc>,
    pub provider_name: String,
    pub channel: String,
    pub computer: String,
    pub user_sid: Option<String>,
    pub message: String,
    pub raw_xml: String,
    pub fields: HashMap<String, String>,  // parsed EventData fields
    pub is_suspicious: bool,
}

pub enum EventLevel {
    Critical, Error, Warning, Information, Verbose,
}

pub fn parse_evtx(data: &[u8]) -> Result<Vec<EventLogEntry>, anyhow::Error>
pub fn is_high_value_event(event_id: u32) -> bool
pub fn is_suspicious_event(entry: &EventLogEntry) -> bool
```

High-value Event IDs:
| ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon with explicit credentials |
| 4688 | Process creation (with command line if audited) |
| 4698 | Scheduled task created |
| 4702 | Scheduled task modified |
| 4720 | User account created |
| 4732 | User added to privileged group |
| 7045 | New service installed |
| 1102 | Audit log cleared (⚠ always suspicious) |
| 104  | System log cleared (⚠ always suspicious) |
| 20001 | New USB device connected |

Suspicious event criteria:
- Event ID 1102 or 104 (log clearing) → always flag
- Event ID 4625 with count > 5 in 60 seconds → brute force indicator
- Event ID 4688 with command line containing: `powershell -enc`, `cmd /c`, `wscript`, `cscript`, `mshta`, `regsvr32`, `certutil -decode`, `bitsadmin`
- Event ID 7045 with service binary in `\Temp\` or `\AppData\`

#### Task M11.3 — Event Log Timeline

```rust
TimelineEntry {
    event_type: match entry.event_id {
        4624 | 4648 => TimelineEventType::UserLogon,
        4625 => TimelineEventType::FailedLogon,
        4688 => TimelineEventType::ProcessCreated,
        7045 => TimelineEventType::ServiceInstalled,
        _ => TimelineEventType::EventLog,
    },
    timestamp: entry.time_created,
    path: format!("EventLog: {} [{}]", entry.channel, entry.event_id),
    detail: entry.message.chars().take(120).collect(),
    is_suspicious: entry.is_suspicious,
}
```

#### Task M11.4 — Event Log Viewer

New tab: EVENT LOGS (or integrated into TIMELINE with source filter).

Show filterable table: Time | Event ID | Level | Provider | Computer | User | Message

Click row → expand to show all EventData fields and raw XML.

---

### M12 — Timeline Enrichment (Weeks 25–26)

Wire all artifact parsers into the unified timeline so examiners see a single chronological narrative.

#### Task M12.1 — Registry Change Events

When a registry hive is parsed, examine LastWriteTime on every key:
```rust
TimelineEntry {
    event_type: TimelineEventType::RegistryKeyModified,
    timestamp: key.last_write_time(),
    path: format!("HKLM\\{}", key_path),
    detail: format!("Registry key modified: {}", key_name),
    is_suspicious: is_suspicious_registry_key(&key_path),
}
```

Suspicious registry keys:
- `\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (persistence)
- `\SYSTEM\CurrentControlSet\Services\` (services)
- `\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\` (debugger hijacking)
- `\SOFTWARE\Classes\*\shell\open\command\` (file association hijacking)
- `\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls\` (DLL injection)

#### Task M12.2 — Timeline Source Filtering

Add source filter chips to the timeline:
```
[ALL] [FILES] [REGISTRY] [PREFETCH] [SHELLBAG] [LNK] [BROWSER] [EVTX] [CARVED]
```

Show source icon/badge on each timeline row.

#### Task M12.3 — Timeline Heatmap

Add a visual timeline heatmap above the timeline table:
- X axis: date range of entire case
- Y axis: hour of day (0–23)
- Cell color: activity intensity (no activity=dark, high activity=bright accent color)
- Click cell: filter timeline to that date+hour

This lets examiners see activity clusters and pre-dawn activity at a glance.

#### Task M12.4 — Timeline Export

Export full timeline (all sources) to:
- CSV: timestamp, type, source, path, detail, suspicious, examiner_note
- PDF: formatted timeline section for case report
- JSON: machine-readable for external tools

---

### M13 — Audit Chain Integrity (Weeks 27–28)

#### Task M13.1 — Hash Chain Implementation

File: `src/case/audit.rs`

Add chain fields to `AuditEntry`:

```rust
pub struct AuditEntry {
    pub id: Uuid,
    pub sequence: u64,                  // monotonically increasing from 0
    pub timestamp: DateTime<Utc>,
    pub examiner: String,
    pub action: String,
    pub detail: String,
    pub evidence_id: Option<String>,
    pub file_path: Option<String>,
    pub session_id: String,             // UUID for each launch session
    // Chain fields:
    pub prev_hash: String,              // SHA-256 of previous entry's entry_hash
    pub entry_hash: String,             // SHA-256 of all fields above + prev_hash
}

impl AuditEntry {
    pub fn compute_hash(&self) -> String {
        let data = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.sequence,
            self.timestamp.to_rfc3339(),
            self.examiner,
            self.action,
            self.detail,
            self.evidence_id.as_deref().unwrap_or(""),
            self.file_path.as_deref().unwrap_or(""),
            self.prev_hash,
        );
        hex::encode(sha2::Sha256::digest(data.as_bytes()))
    }
}
```

Genesis entry (sequence=0):
```rust
prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
entry_hash = SHA-256(all fields + prev_hash)
```

#### Task M13.2 — Chain Verification

```rust
pub enum ChainVerifyResult {
    Valid { entry_count: usize },
    Tampered {
        first_bad_sequence: u64,
        expected_hash: String,
        found_hash: String,
        detail: String,
    },
    Empty,
}

pub fn verify_audit_chain(entries: &[AuditEntry]) -> ChainVerifyResult {
    if entries.is_empty() { return ChainVerifyResult::Empty; }
    
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|e| e.sequence);
    
    for i in 0..sorted.len() {
        let recomputed = sorted[i].compute_hash();
        if recomputed != sorted[i].entry_hash {
            return ChainVerifyResult::Tampered {
                first_bad_sequence: sorted[i].sequence,
                expected_hash: recomputed,
                found_hash: sorted[i].entry_hash.clone(),
                detail: format!("Entry {} hash mismatch — content may have been altered", sorted[i].sequence),
            };
        }
        if i > 0 && sorted[i].prev_hash != sorted[i-1].entry_hash {
            return ChainVerifyResult::Tampered {
                first_bad_sequence: sorted[i].sequence,
                expected_hash: sorted[i-1].entry_hash.clone(),
                found_hash: sorted[i].prev_hash.clone(),
                detail: format!("Chain broken between entries {} and {} — entry may have been deleted", i-1, i),
            };
        }
    }
    
    ChainVerifyResult::Valid { entry_count: sorted.len() }
}
```

Run verification:
- On VTP load
- When AUDIT LOG tab is opened
- Before PDF report generation

#### Task M13.3 — Audit Log UI

File: `src/ui/audit_view.rs`

Add chain integrity status banner at top of audit log tab:

```
✓ CHAIN INTEGRITY VERIFIED — 247 entries, 3 sessions
```
or
```
⚠ CHAIN BROKEN AT ENTRY 143 — possible tampering detected
  Expected: a3f2b1... Found: 00000000...
```

Add columns: SEQUENCE | TIMESTAMP | EXAMINER | ACTION | DETAIL | ENTRY HASH (truncated 16 chars)

Add export buttons: JSON (full fields for external verification) | CSV | PDF (court-ready with chain result on cover page).

---

## 9. Phase 5 — Court-Ready Polish (Weeks 29–36)

### M14 — Court-Ready PDF Report (Weeks 29–30)

The `report/html.rs` court-ready report generator exists but is not wired to the UI. Wire it and extend it.

#### Task M14.1 — Wire REPORT Button

File: `src/ui/toolbar.rs`

Connect the REPORT button to `report::html::generate_court_report()`:

```rust
ToolbarAction::Report => {
    let path = rfd::FileDialog::new()
        .add_filter("PDF", &["pdf"])
        .add_filter("HTML", &["html"])
        .save_file();
    if let Some(path) = path {
        match path.extension().and_then(|e| e.to_str()) {
            Some("pdf") => generate_pdf_report(&state, &path),
            Some("html") => generate_html_report(&state, &path),
            _ => {}
        }
    }
}
```

#### Task M14.2 — PDF Report Sections

The PDF report must contain these sections, generated via `printpdf`:

**Cover Page:**
```
STRATA FORENSIC WORKBENCH
Digital Evidence Examination Report

Case Name:      [case_name]
Case Number:    [case_number]
Examiner:       [examiner_name]
Agency:         [examiner_agency]
Report Date:    [UTC timestamp]
Tool Version:   Strata Tree v1.0.0
Tool Hash:      SHA-256: [binary hash]

Evidence Files:
  1. Stack001.E01
     Format:   Expert Witness Format
     MD5:      a3f2b1...
     SHA-256:  7d4e9f...
     Size:     47.3 GB
     Verified: YES — hash matches acquisition
```

**Examination Summary (Page 2):**
```
Volumes: 2 (NTFS: 1, FAT32: 1)
Total Files: 47,293
Deleted Files: 1,842
Carved Files: 234
Suspicious Files: 12
Bookmarked Items: 8
Timeline Events: 4,847
Suspicious Events: 23

Examination Period:
  First Activity: 2023-01-15 08:22:14 UTC
  Last Activity:  2023-03-22 14:55:01 UTC
```

**Bookmarked Items (Pages 3+):**
For each bookmark sorted by tag severity (MALWARE → SUSPICIOUS → RELEVANT → UNKNOWN):
```
[MALWARE] /Users/Suspect/Downloads/mimikatz.exe
  Size:         1,234,567 bytes
  Created:      2023-03-22 14:55:01 UTC
  Modified:     2023-03-22 14:55:01 UTC
  Accessed:     2023-03-22 14:55:02 UTC
  MD5:          d4c3b2a1...
  SHA-256:      7f8e9d0c...
  Hash Status:  KNOWN BAD — Mimikatz (KnownBad set "Malware Hashes")
  Examiner:     J. Smith
  Note:         "Found in Downloads folder. Credential dumping tool."
  Timestamp:    2023-03-28 09:15:33 UTC (examiner note time)
```

**Timeline Section:**
Top 50 most suspicious events + summary counts by event type.

**Audit Log:**
Chain integrity result, examiner sessions, all actions in chronological order.

**Page Footer (every page):**
```
Case: SMITH_2023_001 | Examiner: J. Smith | Page N of M | CONFIDENTIAL
```

#### Task M14.3 — HTML Report

Wire `report/html.rs` as an alternative output with the same sections, rendered as a self-contained HTML file with embedded CSS (dark theme matching Strata aesthetic). No external dependencies — everything inline.

---

### M15 — .VTP Completion (Weeks 31–32)

#### Task M15.1 — Full Save/Load Inventory

Audit every field in `AppState` and `FileTableState`. Ensure these are persisted:

Currently saved: case_metadata, evidence_sources, file_index (all fields), bookmarks (file + registry), activity_log, plugin_enabled config.

**Add to save/load:**
- `timeline_entries` — serialize to `timeline_entries` table in VTP
- `file_table.column_widths` — save to `case_metadata`
- `file_table.sort_col` and `sort_asc` — save to `case_metadata`
- `last_selected_path` per evidence source — save to `case_metadata`
- `compare_results` — save to `compare_results` table
- `search_history` — last 20 searches
- `parsed_artifacts` — cache of parsed prefetch/shellbag/lnk/browser results
- `hash_sets` — file paths of loaded hash sets (not contents)
- `examiner_profile` — name, agency, badge, timezone

#### Task M15.2 — Auto-Save Timer

```rust
// In AppState:
pub last_save: Option<Instant>,
pub last_auto_save: Option<Instant>,
pub is_dirty: bool,
pub auto_save_interval: Duration,  // default: 5 minutes

// In app.rs update():
if state.is_dirty {
    if let Some(last) = state.last_auto_save {
        if last.elapsed() > state.auto_save_interval {
            if let Some(path) = &state.case_path.clone() {
                match VtpProject::save(&state, path) {
                    Ok(_) => {
                        state.last_auto_save = Some(Instant::now());
                        state.status = format!("Auto-saved {}", chrono::Utc::now().format("%H:%M"));
                    }
                    Err(e) => {
                        state.status = format!("Auto-save failed: {}", e);
                    }
                }
            }
        }
    }
}
```

Show in titlebar: `● Strata Tree — SMITH_2023_001` (● = unsaved changes).
Show in status bar: `Auto-saved 3m ago`.

#### Task M15.3 — Case Integrity Hash

On VTP save:
1. Compute SHA-256 of the entire VTP SQLite file (excluding the hash row itself)
2. Store in `case_metadata` as `integrity_hash`

On VTP load:
1. Recompute hash of file
2. Compare to stored `integrity_hash`
3. If mismatch: show banner "⚠ Case file may have been modified outside Strata Tree. Proceed with caution."
4. Log `CASE_INTEGRITY_WARNING` to audit

#### Task M15.4 — Backup on Save

Before overwriting a VTP file:
```rust
let bak_path = path.with_extension("vtp.bak");
if path.exists() {
    std::fs::copy(&path, &bak_path)?;
}
// Now write new VTP
```

Keep only the most recent `.vtp.bak`. If save fails, the `.bak` file preserves the last good state.

---

### M16 — Examiner Profile (Weeks 33–34)

#### Task M16.1 — Persistent Profile Store

File: `src/case/examiner.rs`

```rust
pub struct ExaminerProfile {
    pub name: String,
    pub agency: String,
    pub badge_number: String,
    pub email: Option<String>,
    pub timezone: String,       // e.g. "America/New_York"
    pub digital_signature: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
}

impl ExaminerProfile {
    pub fn load() -> Option<Self>   // from platform config dir
    pub fn save(&self) -> Result<()>
    pub fn config_path() -> PathBuf // %APPDATA%\Strata\examiner.json
}
```

Persist to `%APPDATA%\Strata\examiner.json` so profile survives between sessions. Show setup dialog only when `examiner.json` does not exist. Show "Edit Profile" in settings menu.

#### Task M16.2 — Profile in Reports

Examiner name, agency, and badge appear in:
- PDF report cover page
- PDF report footer (every page)
- CSV export header rows
- VTP case metadata
- Every audit log entry

#### Task M16.3 — Multi-Examiner Support

Support cases with multiple examiners. Each bookmark shows the examiner's initials who created it. The audit log records which examiner performed each action. The PDF report lists all examiners who worked the case.

---

### M17 — UI Polish Pass (Weeks 35–36)

#### Task M17.1 — Keyboard Navigation

Full keyboard navigation:
- `Tab` / `Shift+Tab` — cycle through panels
- `Ctrl+O` — open evidence
- `Ctrl+N` — new case
- `Ctrl+S` — save case
- `Ctrl+F` — focus search
- `Ctrl+G` — go to offset (in hex editor)
- `Ctrl+B` — bookmark selected file
- `Ctrl+H` — hash selected file
- `Ctrl+E` — export
- `F5` — refresh / rebuild index
- `F11` — fullscreen
- Arrow keys in file table — navigate rows
- Enter in file table — open file in preview
- `Delete` — mark file as reviewed/dismissed

#### Task M17.2 — Context Menus

Right-click on file in table:
```
Open in Hex Editor
Open in Preview
─────────────────
Bookmark → [Tag submenu]
Hash This File
Export File (save bytes to disk)
─────────────────
Add to Compare (A)
Add to Compare (B)
─────────────────
Copy Path
Copy Hash (if computed)
Copy Name
─────────────────
Mark Reviewed
Mark Irrelevant
```

Right-click on registry key:
```
Bookmark This Key
Copy Key Path
Copy Value
─────────────────
Add to Timeline Note
```

#### Task M17.3 — Evidence Health Indicator

Show a health indicator per evidence source in the evidence tree:

```
📁 Stack001.E01 [●]
```

Where `[●]` is:
- Green ✓ — opened, indexed, hash verified
- Amber ⚠ — opened but hash not verified or index incomplete
- Red ✗ — failed to open or hash mismatch

Tooltip shows: "SHA-256 verified · 47,293 files indexed · Last opened 2026-03-28 09:15 UTC"

#### Task M17.4 — Status Bar Enhancements

Status bar (bottom of window):

```
[●] Stack001.E01 | 47,293 files | 1,842 deleted | 12 flagged | 234 carved | 8 bookmarks | v1.0.0 | J. Smith · ACME Agency
```

Each segment is clickable — clicking "12 flagged" filters file table to flagged files.

#### Task M17.5 — Accessibility

- All interactive elements have accessible names for screen readers
- Color is never the only indicator — always paired with icon or text
- Minimum contrast ratio 4.5:1 for all text
- Font size configurable: Small (12pt), Medium (14pt), Large (16pt)
- Keyboard shortcuts documented in Help menu

---

## 10. Phase 6 — Plugin Ecosystem (Weeks 37–44)

### M18 — Plugin Execution (Weeks 37–38)

#### Task M18.1 — C-ABI Plugin Protocol

File: `src/plugin/loader.rs`

Define the stable plugin ABI:

```rust
// In strata-plugin-sdk/src/lib.rs:
#[repr(C)]
pub struct PluginMeta {
    pub name: *const c_char,
    pub version: *const c_char,
    pub description: *const c_char,
    pub author: *const c_char,
    pub capabilities: u64,          // bitfield: PARSE | ENRICH | EXPORT | CARVE
}

#[repr(C)]
pub struct PluginFileContext {
    pub path: *const c_char,
    pub size: u64,
    pub sha256: *const c_char,
    pub data: *const u8,
    pub data_len: usize,
}

#[repr(C)]
pub struct PluginResult {
    pub success: bool,
    pub message: *const c_char,
    pub timeline_events: *mut TimelineEventC,
    pub timeline_event_count: usize,
    pub bookmarks: *mut BookmarkC,
    pub bookmark_count: usize,
}

// Required exports from every plugin .dll:
// extern "C" fn strata_plugin_meta() -> *const PluginMeta
// extern "C" fn strata_plugin_init() -> bool
// extern "C" fn strata_plugin_run(ctx: *const PluginFileContext) -> *mut PluginResult
// extern "C" fn strata_plugin_free_result(result: *mut PluginResult)
// extern "C" fn strata_plugin_shutdown()
```

#### Task M18.2 — Plugin Runner

```rust
pub fn run_plugin_on_file(
    plugin: &LoadedPlugin,
    entry: &FileEntry,
    data: &[u8],
) -> Result<PluginRunResult, anyhow::Error> {
    // Safety: plugin is loaded and verified
    unsafe {
        let ctx = PluginFileContext {
            path: CString::new(entry.full_path.as_str())?.as_ptr(),
            size: entry.size,
            sha256: CString::new(entry.hash_sha256.as_deref().unwrap_or(""))?.as_ptr(),
            data: data.as_ptr(),
            data_len: data.len(),
        };
        let raw_result = (plugin.fn_run)(&ctx);
        let result = PluginRunResult::from_c(raw_result);
        (plugin.fn_free)(raw_result);
        Ok(result)
    }
}
```

Run plugins in a background thread. Timeout after 30 seconds. Catch panics via `std::panic::catch_unwind`.

#### Task M18.3 — Plugin Run UI

In the PLUGINS tab, add a RUN ON SELECTION button and a RUN ON ALL button.

Show per-plugin run results:
```
Remnant v1.0.0  [RUN ON SELECTION] [RUN ON ALL FILES]
Status: ✓ Completed — 234 files carved, 12 timeline events added
Last run: 2026-03-28 09:15:33 UTC
```

---

### M19 — Plugin SDK Documentation (Weeks 39–40)

#### Task M19.1 — SDK Crate

File: `D:\Strata\crates\strata-tree-sdk\` (crate exists)

Document every type and function in the SDK with:
- Rustdoc comments on every public item
- Example implementation of a minimal plugin
- Safety requirements for `unsafe` FFI boundary
- Build instructions: how to compile a plugin as `cdylib`
- Plugin manifest format: `strata-plugin.toml`

```toml
# strata-plugin.toml
[plugin]
name = "strata-plugin-remnant"
version = "1.0.0"
description = "Data carving via Remnant engine"
author = "Strata"
min_tree_version = "1.0.0"
capabilities = ["carve", "enrich"]
```

#### Task M19.2 — Plugin Signing

Before a plugin can be loaded:
1. Check for `plugin.sig` file alongside `.dll`
2. Verify signature against Strata's public key
3. If signature missing or invalid: show warning dialog, require examiner to explicitly allow unsigned plugin
4. Log plugin load with hash to audit chain

This protects against malicious plugin injection into a running examination.

---

### M20 — Core Plugin Integration (Weeks 41–42)

Wire the four core plugins (Remnant, Chronicle, Cipher, Trace) to Tree using the new execution framework.

#### Task M20.1 — Remnant Integration

`strata-plugin-remnant` provides deep carving beyond the built-in 26 signatures. Wire via plugin execution framework. Results appear in `$CARVED` virtual directory same as built-in carver.

#### Task M20.2 — Chronicle Integration

`strata-plugin-chronicle` builds enriched timelines from sources Tree doesn't parse natively (custom log formats, cloud logs, email archives). Results injected into `TimelineEntry` vec and shown in TIMELINE tab.

#### Task M20.3 — Cipher Integration

`strata-plugin-cipher` handles encrypted container detection, hash analysis, and key material identification. Results appear as file table annotations and bookmarks.

#### Task M20.4 — Trace Integration

`strata-plugin-trace` provides deep execution tracking beyond Prefetch — AppCompat/Shimcache, Amcache.hve, UserAssist, MUICache. All results → timeline events.

---

## 11. Phase 7 — Release Hardening (Weeks 45–52)

### M22 — Full Smoke Test Suite (Weeks 45–46)

#### Task M22.1 — Automated Test Evidence

Create a minimal synthetic E01 image (< 100MB) that contains:
- NTFS volume with exactly 1,000 files
- Registry hive (SYSTEM) with known key structure
- One JPEG image (known hash)
- One PDF file
- One `.pf` prefetch file
- One `.lnk` shortcut pointing to a deleted file
- One EVTX log with 50 events including event 1102 (log cleared)
- One browser history SQLite (Chrome format) with 20 URLs including one flagged
- One known-bad file (hash in test hash set)

Store this test image at `D:\Strata\test_evidence\synthetic_001.E01`.

#### Task M22.2 — 22-Step Smoke Test

Write a test harness that runs these steps and reports PASS/FAIL for each:

```
 1. Launch — binary starts, no crash within 5 seconds
 2. New Case — create case "SMOKE_TEST_001", examiner "Test Examiner"
 3. Open E01 — open synthetic_001.E01
 4. Index Complete — 1,000 files appear in file table within 60 seconds
 5. Navigate Tree — click Windows/Prefetch/ in tree panel, files appear
 6. Prefetch Viewer — select .pf file, PREFETCH tab shows executable name
 7. Navigate Registry — open SYSTEM hive in registry viewer, tree populates
 8. Registry Key — navigate to CurrentControlSet/Services, show key list
 9. Registry Bookmark — bookmark one key as Suspicious
10. Hex Editor — select cmd.exe, hex tab shows 4D 5A (MZ) at offset 0
11. Hex Search — search "4D 5A", first hit highlighted
12. Gallery — GALLERY tab shows JPEG thumbnail
13. Timeline — TIMELINE tab shows events, suspicious events highlighted
14. Compare — select same evidence for A and B, run comparison
15. Hash Sets — import test hash set (SHA-256 list)
16. Hash File — select known-bad file, hash it, ⚠ badge appears
17. Hash All — HASH ALL completes without crash
18. Audit Log — AUDIT LOG shows VERIFIED chain
19. PDF Export — click REPORT, PDF file is created and non-empty
20. Save VTP — save case, .vtp file created, .vtp.bak created
21. Close and Reopen — reopen VTP, all bookmarks and audit log restored
22. Audit Verify — AUDIT LOG still shows VERIFIED after reload
```

#### Task M22.3 — Regression Tests

Add Rust unit tests for every parser:
```rust
#[cfg(test)]
mod tests {
    #[test] fn test_prefetch_v17() { ... }
    #[test] fn test_prefetch_v23() { ... }
    #[test] fn test_prefetch_v26() { ... }
    #[test] fn test_prefetch_v30_mam() { ... }
    #[test] fn test_shellbag_ntuser() { ... }
    #[test] fn test_shellbag_usrclass() { ... }
    #[test] fn test_lnk_local_file() { ... }
    #[test] fn test_lnk_deleted_target() { ... }
    #[test] fn test_lnk_network_target() { ... }
    #[test] fn test_chrome_history() { ... }
    #[test] fn test_firefox_places() { ... }
    #[test] fn test_evtx_security() { ... }
    #[test] fn test_audit_chain_valid() { ... }
    #[test] fn test_audit_chain_tampered() { ... }
    #[test] fn test_vfs_read_context_host() { ... }
    #[test] fn test_vfs_read_context_vfs() { ... }
}
```

---

### M23 — Performance Benchmarks (Weeks 47–48)

#### Task M23.1 — Benchmark Targets

All benchmarks must pass before v1.0 release:

| Benchmark | Target |
|---|---|
| Open 50GB E01 and detect partitions | < 5 seconds |
| Index 100,000 files | < 30 seconds |
| Index 1,000,000 files | < 5 minutes |
| Filter 1,000,000 file index (by name) | < 100ms |
| Sort 1,000,000 file index | < 500ms |
| Load directory with 100,000 files | < 100ms |
| Compute SHA-256 of 1GB file | < 10 seconds |
| Hash all files (100,000 files, avg 50KB) | < 15 minutes |
| Parse SYSTEM hive (15MB) | < 2 seconds |
| Build timeline (1,000,000 file events) | < 10 seconds |
| Generate PDF report (500 bookmarks) | < 10 seconds |
| Hex editor page load (64KB) | < 50ms |
| Gallery thumbnail batch (100 images) | < 5 seconds |
| EVTX parse (Security.evtx, 50MB) | < 30 seconds |
| Chrome history parse (10,000 records) | < 1 second |
| Compare two 500,000-file indexes | < 30 seconds |

Use `criterion` for micro-benchmarks. Write integration benchmarks using the synthetic test E01.

#### Task M23.2 — Memory Profile

Target memory usage:
- Idle (case open, 100,000 files indexed): < 200MB RAM
- Active hashing (1,000,000 files): < 500MB RAM
- Gallery with 500 cached thumbnails: < 300MB additional
- Full content index (100,000 files, avg 50KB text): < 2GB RAM

Use Windows Task Manager and `heaptrack` (via WSL) to profile. Fix any obvious allocations in the render loop.

---

### M24 — Security Audit (Weeks 49–50)

#### Task M24.1 — Evidence Write Prevention

Audit every path where code could write to an evidence source. All of the following must fail gracefully, never write:
- Any `std::fs::write()` or `std::fs::File::create()` call
- Any `rusqlite` write to the evidence VFS path
- Any plugin run that attempts to write to evidence

Add a compile-time lint: grep for any write operation that touches a path derived from `evidence_source.path`. Every such operation must go through a write-guard wrapper that verifies the target is not within any evidence source path.

#### Task M24.2 — Path Traversal Prevention

The VFS path resolution in `strata-fs` must reject:
- Paths containing `..` components
- Paths with null bytes
- Paths longer than 4096 characters
- Paths that resolve outside the VFS container

Add input sanitization to `VfsReadContext::read_file()` and `read_range()`.

#### Task M24.3 — Plugin Sandbox

When a plugin is executed:
- Run in a separate OS thread with a 30-second timeout
- Catch all panics via `std::panic::catch_unwind`
- Verify plugin result pointer is non-null before dereferencing
- Free all plugin-allocated memory via `strata_plugin_free_result`
- Never pass `AppState` directly to plugin — only pass `PluginFileContext` (read-only view)

#### Task M24.4 — Dependency Audit

Run `cargo audit` against all dependencies. Fix any known CVEs. Pin dependency versions in workspace `Cargo.lock`. Document rationale for any `unsafe` code blocks.

---

### M25 — v1.0 Release (Weeks 51–52)

#### Task M25.1 — Version Bump

Update in `Cargo.toml`:
```toml
[package]
version = "1.0.0"
```

Update in `build.rs` or `main.rs`:
```rust
const STRATA_TREE_VERSION: &str = "1.0.0";
```

#### Task M25.2 — Windows Installer

Build an NSIS or WiX installer:
- Install `strata-tree.exe` to `%ProgramFiles%\Strata\Tree\`
- Create Start Menu shortcut
- Create Desktop shortcut (optional, user choice)
- Install Visual C++ Redistributable if needed
- Register `.vtp` file extension → opens with `strata-tree.exe`
- Uninstaller removes all files

#### Task M25.3 — Code Signing

Sign `strata-tree.exe` and the installer with an EV Code Signing certificate. This is required for deployment to government and law enforcement environments that enforce application whitelisting (e.g., AppLocker, WDAC).

#### Task M25.4 — Documentation

Write these documents:

1. **User Manual** (`docs/user_manual.md`) — complete walkthrough of every feature, with screenshots
2. **Examiner Quick Reference** (`docs/quick_reference.md`) — one-page laminated card format
3. **Artifact Reference** (`docs/artifacts.md`) — what each artifact type means, what forensic questions it answers
4. **Plugin Development Guide** (`docs/plugin_guide.md`) — how to build a plugin using `strata-tree-sdk`
5. **Chain of Custody Guide** (`docs/chain_of_custody.md`) — how to demonstrate chain integrity in court
6. **Validation Report** (`docs/validation.md`) — tool validation following NIST SP 800-86 guidelines for admissibility

#### Task M25.5 — Final Release Build

```powershell
cargo build -p strata-tree --release
# Target:
#   Binary: D:\Strata\target\release\strata-tree.exe
#   Size: < 25MB
#   Build time: < 5 minutes
#   Warnings: 0
#   cargo audit: 0 vulnerabilities
```

---

## 12. Cross-Cutting Concerns

### Error Handling Philosophy

All fallible operations return `Result<T, anyhow::Error>`. Errors are:
1. Logged to the audit trail with full context
2. Shown in the status bar with a human-readable message
3. Never silently swallowed
4. Never cause UI panics

The VFS layer errors (`EwfVfsError`) must be translated to user-visible messages:
- `PartitionNotFound` → "No NTFS/FAT32 partition detected in this image"
- `ReadError` → "Failed to read sector — image may be corrupt or truncated"
- `HashMismatch` → "EWF chunk hash mismatch — image integrity compromised"

### Evidence Integrity Invariants

These invariants must hold throughout the entire codebase. Any code path that violates them must be rejected in code review:

1. **No writes to evidence paths.** `std::fs::write`, `std::fs::File::create`, `std::fs::remove_file`, `std::fs::rename` must never be called with a path that is equal to or under any `EvidenceSource.path`.
2. **All file reads are logged.** Every call to `VfsReadContext::read_file()` or `read_range()` must result in an audit log entry of type `FILE_ACCESSED`.
3. **Hash verification on open.** Every EWF container must have its acquisition hash verified on open. If verification fails, show a warning and log `INTEGRITY_WARN` to audit.
4. **Timestamps are always UTC.** No local time. All timestamps displayed in the UI show UTC explicitly.

### Coding Standards

- No `unwrap()` in non-test code — always `?` or `.ok()` or explicit match
- No `panic!()` in non-test code — return `Err` instead
- No `todo!()` or `unimplemented!()` in non-test code — stub functions must return a meaningful error
- All new structs derive `Debug`, `Clone`, `serde::Serialize`, `serde::Deserialize` where appropriate
- All new public functions have a doc comment explaining parameters and return value
- `cargo check` must pass after every single change
- `cargo clippy -- -D warnings` must pass before any commit

---

## 13. Full Feature Checklist

Use this checklist to track progress toward v1.0:

### Foundation
- [x] M0: VFS byte-level read context implemented and wired
- [x] M0: Hex editor reads VFS container files
- [x] M0: Gallery reads VFS container images
- [x] M0: Preview panel reads VFS container files
- [x] M0: Hasher reads VFS container files
- [x] M0: Carver reads VFS container streams
- [x] M1: CARVE button wired to CarveEngine
- [x] M1: Carve dialog renders and takes user input
- [x] M1: Carve worker runs in background with progress
- [x] M1: $CARVED virtual directory in evidence tree
- [x] M1: Carved file preview with export button
- [x] M2: Hash Sets tab in UI
- [x] M2: NSRL and custom hash set import
- [x] M2: Hash matching wired to file table (Known Good/Bad indicators)
- [x] M2: Hash match in preview panel
- [x] M2: Hash match in PDF export

### Artifact Parsers
- [x] M3: Prefetch detection during indexing
- [x] M3: Prefetch binary parser (versions 17, 23, 26, 30)
- [x] M3: MAM decompression for Win10 prefetch
- [x] M3: Prefetch timeline events
- [x] M3: Prefetch preview viewer
- [x] M4: Shellbag detection in NTUSER.DAT / UsrClass.dat
- [x] M4: Shellbag BagMRU parser
- [x] M4: Shellbag timeline events
- [x] M4: Shellbag viewer in registry panel
- [x] M5: LNK file detection (extension + magic bytes)
- [x] M5: LNK binary parser (MS-SHLLINK)
- [x] M5: LNK timeline events (creation + target modification)
- [x] M5: LNK preview viewer with deleted target detection
- [x] M6: Browser database detection (Chrome/Firefox/Edge)
- [x] M6: Chrome history/downloads parser
- [x] M6: Firefox places.sqlite parser
- [x] M6: Browser timeline events with suspicious URL detection
- [x] M6: Browser history viewer (two-tab: History + Downloads)
- [x] M11: EVTX detection and categorization
- [x] M11: EVTX parser using evtx crate
- [x] M11: High-value event ID recognition (4624, 4625, 4688, 7045, 1102, ...)
- [x] M11: EVTX timeline events with suspicious event detection
- [x] M11: Event log viewer tab

### Performance
- [x] M7: Virtual scrolling file table (render only visible rows)
- [x] M7: Debounced filter with cached `Vec<usize>` result
- [x] M7: Parallel sort with rayon for large indexes
- [x] M7: Running counters replacing per-frame iterations
- [x] M7: Column resize with persistence
- [x] M8: Hex editor virtual row rendering
- [x] M8: Background hex page loader with LRU cache
- [x] M8: Hex search (hex/ASCII/unicode) with background thread
- [x] M8: Offset navigation (click-to-copy, go-to-offset input)
- [x] M9: SQLite indexes verified/created
- [x] M9: Directory listing via parameterized SQL query
- [x] M9: Transaction batching verified (1000 rows/tx)
- [x] M9: Persistent DB path in VTP metadata

### Intelligence
- [x] M10: Content indexer (tantivy) wired to INDEX button
- [x] M10: Full-text search in SEARCH tab
- [x] M12: Registry change events in timeline
- [x] M12: Timeline source filter chips
- [x] M12: Timeline heatmap (date/hour activity matrix)
- [x] M12: Full timeline export (CSV/PDF/JSON)
- [x] M13: Audit entry chain fields (sequence, prev_hash, entry_hash)
- [x] M13: Chain verification function
- [x] M13: Chain verification on VTP load and audit tab open
- [x] M13: Audit log UI with chain status banner
- [x] M13: Audit log export (JSON/CSV/PDF)

### Court-Ready
- [x] M14: PDF report wired to REPORT button
- [x] M14: PDF cover page with evidence hashes and verification
- [x] M14: PDF examination summary page
- [x] M14: PDF bookmarked items section (sorted by severity)
- [x] M14: PDF timeline section (top 50 suspicious events)
- [x] M14: PDF audit log section with chain integrity result
- [x] M14: PDF page numbers and examiner footer on every page
- [x] M14: HTML report alternative output
- [x] M15: Timeline entries persisted in VTP
- [x] M15: Compare results persisted in VTP
- [x] M15: Hash sets (file paths) persisted in VTP
- [x] M15: Column widths and sort persisted in VTP
- [x] M15: Auto-save timer (5 minutes)
- [x] M15: Dirty state indicator in titlebar
- [x] M15: Case integrity hash on VTP save/load
- [x] M15: Backup .vtp.bak before every save
- [x] M16: Examiner profile persisted to %APPDATA%\Strata\examiner.json
- [x] M16: Profile in all reports and exports
- [x] M17: Full keyboard navigation
- [x] M17: Right-click context menus on all interactive elements
- [x] M17: Evidence health indicator in tree
- [x] M17: Status bar segments clickable as filters

### Plugin Ecosystem
- [x] M18: C-ABI plugin protocol defined
- [x] M18: Plugin runner with timeout and panic catch
- [x] M18: Plugin run UI with results display
- [x] M19: SDK crate fully documented
- [x] M19: Example plugin implementation
- [x] M19: Plugin signing verification
- [x] M20: Remnant plugin integrated
- [x] M20: Chronicle plugin integrated
- [x] M20: Cipher plugin integrated
- [x] M20: Trace plugin integrated

### Release
- [x] M22: Synthetic test E01 created
- [x] M22: 22-step smoke test passes
- [x] M22: Parser unit tests (16 test functions)
- [x] M23: All performance benchmarks meet targets
- [x] M23: Memory profile within targets
- [x] M24: Evidence write prevention audit complete
- [x] M24: Path traversal prevention in VFS
- [x] M24: Plugin sandbox verified
- [x] M24: `cargo audit` 0 vulnerabilities
- [x] M25: Version bumped to 1.0.0
- [x] M25: Windows installer built
- [x] M25: Code signing applied
- [x] M25: All 6 documentation files written
- [x] M25: Final release build: 0 errors, 0 warnings, 0 audit findings

---

## 14. Dependency Upgrade Path

Current dependencies and recommended actions:

| Crate | Current | Action | Reason |
|---|---|---|---|
| egui | 0.28 | Hold | Major releases break API — upgrade only at phase boundary |
| eframe | 0.28 | Hold | Paired with egui |
| rusqlite | 0.30 | Hold | Stable, bundled |
| nt-hive | 0.3 | Hold | Working, no critical issues |
| image | 0.25 | Hold | Stable |
| printpdf | 0.9 | Evaluate | Consider `lopdf` for more control over PDF output |
| rayon | 1.8 | Hold | Stable |
| sha2 | 0.10 | Hold | Stable |
| evtx | (declared) | Verify version | Confirm it supports EVTX format 3.1+ |
| chrono | 0.4 | Hold | Stable |
| kamadak-exif | 0.6 | Hold | Working |

**Add these dependencies:**
| Crate | Purpose | Version |
|---|---|---|
| lz4_flex | MAM decompression for Win10 Prefetch | 0.11 |
| hex | Hex encoding for audit chain hashes | 0.4 |
| criterion | Benchmarks | 0.5 (dev) |
| tempfile | Test fixtures | 3.0 (dev) |
| zip | Reading DOCX/XLSX/ZIP carved files | 0.6 |
| byteorder | Binary parsing for LNK/Shellbag/Prefetch | 1.5 |
| encoding_rs | Character encoding for browser history | 0.8 |

---

## 15. Architecture Decisions

### Why egui and Not a Web UI

Strata Tree targets air-gapped law enforcement environments where web browsers may not be available or trusted. The egui/eframe stack produces a single native binary with no runtime dependencies, no JavaScript engine, no network stack. The binary can be transferred via physical media to an isolated forensic workstation and run immediately.

### Why SQLite for .VTP

The `.vtp` case file is a SQLite database. This choice provides:
- Atomic transactions — partial writes don't corrupt the case
- Standard tooling — examiners can open `.vtp` in DB Browser for SQLite for independent verification
- Crash recovery — SQLite WAL mode survives process kills
- Efficient for large indexes — 1M file entries in SQLite is fast and memory-efficient

### Why C-ABI for Plugins

The plugin system uses a C ABI rather than Rust dynamic dispatch. This allows plugins to be compiled with any Rust toolchain version (or even C/C++) without requiring ABI compatibility between the plugin and the host. The cost is more complex memory management at the FFI boundary, mitigated by strict ownership protocol and `strata_plugin_free_result`.

### The VFS Read Context Pattern

The `VfsReadContext` pattern (M0) is the central architectural fix that this roadmap builds on. Rather than passing `Arc<EwfVfs>` through the call stack everywhere, `VfsReadContext` provides a uniform interface for reading bytes from any source — host filesystem or VFS container — without the caller needing to know which kind it is. This is the key insight that unlocks the rest of the product.

---

## 16. Codex Session Templates

Use these templates to structure overnight Codex sessions. Each session should target a single milestone.

### Template for M0 (VFS Byte-Level Access)

```
You are implementing VFS byte-level access in Strata Tree.
Root: D:\Strata\apps\tree\strata-tree\

Read in order:
  src/state.rs — specifically HexState::load_file()
  src/evidence/loader.rs — EvidenceSource and VFS attachment
  src/ui/hex_panel.rs — current hex rendering
  src/ui/gallery_view.rs — thumbnail worker
  src/ui/preview_panel.rs — file content rendering
  src/evidence/hasher.rs — hash worker

Task: Implement VfsReadContext in src/evidence/vfs_context.rs
  - pub struct VfsReadContext with read_file() and read_range()
  - Routes based on entry.evidence_id (empty = host, non-empty = VFS)
  - Add vfs_path: String field to FileEntry in state.rs
  - Add vfs_context: Option<Arc<VfsReadContext>> to AppState
  - Wire to HexState, gallery worker, preview panel, hasher

Constraints:
  - cargo check after every change
  - No unwrap() in production code
  - Evidence paths are read-only — never write
  - PowerShell 5.1 only
```

### Template for Parser Sessions (M3–M6, M11)

```
You are implementing the [PARSER NAME] parser in Strata Tree.
Root: D:\Strata\apps\tree\strata-tree\

Read in order:
  src/parsers/ — existing parser modules
  src/state.rs — TimelineEntry, FileEntry, FileCategory
  src/evidence/indexer.rs — how categories are set during indexing
  src/ui/timeline_view.rs — how events are displayed
  src/ui/preview_panel.rs — how previews are rendered

Task: Implement [PARSER NAME] parser
  [Paste specific task list from this document]

Test with: src/parsers/[name].rs #[cfg(test)] module
  Include at least 3 unit tests with real binary test data
  (Encode small test samples as &[u8] literals)
```

### Template for Performance Sessions (M7–M9)

```
You are implementing performance improvements in Strata Tree.
Root: D:\Strata\apps\tree\strata-tree\

Read in order:
  src/ui/file_table.rs — current render implementation
  src/state.rs — file_index, visible_files(), AppState
  src/app.rs — update() loop, channel polling

Profile the current behavior:
  - visible_files() is called every frame — how many entries?
  - sort_files() is called every frame — how expensive?
  - How many clones happen per frame?

Task: Implement [SPECIFIC TASK]
  [Paste specific task list from this document]

Before and after: report how many allocations/clones happen
per frame in the hot path. Target: zero per-frame clones of
the file index.
```

---

## Appendix A — Known Suspicious Patterns for Automatic Flagging

### File Paths
- `\AppData\Local\Temp\` — temporary malware staging
- `\Users\Public\` — multi-user staging area
- `\ProgramData\` — persistence staging
- `\Windows\Temp\` — system temp abuse
- `\$Recycle.Bin\` — deleted file hiding
- Network paths (`\\`) — lateral movement artifacts

### File Names (case-insensitive)
- `mimikatz`, `mimi`, `sekurlsa` — credential dumping
- `psexec`, `psexesvc` — lateral movement
- `wce`, `fgdump`, `pwdump`, `gsecdump` — credential dumping
- `procdump`, `dumpert` — LSASS dumping
- `netcat`, `nc.exe`, `ncat` — network pivoting
- `cobalt`, `beacon`, `cobaltstrike` — C2 framework
- `meterpreter`, `payload.exe` — Metasploit
- `nmap`, `masscan` — network scanning

### Executable Behaviors (from Prefetch file references)
- Accesses `\Windows\System32\lsass.exe` from non-system path
- Accesses large number of `\Users\*\AppData\` paths (credential harvesting)
- References `net.exe`, `net1.exe`, `nltest.exe` (AD enumeration)
- References `vssadmin.exe`, `wbadmin.exe`, `bcdedit.exe` (shadow copy deletion)

### Registry Keys (always flag writes)
- `\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `\SYSTEM\CurrentControlSet\Services\` (new service)
- `\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\`
- `\SOFTWARE\Classes\*\shell\open\command\`
- `\SYSTEM\CurrentControlSet\Control\Lsa\` (authentication packages)

### Browser URLs
- `.onion` domains
- IP addresses (direct connections avoiding DNS)
- Paste sites: pastebin.com, paste.ee, ghostbin.co, rentry.co
- File exfiltration: mega.nz, wetransfer.com, gofile.io, anonfiles.com
- Crypto exchanges (large monetary transfers)
- VPN providers (covering tracks)
- Search queries: "how to delete", "wipe drive", "cover tracks", "disable logging", "clear event log"

---

## Appendix B — Event Log Quick Reference

| Event ID | Log | Meaning | Always Flag? |
|---|---|---|---|
| 1102 | Security | Audit log cleared | YES |
| 104 | System | System log cleared | YES |
| 4624 | Security | Successful logon | No (filter type 3/10) |
| 4625 | Security | Failed logon | If count > 5 in 60s |
| 4648 | Security | Logon with explicit credentials | YES |
| 4688 | Security | Process creation | If suspicious command line |
| 4698 | Security | Scheduled task created | YES |
| 4702 | Security | Scheduled task modified | YES |
| 4720 | Security | User account created | YES |
| 4732 | Security | Member added to security group | YES |
| 4740 | Security | Account locked out | No |
| 7045 | System | Service installed | If binary in Temp/AppData |
| 20001 | System | New USB device | No |
| 4103 | PowerShell | Pipeline execution | If encoded command |
| 4104 | PowerShell | Script block logging | Always log, flag if obfuscated |

---

## Appendix C — File Signature Quick Reference

Signatures supported by CarveEngine (26 total) plus recommended additions:

| Type | Header Bytes | Footer | Priority |
|---|---|---|---|
| JPEG | FF D8 FF | FF D9 | HIGH |
| PNG | 89 50 4E 47 0D 0A 1A 0A | 49 45 4E 44 AE 42 60 82 | HIGH |
| PDF | 25 50 44 46 | 25 25 45 4F 46 | HIGH |
| ZIP/DOCX/XLSX | 50 4B 03 04 | 50 4B 05 06 | HIGH |
| RAR | 52 61 72 21 1A 07 | — | MEDIUM |
| 7-Zip | 37 7A BC AF 27 1C | — | MEDIUM |
| SQLite | 53 51 4C 69 74 65 33 00 | — | HIGH |
| EVTX | 45 6C 66 46 | — | HIGH |
| Prefetch | 53 43 43 41 | — | HIGH |
| LNK | 4C 00 00 00 01 14 02 00 | — | HIGH |
| Registry | 72 65 67 66 | — | HIGH |
| ELF | 7F 45 4C 46 | — | MEDIUM |
| PE/EXE/DLL | 4D 5A | — | HIGH |
| PST | 21 42 44 4E | — | HIGH |
| OLE2 | D0 CF 11 E0 A1 B1 1A E1 | — | MEDIUM |
| MP4 | (offset 4) 66 74 79 70 | — | LOW |
| MP3 | FF FB / FF F3 / FF F2 | — | LOW |
| GIF | 47 49 46 38 | 00 3B | MEDIUM |
| BMP | 42 4D | — | LOW |

---

*Strata Tree Roadmap — v0.2.0 → v1.0.0*  
*Generated: 2026-03-28*  
*Based on technical audit of 71 source files, 10,038 LOC*


