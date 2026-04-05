# Strata Tree — Complete Architecture & Build Gameplan
**Tool:** Strata Tree — Standalone Forensic Analysis Workbench
**Target Customers:** Government, Law Enforcement, National Security
**Build Executor:** Opus 4.6 (autonomous, phase-by-phase)
**Generated:** 2026-03-27
**Location:** D:\Strata\apps\tree\

---

> **NORTH STAR**
> Strata Tree is a cross-platform, portable, standalone forensic analysis
> workbench. It runs as a single executable on Windows, macOS, and Linux
> with no installation, no database server, no cloud dependency, and no
> runtime requirements. An examiner copies one file to a USB drive and
> has a complete forensic workbench on any machine in any environment
> including Windows PE/FE, air-gapped networks, and classified labs.
> X-Ways runs only on Windows. Tree runs everywhere.

---

## Primary Competitive Differentiators Over X-Ways

| Capability | X-Ways Forensics | Strata Tree |
|------------|-----------------|-------------|
| Windows support | YES | YES |
| macOS support | NO | YES |
| Linux support | NO | YES |
| Portable single exe | YES | YES |
| No installer required | YES | YES |
| Air-gap compatible | YES | YES |
| Windows PE/FE | YES | YES |
| Open source parsers | NO (proprietary) | YES (Rust/open) |
| Ecosystem integration | NO (standalone only) | YES (optional Strata sync) |
| Price | $18,589+ | TBD (gov licensing) |
| Cross-platform case files | NO | YES (.vtp works everywhere) |

---

## Core Design Principles (Non-Negotiable)

1. **Portable** — Single executable, zero dependencies, runs from USB
2. **Cross-platform** — Identical feature set on Windows, macOS, Linux
3. **Sovereign** — No network calls, no telemetry, no cloud, air-gap safe
4. **Truthful** — Never fabricate results, honest capability labeling
5. **Examiner-controlled** — Every action is deliberate, nothing automatic
6. **Court-defensible** — Complete audit trail, hash-verified evidence
7. **Standalone** — Zero dependency on Shield, Guardian, or Forge
8. **Fast** — Parallel indexing, background processing, responsive UI

---

## Technology Stack

### GUI Framework: egui (Immediate Mode GUI)
- Pure Rust, compiles into the binary with no external runtime
- Cross-platform: same code compiles to Windows exe, macOS binary, Linux binary
- Handles millions of rows efficiently via virtual scrolling
- No WebView dependency unlike Tauri — works in Windows PE/FE
- Library: egui + eframe for windowing

### Storage: SQLite via rusqlite
- Case database is a single portable .vtp file
- No server, no setup, no connection strings
- Examiner can copy the .vtp file between machines
- Same file format works on Windows, macOS, Linux

### Filesystem Parsing: strata-fs + strata-core
- Reuses all existing NTFS, APFS, ext4, E01, RAW parsing
- Tree adds no new parser logic — it consumes what already exists
- Clean separation: Tree is a consumer of strata-fs, not a fork

### Hashing: blake3 + sha2 + md5
- Parallel mass hashing using rayon
- BLAKE3 for speed, SHA-256 and MD5 for compatibility with NSRL

### Search: tantivy full-text search library
- Fast indexed search across file contents
- Boolean operators, proximity, fuzzy matching
- Index stored inside the .vtp case directory

### Build Target
```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
```
Result: ~15-25MB single executable on all platforms.

---

## Project Structure

```
D:\Strata\apps\tree\
├── Cargo.toml
├── build.rs                    — embed version, icon, Windows manifest
├── assets/
│   ├── icon.ico                — Windows executable icon
│   ├── icon.png                — macOS/Linux icon
│   └── fonts/
│       └── JetBrainsMono.ttf   — monospace font for hex editor
├── src/
│   ├── main.rs                 — entry point, platform init, window
│   ├── app.rs                  — main app struct, egui loop
│   ├── state.rs                — AppState: all runtime state
│   ├── platform.rs             — platform-specific helpers
│   │
│   ├── case/
│   │   ├── mod.rs
│   │   ├── manager.rs          — open/create/close/save cases
│   │   ├── project.rs          — .vtp SQLite schema
│   │   └── examiner.rs         — examiner identity, session tracking
│   │
│   ├── evidence/
│   │   ├── mod.rs
│   │   ├── loader.rs           — load evidence containers
│   │   ├── indexer.rs          — parallel filesystem walk
│   │   └── watcher.rs          — background indexing progress
│   │
│   ├── ui/
│   │   ├── mod.rs
│   │   ├── layout.rs           — three-pane layout manager
│   │   ├── toolbar.rs          — top toolbar buttons
│   │   ├── statusbar.rs        — bottom status bar
│   │   ├── file_browser.rs     — left pane: directory tree
│   │   ├── file_table.rs       — center pane: file listing
│   │   ├── hex_editor.rs       — hex view with data interpreter
│   │   ├── preview.rs          — file content preview
│   │   ├── search_panel.rs     — search query builder
│   │   ├── bookmark_panel.rs   — examiner bookmarks/notes
│   │   ├── hash_panel.rs       — hash calculation progress
│   │   ├── gallery.rs          — thumbnail gallery view (Phase 2)
│   │   ├── timeline.rs         — calendar/timeline view (Phase 2)
│   │   ├── registry_viewer.rs  — registry hive viewer (Phase 2)
│   │   └── dialogs/
│   │       ├── open_evidence.rs
│   │       ├── new_case.rs
│   │       ├── search.rs
│   │       └── export.rs
│   │
│   ├── search/
│   │   ├── mod.rs
│   │   ├── filename.rs         — fast filename/path search
│   │   ├── content.rs          — tantivy full-text index
│   │   └── filters.rs          — type, size, date, hash filters
│   │
│   ├── hash/
│   │   ├── mod.rs
│   │   ├── calculator.rs       — parallel hash computation
│   │   └── hashset.rs          — NSRL/Project VIC/custom sets
│   │
│   ├── carve/
│   │   ├── mod.rs
│   │   └── engine.rs           — signature-based file carving
│   │
│   ├── report/
│   │   ├── mod.rs
│   │   ├── html.rs             — HTML case report generator
│   │   └── csv.rs              — CSV export
│   │
│   └── export/
│       ├── mod.rs
│       └── bundle.rs           — evidence export bundles
│
└── tests/
    ├── fixture_tests.rs
    └── integration_tests.rs
```

---

## The .vtp Case Format

A .vtp file is a SQLite database. It is the entire case — portable,
self-contained, cross-platform. Copy it to a USB drive and open it on
any machine running Tree on any operating system.

```sql
CREATE TABLE schema_version (
    version INTEGER NOT NULL,
    created_utc TEXT NOT NULL,
    tool_version TEXT NOT NULL
);

CREATE TABLE evidence_sources (
    id TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    format TEXT NOT NULL,
    sha256 TEXT,
    hash_verified INTEGER DEFAULT 0,
    loaded_utc TEXT NOT NULL,
    size_bytes INTEGER,
    label TEXT,
    notes TEXT
);

CREATE TABLE file_index (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_sources(id),
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    extension TEXT,
    size INTEGER,
    is_dir INTEGER NOT NULL DEFAULT 0,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    created_utc TEXT,
    modified_utc TEXT,
    accessed_utc TEXT,
    mft_changed_utc TEXT,
    md5 TEXT,
    sha1 TEXT,
    sha256 TEXT,
    category TEXT,
    mft_record INTEGER,
    inode INTEGER,
    permissions TEXT,
    filesystem TEXT,
    volume_index INTEGER,
    hash_flagged TEXT
);

CREATE TABLE bookmarks (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL REFERENCES file_index(id),
    examiner TEXT NOT NULL,
    label TEXT,
    note TEXT,
    color TEXT,
    created_utc TEXT NOT NULL,
    modified_utc TEXT
);

CREATE TABLE search_hits (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL REFERENCES file_index(id),
    query TEXT NOT NULL,
    hit_type TEXT NOT NULL,
    offset INTEGER,
    context TEXT,
    found_utc TEXT NOT NULL
);

CREATE TABLE activity_log (
    id TEXT PRIMARY KEY,
    examiner TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT,
    file_id TEXT
);

CREATE TABLE case_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

---

## UI Layout Specification

```
+-----------------------------------------------------------------------+
| Strata Tree v1.0  [Case: CASE-2026-0147]    [Examiner: SA Smith]      |
+-----------------------------------------------------------------------+
| [Open Evidence] [New Case] [Search] [Hash] [Carve] [Report] [Export]  |
+------------------+----------------------------------+-----------------+
| EVIDENCE TREE    | FILE TABLE                       | PREVIEW         |
|                  |                                  |                 |
| Image.E01        | Name    Ext  Size  Modified  Del | [hex view]      |
|  NTFS Vol 1      | ntuser  .dat 2.1MB 2026-01..     |                 |
|   Users          | sam          256KB 2025-12..     | [text view]     |
|    Smith         | deleted .txt 14KB  2025-11..  D  |                 |
|     Desktop      | pagefile.sys 8GB   2026-01..     | [image view]    |
|                  |                                  |                 |
| [+ Add Source]   | 47,832 files | 3 deleted | Ready |                 |
+------------------+----------------------------------+-----------------+
| HEX EDITOR  [READ ONLY - Evidence integrity preserved]                |
| 00000000: 4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  MZ......   |
+-----------------------------------------------------------------------+
| Indexed: 47,832 | Deleted: 3 | Hits: 0 | SHA256: VERIFIED | SA Smith  |
+-----------------------------------------------------------------------+
```

---

## Phase 1 — Foundation (Weeks 1-3)
### Goal: Working portable exe that opens evidence and shows a file tree

---

### Task 1.1 — Project Scaffold and Dependencies

**Objective:** Create the Cargo.toml, project structure, and verify it
compiles to a single executable on all platforms.

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Forensics
New tool location: D:\Strata\apps\tree\
This is a completely standalone tool. It does NOT depend on Tauri,
the Shield GUI, or any web technology whatsoever.

TASK
====
Create the complete project scaffold for Strata Tree.

1. Create D:\Strata\apps\tree\Cargo.toml:

[package]
name = "strata-tree"
version = "0.1.0"
edition = "2021"
description = "Strata Tree - Portable Forensic Analysis Workbench"

[[bin]]
name = "strata-tree"
path = "src/main.rs"

[dependencies]
egui = "0.27"
eframe = { version = "0.27", features = ["default"] }
strata-fs = { path = "../../crates/strata-fs" }
strata-core = { path = "../../crates/strata-core" }
rusqlite = { version = "0.31", features = ["bundled"] }
sha2 = "0.10"
md5 = "0.7"
blake3 = "1.5"
rayon = "1.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
uuid = { version = "1.6", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
tracing-subscriber = "0.3"
anyhow = "1.0"
thiserror = "1.0"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true

2. Create all directories in the project structure shown in the
   architecture document.

3. Create stub files for every module with:
   - A comment explaining what the module does
   - Empty structs and placeholder functions that compile
   - pub mod declarations in parent mod.rs files

4. Create src/main.rs that opens an eframe window titled
   "Strata Tree v0.1 - Forensic Analysis Workbench" and shows
   a centered label "Strata Tree - Loading..."

5. Add strata-tree to the workspace Cargo.toml members list at
   D:\Strata\Cargo.toml

CONSTRAINTS
===========
Do not implement any logic yet - only the scaffold.
After creation run: cargo check -p strata-tree
Target: 0 errors, compiles successfully.
Report any dependency version conflicts.
```

**Verification:**
```powershell
# Run from: D:\Strata
cargo check -p strata-tree 2>&1 | Select-String "^error" | Measure-Object
```

**Deliverable:** Project compiles clean as a single exe target.

---

### Task 1.2 — Application State and Case Management

**Objective:** Implement AppState and .vtp case database format.

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree
Files:
  D:\Strata\apps\tree\src\state.rs
  D:\Strata\apps\tree\src\case\project.rs
  D:\Strata\apps\tree\src\case\manager.rs
  D:\Strata\apps\tree\src\case\examiner.rs

TASK
====
Implement the application state and case management layer.

1. In src/state.rs implement AppState with these fields:
   - case: Option<ActiveCase>
   - evidence_sources: Vec<EvidenceSource>
   - file_index: Vec<IndexedFile>
   - selected_file: Option<String>
   - selected_files: Vec<String>
   - search_query: String
   - search_results: Vec<SearchHit>
   - bookmarks: Vec<Bookmark>
   - indexing_status: IndexingStatus (Idle/Running/Complete/Failed)
   - hex_view: HexViewState
   - current_examiner: String
   - ui_state: UiState
   - status_message: String
   - error_message: Option<String>

2. In src/case/project.rs implement the complete SQLite schema
   as specified in the architecture. All tables must be created
   on new case creation. Implement:
   - VtpProject::create(path, case_name, examiner) -> Result<Self>
   - VtpProject::open(path) -> Result<Self>
   - VtpProject::close(&mut self)
   - Schema version migration support for future updates

3. In src/case/manager.rs implement:
   - CaseManager::new_case(name, examiner, output_path) -> Result<VtpProject>
   - CaseManager::open_case(path) -> Result<VtpProject>
   - CaseManager::recent_cases() -> Vec<RecentCase>

4. In src/case/examiner.rs implement ExaminerSession:
   - Required before any case work begins
   - Default is "Unidentified Examiner" - show visible warning
   - All activity_log entries include examiner name
   - Session start/end recorded

CONSTRAINTS
===========
All timestamps stored as ISO 8601 UTC strings.
.vtp file must be openable on Windows, macOS, and Linux.
rusqlite bundled feature means SQLite is compiled into the binary.
After implementation run: cargo check -p strata-tree
```

**Verification:**
```powershell
# Run from: D:\Strata
cargo check -p strata-tree 2>&1 | Select-String "^error" | Measure-Object
```

**Deliverable:** AppState and .vtp case format compile and ready for UI wiring.

---

### Task 1.3 — Evidence Loading and File Indexing

**Objective:** Load evidence containers and index all files into .vtp using strata-fs.

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree
Files:
  D:\Strata\apps\tree\src\evidence\loader.rs
  D:\Strata\apps\tree\src\evidence\indexer.rs
  D:\Strata\apps\tree\src\evidence\watcher.rs

BACKGROUND
==========
strata-fs already provides VFS adapters (RawVfs, EwfVfs) with
enumerate_volume() returning Vec<VfsEntry>. Tree consumes this.

TASK
====
1. In loader.rs implement EvidenceLoader:
   pub fn load_evidence(
       path: &Path,
       case_db: &VtpProject,
       progress_tx: Sender<IndexingProgress>,
   ) -> Result<EvidenceSource>

   Steps:
   a. Detect format from extension (E01, dd, raw, vhd, vmdk, directory)
   b. Compute SHA-256 of the evidence container file
   c. Insert into evidence_sources table
   d. Spawn background thread to run indexer
   e. Return immediately - indexing continues in background

2. In indexer.rs implement EvidenceIndexer:
   pub fn index_evidence(
       vfs: Box<dyn VanitorVfs>,
       evidence_id: &str,
       case_db: &VtpProject,
       progress_tx: Sender<IndexingProgress>,
   ) -> Result<IndexingStats>

   Steps:
   a. Walk VFS recursively via enumerate_volume()
   b. Insert each VfsEntry as a row in file_index
   c. Detect file extension and assign category
   d. Mark deleted files with is_deleted = 1
   e. Send progress every 1000 files via channel
   f. Use SQLite transactions batched in groups of 1000 for speed

3. In watcher.rs implement IndexingWatcher:
   - Receives progress via mpsc channel
   - Updates AppState.indexing_status
   - Triggers egui repaint on progress

4. pub enum IndexingProgress {
       FileFound { path: String, count: u64 },
       VolumeComplete { volume_index: usize, file_count: u64 },
       Complete(IndexingStats),
       Failed(String),
   }

CONSTRAINTS
===========
Indexing must run in a background thread - UI stays responsive.
Individual VfsEntry failures are logged as warnings, not aborts.
Batch inserts using SQLite transactions for performance.
After implementation run: cargo check -p strata-tree
```

**Verification:**
```powershell
# Run from: D:\Strata
cargo check -p strata-tree 2>&1 | Select-String "^error" | Measure-Object
```

**Deliverable:** Evidence loads in background, file_index populated.

---

### Task 1.4 — Three-Pane UI Layout

**Objective:** Build the main window with file browser, file table, and preview.

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree
Files:
  D:\Strata\apps\tree\src\app.rs
  D:\Strata\apps\tree\src\ui\layout.rs
  D:\Strata\apps\tree\src\ui\toolbar.rs
  D:\Strata\apps\tree\src\ui\file_browser.rs
  D:\Strata\apps\tree\src\ui\file_table.rs
  D:\Strata\apps\tree\src\ui\statusbar.rs

TASK
====
Implement the main three-pane forensic workbench layout in egui.

1. In app.rs implement eframe::App for StrataTreeApp:
   - TopBottomPanel top: toolbar
   - TopBottomPanel bottom: statusbar
   - TopBottomPanel bottom (above statusbar): hex editor, resizable, 160px default
   - SidePanel left: file browser, resizable, 220px default
   - SidePanel right: preview panel, resizable, 280px default
   - CentralPanel: file table (takes remaining space)

2. In toolbar.rs implement the toolbar:
   Buttons: Open Evidence | New Case | Search | Hash Files |
            Carve | Report | Export | Bookmarks | Settings
   Show current case name and examiner name always visible.
   Disable buttons that require an open case when no case is loaded.

3. In file_browser.rs implement the directory tree:
   - Collapsible tree showing evidence sources and directories
   - Clicking a directory filters the file table
   - Show volume/partition labels
   - Show evidence SHA-256 on hover (truncated)

4. In file_table.rs implement the file listing:
   - Virtual scrolling via egui ScrollArea for 1M+ file performance
   - Columns: Name | Extension | Size | Modified | Created | SHA256 | Category | Deleted
   - Click column header to sort ascending/descending
   - Deleted files shown in muted distinct color with D indicator
   - Right-click context menu: Bookmark | View in Hex | Export | Add Note
   - Multi-select: Ctrl+click and Shift+click

5. In statusbar.rs implement the status bar:
   Show: file count | deleted count | search hits | indexing status |
         hash verification status | examiner name (always visible)

FORENSIC UI RULES
=================
Never show "0" where data has not loaded - show dash instead
When indexing runs, show animated progress indicator in status bar
Deleted files must ALWAYS be visually distinct - never hidden by default
Examiner name must be visible at all times - it is part of chain of custody
No animations, gradients, or decorative elements - professional forensic tool

CONSTRAINTS
===========
Pure egui styling only - no external CSS or web assets
Readable on both 1080p and 4K displays
All panes resizable by drag handle
After implementation: cargo check -p strata-tree
Then: cargo run -p strata-tree to verify window opens
```

**Verification:**
```powershell
# Run from: D:\Strata
cargo check -p strata-tree 2>&1 | Select-String "^error" | Measure-Object
cargo run -p strata-tree
```

**Deliverable:** Three-pane layout renders, window opens cleanly.

---

### Task 1.5 — Hex Editor

**Objective:** Read-only hex editor with data interpreter for forensic file analysis.

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree
File: D:\Strata\apps\tree\src\ui\hex_editor.rs

TASK
====
Implement a forensic read-only hex editor panel.

Display format:
  Offset    Hex bytes (16 per row)                ASCII
  00000000: 4D 5A 90 00 03 00 00 00  04 00 00 00  MZ......

1. HexEditorState struct:
   - data: Vec<u8> (current 64KB chunk loaded)
   - offset: u64 (current view offset)
   - selected_offset: u64 (cursor position)
   - bytes_per_row: usize (default 16)
   - total_size: u64
   - source: HexSource enum (None, File, Sector)

2. Implement render_hex_editor():
   - Offset column in 8-digit hex
   - 16 bytes per row with space grouping
   - ASCII column (printable chars, dot for others)
   - Highlight selected byte in both hex and ASCII columns
   - Click any byte to select it
   - Keyboard navigation: arrow keys, Page Up/Down, Ctrl+G to goto offset

3. Data Interpreter panel (below or beside hex):
   Interpret selected bytes as:
   - Int8, UInt8, Int16/32/64 LE and BE, UInt16/32/64 LE and BE
   - Float32 and Float64 LE and BE
   - Windows FILETIME (64-bit) converted to UTC string
   - Unix timestamp (32-bit) converted to UTC string
   - GUID (16 bytes formatted as standard GUID string)

4. Navigation:
   - Offset input field to jump to specific position
   - Show "Offset X of Y (Z%)" in header
   - Only load 64KB at a time for large file handling

FORENSIC REQUIREMENT
====================
Display prominent label: "READ ONLY - Evidence integrity preserved"
The hex editor NEVER writes to evidence - this is enforced in code.
Data interpreter values are labeled as "interpretation" not fact.

CONSTRAINTS
===========
Use egui monospace font for hex display.
Handle files larger than RAM by loading 64KB windows at a time.
After implementation run: cargo check -p strata-tree
```

**Verification:**
```powershell
# Run from: D:\Strata
cargo check -p strata-tree 2>&1 | Select-String "^error" | Measure-Object
```

**Deliverable:** Hex editor displays file bytes with full data interpreter.

---

### Task 1.6 — Hash Calculation

**Objective:** Parallel mass hash calculation with NSRL and Project VIC integration.

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree
Files:
  D:\Strata\apps\tree\src\hash\calculator.rs
  D:\Strata\apps\tree\src\hash\hashset.rs
  D:\Strata\apps\tree\src\ui\hash_panel.rs

TASK
====
1. In calculator.rs implement HashCalculator:
   pub fn hash_all_files(
       vfs: &dyn VanitorVfs,
       case_db: &VtpProject,
       evidence_id: &str,
       algorithms: HashAlgorithms { md5: bool, sha1: bool, sha256: bool },
       progress_tx: Sender<HashProgress>,
   ) -> Result<HashStats>
   - Run in background thread using rayon for parallelism
   - Update file_index rows with computed hashes
   - Send progress every 100 files
   - Return HashStats { hashed, skipped, failed, elapsed_ms }

2. In hashset.rs implement HashSetManager:
   - load_nsrl(path) - load NSRL RDS hashset (MD5-based)
   - load_project_vic(path) - load Project VIC JSON/ODATA
   - load_custom(path, category) - load custom hash list
   - lookup(md5) -> HashMatch (KnownGood, KnownBad, Notable, Unknown)
   - After matching: update hash_flagged column in file_index

3. In hash_panel.rs implement the hash UI:
   - Progress bar during calculation
   - Hash set statistics display
   - Buttons: Hash All Files | Load NSRL | Load Project VIC | Load Custom
   - Known-bad match count shown prominently in RED if greater than zero
   - Export known-bad hits to CSV

FORENSIC REQUIREMENTS
=====================
Known-bad matches prominently flagged in file table (red background)
Hash calculation is always read-only
Report hash algorithm alongside every exported hash value
NSRL known-good matches de-emphasized but never hidden
Project VIC integration is law enforcement use only - label it clearly

CONSTRAINTS
===========
After implementation run: cargo check -p strata-tree
```

**Verification:**
```powershell
# Run from: D:\Strata
cargo check -p strata-tree 2>&1 | Select-String "^error" | Measure-Object
```

**Deliverable:** Mass hash calculation works in background, NSRL matching functional.

---

### Task 1.7 — Keyword Search

**Objective:** Filename keyword search with filters, results stored in case database.

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree
Files:
  D:\Strata\apps\tree\src\search\filename.rs
  D:\Strata\apps\tree\src\search\filters.rs
  D:\Strata\apps\tree\src\ui\search_panel.rs

TASK
====
1. In filename.rs implement FilenameSearch:
   pub fn search_filenames(
       query: &str,
       case_db: &VtpProject,
       options: SearchOptions,
   ) -> Result<Vec<SearchHit>>

   SearchOptions includes:
   - case_sensitive: bool
   - regex: bool
   - include_paths: bool (search full path not just filename)
   - include_deleted: bool
   - extension_filter: Vec<String>

   Store results in search_hits table.
   Log every search to activity_log with query and result count.

2. In filters.rs implement FileFilter:
   - min_size / max_size: Option<u64>
   - modified_after / modified_before: Option<DateTime<Utc>>
   - extensions: Vec<String>
   - categories: Vec<String>
   - deleted_only: bool
   - has_hash: bool
   - hash_flag: Option<HashMatch>
   Apply to file_index queries as SQL WHERE clauses.

3. In search_panel.rs implement search UI:
   - Query input with Enter key to search
   - Toggle options: case sensitive, regex, include deleted
   - Extension filter chips (add/remove)
   - Date range pickers
   - Size range inputs (min/max bytes)
   - Result count and list
   - Click result to navigate file table to that file
   - Export results to CSV

FORENSIC REQUIREMENT
====================
All searches logged in activity_log for court record.
Results stored in search_hits table - part of the case file.

CONSTRAINTS
===========
After implementation run: cargo check -p strata-tree
```

**Verification:**
```powershell
# Run from: D:\Strata
cargo check -p strata-tree 2>&1 | Select-String "^error" | Measure-Object
```

**Deliverable:** Filename search works, results stored in case database.

---

### Task 1.8 — Bookmarks and Court-Ready Report

**Objective:** Examiner bookmarking system and HTML case report generation.

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree
Files:
  D:\Strata\apps\tree\src\ui\bookmark_panel.rs
  D:\Strata\apps\tree\src\report\html.rs
  D:\Strata\apps\tree\src\report\csv.rs

TASK
====
1. Bookmark system:
   Right-click any file to bookmark with color label:
   - Red: Critical evidence
   - Yellow: Notable / review needed
   - Green: Cleared / accounted for
   - Blue: Reference / background
   Add text notes to any bookmarked file.
   Bookmark panel groups by color, click to navigate to file.
   All bookmarks logged in activity_log.

2. Court-ready HTML report with these required sections:

   SECTION 1 - CASE HEADER
   Case name, number, examiner name, agency
   Report generated UTC timestamp
   Tool: "Strata Tree vX.X.X"

   SECTION 2 - EVIDENCE INTEGRITY
   Evidence source path, container format
   SHA-256 hash of evidence container
   Hash verification status: VERIFIED or UNVERIFIED
   Date/time evidence was loaded

   SECTION 3 - EXAMINATION SUMMARY
   Total files indexed, deleted files found
   Hash calculation status and known-bad count
   Search queries performed
   Time range of evidence (earliest to latest timestamp)

   SECTION 4 - NOTABLE FILES (Bookmarks)
   Red bookmarks listed first with full path, all four hashes, timestamps
   Then yellow, green, blue
   Examiner notes included verbatim

   SECTION 5 - SEARCH RESULTS
   Each search query run during the examination
   Result count per query
   Top 50 hits per query with file path and match context

   SECTION 6 - METHODOLOGY
   Tool name, version, and SHA-256 of the tree executable
   Analysis approach: "Read-only examination of evidence container"
   Examiner attestation statement
   Signature placeholder line

   SECTION 7 - LIMITATIONS
   Standard Experimental parser disclaimer
   "This tool does not modify evidence sources"
   Hash algorithm disclosure

   APPENDIX - ACTIVITY LOG
   Complete chronological examiner activity log
   (All entries from activity_log table)

3. CSV exports for file listing, bookmarks, and search results.

CONSTRAINTS
===========
HTML report is single self-contained file with inline CSS - no CDN.
All timestamps in UTC with explicit timezone notation.
Report is read-only - cannot be modified from within Tree.
After implementation run: cargo check -p strata-tree
```

**Verification:**
```powershell
# Run from: D:\Strata
cargo check -p strata-tree 2>&1 | Select-String "^error" | Measure-Object
```

**Deliverable:** Bookmarks work, HTML report generates with all 8 sections.

---

### Phase 1 Milestone Checkpoint

```powershell
# Run from: D:\Strata
cargo check -p strata-tree 2>&1 | Select-String "^error" | Measure-Object
```

```powershell
# Run from: D:\Strata
cargo build --release -p strata-tree 2>&1 | Select-String "^error" | Measure-Object
```

```powershell
# Run from: D:\Strata
Get-Item "target\release\strata-tree.exe" | Select-Object Name, Length
```

Manual checklist before Phase 2:
- [x] Window opens with correct title
- [x] Three-pane layout renders and all panes are resizable
- [x] Can open an E01 or RAW evidence file
- [x] File tree populates in left pane
- [x] File table shows indexed files with correct columns
- [x] Deleted files visually distinct with D indicator
- [x] Hex editor shows file bytes when file selected
- [x] Data interpreter shows values at cursor
- [x] Hash calculation runs in background without blocking UI
- [x] Keyword search returns results stored in case database
- [x] Bookmark can be added to a file with color label
- [x] HTML report generates with all 8 sections
- [x] Examiner name always visible in toolbar and statusbar
- [x] Binary is a single .exe file under 50MB

---

## Phase 2 — Deep Analysis (Weeks 4-8)
### Goal: Full forensic depth matching X-Ways core capabilities

---

### Task 2.1 — Full-Text Content Indexing

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree
File: D:\Strata\apps\tree\src\search\content.rs

TASK
====
Add tantivy to Cargo.toml: tantivy = "0.21"

Implement ContentIndexer that:
1. Builds a tantivy index in a <casename>.vtp.index/ directory
2. Indexes text-type files (txt, log, csv, xml, html, json, eml,
   cfg, ini, py, js, etc.) up to 10MB per file
3. Stores file_index.id as the document ID for lookup

Implement ContentSearch:
   pub fn search_content(
       query: &str,
       index: &tantivy::Index,
       options: ContentSearchOptions,
   ) -> Result<Vec<ContentSearchHit>>

ContentSearchOptions: max_results, boolean_mode, fuzzy
ContentSearchHit: file_id, file_path, snippet, score

Add a "Content" tab to the search panel alongside filename search.
Content indexing runs as background job after file indexing completes.
Log content index stats: files indexed, files skipped, elapsed_ms.

CONSTRAINTS
===========
Only index text-extractable files - skip binary files.
Respect 10MB per file limit - truncate large files.
After changes run: cargo check -p strata-tree
```

---

### Task 2.2 — File Carving

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree
File: D:\Strata\apps\tree\src\carve\engine.rs

TASK
====
Implement signature-based file carving from unallocated space.

1. Embed a file signature JSON database in the binary with at
   least 25 file types including:
   JPEG, PNG, PDF, ZIP, DOCX, XLSX, PPTX, MP4, MP3, GIF, BMP,
   TIFF, AVI, MOV, EXE, DLL, SQLite, PST, OST, EML, XML, RAR,
   7Z, TAR.GZ, LNK

   Each signature has: name, hex header, hex footer (nullable),
   extension, max_size_mb

2. Implement CarveEngine:
   pub fn carve_unallocated(
       vfs, evidence_id, case_db, output_dir,
       signatures, progress_tx
   ) -> Result<CarveStats>

   - Read unallocated space in 512KB chunks
   - Scan for known file headers
   - Read forward to footer or max_size when header found
   - Write carved file to output_dir: CARVED_0001.jpg etc.
   - Add carved files to file_index with category = "carved"

3. Carve button opens dialog:
   - Output directory selector
   - Checkbox list of file types to carve
   - Progress bar
   - Results summary on completion

FORENSIC REQUIREMENT
====================
Carved files are copies - evidence is never modified.
All carved files logged in activity_log.
Output directory is user-specified - never writes to evidence path.

CONSTRAINTS
===========
Carving runs in background thread.
After changes run: cargo check -p strata-tree
```

---

### Task 2.3 — Gallery and Timeline Views

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree
Files:
  D:\Strata\apps\tree\src\ui\gallery.rs
  D:\Strata\apps\tree\src\ui\timeline.rs

TASK
====
1. Gallery View:
   - Thumbnail grid for image files (JPEG, PNG, GIF, BMP, TIFF, WebP)
   - Lazy loading - only decode visible thumbnails
   - Click to open full preview
   - Right-click to bookmark
   - Thumbnail size slider
   - Filter to current directory selection

2. Timeline View (METADATA timeline only):
   - Calendar heatmap: days as columns, activity intensity as height
   - Click a day to filter file table to files modified that day
   - Date range selector to zoom
   - Filter by: created, modified, accessed, MFT changed timestamps
   - Show top 10 busiest days with file counts
   - This is a file TIMESTAMP timeline not an artifact timeline

IMPORTANT DISTINCTION
=====================
This timeline shows file system metadata timestamps.
It is NOT the same as Chronicle in Shield which shows parsed artifacts.
Label it clearly: "File System Timestamp View"

CONSTRAINTS
===========
Gallery handles 10,000+ images without hanging - lazy loading required.
After changes run: cargo check -p strata-tree
```

---

### Task 2.4 — Volume Shadow Copy Support

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree

TASK
====
Add VSS (Volume Shadow Copy) enumeration for NTFS evidence.

1. Detect VSS snapshots in NTFS volumes at:
   \System Volume Information\{GUID}\

2. Implement VssEnumerator:
   - List available snapshots with creation date and snapshot ID
   - Allow examiner to add a snapshot as an additional evidence source
   - Index snapshot contents into file_index
   - Mark snapshot files with snapshot date in category field

3. File browser shows snapshots as separate evidence sources:
   Image.E01 (live volume)
   Image.E01 - VSS 2026-01-15
   Image.E01 - VSS 2025-12-01

4. Delta view option: show only files that differ between
   live volume and a selected snapshot.

FORENSIC REQUIREMENT
====================
VSS data must ALWAYS be labeled with its snapshot date.
Never present snapshot data as the live filesystem.

CONSTRAINTS
===========
If VSS parsing fails, log warning and continue without it.
After changes run: cargo check -p strata-tree
```

---

### Phase 2 Milestone Checkpoint

```powershell
# Run from: D:\Strata
cargo build --release -p strata-tree 2>&1 | Select-String "^error" | Measure-Object
```

Manual checklist:
- [x] Content search finds text within files
- [x] File carving produces carved files in output directory
- [x] Gallery shows image thumbnails with lazy loading
- [x] Timeline shows calendar heatmap by file timestamps
- [x] VSS snapshots enumerated when present
- [x] Binary is still a single exe under 50MB

---

## Phase 3 — Production Hardening (Months 3-6)
### Goal: Gov/LE/national security ready

---

### Task 3.1 — Complete Examiner Audit Trail

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree

TASK
====
Implement a complete forensic audit trail.

Every user action writes to activity_log:
- Open evidence (path, sha256, timestamp)
- Run hash calculation (algorithm, file count)
- Run search (query, result count)
- Add/remove bookmark (file path, label)
- Add note (file path, note snippet)
- Export files (destination, count)
- Generate report (output path)
- View file in hex (file path)
- Run carving (signatures used, output dir, found count)
- Open/close case
- Set examiner name

Add AuditLog viewer panel:
- Chronological list of all actions
- Filter by action type
- Export to CSV for discovery
- Cannot be deleted or edited from within Tree
- Included as Appendix in HTML report

FORENSIC REQUIREMENT
====================
The audit log is part of the court record.
It is physically part of the .vtp case file.
It cannot be cleared from within the application.
```

---

### Task 3.2 — Cross-Platform CI Build

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree

TASK
====
Set up cross-platform CI that builds Tree on all three platforms.

1. Create .github/workflows/tree-build.yml with three jobs:
   - windows-build (windows-latest runner)
   - macos-build (macos-latest runner)
   - linux-build (ubuntu-latest runner)

   Each job:
   a. Checkout repo
   b. Install Rust stable
   c. cargo build --release -p strata-tree
   d. Verify binary exists
   e. Upload binary as GitHub Actions artifact

2. In build.rs:
   - Embed version from Cargo.toml
   - Windows: embed icon.ico
   - Windows: embed manifest requesting medium integrity (not admin)
   - Set binary metadata

3. Create apps/tree/PLATFORM_NOTES.md documenting:
   - Feature parity across platforms
   - Physical disk access requirements per platform
   - How to run on Windows PE/FE
   - Known limitations per platform (document honestly)

CONSTRAINTS
===========
Binary must be self-contained on all platforms.
No installer required anywhere.
```

---

### Task 3.3 — Plugin API (X-Tensions Equivalent)

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree

TASK
====
Create a plugin API that lets agencies extend Tree with custom modules.

1. Create new crate D:\Strata\crates\strata-tree-sdk\Cargo.toml

2. Define the plugin trait:
   pub trait TreePlugin: Send + Sync {
       fn name(&self) -> &str;
       fn version(&self) -> &str;
       fn description(&self) -> &str;
       fn on_file_indexed(&self, file: &IndexedFile) -> PluginResult;
       fn on_case_opened(&self, case: &CaseInfo) -> PluginResult;
       fn custom_menu_items(&self) -> Vec<MenuItem>;
   }

3. Plugins are dynamic libraries:
   - Windows: .dll
   - macOS: .dylib
   - Linux: .so
   Placed in plugins/ directory alongside the Tree executable.

4. Add libloading = "0.8" to Tree Cargo.toml
   Load plugins at startup from the plugins/ directory.

5. Plugin results can:
   - Add tags to files
   - Add bookmark entries
   - Add activity log entries
   - Display custom UI panels

6. Create README in strata-tree-sdk explaining the API.

FORENSIC REQUIREMENTS
=====================
Plugins clearly labeled as third-party in the UI.
Plugin actions logged in activity_log with plugin name.
Plugin errors never crash Tree - all caught and logged.
Examiner must explicitly enable each plugin at startup.

CONSTRAINTS
===========
After changes run: cargo check -p strata-tree cargo check -p strata-tree-sdk
```

---

### Task 3.4 — RAID Reconstruction

**[PROMPT FOR OPUS]**
```
CONTEXT
=======
Project: Strata Tree

TASK
====
Add RAID reconstruction for complex evidence scenarios.

Support: JBOD, RAID-0, RAID-5

1. RaidBuilder UI in Open Evidence dialog:
   - "Reconstruct RAID" option
   - Select multiple image files as RAID members
   - Select RAID type and stripe size
   - Preview reconstructed virtual disk size
   - Open as single evidence source

2. Implement RaidVfs in strata-fs:
   - Takes Vec<Box<dyn VanitorVfs>> as member disks
   - Presents unified virtual disk
   - RAID-0: stripe reading across members
   - RAID-5: XOR parity reconstruction

3. Evidence browser shows RAID info:
   "RAID-0: 4 disks, 64KB stripe | Virtual size: 4TB"

FORENSIC REQUIREMENT
====================
If RAID reconstruction fails, surface a clear error.
Never present partial or incorrect reconstructed data silently.

CONSTRAINTS
===========
RAID-6 is Phase 4.
After changes run: cargo check -p strata-tree cargo check -p strata-fs
```

---

### Phase 3 Milestone Checkpoint

Manual checklist before declaring production ready:
- [x] Every examiner action logged in activity_log
- [x] Audit log appears in HTML report as appendix
- [x] Windows binary builds in CI
- [x] macOS binary builds in CI
- [x] Linux binary builds in CI
- [x] Plugin API loads a test plugin without crashing
- [x] RAID-0 reconstruction opens a striped image
- [x] PLATFORM_NOTES.md documents all limitations honestly
- [x] Zero network calls in any operation (verify with network monitor)
- [x] Binary runs from USB with no dependencies on any test machine

---

## Gov/LE/National Security Deployment Requirements

These requirements must be verified before any agency deployment.

### Chain of Custody
- Evidence SHA-256 computed on first load and stored in .vtp
- Hash re-verified on every subsequent open - mismatch shown as warning
- All examiner actions timestamped and stored in activity_log
- Case file modification tracked

### Court Readiness
- HTML report includes all 8 sections including audit appendix
- Examiner attestation in every report
- Tool name, version, and hash in every report
- All timestamps in UTC with timezone disclosure
- Report is self-contained single HTML file

### Air-Gap Compatibility (Verified)
- Zero network calls in any operation mode
- No license server dependency
- No update checks or telemetry
- Functional test: disconnect all network interfaces, full feature test

### Evidence Integrity (Non-Negotiable)
- All evidence access is read-only
- No write operations to evidence paths ever
- Carved files go to user-specified separate directory
- Explicit warning if any write to evidence path is attempted

### Examiner Accountability
- Examiner name required before case work begins
- Warning shown if using default "Unidentified Examiner"
- All exports include examiner name
- Multi-examiner support: separate bookmark sets per examiner
- Session start/end in audit trail

---

## Operating Rules for Tree Build

1. Always run cargo check -p strata-tree after every change
2. Never add Tauri, WebView, or browser dependencies - ever
3. Never add any network calls - zero external connections
4. egui version must stay consistent - check after any update
5. All UI text is professional forensic language
6. Never show "0" where data has not loaded - show dash
7. Deleted files are always visually distinct - never hidden by default
8. Every user action writes to activity_log
9. Examiner name must be visible at all times
10. Evidence access is read-only - enforced in code not just policy

---

## Quick Reference

| What | Where |
|------|-------|
| Main entry | apps/tree/src/main.rs |
| App loop | apps/tree/src/app.rs |
| App state | apps/tree/src/state.rs |
| Case format | apps/tree/src/case/project.rs |
| Evidence loader | apps/tree/src/evidence/loader.rs |
| File indexer | apps/tree/src/evidence/indexer.rs |
| Hex editor | apps/tree/src/ui/hex_editor.rs |
| File table | apps/tree/src/ui/file_table.rs |
| Search | apps/tree/src/search/ |
| Hash calc | apps/tree/src/hash/ |
| File carving | apps/tree/src/carve/engine.rs |
| Report gen | apps/tree/src/report/html.rs |
| Plugin SDK | crates/strata-tree-sdk/ |
| CI builds | .github/workflows/tree-build.yml |
| Platform notes | apps/tree/PLATFORM_NOTES.md |

---

## North Star

Strata Tree is the forensic workbench an examiner carries everywhere.
One file on a USB drive. Runs on the Windows lab machine, the macOS
laptop, the Linux server in the classified network, the Windows PE
boot environment at a crime scene. Same features, same case format,
same interface everywhere. No install. No admin. No network. No excuses.

X-Ways runs on Windows.
Tree runs everywhere.
