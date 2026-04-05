ROLE
====
You are continuing development on Strata Tree — a Rust/egui
forensic workbench at D:\Strata\apps\tree\strata-tree\

This is a long overnight session. Work through every task
sequentially. Read every file before modifying it.
Run: cargo check -p strata-tree after every single change.
PowerShell 5.1 only — no &&, no ternary, no null coalescing.
Evidence always read-only — never write to evidence paths.
Do not use unwrap() in production code paths.
All timestamps UTC.

BOUNDARY: You own D:\Strata\apps\tree\ ONLY.
Do NOT touch D:\Strata\apps\forge\ — Opus owns that.

Report format after each task:
  TASK [N]: [name] — DONE / BLOCKED / PARTIAL
  Files changed: [list]
  cargo check: PASS / FAIL
  Notes: [anything relevant]

=============================================================
CONTEXT — WHAT HAS BEEN COMPLETED
=============================================================
The following are DONE and working:
  ✓ E01 opening via strata-fs VFS
  ✓ NTFS indexing with real file counts
  ✓ SQLite-backed .vtp case files
  ✓ 9 UI tabs all rendering real content
  ✓ Registry viewer (nt-hive, 16 forensic keys, search)
  ✓ Timeline (file timestamps, suspicious detection)
  ✓ Gallery (thumbnails, LRU-500 cache)
  ✓ Evidence comparison (diff, timestomping detection)
  ✓ Bookmarks (file + registry, tags, notes)
  ✓ Export (CSV, HTML, PDF via printpdf)
  ✓ Audit log (13 action types, VTP persistence)
  ✓ Hash worker (SHA-256 + MD5, HASH ALL button)
  ✓ Plugin loader (loads DLLs, not yet executed)

PRIMARY GAP — THE MOST CRITICAL ISSUE:
  HexState::load_file() uses std::fs::read() only.
  Files inside E01/VHD containers show NOTHING in:
    - Hex editor
    - Gallery thumbnails
    - Preview panel
    - Hasher
    - Carver
  VFS exists and works but is not wired to these subsystems.

Before starting Task 1, run:
  cargo build -p strata-tree 2>&1 | Select-String "^error"

Fix ALL compile errors before proceeding.

=============================================================
TASK 1 — VFS READ CONTEXT (CRITICAL — DO THIS FIRST)
=============================================================
Read: src/state.rs (HexState::load_file)
Read: src/evidence/loader.rs (EvidenceSource, VFS)
Read: src/ui/hex_panel.rs
Read: src/ui/gallery_view.rs
Read: src/ui/preview_panel.rs
Read: src/evidence/hasher.rs

This is the single most important task. It unlocks everything.

PART A — Create: src/evidence/vfs_context.rs

  use std::collections::HashMap;
  use std::sync::Arc;
  use anyhow::Result;

  /// Routes file reads to host filesystem OR VFS container.
  /// evidence_id empty string = host filesystem file.
  /// evidence_id non-empty = look up VFS by that ID.
  pub struct VfsReadContext {
      pub vfs_map: Arc<HashMap<String, Arc<dyn VfsReader + Send + Sync>>>,
  }

  pub trait VfsReader {
      fn read_file(&self, vfs_path: &str) -> Result<Vec<u8>>;
      fn read_range(&self, vfs_path: &str, offset: u64, len: usize) -> Result<Vec<u8>>;
      fn file_size(&self, vfs_path: &str) -> Result<u64>;
  }

  impl VfsReadContext {
      pub fn new(vfs_map: Arc<HashMap<String, Arc<dyn VfsReader + Send + Sync>>>) -> Self

      /// Read entire file — use only for files < 64MB.
      pub fn read_file(&self, entry: &FileEntry) -> Result<Vec<u8>>

      /// Read a byte range — use for hex editor and streaming.
      pub fn read_range(&self, entry: &FileEntry, offset: u64, len: usize) -> Result<Vec<u8>>

      /// Get file size without reading content.
      pub fn file_size(&self, entry: &FileEntry) -> Result<u64>
  }

  Add field to FileEntry in state.rs:
    pub vfs_path: String,  // empty for host files, VFS-internal path for container files

  Add field to AppState:
    pub vfs_context: Option<Arc<VfsReadContext>>,

  Build vfs_context in app.rs when evidence is loaded.

PART B — Wire hex editor:

  In src/state.rs, replace HexState::load_file(path: &str)
  with HexState::load_entry(entry: &FileEntry, ctx: &VfsReadContext)

  Load first 64KB via ctx.read_range(entry, 0, 65536).
  Store file_size separately so virtual scroll knows total size.
  Show error message if read fails (not panic, not unwrap).

PART C — Wire gallery thumbnails:

  In src/ui/gallery_view.rs, the thumbnail worker currently
  opens files via std::fs. Replace with:
    ctx.read_file(entry) → decode image → make thumbnail

  Pass Arc<VfsReadContext> to the thumbnail worker closure.

PART D — Wire preview panel:

  In src/ui/preview_panel.rs, all std::fs::read calls must
  go through ctx.read_file(entry).

PART E — Wire hasher:

  In src/evidence/hasher.rs, replace std::fs::File::open
  with ctx.read_range() in 64KB chunks.
  This makes HASH ALL work for VFS container files.

PART F — Wire carver entry point:

  In src/carve/engine.rs (if it exists), add a function:
    pub fn scan_entry(
        entry: &FileEntry,
        ctx: &VfsReadContext,
        signatures: &[SignatureType],
        tx: Sender<CarveMessage>,
    )
  that reads the file through ctx in 1MB chunks and scans.

Verify after this task: selecting a file INSIDE an E01
must show real bytes in the hex editor.

=============================================================
TASK 2 — CARVE ENGINE UI
=============================================================
Read: src/carve/engine.rs (exists with 26 signatures)
Read: src/ui/toolbar.rs (CARVE button is a stub)
Read: src/ui/dialogs/ (carve_dialog.rs exists but not rendered)

PART A — Wire CARVE toolbar button:
  Replace the stub status message with:
    state.show_carve_dialog = true;

PART B — Render CarveDialog from dialogs/mod.rs:
  if state.show_carve_dialog {
      carve_dialog::render(ctx, state, vfs_context);
  }

PART C — CarveDialog UI:
  - Evidence source selector (which partition to carve)
  - Signature checkboxes: JPEG, PNG, PDF, ZIP, SQLite,
    EVTX, PE/EXE, DOCX, MP4, GIF, BMP, RAR, 7z
    (check engine.rs for what's actually supported)
  - [START CARVING] button — spawns background worker
  - [CANCEL] button — sends cancel signal to worker
  - Progress bar: "Scanning... 1.2 GB / 47.3 GB (2.5%)"
  - Result: "Found 234 files — JPEG: 180, PDF: 32, ZIP: 22"

PART D — Background carve worker:
  Wire CarveEngine to a background thread using the pattern:
    pub enum CarveMessage {
        Progress { scanned: u64, total: u64 },
        FileFound { entry: FileEntry },
        Complete { count: usize },
        Error { msg: String },
    }
  Poll carve_rx in app.rs::update() per frame.
  When FileFound arrives, add to state.file_index with
    is_carved = true
    full_path = "$CARVED/{sig}/{offset:016x}"
    parent_path = "$CARVED/{sig}"

PART E — $CARVED tree node:
  In src/ui/tree_panel.rs, add a $CARVED virtual node
  under each evidence source when carved files exist.
  Expandable to show: JPEG (180), PDF (32), ZIP (22).

=============================================================
TASK 3 — HASH SET MANAGER UI
=============================================================
Read: src/hash/hashset.rs (HashSetManager exists but no UI)
Read: src/ui/mod.rs (tab list)

PART A — Add HASH SETS tab:
  Add to tab bar between PLUGINS and AUDIT LOG.
  Create: src/ui/hash_sets_view.rs

PART B — Hash Sets UI layout:
  [IMPORT HASH SET]  [CLEAR ALL]

  Loaded Hash Sets:
  ┌─────────────────────────────────────────────────────┐
  │ Name          │ Type       │ Entries  │ Source       │
  ├───────────────┼────────────┼──────────┼──────────────┤
  │ NSRL v3.1     │ Known Good │ 145,234  │ NSRLFile.txt │
  │ Malware MD5s  │ Known Bad  │  12,847  │ custom.txt   │
  └─────────────────────────────────────────────────────┘

  Note: "Download NSRL from https://www.nist.gov/..."
  Import formats: NSRL RDS, SHA-256 list, MD5 list, CSV

PART C — Import dialog:
  [IMPORT HASH SET] → rfd::FileDialog → pick file
  Auto-detect format:
    - NSRL header present → parse NSRLFile.txt format
    - Single hex column (64 chars) → SHA-256 list
    - Single hex column (32 chars) → MD5 list
    - .csv with headers → parse columns
  Show progress during import: "Importing... 12,847 entries"

PART D — Wire hash matching to file table:
  After hashing a file, call hash_set_manager.lookup(sha256):
    KnownGood → dim row (opacity 0.5), ✓ in hash column
    KnownBad  → red left border, ⚠ badge, increment FLAGGED
    Notable   → amber indicator in hash column
  Add hash_match: Option<HashSetMatch> to FileEntry.

PART E — Hash match in preview panel:
  Show match result in preview INFO tab:
    "KNOWN BAD — Malware.Generic (KnownBad: Malware MD5s)"
    "KNOWN GOOD — Windows System File (NSRL v3.1)"

=============================================================
TASK 4 — VIRTUAL SCROLLING FILE TABLE
=============================================================
Read: src/ui/file_table.rs (clones entire Vec every frame)
Read: src/state.rs (visible_files, file_index)

The file table clones and sorts the entire index every frame.
At 1M+ files this will freeze. Fix it.

PART A — FileTableState struct:
  pub struct FileTableState {
      pub scroll_offset_px: f32,
      pub selected_id: Option<Uuid>,
      pub sort_col: SortCol,
      pub sort_asc: bool,
      pub filter: FileFilter,
      pub filtered_ids: Vec<usize>,  // indices into file_index, no cloning
      pub filter_dirty: bool,
      pub sort_dirty: bool,
      pub debounce_timer: Option<std::time::Instant>,
      pub last_filter_text: String,
      pub column_widths: [f32; 7],
  }

PART B — Virtual scroll rendering:
  const ROW_HEIGHT: f32 = 22.0;
  const BUFFER_ROWS: usize = 50;

  total_rows = filtered_ids.len()
  total_height = total_rows * ROW_HEIGHT
  first_visible = scroll_offset / ROW_HEIGHT
  render_start = first_visible.saturating_sub(BUFFER_ROWS)
  render_end = (first_visible + viewport_rows + BUFFER_ROWS).min(total_rows)

  Render top spacer: render_start * ROW_HEIGHT
  Render only rows render_start..render_end
  Render bottom spacer: (total_rows - render_end) * ROW_HEIGHT

PART C — Debounced filter (300ms):
  In app.rs update():
  if filter text changed:
      reset debounce timer
  if debounce_timer elapsed > 300ms:
      rebuild filtered_ids using filter
      mark sort_dirty = true

PART D — Parallel sort:
  if filtered_ids.len() > 10_000 {
      filtered_ids.par_sort_unstable_by(comparator);
  } else {
      filtered_ids.sort_unstable_by(comparator);
  }

PART E — Running counters:
  Remove per-frame iterations in titlebar.rs.
  Add to AppState:
    pub deleted_count: usize,
    pub carved_count: usize,
    pub hashed_count: usize,
    pub flagged_count: usize,
  Update these only when file_index changes (batch arrival),
  not every frame.

PART F — Column resize:
  Drag handles between column headers.
  Persist column_widths in AppState.
  Save to VTP case metadata on save.
  Default: [280, 400, 90, 160, 80, 200, 80]

=============================================================
TASK 5 — HEX EDITOR VIRTUAL RENDERING
=============================================================
Read: src/ui/hex_panel.rs

Large files (100MB+) must not load entirely into memory.

PART A — Page-based HexState:
  pub struct HexState {
      pub file_size: u64,
      pub scroll_byte_offset: u64,
      pub page_cache: std::collections::HashMap<u64, HexPage>,
      pub pending_pages: std::collections::HashSet<u64>,
      pub search_query: String,
      pub search_mode: HexSearchMode,  // Hex, Ascii, Unicode
      pub search_hits: Vec<u64>,
      pub search_hit_idx: usize,
      pub goto_input: String,
      pub file_entry_id: Option<Uuid>,
  }

  pub struct HexPage {
      pub start_offset: u64,
      pub data: Vec<u8>,     // PAGE_SIZE bytes
  }

  const PAGE_SIZE: usize = 65536;    // 64KB per page
  const MAX_PAGES: usize = 16;       // 1MB total in cache

PART B — Virtual row rendering:
  const ROW_BYTES: usize = 16;
  const ROW_HEIGHT: f32 = 18.0;

  first_row = scroll_byte_offset / ROW_BYTES
  last_row  = first_row + viewport_rows + 2

  For each row:
    page_offset = (row * 16) & !(PAGE_SIZE - 1)
    if page in cache: render row
    else: show "Loading..." and request page from worker

  Top spacer: first_row * ROW_HEIGHT
  Bottom spacer: (total_rows - last_row) * ROW_HEIGHT

PART C — Background page loader:
  pub enum HexPageMessage {
      Loaded { offset: u64, data: Vec<u8> },
      Error { offset: u64, msg: String },
  }

  Spawn page loads via background thread.
  Poll hex_page_rx in app.rs update().
  Evict oldest pages when cache > MAX_PAGES.
  Pre-fetch next page when within 2 rows of page boundary.

PART D — Hex search:
  Search bar above hex view:
    [Mode: HEX ▼] [4D 5A 90 00     ] [Search] ← Prev → Next (3/47)

  Search runs in background thread over full file.
  Progress: "Searching... 24% (1.2 GB / 5.0 GB)"
  Highlights matching bytes in the view.
  Prev/Next navigation through hits.

PART E — Offset navigation:
  Click offset column → copy to clipboard.
  "Go to offset:" input at top — accept decimal or 0x hex.
  Jump to offset on Enter.

=============================================================
TASK 6 — PREFETCH PARSER
=============================================================
Read: src/parsers/ (if exists, check what's there)
Read: src/evidence/indexer.rs (how categories are set)
Read: src/ui/timeline_view.rs (TimelineEntry, TimelineEventType)

PART A — Detection:
  During NTFS indexing, if path matches */Windows/Prefetch/*.pf:
    entry.category = Some(FileCategory::Prefetch)

PART B — Parser: create src/parsers/prefetch.rs

  pub struct PrefetchFile {
      pub version: u8,                    // 17, 23, 26, 30
      pub executable_name: String,
      pub prefetch_hash: u32,
      pub run_count: u32,
      pub last_run_times: Vec<DateTime<Utc>>,  // up to 8
      pub volume_paths: Vec<String>,
      pub file_references: Vec<String>,   // files accessed
  }

  pub fn parse_prefetch(data: &[u8]) -> Result<PrefetchFile, anyhow::Error>

  Support versions 17, 23, 26, 30.
  Version 30 (Win10): detect MAM magic 4D 41 4D 04,
  decompress before parsing. Use lz4_flex crate if needed.

PART C — Timeline integration:
  For each last_run_time, add TimelineEntry:
    event_type: ProcessExecuted (add this variant if missing)
    path: entry.full_path
    detail: "{exe} executed (run {n} of {total})"
    is_suspicious: check path for Temp, Downloads, Public, AppData

PART D — Prefetch preview:
  When .pf file selected, show PREFETCH tab in preview:
    Executable:   MIMIKATZ.EXE
    Hash:         0xABCD1234
    Run Count:    3
    Format:       Win10 v30
    Last Run:     2023-03-22 14:55:01 UTC
    Prior Runs:   2023-03-21 09:12:44 UTC
    Volumes:      \DEVICE\HARDDISKVOLUME2
    Files (first 20): [list]
    ⚠ SUSPICIOUS: known credential dumping tool name
    ⚠ SUSPICIOUS: executed from Downloads path

PART E — Unit tests:
  #[cfg(test)]
  mod tests {
      #[test] fn test_parse_prefetch_v17() { ... }
      #[test] fn test_parse_prefetch_v30() { ... }
  }
  Use tiny hand-crafted binary test samples as &[u8] literals.

=============================================================
TASK 7 — LNK FILE PARSER
=============================================================
Read: src/parsers/

PART A — Detection:
  Extension .lnk AND magic bytes 4C 00 00 00 01 14 02 00
  Set: entry.category = Some(FileCategory::LnkShortcut)

PART B — Parser: create src/parsers/lnk.rs

  pub struct LnkFile {
      pub target_path: Option<String>,
      pub target_size: Option<u64>,
      pub target_modified: Option<DateTime<Utc>>,
      pub target_created: Option<DateTime<Utc>>,
      pub working_directory: Option<String>,
      pub arguments: Option<String>,
      pub machine_id: Option<String>,
      pub drive_type: DriveLinkType,   // Fixed, Removable, Network, CdRom
      pub volume_label: Option<String>,
      pub network_share: Option<String>,
      pub lnk_created: Option<DateTime<Utc>>,
      pub lnk_modified: Option<DateTime<Utc>>,
  }

  pub fn parse_lnk(data: &[u8]) -> Result<LnkFile, anyhow::Error>

  Parse per MS-SHLLINK spec:
  Offset 0: Shell Link Header (76 bytes)
  Flags word at offset 20 tells what sections follow.
  Read LinkTargetIDList → LinkInfo → StringData.

PART C — Timeline:
  lnk_created → UserActivity event: "Shortcut created to: {path}"
  Flag if: target not in file_index (deleted), removable drive,
  or machine_id differs from evidence machine hostname.

PART D — Preview:
  Show LNK tab in preview panel:
    Target Path:    C:\Users\Suspect\Desktop\stolen.zip
    Target Size:    1,234,567 bytes
    Target Modified:2023-03-22 14:55:01 UTC
    Working Dir:    C:\Users\Suspect\Desktop
    Arguments:      (none)
    Machine ID:     SUSPECT-PC
    Drive Type:     Local Fixed Disk
    LNK Created:    2023-03-22 14:55:01 UTC
    ⚠ TARGET NOT FOUND IN EVIDENCE — deleted or external

=============================================================
TASK 8 — BROWSER HISTORY PARSER
=============================================================
Read: src/parsers/

PART A — Detection by path pattern:
  Chrome: */AppData/Local/Google/Chrome/User Data/*/History
  Edge:   */AppData/Local/Microsoft/Edge/User Data/*/History
  Firefox:*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite
  Set: entry.category = Some(FileCategory::BrowserDatabase)

PART B — Parser: create src/parsers/browser.rs

  pub struct BrowserVisit {
      pub url: String,
      pub title: Option<String>,
      pub visit_time: DateTime<Utc>,
      pub visit_count: u32,
      pub typed_count: u32,
      pub transition: String,
      pub browser: String,
  }

  pub struct BrowserDownload {
      pub url: String,
      pub target_path: String,
      pub start_time: DateTime<Utc>,
      pub total_bytes: i64,
      pub state: String,
      pub browser: String,
  }

  pub fn parse_chrome_history(data: &[u8]) -> Result<Vec<BrowserVisit>>
  pub fn parse_chrome_downloads(data: &[u8]) -> Result<Vec<BrowserDownload>>
  pub fn parse_firefox_places(data: &[u8]) -> Result<Vec<BrowserVisit>>

  Open SQLite from in-memory bytes:
    rusqlite::Connection::open_in_memory() then restore from bytes
  Chrome timestamps: microseconds since 1601-01-01
    Convert: unix_ts = chrome_ts / 1_000_000 - 11_644_473_600
  Firefox timestamps: microseconds since 1970-01-01 (standard)

PART C — Timeline:
  Each visit → WebVisit event (add variant if missing)
  Flag suspicious URLs:
    .onion domains
    Paste sites: pastebin.com, paste.ee, rentry.co, ghostbin.co
    File hosts: mega.nz, wetransfer.com, gofile.io, anonfiles.com
    VPN providers: protonvpn.com, mullvad.net, nordvpn.com
    Search queries containing: "how to delete", "wipe drive",
    "cover tracks", "disable logging", "clear event log"

PART D — Browser viewer in preview:
  HISTORY tab: Time | URL | Title | Visits | Typed | ⚠
  DOWNLOADS tab: Time | URL | Local Path | Size | Status
  Filter by date range and keyword.
  Export to CSV button.

=============================================================
TASK 9 — AUDIT CHAIN INTEGRITY
=============================================================
Read: src/case/audit.rs (or wherever audit is defined)
Read: src/state.rs (AuditEntry)

PART A — Add chain fields to AuditEntry:
  pub struct AuditEntry {
      // existing fields...
      pub sequence: u64,
      pub session_id: String,
      pub prev_hash: String,    // SHA-256 of previous entry's entry_hash
      pub entry_hash: String,   // SHA-256 of all fields + prev_hash
  }

  Computing entry_hash:
    let data = format!("{}|{}|{}|{}|{}|{}",
        entry.sequence,
        entry.timestamp.to_rfc3339(),
        entry.examiner,
        entry.action,
        entry.detail,
        entry.prev_hash,
    );
    entry.entry_hash = hex::encode(sha2::Sha256::digest(data.as_bytes()));

  Genesis entry (sequence=0):
    prev_hash = "0" * 64

PART B — Chain verification:
  pub enum ChainVerifyResult {
      Valid { count: usize },
      Tampered { sequence: u64, detail: String },
      Empty,
  }

  pub fn verify_audit_chain(entries: &[AuditEntry]) -> ChainVerifyResult

  Sort by sequence, recompute each hash, verify prev_hash chain.
  Run on: VTP load, AUDIT LOG tab open, before PDF export.

PART C — Audit log UI update:
  Show chain integrity banner at top of AUDIT LOG tab:
    ✓ CHAIN VERIFIED — 247 entries, 3 sessions
    ⚠ CHAIN BROKEN at entry 143 — possible tampering

  Add columns: SEQ | TIMESTAMP | EXAMINER | ACTION | HASH (16 chars)
  Export buttons: JSON (full fields) | CSV | PDF

=============================================================
TASK 10 — .VTP COMPLETION
=============================================================
Read: src/case/project.rs (VtpProject::save/load)
Read: src/state.rs (AppState fields)

PART A — Add missing tables to VTP SQLite schema:
  timeline_entries table (persist built timeline):
    CREATE TABLE IF NOT EXISTS timeline_entries (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        path TEXT NOT NULL,
        detail TEXT,
        is_suspicious INTEGER NOT NULL DEFAULT 0,
        evidence_id TEXT
    );

  compare_results table:
    CREATE TABLE IF NOT EXISTS compare_results (
        id TEXT PRIMARY KEY,
        evidence_a TEXT, evidence_b TEXT,
        result_json TEXT,
        run_at TEXT
    );

  hash_sets table (file paths only, not content):
    CREATE TABLE IF NOT EXISTS hash_set_refs (
        id TEXT PRIMARY KEY,
        name TEXT, path TEXT, category TEXT,
        entry_count INTEGER
    );

  ui_prefs table:
    CREATE TABLE IF NOT EXISTS ui_prefs (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    -- Store: column_widths, sort_col, sort_asc, last_selected_path

PART B — Auto-save timer:
  Add to AppState:
    pub is_dirty: bool,
    pub last_auto_save: Option<std::time::Instant>,

  In app.rs update():
    if is_dirty && last_auto_save.elapsed() > 5 minutes {
        if let Some(path) = &state.case_path.clone() {
            match VtpProject::save(&state, path) {
                Ok(_) => update last_auto_save, clear dirty
                Err(e) => show status message
            }
        }
    }

  Show in titlebar: ● case_name (dot = unsaved changes)
  Show in status bar: "Auto-saved 3m ago"

PART C — Case integrity hash:
  On save: compute SHA-256 of entire VTP file content
  (excluding the hash row), store in ui_prefs as "integrity_hash".

  On load: recompute, compare, warn if mismatch.
  Log CASE_INTEGRITY_WARNING to audit.

PART D — .vtp.bak before every save:
  Before overwriting:
    let bak = path.with_extension("vtp.bak");
    std::fs::copy(&path, &bak)?;
  Keep only the most recent .bak.

=============================================================
TASK 11 — EXAMINER PROFILE PERSISTENCE
=============================================================
Read: src/case/examiner.rs (ExaminerProfile if it exists)

The examiner setup dialog shows every launch. Fix it.

PART A — Persist profile to %APPDATA%\Strata\examiner.json:
  pub struct ExaminerProfile {
      pub name: String,
      pub agency: String,
      pub badge_number: String,
      pub email: Option<String>,
      pub timezone: String,
  }

  impl ExaminerProfile {
      pub fn load() -> Option<Self>   // reads from config dir
      pub fn save(&self) -> Result<()>
      pub fn config_path() -> std::path::PathBuf
  }

  Use dirs crate (or std::env) to find %APPDATA%\Strata\.
  Create directory if it doesn't exist.

PART B — Show setup dialog ONLY when examiner.json is missing.
  Add "Edit Profile" to a settings menu or toolbar.

PART C — Examiner in all outputs:
  Verify examiner name appears in:
    Every audit log entry
    PDF report header and footer
    CSV export header
    VTP case metadata
  Fix any missing locations.

=============================================================
TASK 12 — COURT-READY PDF REPORT
=============================================================
Read: src/ui/export.rs
Read: src/report/html.rs (court-ready report generator — exists
      but not exposed from toolbar REPORT button)

PART A — Wire REPORT button in toolbar:
  ToolbarAction::Report => {
      let path = rfd::FileDialog::new()
          .add_filter("PDF", &["pdf"])
          .save_file();
      if let Some(path) = path {
          generate_court_pdf(&state, &path)?;
          audit!(state, "EXPORT_REPORT", &path.display());
      }
  }

PART B — generate_court_pdf() sections:

  Cover page:
    STRATA FORENSIC WORKBENCH — Examination Report
    Case Name, Case Number, Examiner, Agency, Badge
    Date of Report (UTC)
    Tool Version, Build Hash
    Evidence Files (path, format, MD5, SHA-256, Verified Y/N)

  Examination Summary:
    Volumes found, total files, deleted files, carved files
    Suspicious files, bookmarked items, timeline events
    First/last activity timestamps

  Bookmarked Items (sorted by tag severity):
    [TAG] Full path
    Size, Created, Modified, Accessed, MD5, SHA-256
    Hash Status (KNOWN BAD / KNOWN GOOD / unverified)
    Examiner note + timestamp

  Timeline (top 50 suspicious events):
    Timestamp | Event Type | Path | Detail

  Audit Log:
    Chain integrity result
    All entries in chronological order
    Sequence | Timestamp | Examiner | Action | Hash (16 chars)

  Footer on every page:
    Case: {case_number} | Examiner: {name} | Page N of M

PART C — HTML report:
  Wire report/html.rs to also be accessible from the export menu.
  Generate as a self-contained HTML file (embedded CSS, no external deps).

=============================================================
TASK 13 — SHELLBAG PARSER
=============================================================
Read: src/parsers/
Read: src/ui/registry_view.rs

Shellbags prove user browsed to a directory — even deleted ones.

PART A — Detection:
  When NTUSER.DAT or UsrClass.dat is loaded in registry viewer,
  check for BagMRU key. If present, show [PARSE SHELLBAGS] button.

PART B — Parser: create src/parsers/shellbag.rs

  pub struct ShellbagEntry {
      pub path: String,                    // reconstructed path
      pub last_interacted: Option<DateTime<Utc>>,
      pub bag_key: String,                 // registry path
      pub is_network: bool,
      pub is_removable: bool,
  }

  pub fn parse_shellbags(
      hive: &nt_hive::Hive,
      source: ShellbagSource,
  ) -> Result<Vec<ShellbagEntry>>

  pub enum ShellbagSource { NtUser, UsrClass }

  Walk BagMRU recursively. Decode ShellItem blobs:
    0x1F → Desktop/special folder
    0x2F → Drive letter (C:\)
    0x31, 0x32 → Folder
    0x40 → Network
    0x61 → URI

PART C — Timeline:
  Each shellbag entry → UserActivity event
  Flag: removable paths, network paths,
  paths containing "evidence", "deleted", "password"

PART D — Viewer:
  SHELLBAGS section in registry panel when hive supports it.
  Tree view: reconstructed folder hierarchy
  Columns: Path | Last Accessed | Type | Flags

=============================================================
TASK 14 — WINDOWS EVENT LOG PARSER (EVTX)
=============================================================
Read: Cargo.toml (evtx crate should be listed)

PART A — Detection:
  Files ending .evtx → FileCategory::EventLog
  High-value logs: Security.evtx, System.evtx,
  Microsoft-Windows-PowerShell*.evtx,
  Microsoft-Windows-TaskScheduler*.evtx

PART B — Parser: create src/parsers/evtx.rs

  Use the evtx crate to parse event log files.
  Extract per event:
    event_id: u32
    time_created: DateTime<Utc>
    provider_name: String
    computer: String
    user_sid: Option<String>
    message: String (formatted)
    fields: HashMap<String, String>

  High-value event IDs:
    4624 (Logon), 4625 (Failed logon), 4648 (Explicit creds)
    4688 (Process creation), 4698/4702 (Scheduled task)
    4720 (Account created), 4732 (Group membership)
    7045 (Service installed)
    1102, 104 (Log cleared — ALWAYS suspicious)
    4103, 4104 (PowerShell — flag encoded commands)

PART C — Timeline:
  Each event → TimelineEntry with appropriate event type
  1102/104 always flagged suspicious
  4625 × 5 within 60s → brute force indicator
  4688 with encoded PS (-enc) → suspicious

PART D — Event log viewer:
  When .evtx selected, show EVENT LOG tab in preview:
  Table: Time | ID | Level | Provider | Computer | Message
  Click row → expand full EventData fields + raw XML
  Filter by event ID, date range, keyword

=============================================================
TASK 15 — CONTENT SEARCH UI (WIRE TANTIVY)
=============================================================
Read: src/search/content.rs (tantivy ContentIndexer exists)
Read: src/ui/search_view.rs (metadata search only currently)
Read: src/ui/toolbar.rs (INDEX button is stub)

PART A — Wire INDEX toolbar button:
  ToolbarAction::Index => {
      if state.vfs_context.is_some() && !state.content_indexing {
          state.content_indexing = true;
          spawn_content_indexer(&state, vfs_ctx, content_tx);
      }
  }

PART B — Content indexer worker:
  Wire ContentIndexer::index_all() to a background thread.
  For each file: read via VfsReadContext, extract text, index.
  Skip binary files (check category or magic bytes).
  Progress: "Indexing content... 12,847 / 47,293 files"
  Show progress in status bar.

PART C — Search tab extension:
  Add toggle: [METADATA] / [CONTENT]

  CONTENT mode:
    Query: Boolean operators supported (AND, OR, NOT)
    Example: "stolen" OR "exfiltrate" OR "password"
    Results table: File | Match Context (snippet)
    Click → navigate to file in explorer + preview
    Highlight matching text in preview panel

PART D — Status indicator:
  In titlebar, show:
    "Content index: ready (47,293 files)"
    "Content index: building (24%)..."
    "Content index: not built" → show [Build Index] button

=============================================================
TASK 16 — FINAL SMOKE TEST + v0.3.0 RELEASE
=============================================================

PART A — unwrap() final audit:
  Get-ChildItem -Recurse -Filter "*.rs" src\ |
    Select-String "\.unwrap()" |
    Where-Object { $_.Line -notmatch "//.*unwrap|#\[test\]|mod tests" } |
    Select-Object Path, LineNumber, Line

  Fix every remaining unwrap() in production paths.

PART B — Run this 22-step verification sequence:
  For each step report PASS or the specific failure:

   1. App launches, no crash within 5s
   2. New case created, examiner set
   3. Open E01, indexing starts
   4. File count appears in titlebar within 60s
   5. Navigate tree → file table populates
   6. Select file inside E01 → hex editor shows bytes ✓
      (This must pass — it's the VFS fix from Task 1)
   7. Select image inside E01 → gallery shows thumbnail ✓
   8. Navigate to Windows/Prefetch/ → .pf files visible
   9. Select .pf file → PREFETCH tab shows data
  10. Open SYSTEM hive → registry tree populates
  11. Navigate registry → keys and values display
  12. Bookmark a registry key as Suspicious
  13. HASH SETS tab → import a test SHA-256 list
  14. HASH ALL → completes, known-bad badge appears
  15. GALLERY tab → thumbnails render for images in E01
  16. TIMELINE tab → events visible, suspicious flagged
  17. CARVE → dialog opens, carving starts, $CARVED node appears
  18. COMPARE → run A=B diff, shows 0 differences
  19. AUDIT LOG → shows CHAIN VERIFIED
  20. REPORT button → PDF file created and non-empty
  21. Save .vtp → file saved, .vtp.bak created
  22. Close + reopen .vtp → bookmarks + audit restored,
      AUDIT LOG still shows CHAIN VERIFIED

PART C — Version bump:
  apps/tree/strata-tree/Cargo.toml: version = "0.3.0"
  Update STRATA_TREE_VERSION constant in source.

  v0.3.0 milestone:
    VFS byte-level access wired throughout
    Carve engine wired to UI
    Hash set manager wired
    Virtual scrolling file table
    Hex editor demand paging + search
    Prefetch, LNK, Browser, Shellbag, EVTX parsers
    Audit chain integrity
    Complete .vtp persistence
    Examiner profile persistence
    Court-ready PDF report
    Content search wired

PART D — Release build:
  cargo build -p strata-tree --release 2>&1 |
    Select-String "^error|^warning|Finished"

  Report:
    Binary size
    Build time
    Warning count (target: 0)
    cargo audit result

=============================================================
CONSTRAINTS
=============================================================
- Read every file before modifying it
- cargo check after EVERY single change
- Evidence paths are ALWAYS read-only
- No unwrap() in production code
- No panic!() in production code
- All timestamps UTC
- PowerShell 5.1 only — no && operators
- Do not touch D:\Strata\apps\forge\ — Opus owns that
- If blocked on a task, note it clearly and move to next
- Report binary size and build time at end of Task 16
