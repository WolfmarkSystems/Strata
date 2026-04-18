//! AppState — all runtime state for Strata.

use crate::hash::hashset::HashSetManager;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

// ─── Design constants ─────────────────────────────────────────────────────────
pub mod colors {
    use egui::Color32;
    pub const SURFACE_EL: Color32 = Color32::from_rgb(0x0f, 0x10, 0x14);
    pub const BORDER_SUBTLE: Color32 = Color32::from_rgb(0x12, 0x16, 0x20);
    pub const ACCENT: Color32 = Color32::from_rgb(0xd8, 0xe2, 0xec);
    pub const TEXT_PRI: Color32 = Color32::from_rgb(0xd8, 0xe2, 0xec);
    pub const TEXT_SEC: Color32 = Color32::from_rgb(0x8a, 0x9a, 0xaa);
    pub const TEXT_MUTED: Color32 = Color32::from_rgb(0x3a, 0x48, 0x58);
    pub const DANGER: Color32 = Color32::from_rgb(0xa8, 0x40, 0x40);
    pub const AMBER: Color32 = Color32::from_rgb(0xb8, 0x78, 0x40);
    pub const GREEN_OK: Color32 = Color32::from_rgb(0x48, 0x78, 0x58);
}

// ─── Core types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileEntry {
    pub id: String,
    pub evidence_id: String,
    pub path: String,
    pub vfs_path: String,
    pub parent_path: String, // parent directory path for tree navigation
    pub name: String,
    pub extension: Option<String>,
    pub size: Option<u64>,
    pub is_dir: bool,
    pub is_deleted: bool,
    pub is_carved: bool,
    pub is_system: bool,
    pub is_hidden: bool,
    pub created_utc: Option<String>,
    pub modified_utc: Option<String>,
    pub accessed_utc: Option<String>,
    pub mft_record: Option<u64>,
    pub md5: Option<String>,
    pub sha256: Option<String>,
    pub category: Option<String>,
    pub hash_flag: Option<String>, // "KnownBad" | "KnownGood" | "Notable"
    pub signature: Option<String>, // detected file signature (e.g. "PE Executable (MZ)")
}

#[derive(Debug, Clone, Default)]
pub struct EvidenceSource {
    pub id: String,
    pub path: String,
    pub format: String,
    pub sha256: Option<String>,
    pub hash_verified: bool,
    pub loaded_utc: String,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct Bookmark {
    pub id: String,
    pub file_id: Option<String>,
    pub registry_path: Option<String>,
    pub tag: String, // Notable|Relevant|Reviewed|Irrelevant|Suspicious|Exculpatory
    pub examiner: String,
    pub note: String,
    pub created_utc: String,
}

#[derive(Debug, Clone, Default)]
pub struct SearchHit {
    pub file_id: String,
    pub query: String,
    pub context: String,
    pub hit_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchMode {
    #[default]
    Metadata,
    FullText,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimelineEventType {
    FileCreated,
    FileModified,
    FileAccessed,
    FileMftModified,
    FileDeleted,
    RegistryKeyCreated,
    RegistryKeyModified,
    RegistryValueSet,
    ProcessExecuted,
    UserLogin,
    UserActivity,
    WebVisit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: TimelineEventType,
    pub path: String,
    pub evidence_id: String,
    pub detail: String,
    pub file_id: Option<String>,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceDiff {
    pub evidence_a_id: String,
    pub evidence_b_id: String,
    pub only_in_a: Vec<FileEntry>,
    pub only_in_b: Vec<FileEntry>,
    pub modified: Vec<(FileEntry, FileEntry)>,
    pub identical: Vec<FileEntry>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum CompareFilter {
    #[default]
    All,
    Added,
    Deleted,
    Modified,
    Identical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineFilterState {
    pub show_created: bool,
    pub show_modified: bool,
    pub show_accessed: bool,
    pub show_deleted: bool,
}

impl Default for TimelineFilterState {
    fn default() -> Self {
        Self {
            show_created: true,
            show_modified: true,
            show_accessed: true,
            show_deleted: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum ViewMode {
    #[default]
    FileExplorer,
    Artifacts,
    Bookmarks,
    Gallery,
    Compare,
    Timeline,
    Registry,
    EventLogs,
    BrowserHistory,
    Search,
    HashSets,
    AuditLog,
    Plugins,
    Settings,
    #[allow(dead_code)]
    Summary,
    #[allow(dead_code)]
    CsamReview,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum IndexingState {
    #[default]
    Idle,
    Running {
        files_found: u64,
    },
    Complete {
        file_count: u64,
    },
    Failed(String),
}

#[derive(Debug, Clone, Default)]
pub struct ActiveCase {
    pub name: String,
    pub id: String,
    pub agency: String,
    pub path: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HashSetListItem {
    pub name: String,
    pub category: String,
    pub source: String,
    pub entry_count: usize,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub last_updated: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTableState {
    pub scroll_offset: f32,
    pub selected_id: Option<String>,
    pub sort_col: usize,
    pub sort_asc: bool,
    pub sort_dirty: bool,
    pub filter: String,
    pub total_rows: usize,
    pub visible_start: usize,
    pub visible_end: usize,
    #[serde(default = "default_file_table_column_widths")]
    pub column_widths: Vec<f32>,
    #[serde(default = "default_visible_columns")]
    pub visible_columns: Vec<bool>,
    /// Multi-selected file IDs (Shift+Click range, Ctrl+Click toggle).
    #[serde(skip)]
    pub selected_ids: Vec<String>,
    /// Last clicked row index for Shift+Click range selection.
    #[serde(skip)]
    pub last_click_row: Option<usize>,
}

fn default_visible_columns() -> Vec<bool> {
    // NAME, SIZE, MODIFIED, CREATED, SHA-256, CATEGORY
    // Default: NAME=show, SIZE=show, MODIFIED=show, CREATED=hide, SHA-256=show, CATEGORY=show
    vec![true, true, true, false, true, true]
}

impl Default for FileTableState {
    fn default() -> Self {
        Self {
            scroll_offset: 0.0,
            selected_id: None,
            sort_col: 0,
            sort_asc: true,
            sort_dirty: true,
            filter: String::new(),
            total_rows: 0,
            visible_start: 0,
            visible_end: 0,
            column_widths: default_file_table_column_widths(),
            visible_columns: default_visible_columns(),
            selected_ids: Vec::new(),
            last_click_row: None,
        }
    }
}

fn default_file_table_column_widths() -> Vec<f32> {
    vec![280.0, 90.0, 160.0, 160.0, 200.0, 80.0]
}

// ─── Hex editor state ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct HexState {
    pub data: Vec<u8>,
    pub file_path: String,
    pub file_name: String,
    pub file_id: Option<String>,
    pub file_size: u64,
    pub window_offset: u64,
    pub cursor_byte: usize,
    pub scroll_offset: usize,
    pub load_error: bool,
    pub search_query: String,
    pub search_hits: Vec<usize>,
    pub search_hit_index: usize,
    pub search_match_len: usize,
    pub goto_offset_input: String,
}

#[derive(Debug, Clone)]
pub enum HexSearchMessage {
    Progress { scanned: u64, total: u64 },
    Done { hits: Vec<u64>, match_len: usize },
    Error(String),
}

pub const HEX_WINDOW_SIZE: usize = 256 * 1024;
pub const HEX_PAGE_SIZE: usize = 65_536;
pub const HEX_MAX_CACHED_PAGES: usize = 16;

#[derive(Debug, Clone)]
pub struct HexPage {
    pub file_id: String,
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum HexPageMessage {
    Loaded(HexPage),
    Error {
        file_id: String,
        offset: u64,
        error: String,
    },
}

impl HexState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn absolute_cursor_offset(&self) -> u64 {
        self.window_offset.saturating_add(self.cursor_byte as u64)
    }
}

/// Detect file type from magic bytes in the first 512 bytes.
pub fn detect_signature(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 2 {
        return None;
    }
    match bytes {
        [0x4D, 0x5A, ..] => Some("PE Executable (MZ)"),
        [0x50, 0x4B, 0x03, 0x04, ..] => Some("ZIP Archive"),
        [0x50, 0x4B, 0x05, 0x06, ..] => Some("ZIP Archive (empty)"),
        [0x25, 0x50, 0x44, 0x46, ..] => Some("PDF Document"),
        [0xFF, 0xD8, 0xFF, ..] => Some("JPEG Image"),
        [0x89, 0x50, 0x4E, 0x47, ..] => Some("PNG Image"),
        [0x47, 0x49, 0x46, 0x38, ..] => Some("GIF Image"),
        [0xD0, 0xCF, 0x11, 0xE0, ..] => Some("OLE2 Compound (Office/MSG)"),
        [0x52, 0x61, 0x72, 0x21, ..] => Some("RAR Archive"),
        [0x37, 0x7A, 0xBC, 0xAF, ..] => Some("7-Zip Archive"),
        [0x1F, 0x8B, ..] => Some("GZIP Compressed"),
        [0x42, 0x5A, 0x68, ..] => Some("BZip2 Compressed"),
        [0xEF, 0xBB, 0xBF, ..] => Some("UTF-8 Text (BOM)"),
        [0xFF, 0xFE, ..] => Some("UTF-16 LE Text (BOM)"),
        [0xFE, 0xFF, ..] => Some("UTF-16 BE Text (BOM)"),
        [0x7F, 0x45, 0x4C, 0x46, ..] => Some("ELF Binary"),
        [0xCA, 0xFE, 0xBA, 0xBE, ..] => Some("Mach-O Universal Binary"),
        [0xCF, 0xFA, 0xED, 0xFE, ..] => Some("Mach-O 64-bit Binary"),
        [0xCE, 0xFA, 0xED, 0xFE, ..] => Some("Mach-O 32-bit Binary"),
        [0x53, 0x51, 0x4C, 0x69, ..] => Some("SQLite Database"),
        [0x52, 0x65, 0x67, 0x66, ..] => Some("Windows Registry Hive"),
        [0x45, 0x56, 0x54, 0x58, ..] => Some("Windows Event Log (EVTX)"),
        [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, ..] => Some("Windows Shell Link (LNK)"),
        [0x00, 0x00, 0x01, 0x00, ..] => Some("Windows Icon (ICO)"),
        [0x49, 0x44, 0x33, ..] => Some("MP3 Audio (ID3)"),
        [0x66, 0x74, 0x79, 0x70, ..] if bytes.len() >= 8 => Some("MP4/MOV Container"),
        _ if bytes.len() >= 8 && &bytes[4..8] == b"ftyp" => Some("MP4/MOV Container"),
        _ if bytes
            .iter()
            .take(512.min(bytes.len()))
            .all(|b| b.is_ascii()) =>
        {
            Some("ASCII Text")
        }
        _ => None,
    }
}

// ─── Audit log ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AuditEntry {
    pub id: String,
    pub sequence: u64,
    pub timestamp_utc: String,
    pub examiner: String,
    pub action: String,
    pub detail: String,
    pub evidence_id: Option<String>,
    pub file_path: Option<String>,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone)]
pub enum ChainVerifyResult {
    Verified { count: usize },
    Broken { sequence: u64, detail: String },
}

// ─── Dialog state ─────────────────────────────────────────────────────────────

pub use crate::ui::dialogs::examiner_setup::ExaminerSetupDialog;

#[derive(Debug, Clone, Default)]
pub struct NewCaseDialog {
    pub open: bool,
    pub name: String,
    pub id: String,
    pub examiner: String,
    pub agency: String,
    pub save_path: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OpenEvidenceDialog {
    pub open: bool,
    pub path: String,
    pub format: Option<String>,
    pub error: Option<String>,
}

// ─── AppState ─────────────────────────────────────────────────────────────────

pub struct AppState {
    // ── Case ──
    pub case: Option<ActiveCase>,
    pub examiner_name: String,

    // ── Charges (Gov/Mil only) ──
    pub selected_charges: strata_charges::SelectedCharges,
    pub charge_highlight_map: strata_charges::ChargeHighlightMap,
    pub charge_search_query: String,
    pub charge_search_results: Vec<strata_charges::ChargeEntry>,
    pub charge_db: Option<strata_charges::ChargeDatabase>,

    // ── Executive Summary (ML-assisted) ──
    pub generated_summary: Option<strata_ml_summary::GeneratedSummary>,
    pub summary_generating: bool,

    // ── Evidence ──
    pub evidence_sources: Vec<EvidenceSource>,
    pub vfs_context: Option<std::sync::Arc<crate::evidence::vfs_context::VfsReadContext>>,
    pub file_index: Vec<FileEntry>,
    pub indexing_state: IndexingState,
    pub total_files_count: usize,
    pub hashed_files_count: usize,
    pub flagged_files_count: usize,
    pub deleted_files_count: usize,
    pub carved_files_count: usize,
    pub counters_dirty: bool,

    // ── Selection ──
    pub selected_file_id: Option<String>,
    pub selected_tree_path: Option<String>,
    pub pending_registry_nav: Option<String>,

    // ── Search ──
    pub search_query: String,
    pub search_results: Vec<SearchHit>,
    pub search_active: bool,
    pub search_mode: SearchMode,
    pub content_index_rx:
        Option<std::sync::mpsc::Receiver<crate::search::content::ContentIndexProgress>>,
    pub content_indexing_active: bool,
    pub content_index_progress: (u64, u64), // (processed, total)
    pub content_index_ready: bool,
    pub content_indexed_files: u64,
    pub content_search_hits: Vec<crate::search::content::ContentSearchHit>,
    pub content_index_error: Option<String>,
    pub timeline_entries: Vec<TimelineEntry>,
    pub timeline_filter: TimelineFilterState,
    pub timeline_query: String,
    pub timeline_from_utc: String,
    pub timeline_to_utc: String,
    pub timeline_rx: Option<std::sync::mpsc::Receiver<Vec<TimelineEntry>>>,
    pub suspicious_event_count: usize,
    pub compare_a_id: Option<String>,
    pub compare_b_id: Option<String>,
    pub compare_result: Option<EvidenceDiff>,
    pub compare_filter: CompareFilter,

    // ── Bookmarks ──
    pub bookmarks: Vec<Bookmark>,
    pub active_tag: String,
    pub examiner_note: String,

    // ── Hex editor ──
    pub hex: HexState,
    pub hex_search_rx: Option<std::sync::mpsc::Receiver<HexSearchMessage>>,
    pub hex_search_active: bool,
    pub hex_search_progress: (u64, u64), // (scanned, total)
    pub hex_search_hits_abs: Vec<u64>,
    pub hex_search_error: Option<String>,
    pub hex_page_tx: Option<std::sync::mpsc::Sender<HexPageMessage>>,
    pub hex_page_rx: Option<std::sync::mpsc::Receiver<HexPageMessage>>,
    pub hex_page_cache_file_id: Option<String>,
    pub hex_page_cache: VecDeque<HexPage>,
    pub hex_page_loading_offsets: HashSet<u64>,
    pub hex_pending_window_offset: Option<u64>,
    pub hex_pending_window_len: usize,
    pub hex_window_loading: bool,

    // ── View ──
    pub view_mode: ViewMode,
    pub preview_tab: u8,         // 0=Metadata 1=Hex 2=Text 3=Image
    pub theme_index: usize,      // index into theme::THEMES
    pub metadata_expanded: bool, // collapsible metadata strip below file table
    pub navigator_collapsed: bool,  // Ctrl+B toggle for 3-panel layout
    pub court_mode: bool,           // Ctrl+Shift+C — presentation-safe mode
    pub court_mode_prev_theme: Option<usize>, // theme to restore on exit

    // ── Sort ──
    pub sort_col: usize,
    pub sort_asc: bool,

    // ── Dialogs ──
    pub new_case_dlg: NewCaseDialog,
    pub open_ev_dlg: OpenEvidenceDialog,
    pub examiner_setup_dlg: ExaminerSetupDialog,
    pub show_carve_dialog: bool,
    pub show_advanced_search: bool,
    pub show_export_dialog: bool,

    // ── Settings panel tab ──
    pub settings_tab: u8, // 0=Appearance, 1=Examiner, 2=HashSets, 3=License, 4=About

    // ── Global search bar ──
    pub global_search_query: String,
    pub global_search_active: bool,
    pub global_search_results: Vec<usize>, // indices into file_index
    #[allow(dead_code)]
    pub global_search_tab: u8, // 0=Files, 1=Artifacts, 2=Bookmarks

    // ── Advanced search fields ──
    pub adv_search_filename: String,
    pub adv_search_extension: String,
    pub adv_search_min_size: String,
    pub adv_search_max_size: String,
    pub adv_search_date_after: String,
    pub adv_search_date_before: String,
    pub adv_search_category: String,
    pub adv_search_hash: String,
    pub adv_search_content: String,
    pub adv_search_deleted_only: bool,
    pub adv_search_hashed_only: bool,
    pub adv_search_flagged_only: bool,

    // ── Gallery filters ──
    pub gallery_ext_filter: String,
    pub gallery_min_size: u64,
    pub gallery_max_size: u64,

    // ── Artifact counts (populated by plugins) ──
    pub artifact_counts: std::collections::HashMap<String, usize>,
    pub artifact_total: usize,
    pub selected_artifact_idx: Option<usize>,
    pub plugin_results: Vec<strata_plugin_sdk::PluginOutput>,
    pub plugin_host: crate::plugin_host::PluginHost,

    // ── Activation flow ──
    pub show_splash: bool,
    pub splash_license_key: String,
    pub splash_error: String,

    // ── Case creation (enhanced) ──
    pub case_number: String,
    #[allow(dead_code)]
    pub case_classification: String,
    #[allow(dead_code)]
    pub case_requesting_agency: String,
    #[allow(dead_code)]
    pub case_date_received: String,
    #[allow(dead_code)]
    pub case_notes: String,

    // ── Evidence drive enforcement ──
    pub show_drive_selection: bool,
    pub available_drives: Vec<crate::ui::evidence_drive::DriveInfo>,
    pub selected_drive_index: Option<usize>,
    pub drive_block_message: String,
    pub evidence_drive_path: Option<std::path::PathBuf>,
    pub evidence_case_dir: Option<std::path::PathBuf>,

    // ── Export options ──
    pub export_files_csv: bool,
    pub export_bookmarks: bool,
    pub export_timeline: bool,
    pub export_audit_log: bool,
    pub export_hashes: bool,
    pub export_pdf_report: bool,

    // ── Audit log ──
    pub audit_log: Vec<AuditEntry>,

    // ── Status / error ──
    pub status: String,
    pub error: Option<String>,
    pub case_dirty: bool,
    pub last_auto_save_at: Option<std::time::Instant>,
    pub last_auto_save_utc: Option<String>,
    pub plugin_enabled: std::collections::HashMap<String, bool>,
    pub selected_plugin: Option<String>,
    pub license_state: crate::license_state::AppLicenseState,
    pub show_license_panel: bool,

    // ── Pending channel receiver (set by app.rs dispatcher) ──
    pub indexing_rx: Option<std::sync::mpsc::Receiver<IndexBatch>>,
    pub file_filter: String,
    pub file_table_state: FileTableState,
    pub filtered_file_indices: Vec<usize>,
    pub filter_dirty: bool,
    pub filter_last_edit: Option<std::time::Instant>,

    // ── Hash worker ──
    pub hashing_rx: Option<std::sync::mpsc::Receiver<crate::evidence::hasher::HashMessage>>,
    pub hashing_active: bool,
    pub hashing_progress: (u64, u64), // (completed, total)
    pub hash_set_manager: HashSetManager,
    pub hash_sets: Vec<HashSetListItem>,
    pub hash_set_status: String,

    // ── Carve worker ──
    pub carve_rx: Option<std::sync::mpsc::Receiver<crate::carve::engine::CarveProgress>>,
    pub carve_active: bool,
    pub carve_source_evidence_id: Option<String>,
    pub carve_target_evidence_id: Option<String>,
    pub carve_cancel_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub carve_progress_bytes: (u64, u64),
    pub carve_files_found: u64,
    pub carve_selected_signatures: std::collections::HashSet<String>,
    pub carve_output_dir: String,

    // ── CSAM Sentinel plugin state ──
    // All CSAM-specific fields live here. Methods are implemented
    // in `state_csam.rs` to keep this file from growing further.
    // The CSAM scanner is a sentinel plugin (free on all license
    // tiers); see plugins/strata-plugin-csam/src/lib.rs.
    //
    // **Audit chain note:** there is intentionally NO separate CSAM
    // audit log here. CSAM events are routed through the unified
    // case audit log via `self.log_action(...)` so they share one
    // chain (Decision 3 / Option i — unified chain in the case
    // `audit_log` SQLite table with `CSAM_*` action namespace).
    // The strata-csam crate's `CsamAuditLog` and `flush_to_sqlite`
    // helpers are still correct and tested but are used by the
    // strata-engine-adapter / Forge IPC layer, not here.
    pub csam_hash_dbs: Vec<strata_csam::CsamHashDb>,
    pub csam_hits: Vec<strata_csam::CsamHit>,
    pub csam_status: String,
    pub csam_scan_running: bool,
    pub csam_scan_config: strata_csam::ScanConfig,
    /// When `Some(hit_id)`, the UI shows the "you are about to view
    /// flagged content" warning modal. The hit_id identifies which
    /// hit triggered the request. Set by the [REVIEW] button.
    pub csam_pending_review: Option<String>,
    /// Per-hit examiner notes buffer (keyed by hit_id) — bound to
    /// the text box that feeds into `csam_confirm_hit`.
    pub csam_note_buffers: std::collections::HashMap<String, String>,

    // ── Obstruction Score ──
    pub obstruction_assessment: Option<strata_ml_obstruction::ObstructionAssessment>,
}

#[derive(Debug)]
pub enum IndexBatch {
    Files(Vec<FileEntry>),
    Done { total: u64, elapsed_ms: u64 },
    Error(String),
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            case: None,
            examiner_name: "Unidentified Examiner".to_string(),
            selected_charges: strata_charges::SelectedCharges::default(),
            charge_highlight_map: strata_charges::ChargeHighlightMap::default(),
            charge_search_query: String::new(),
            charge_search_results: Vec::new(),
            charge_db: None,
            generated_summary: None,
            summary_generating: false,
            evidence_sources: Vec::new(),
            vfs_context: None,
            file_index: Vec::new(),
            indexing_state: IndexingState::Idle,
            total_files_count: 0,
            hashed_files_count: 0,
            flagged_files_count: 0,
            deleted_files_count: 0,
            carved_files_count: 0,
            counters_dirty: true,
            selected_file_id: None,
            selected_tree_path: None,
            pending_registry_nav: None,
            search_query: String::new(),
            search_results: Vec::new(),
            search_active: false,
            search_mode: SearchMode::Metadata,
            content_index_rx: None,
            content_indexing_active: false,
            content_index_progress: (0, 0),
            content_index_ready: false,
            content_indexed_files: 0,
            content_search_hits: Vec::new(),
            content_index_error: None,
            timeline_entries: Vec::new(),
            timeline_filter: TimelineFilterState::default(),
            timeline_query: String::new(),
            timeline_from_utc: String::new(),
            timeline_to_utc: String::new(),
            timeline_rx: None,
            suspicious_event_count: 0,
            compare_a_id: None,
            compare_b_id: None,
            compare_result: None,
            compare_filter: CompareFilter::All,
            bookmarks: Vec::new(),
            active_tag: "NOTABLE".to_string(),
            examiner_note: String::new(),
            hex: HexState::new(),
            hex_search_rx: None,
            hex_search_active: false,
            hex_search_progress: (0, 0),
            hex_search_hits_abs: Vec::new(),
            hex_search_error: None,
            hex_page_tx: None,
            hex_page_rx: None,
            hex_page_cache_file_id: None,
            hex_page_cache: VecDeque::new(),
            hex_page_loading_offsets: HashSet::new(),
            hex_pending_window_offset: None,
            hex_pending_window_len: 0,
            hex_window_loading: false,
            view_mode: ViewMode::FileExplorer,
            preview_tab: 0,
            theme_index: crate::theme::load_theme_index(),
            metadata_expanded: false,
            navigator_collapsed: false,
            court_mode: false,
            court_mode_prev_theme: None,
            sort_col: 0,
            sort_asc: true,
            new_case_dlg: NewCaseDialog::default(),
            open_ev_dlg: OpenEvidenceDialog::default(),
            examiner_setup_dlg: ExaminerSetupDialog {
                is_open: true,
                timezone: "UTC".to_string(),
                ..Default::default()
            },
            show_carve_dialog: false,
            settings_tab: 0,
            show_advanced_search: false,
            global_search_query: String::new(),
            global_search_active: false,
            global_search_results: Vec::new(),
            global_search_tab: 0,
            show_export_dialog: false,
            adv_search_filename: String::new(),
            adv_search_extension: String::new(),
            adv_search_min_size: String::new(),
            adv_search_max_size: String::new(),
            adv_search_date_after: String::new(),
            adv_search_date_before: String::new(),
            adv_search_category: String::new(),
            adv_search_hash: String::new(),
            adv_search_content: String::new(),
            adv_search_deleted_only: false,
            adv_search_hashed_only: false,
            adv_search_flagged_only: false,
            gallery_ext_filter: String::new(),
            gallery_min_size: 0,
            gallery_max_size: 0,
            artifact_counts: std::collections::HashMap::new(),
            artifact_total: 0,
            selected_artifact_idx: None,
            plugin_results: Vec::new(),
            plugin_host: crate::plugin_host::PluginHost::new(),
            show_splash: false, // Set to true in app.rs if no valid license
            splash_license_key: String::new(),
            splash_error: String::new(),
            case_number: String::new(),
            case_classification: "Unclassified".to_string(),
            case_requesting_agency: String::new(),
            case_date_received: String::new(),
            case_notes: String::new(),
            show_drive_selection: false,
            available_drives: Vec::new(),
            selected_drive_index: None,
            drive_block_message: String::new(),
            evidence_drive_path: None,
            evidence_case_dir: None,
            export_files_csv: true,
            export_bookmarks: true,
            export_timeline: true,
            export_audit_log: true,
            export_hashes: true,
            export_pdf_report: true,
            audit_log: Vec::new(),
            status: "Ready".to_string(),
            error: None,
            case_dirty: false,
            last_auto_save_at: None,
            last_auto_save_utc: None,
            plugin_enabled: std::collections::HashMap::new(),
            selected_plugin: None,
            license_state: crate::license_state::AppLicenseState::load(),
            show_license_panel: false,
            indexing_rx: None,
            file_filter: String::new(),
            file_table_state: FileTableState::default(),
            filtered_file_indices: Vec::new(),
            filter_dirty: true,
            filter_last_edit: None,
            hashing_rx: None,
            hashing_active: false,
            hashing_progress: (0, 0),
            hash_set_manager: HashSetManager::new(),
            hash_sets: Vec::new(),
            hash_set_status: String::new(),
            carve_rx: None,
            carve_active: false,
            carve_source_evidence_id: None,
            carve_target_evidence_id: None,
            carve_cancel_flag: None,
            carve_progress_bytes: (0, 0),
            carve_files_found: 0,
            carve_selected_signatures: std::collections::HashSet::new(),
            carve_output_dir: String::new(), // Set from evidence path when dialog opens

            // ── CSAM Sentinel plugin defaults ──
            csam_hash_dbs: Vec::new(),
            csam_hits: Vec::new(),
            csam_status: String::new(),
            csam_scan_running: false,
            csam_scan_config: strata_csam::ScanConfig::default(),
            csam_pending_review: None,
            csam_note_buffers: std::collections::HashMap::new(),
            obstruction_assessment: None,
        }
    }
}

impl AppState {
    pub fn has_feature(&self, feature: &str) -> bool {
        self.license_state.has_feature(feature)
    }

    /// Returns true if the current license tier includes charge tracking.
    /// Gov/Mil (.gov/.mil Free tier) always has access; commercial tiers
    /// do not.
    pub fn charges_available(&self) -> bool {
        self.license_state.has_feature("charges")
    }

    /// Add a charge to the current case and recalculate highlights.
    pub fn add_charge(&mut self, charge: strata_charges::ChargeEntry) {
        if self
            .selected_charges
            .charges
            .iter()
            .any(|c| c.citation == charge.citation)
        {
            return;
        }
        self.selected_charges.charges.push(charge);
        self.selected_charges.selected_at =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        self.charge_highlight_map =
            strata_charges::ChargeHighlightMap::from_selected(&self.selected_charges.charges);
    }

    /// Remove a charge from the current case by citation and recalculate highlights.
    pub fn remove_charge(&mut self, citation: &str) {
        self.selected_charges
            .charges
            .retain(|c| c.citation != citation);
        self.selected_charges.selected_at =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        self.charge_highlight_map =
            strata_charges::ChargeHighlightMap::from_selected(&self.selected_charges.charges);
    }

    /// Initialize the charge database (call once at startup).
    pub fn init_charge_db(&mut self) {
        if self.charge_db.is_some() {
            return;
        }
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let db_dir = std::path::PathBuf::from(home)
            .join(".strata")
            .join("charges");
        let _ = std::fs::create_dir_all(&db_dir);
        let db_path = db_dir.join("federal.db");
        match strata_charges::ChargeDatabase::open(&db_path) {
            Ok(db) => {
                self.charge_db = Some(db);
            }
            Err(e) => {
                tracing::error!("Failed to open charge database: {}", e);
            }
        }
    }

    /// Approve the current generated summary for report inclusion.
    pub fn approve_summary(&mut self) {
        if let Some(ref mut summary) = self.generated_summary {
            summary.examiner_approved = true;
            summary.status = strata_ml_summary::SummaryStatus::Approved;
        }
    }

    /// Reject the current summary — it will not be included in reports.
    pub fn reject_summary(&mut self) {
        if let Some(ref mut summary) = self.generated_summary {
            summary.examiner_approved = false;
            summary.status = strata_ml_summary::SummaryStatus::Rejected;
        }
    }

    /// Edit a summary section, revoking approval and tracking the change.
    #[allow(dead_code)]
    pub fn update_summary_section(
        &mut self,
        section_type: strata_ml_summary::SectionType,
        new_text: String,
        reason: Option<String>,
    ) {
        let Some(ref mut summary) = self.generated_summary else {
            return;
        };
        let Some(section) = summary
            .sections
            .iter_mut()
            .find(|s| s.section_type == section_type)
        else {
            return;
        };
        if !section.is_editable {
            return;
        }
        let original = section.content.clone();
        section.content = new_text.clone();
        summary.examiner_edits.push(strata_ml_summary::ExaminerEdit {
            section_type,
            original_text: original,
            edited_text: new_text,
            edited_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            edit_reason: reason,
        });
        summary.examiner_approved = false;
        summary.status = strata_ml_summary::SummaryStatus::UnderReview;
    }

    /// Toggle court-mode. Switches to Ash theme, collapses navigator,
    /// hides CSAM. Does NOT change analysis state.
    pub fn toggle_court_mode(&mut self) {
        if self.court_mode {
            // Restore
            if let Some(prev) = self.court_mode_prev_theme.take() {
                self.theme_index = prev;
            }
            self.court_mode = false;
        } else {
            // Engage
            self.court_mode_prev_theme = Some(self.theme_index);
            self.theme_index = 4; // Ash (light theme)
            self.navigator_collapsed = true;
            // If on CsamReview, switch away
            if matches!(self.view_mode, ViewMode::CsamReview) {
                self.view_mode = ViewMode::FileExplorer;
            }
            self.court_mode = true;
        }
        self.log_action(
            "COURT_MODE",
            if self.court_mode { "enabled" } else { "disabled" },
        );
    }

    pub fn refresh_license_state(&mut self) {
        self.license_state = crate::license_state::AppLicenseState::load();
    }

    /// Current theme.
    pub fn theme(&self) -> &crate::theme::StrataTheme {
        // Iron Wolf is always the active render theme. Theme selector stores
        // preference but does not change rendering until theme switching is
        // fully implemented and tested across all panels.
        &crate::theme::THEMES[0] // Iron Wolf
    }

    /// Switch theme and save.
    pub fn set_theme(&mut self, index: usize) {
        self.theme_index = index.min(crate::theme::THEMES.len().saturating_sub(1));
        crate::theme::save_theme_index(self.theme_index);
    }

    pub fn rebuild_vfs_context(&mut self) {
        self.vfs_context = Some(std::sync::Arc::new(
            crate::evidence::vfs_context::VfsReadContext::from_sources(&self.evidence_sources),
        ));
    }

    pub fn log_action(&mut self, action: &str, detail: &str) {
        self.ensure_audit_genesis();

        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let sequence = self.audit_log.len() as u64;
        let prev_hash = self
            .audit_log
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let entry_hash = compute_audit_entry_hash(
            sequence,
            &now,
            &self.examiner_name,
            action,
            detail,
            None,
            &prev_hash,
        );

        self.audit_log.push(AuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            sequence,
            timestamp_utc: now,
            examiner: self.examiner_name.clone(),
            action: action.to_string(),
            detail: detail.to_string(),
            evidence_id: None,
            file_path: None,
            prev_hash,
            entry_hash,
        });
        self.status = format!("{}: {}", action, detail);

        if let Some(case_path) = self.case.as_ref().map(|c| c.path.clone()) {
            if !case_path.is_empty() {
                if let Ok(project) = crate::case::project::VtpProject::open(&case_path) {
                    let _ = project.save_audit_log(&self.audit_log);
                }
            }
        }
    }

    /// Run a plugin by name on the current evidence and store results.
    pub fn run_plugin(&mut self, plugin_name: &str) {
        let root_path = self
            .evidence_sources
            .first()
            .map(|s| s.path.clone())
            .unwrap_or_default();

        if root_path.is_empty() {
            self.status = "No evidence loaded — cannot run plugin.".to_string();
            return;
        }

        // ── License-tier gating ──────────────────────────────────────
        // A plugin runs iff the user's current tier is at least the
        // plugin's `required_tier()`. The CSAM Sentinel plugin returns
        // `PluginTier::Free`, which every license tier satisfies, so
        // it is never blocked here. Conventional analyzer/carver
        // plugins default to `Professional` and are only allowed for
        // Pro/Enterprise users when feature gating ships. Today
        // `has_feature("plugins")` is hard-coded to true during dev,
        // so the gate is informational — but the comparison is the
        // forge-resistant form that survives feature-flag flips.
        let user_tier = self.license_state.current_plugin_tier();
        let required_tier = self
            .plugin_host
            .list()
            .iter()
            .find(|p| p.name() == plugin_name)
            .map(|p| p.required_tier());

        if let Some(required) = required_tier {
            if user_tier < required {
                self.status = format!(
                    "{} requires {} tier (you have {}).",
                    plugin_name,
                    required.as_str(),
                    user_tier.as_str()
                );
                // Do NOT write a PLUGIN_START audit row here — the
                // run is rejected before any side effect lands.
                return;
            }
        }

        let context = strata_plugin_sdk::PluginContext {
            root_path,
            vfs: None,
            config: std::collections::HashMap::new(),
            prior_results: self.plugin_results.clone(),
        };

        self.log_action(
            "PLUGIN_START",
            &format!("{} starting on evidence", plugin_name),
        );

        match self.plugin_host.run_plugin(plugin_name, context) {
            Ok(output) => {
                let artifact_count = output.artifacts.len();
                let suspicious_count = output.artifacts.iter().filter(|a| a.is_suspicious).count();

                // Update artifact counts from this plugin's results
                for record in &output.artifacts {
                    let cat = record.category.as_str().to_string();
                    *self.artifact_counts.entry(cat).or_insert(0) += 1;
                    let sub = record.subcategory.clone();
                    *self.artifact_counts.entry(sub).or_insert(0) += 1;
                }
                self.artifact_total += artifact_count;

                self.log_action(
                    "PLUGIN_COMPLETE",
                    &format!(
                        "{} — {} artifacts, {} suspicious",
                        plugin_name, artifact_count, suspicious_count
                    ),
                );

                self.status = format!(
                    "{}: {} artifacts ({} suspicious)",
                    plugin_name, artifact_count, suspicious_count
                );

                self.plugin_results.push(output);
            }
            Err(e) => {
                self.log_action(
                    "PLUGIN_ERROR",
                    &format!("{} — {}", plugin_name, e),
                );
                self.status = format!("Plugin error: {} — {}", plugin_name, e);
            }
        }
    }

    pub fn mark_case_dirty(&mut self) {
        self.case_dirty = true;
    }

    pub fn mark_counters_dirty(&mut self) {
        self.counters_dirty = true;
    }

    pub fn refresh_running_counters(&mut self) {
        if !self.counters_dirty {
            return;
        }

        let mut total_files = 0usize;
        let mut hashed = 0usize;
        let mut flagged = 0usize;
        let mut deleted = 0usize;
        let mut carved = 0usize;

        for f in &self.file_index {
            if f.is_dir {
                continue;
            }
            total_files = total_files.saturating_add(1);
            if f.sha256.is_some() || f.md5.is_some() {
                hashed = hashed.saturating_add(1);
            }
            if f.hash_flag.as_deref() == Some("KnownBad") {
                flagged = flagged.saturating_add(1);
            }
            if f.is_deleted {
                deleted = deleted.saturating_add(1);
            }
            if f.is_carved {
                carved = carved.saturating_add(1);
            }
        }

        self.total_files_count = total_files;
        self.hashed_files_count = hashed;
        self.flagged_files_count = flagged;
        self.deleted_files_count = deleted;
        self.carved_files_count = carved;
        self.counters_dirty = false;
    }

    pub fn content_index_dir(&self) -> Option<std::path::PathBuf> {
        let case_path = self.case.as_ref().map(|c| c.path.clone())?;
        if case_path.trim().is_empty() {
            return None;
        }
        Some(crate::search::content::ContentIndexer::index_dir_for_case(
            std::path::Path::new(&case_path),
        ))
    }

    pub fn start_content_indexing(&mut self) -> Result<(), String> {
        if self.content_indexing_active {
            return Err("Content indexing already running".to_string());
        }
        if self.file_index.is_empty() {
            return Err("No indexed files available".to_string());
        }
        let Some(index_dir) = self.content_index_dir() else {
            return Err("Open or create a case before content indexing".to_string());
        };

        let files: Vec<FileEntry> = self
            .file_index
            .iter()
            .filter(|f| !f.is_dir)
            .cloned()
            .collect();
        let total = files.len() as u64;
        if total == 0 {
            return Err("No files available for indexing".to_string());
        }

        let ctx = self.vfs_context.clone();
        let (tx, rx) = std::sync::mpsc::channel::<crate::search::content::ContentIndexProgress>();
        std::thread::spawn(move || {
            let indexer = crate::search::content::ContentIndexer::new(index_dir);
            let tx_done = tx.clone();
            let result = indexer.build_index(&files, ctx.as_deref(), Some(tx));
            if let Err(err) = result {
                let _ = tx_done.send(crate::search::content::ContentIndexProgress::Failed(
                    err.to_string(),
                ));
            }
        });

        self.content_index_rx = Some(rx);
        self.content_indexing_active = true;
        self.content_index_progress = (0, total);
        self.content_index_ready = false;
        self.content_indexed_files = 0;
        self.content_index_error = None;
        self.status = format!("Content indexing started: {} files queued", total);
        self.log_action("CONTENT_INDEX_START", &format!("files={}", total));
        Ok(())
    }

    pub fn run_content_search(&mut self) -> Result<(), String> {
        let query = self.search_query.trim().to_string();
        if query.is_empty() {
            self.search_results.clear();
            self.content_search_hits.clear();
            self.search_active = false;
            self.persist_search_results();
            return Ok(());
        }

        let Some(index_dir) = self.content_index_dir() else {
            return Err("No case index directory available".to_string());
        };
        let indexer = crate::search::content::ContentIndexer::new(index_dir);
        let hits = indexer
            .search(&query, 500)
            .map_err(|e| format!("Content search failed: {}", e))?;

        self.search_results = hits
            .iter()
            .map(|h| SearchHit {
                file_id: h.file_id.clone(),
                query: query.clone(),
                context: format!("score={:.3} {}", h.score, h.file_path),
                hit_type: "content".to_string(),
            })
            .collect();
        self.content_search_hits = hits;
        self.search_active = true;
        self.log_action(
            "CONTENT_SEARCH",
            &format!("query='{}' results={}", query, self.search_results.len()),
        );
        self.persist_search_results();
        Ok(())
    }

    pub fn persist_search_results(&mut self) {
        let Some(case_path) = self.case.as_ref().map(|c| c.path.clone()) else {
            return;
        };
        if case_path.trim().is_empty() {
            return;
        }
        if let Ok(project) = crate::case::project::VtpProject::open(&case_path) {
            let _ = project.save_search_results(&self.search_results);
        }
    }

    pub fn maybe_auto_save_case(&mut self) {
        if !self.case_dirty {
            return;
        }
        let should_save = match self.last_auto_save_at {
            Some(t) => t.elapsed() >= std::time::Duration::from_secs(300),
            None => true,
        };
        if !should_save {
            return;
        }
        let _ = self.persist_case_snapshot();
    }

    pub fn persist_case_snapshot(&mut self) -> Result<(), String> {
        let Some(case_path) = self.case.as_ref().map(|c| c.path.clone()) else {
            return Err("No case open".to_string());
        };
        if case_path.is_empty() {
            return Err("No case path".to_string());
        }

        let case_path_buf = std::path::PathBuf::from(&case_path);
        self.ensure_output_path_safe(case_path_buf.as_path())?;
        if case_path_buf.exists() {
            let bak_path = std::path::PathBuf::from(format!("{}.bak", case_path));
            self.ensure_output_path_safe(bak_path.as_path())?;
            let _ = std::fs::copy(&case_path_buf, &bak_path);
        }

        let project = crate::case::project::VtpProject::open(&case_path)
            .map_err(|e| format!("open case failed: {}", e))?;
        project
            .save_evidence_sources(&self.evidence_sources)
            .map_err(|e| format!("save evidence failed: {}", e))?;
        project
            .save_file_index(&self.file_index)
            .map_err(|e| format!("save file index failed: {}", e))?;
        project
            .save_bookmarks(&self.bookmarks)
            .map_err(|e| format!("save bookmarks failed: {}", e))?;
        project
            .save_audit_log(&self.audit_log)
            .map_err(|e| format!("save audit failed: {}", e))?;
        project
            .save_search_results(&self.search_results)
            .map_err(|e| format!("save search results failed: {}", e))?;

        if let Ok(timeline_json) = serde_json::to_string(&self.timeline_entries) {
            let _ = project.set_meta("timeline_entries_json", &timeline_json);
        }
        let _ = project.save_timeline_entries(&self.timeline_entries);
        if let Some(compare) = &self.compare_result {
            let _ = project.save_compare_result(
                self.compare_a_id.as_deref(),
                self.compare_b_id.as_deref(),
                Some(compare),
            );
        } else {
            let _ = project.save_compare_result(
                self.compare_a_id.as_deref(),
                self.compare_b_id.as_deref(),
                None,
            );
        }
        if let Ok(hash_sets_json) = serde_json::to_string(&self.hash_sets) {
            let _ = project.set_meta("hash_sets_json", &hash_sets_json);
        }
        let _ = project.save_hash_sets(&self.hash_sets);
        let _ = project.save_hash_set_refs(&self.hash_sets);
        if let Ok(table_state_json) = serde_json::to_string(&self.file_table_state) {
            let _ = project.set_meta("file_table_state_json", &table_state_json);
            let _ = project.set_ui_pref("file_table_state_json", &table_state_json);
        }
        if let Some(compare) = &self.compare_result {
            if let Ok(compare_json) = serde_json::to_string(compare) {
                let _ = project.set_meta("compare_result_json", &compare_json);
            }
        }
        if let Some(a) = &self.compare_a_id {
            let _ = project.set_meta("compare_a_id", a);
            let _ = project.set_ui_pref("compare_a_id", a);
        }
        if let Some(b) = &self.compare_b_id {
            let _ = project.set_meta("compare_b_id", b);
            let _ = project.set_ui_pref("compare_b_id", b);
        }
        if let Ok(filter_json) = serde_json::to_string(&self.timeline_filter) {
            let _ = project.set_meta("timeline_filter_json", &filter_json);
            let _ = project.set_ui_pref("timeline_filter_json", &filter_json);
        }
        let _ = project.set_meta("timeline_query", &self.timeline_query);
        let _ = project.set_ui_pref("timeline_query", &self.timeline_query);
        let _ = project.set_meta("timeline_from_utc", &self.timeline_from_utc);
        let _ = project.set_ui_pref("timeline_from_utc", &self.timeline_from_utc);
        let _ = project.set_meta("timeline_to_utc", &self.timeline_to_utc);
        let _ = project.set_ui_pref("timeline_to_utc", &self.timeline_to_utc);
        let _ = project.set_meta("file_filter", &self.file_filter);
        let _ = project.set_ui_pref("file_filter", &self.file_filter);
        let _ = project.set_meta(
            "view_mode",
            match self.view_mode {
                ViewMode::FileExplorer => "file_explorer",
                ViewMode::Bookmarks => "bookmarks",
                ViewMode::Gallery => "gallery",
                ViewMode::Compare => "compare",
                ViewMode::Timeline => "timeline",
                ViewMode::Registry => "registry",
                ViewMode::EventLogs => "event_logs",
                ViewMode::BrowserHistory => "browser_history",
                ViewMode::Search => "search",
                ViewMode::HashSets => "hash_sets",
                ViewMode::AuditLog => "audit_log",
                ViewMode::Plugins => "plugins",
                ViewMode::Artifacts => "artifacts",
                ViewMode::Settings => "settings",
                ViewMode::Summary => "summary",
                ViewMode::CsamReview => "csam_review",
            },
        );
        let _ = project.set_ui_pref(
            "view_mode",
            match self.view_mode {
                ViewMode::FileExplorer => "file_explorer",
                ViewMode::Bookmarks => "bookmarks",
                ViewMode::Gallery => "gallery",
                ViewMode::Compare => "compare",
                ViewMode::Timeline => "timeline",
                ViewMode::Registry => "registry",
                ViewMode::EventLogs => "event_logs",
                ViewMode::BrowserHistory => "browser_history",
                ViewMode::Search => "search",
                ViewMode::HashSets => "hash_sets",
                ViewMode::AuditLog => "audit_log",
                ViewMode::Plugins => "plugins",
                ViewMode::Artifacts => "artifacts",
                ViewMode::Settings => "settings",
                ViewMode::Summary => "summary",
                ViewMode::CsamReview => "csam_review",
            },
        );
        if let Some(selected_file_id) = &self.selected_file_id {
            let _ = project.set_meta("last_selected_file_id", selected_file_id);
            let _ = project.set_ui_pref("last_selected_file_id", selected_file_id);
        }
        if let Some(selected_tree_path) = &self.selected_tree_path {
            let _ = project.set_meta("last_selected_tree_path", selected_tree_path);
            let _ = project.set_ui_pref("last_selected_tree_path", selected_tree_path);
        }
        let _ = project.set_meta("timeline_rebuild_required", "0");
        if let Ok(plugin_enabled_json) = serde_json::to_string(&self.plugin_enabled) {
            let _ = project.set_meta("plugin_enabled_json", &plugin_enabled_json);
        }
        let default_db = std::path::PathBuf::from(&case_path)
            .parent()
            .map(|p| p.join("strata_index.db"))
            .unwrap_or_else(|| std::path::PathBuf::from("strata_index.db"));
        let _ = project.set_meta("database_path", &default_db.to_string_lossy());
        let _ = project.set_meta("tool_version", env!("CARGO_PKG_VERSION"));
        let _ = project.set_meta("examiner", &self.examiner_name);
        if let Some(case) = &self.case {
            if !case.agency.trim().is_empty() {
                let _ = project.set_meta("agency", &case.agency);
            }
        }
        let _ = project.set_meta("active_tag", &self.active_tag);
        let _ = project.set_ui_pref("active_tag", &self.active_tag);
        let _ = project.set_meta("examiner_note", &self.examiner_note);
        let _ = project.set_ui_pref("examiner_note", &self.examiner_note);
        let _ = project.set_meta("preview_tab", &self.preview_tab.to_string());
        let _ = project.set_ui_pref("preview_tab", &self.preview_tab.to_string());
        if let Some(selected_plugin) = &self.selected_plugin {
            let _ = project.set_meta("selected_plugin", selected_plugin);
            let _ = project.set_ui_pref("selected_plugin", selected_plugin);
        }

        let integrity_hash = project
            .compute_integrity_hash()
            .map_err(|e| format!("compute integrity hash failed: {}", e))?;
        project
            .set_meta("case_integrity_hash", &integrity_hash)
            .map_err(|e| format!("save integrity hash failed: {}", e))?;

        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        self.last_auto_save_at = Some(std::time::Instant::now());
        self.last_auto_save_utc = Some(now);
        self.case_dirty = false;
        Ok(())
    }

    pub fn compute_case_integrity_hash(&self) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();

        hasher.update(format!("evidence_count={}\n", self.evidence_sources.len()).as_bytes());
        for e in &self.evidence_sources {
            hasher.update(e.id.as_bytes());
            hasher.update(e.path.as_bytes());
            hasher.update(e.format.as_bytes());
            hasher.update(e.sha256.as_deref().unwrap_or("").as_bytes());
            hasher.update(format!("{}{}\n", e.hash_verified as u8, e.loaded_utc).as_bytes());
        }

        hasher.update(format!("file_count={}\n", self.file_index.len()).as_bytes());
        for f in &self.file_index {
            hasher.update(f.id.as_bytes());
            hasher.update(f.evidence_id.as_bytes());
            hasher.update(f.path.as_bytes());
            hasher.update(f.parent_path.as_bytes());
            hasher.update(f.name.as_bytes());
            hasher.update(f.sha256.as_deref().unwrap_or("").as_bytes());
            hasher.update(f.md5.as_deref().unwrap_or("").as_bytes());
            hasher.update(f.modified_utc.as_deref().unwrap_or("").as_bytes());
            hasher.update(
                format!(
                    "{}{}{}\n",
                    f.is_deleted as u8, f.is_carved as u8, f.is_dir as u8
                )
                .as_bytes(),
            );
        }

        hasher.update(format!("bookmark_count={}\n", self.bookmarks.len()).as_bytes());
        for b in &self.bookmarks {
            hasher.update(b.id.as_bytes());
            hasher.update(b.file_id.as_deref().unwrap_or("").as_bytes());
            hasher.update(b.registry_path.as_deref().unwrap_or("").as_bytes());
            hasher.update(b.tag.as_bytes());
            hasher.update(b.examiner.as_bytes());
            hasher.update(b.note.as_bytes());
            hasher.update(b.created_utc.as_bytes());
        }

        hasher.update(format!("audit_count={}\n", self.audit_log.len()).as_bytes());
        for a in &self.audit_log {
            hasher.update(a.id.as_bytes());
            hasher.update(format!("{}\n", a.sequence).as_bytes());
            hasher.update(a.timestamp_utc.as_bytes());
            hasher.update(a.examiner.as_bytes());
            hasher.update(a.action.as_bytes());
            hasher.update(a.detail.as_bytes());
            hasher.update(a.evidence_id.as_deref().unwrap_or("").as_bytes());
            hasher.update(a.file_path.as_deref().unwrap_or("").as_bytes());
            hasher.update(a.prev_hash.as_bytes());
            hasher.update(a.entry_hash.as_bytes());
        }

        hasher.update(format!("timeline_count={}\n", self.timeline_entries.len()).as_bytes());
        for t in &self.timeline_entries {
            hasher.update(
                t.timestamp
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                    .as_bytes(),
            );
            hasher.update(format!("{:?}", t.event_type).as_bytes());
            hasher.update(t.path.as_bytes());
            hasher.update(t.evidence_id.as_bytes());
            hasher.update(t.detail.as_bytes());
            hasher.update(t.file_id.as_deref().unwrap_or("").as_bytes());
            hasher.update(format!("{}\n", t.suspicious as u8).as_bytes());
        }

        hasher.update(format!("hash_set_count={}\n", self.hash_sets.len()).as_bytes());
        for hs in &self.hash_sets {
            hasher.update(hs.name.as_bytes());
            hasher.update(hs.category.as_bytes());
            hasher.update(hs.source.as_bytes());
            hasher.update(format!("{}\n", hs.entry_count).as_bytes());
        }

        hasher.update(self.file_filter.as_bytes());
        hasher.update(self.timeline_query.as_bytes());
        hasher.update(self.timeline_from_utc.as_bytes());
        hasher.update(self.timeline_to_utc.as_bytes());
        hasher.update(format!("{}|{}", self.sort_col, self.sort_asc as u8).as_bytes());
        hasher.update(self.active_tag.as_bytes());
        hasher.update(self.examiner_note.as_bytes());
        hasher.update(format!("{}\n", self.preview_tab).as_bytes());

        format!("{:x}", hasher.finalize())
    }

    pub fn recompute_hash_flags(&mut self) {
        for file in &mut self.file_index {
            let mut flag = None;
            if let Some(sha) = &file.sha256 {
                flag = match self.hash_set_manager.lookup(sha) {
                    crate::hash::hashset::HashMatch::KnownBad => Some("KnownBad".to_string()),
                    crate::hash::hashset::HashMatch::KnownGood => Some("KnownGood".to_string()),
                    crate::hash::hashset::HashMatch::Notable => Some("Notable".to_string()),
                    crate::hash::hashset::HashMatch::Unknown => None,
                };
            }
            if flag.is_none() {
                if let Some(md5) = &file.md5 {
                    flag = match self.hash_set_manager.lookup(md5) {
                        crate::hash::hashset::HashMatch::KnownBad => Some("KnownBad".to_string()),
                        crate::hash::hashset::HashMatch::KnownGood => Some("KnownGood".to_string()),
                        crate::hash::hashset::HashMatch::Notable => Some("Notable".to_string()),
                        crate::hash::hashset::HashMatch::Unknown => None,
                    };
                }
            }
            file.hash_flag = flag;
        }
        self.mark_counters_dirty();
    }

    fn ensure_audit_genesis(&mut self) {
        if !self.audit_log.is_empty() {
            return;
        }
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let detail = format!("Case initialized by {} on {}", self.examiner_name, now);
        let prev_hash = "0".repeat(64);
        let entry_hash = compute_audit_entry_hash(
            0,
            &now,
            &self.examiner_name,
            "CASE_CREATED",
            &detail,
            None,
            &prev_hash,
        );

        self.audit_log.push(AuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            sequence: 0,
            timestamp_utc: now,
            examiner: self.examiner_name.clone(),
            action: "CASE_CREATED".to_string(),
            detail,
            evidence_id: None,
            file_path: None,
            prev_hash,
            entry_hash,
        });
    }

    pub fn selected_file(&self) -> Option<&FileEntry> {
        let id = self.selected_file_id.as_deref()?;
        self.file_index.iter().find(|f| f.id == id)
    }

    pub fn ensure_output_path_safe(&self, output_path: &std::path::Path) -> Result<(), String> {
        if self.is_path_within_evidence(output_path) {
            return Err(format!(
                "Refusing write under evidence path: {}",
                output_path.display()
            ));
        }
        Ok(())
    }

    pub fn is_path_within_evidence(&self, output_path: &std::path::Path) -> bool {
        let Some(target_norm) = normalize_path_for_guard(output_path) else {
            return false;
        };

        for source in &self.evidence_sources {
            let source_path = std::path::Path::new(&source.path);
            let Some(source_norm) = normalize_path_for_guard(source_path) else {
                continue;
            };
            if target_norm == source_norm {
                return true;
            }
            let prefix = format!("{}/", source_norm.trim_end_matches('/'));
            if target_norm.starts_with(&prefix) {
                return true;
            }
        }
        false
    }

    pub fn load_hex_for_file(&mut self, file_id: &str) {
        self.hex_search_hits_abs.clear();
        self.hex_search_progress = (0, 0);
        self.hex_search_active = false;
        self.hex_search_error = None;
        self.hex_search_rx = None;
        self.load_hex_window(file_id, 0);
    }

    pub fn load_hex_window(&mut self, file_id: &str, offset: u64) {
        let entry = self.file_index.iter().find(|f| f.id == file_id).cloned();
        let Some(entry) = entry else {
            return;
        };
        self.begin_hex_window_load(&entry, offset);
    }

    pub fn seek_hex_offset(&mut self, absolute_offset: u64) {
        let Some(file_id) = self.hex.file_id.clone() else {
            return;
        };
        let window_start = self.hex.window_offset;
        let window_end = window_start.saturating_add(self.hex.data.len() as u64);
        if absolute_offset >= window_start && absolute_offset < window_end {
            let relative = absolute_offset.saturating_sub(window_start);
            self.hex.cursor_byte = usize::try_from(relative).unwrap_or(usize::MAX);
            self.queue_hex_prefetch_for_cursor();
            return;
        }

        let window_len = HEX_WINDOW_SIZE as u64;
        let aligned = (absolute_offset / 16).saturating_mul(16);
        let new_start = aligned.saturating_sub(window_len / 2);
        self.load_hex_window(&file_id, new_start);
        if absolute_offset >= self.hex.window_offset {
            let desired_u64 = absolute_offset.saturating_sub(self.hex.window_offset);
            let desired = usize::try_from(desired_u64).unwrap_or(usize::MAX);
            self.hex.cursor_byte = desired.min(self.hex.data.len().saturating_sub(1));
        }
    }

    fn begin_hex_window_load(&mut self, entry: &FileEntry, offset: u64) {
        let file_size = if let Some(size) = entry.size {
            size
        } else if let Some(ctx) = self.vfs_context.as_deref() {
            ctx.file_size(entry).unwrap_or(0)
        } else {
            0
        };
        let bounded = if file_size > 0 {
            offset.min(file_size.saturating_sub(1))
        } else {
            offset
        };
        let page_size = HEX_PAGE_SIZE as u64;
        let aligned = (bounded / page_size).saturating_mul(page_size);
        let window_len = hex_window_len(file_size, aligned);

        self.hex.file_path = entry.path.clone();
        self.hex.file_name = entry.name.clone();
        self.hex.file_id = Some(entry.id.clone());
        self.hex.file_size = file_size;
        self.hex.window_offset = aligned;
        self.hex.scroll_offset = 0;
        self.hex.load_error = false;
        self.hex.data.clear();
        self.hex.search_hits.clear();
        self.hex.search_hit_index = 0;
        self.hex.search_match_len = 0;
        self.hex_window_loading = false;

        if self.hex_page_cache_file_id.as_deref() != Some(entry.id.as_str()) {
            self.hex_page_cache_file_id = Some(entry.id.clone());
            self.hex_page_cache.clear();
            self.hex_page_loading_offsets.clear();
        }

        self.hex_pending_window_offset = Some(aligned);
        self.hex_pending_window_len = window_len;

        if self.try_fill_hex_window_from_cache() {
            self.queue_hex_prefetch_for_cursor();
            return;
        }

        let required_pages = hex_required_page_offsets(aligned, window_len);
        for page_offset in &required_pages {
            self.queue_hex_page_load(entry, *page_offset);
        }
        self.queue_neighbor_prefetch(entry, &required_pages);
        self.hex_window_loading = true;
    }

    fn ensure_hex_page_channel(&mut self) -> std::sync::mpsc::Sender<HexPageMessage> {
        if let Some(tx) = &self.hex_page_tx {
            return tx.clone();
        }
        let (tx, rx) = std::sync::mpsc::channel::<HexPageMessage>();
        self.hex_page_tx = Some(tx.clone());
        self.hex_page_rx = Some(rx);
        tx
    }

    fn queue_hex_page_load(&mut self, entry: &FileEntry, page_offset: u64) {
        if let Some(file_size) = entry.size {
            if page_offset >= file_size {
                return;
            }
        }
        if self.find_hex_page_index(page_offset).is_some() {
            return;
        }
        if self.hex_page_loading_offsets.contains(&page_offset) {
            return;
        }

        self.hex_page_loading_offsets.insert(page_offset);
        let tx = self.ensure_hex_page_channel();
        let entry_clone = entry.clone();
        let file_id = entry.id.clone();
        let ctx = self.vfs_context.clone();
        std::thread::spawn(move || {
            match read_hex_page(&entry_clone, ctx.as_deref(), page_offset, HEX_PAGE_SIZE) {
                Ok(data) => {
                    let _ = tx.send(HexPageMessage::Loaded(HexPage {
                        file_id,
                        offset: page_offset,
                        data,
                    }));
                }
                Err(error) => {
                    let _ = tx.send(HexPageMessage::Error {
                        file_id,
                        offset: page_offset,
                        error,
                    });
                }
            }
        });
    }

    fn queue_neighbor_prefetch(&mut self, entry: &FileEntry, pages: &[u64]) {
        if pages.is_empty() {
            return;
        }
        let page_size = HEX_PAGE_SIZE as u64;
        if let Some(first) = pages.first().copied() {
            if first >= page_size {
                self.queue_hex_page_load(entry, first.saturating_sub(page_size));
            }
        }
        if let Some(last) = pages.last().copied() {
            self.queue_hex_page_load(entry, last.saturating_add(page_size));
        }
    }

    fn queue_hex_prefetch_for_cursor(&mut self) {
        let Some(file_id) = self.hex.file_id.clone() else {
            return;
        };
        let entry = self.file_index.iter().find(|f| f.id == file_id).cloned();
        let Some(entry) = entry else {
            return;
        };
        let abs = self.hex.absolute_cursor_offset();
        let page_size = HEX_PAGE_SIZE as u64;
        let current_page = (abs / page_size).saturating_mul(page_size);
        if current_page >= page_size {
            self.queue_hex_page_load(&entry, current_page.saturating_sub(page_size));
        }
        self.queue_hex_page_load(&entry, current_page.saturating_add(page_size));
    }

    fn find_hex_page_index(&self, page_offset: u64) -> Option<usize> {
        self.hex_page_cache
            .iter()
            .position(|page| page.offset == page_offset)
    }

    fn touch_hex_page(&mut self, page_offset: u64) -> Option<Vec<u8>> {
        let idx = self.find_hex_page_index(page_offset)?;
        let page = self.hex_page_cache.remove(idx)?;
        let data = page.data.clone();
        self.hex_page_cache.push_front(page);
        Some(data)
    }

    fn insert_hex_page(&mut self, page: HexPage) {
        if self.hex_page_cache_file_id.as_deref() != Some(page.file_id.as_str()) {
            return;
        }
        if let Some(idx) = self.find_hex_page_index(page.offset) {
            let _ = self.hex_page_cache.remove(idx);
        }
        self.hex_page_cache.push_front(page);
        while self.hex_page_cache.len() > HEX_MAX_CACHED_PAGES {
            let _ = self.hex_page_cache.pop_back();
        }
    }

    fn try_fill_hex_window_from_cache(&mut self) -> bool {
        let Some(file_id) = self.hex.file_id.clone() else {
            return false;
        };
        if self.hex_page_cache_file_id.as_deref() != Some(file_id.as_str()) {
            return false;
        }

        let window_offset = self
            .hex_pending_window_offset
            .unwrap_or(self.hex.window_offset);
        let window_len = self.hex_pending_window_len;
        if window_len == 0 {
            self.hex.data.clear();
            self.hex_window_loading = false;
            self.hex_pending_window_offset = None;
            self.hex_pending_window_len = 0;
            return true;
        }

        let page_offsets = hex_required_page_offsets(window_offset, window_len);
        let mut merged = Vec::with_capacity(window_len.saturating_add(HEX_PAGE_SIZE));
        for page_offset in &page_offsets {
            let Some(bytes) = self.touch_hex_page(*page_offset) else {
                return false;
            };
            merged.extend_from_slice(&bytes);
        }

        let first_page = page_offsets.first().copied().unwrap_or(window_offset);
        let start = usize::try_from(window_offset.saturating_sub(first_page)).unwrap_or(0);
        let end = start.saturating_add(window_len).min(merged.len());
        if start >= end {
            self.hex.data.clear();
        } else {
            self.hex.data = merged[start..end].to_vec();
        }
        if self.hex.cursor_byte >= self.hex.data.len() {
            self.hex.cursor_byte = self.hex.data.len().saturating_sub(1);
        }
        let start = self.hex.window_offset;
        let end = start.saturating_add(self.hex.data.len() as u64);
        self.hex.search_hits.clear();
        for &abs in &self.hex_search_hits_abs {
            if abs >= start && abs < end {
                self.hex.search_hits.push((abs - start) as usize);
            }
        }
        self.hex.window_offset = window_offset;
        self.hex_window_loading = false;
        self.hex_pending_window_offset = None;
        self.hex_pending_window_len = 0;
        true
    }

    pub fn apply_hex_page_message(&mut self, msg: HexPageMessage) {
        match msg {
            HexPageMessage::Loaded(page) => {
                self.hex_page_loading_offsets.remove(&page.offset);
                self.insert_hex_page(page);
                if self.hex_window_loading {
                    let _ = self.try_fill_hex_window_from_cache();
                }
            }
            HexPageMessage::Error {
                file_id,
                offset,
                error,
            } => {
                self.hex_page_loading_offsets.remove(&offset);
                if self.hex.file_id.as_deref() == Some(file_id.as_str()) {
                    self.hex.load_error = true;
                    self.hex_window_loading = false;
                    self.status = format!("Hex page load failed @0x{:X}: {}", offset, error);
                }
            }
        }
    }

    pub fn start_hex_search(&mut self) {
        self.hex_search_hits_abs.clear();
        self.hex.search_hits.clear();
        self.hex.search_hit_index = 0;
        self.hex.search_match_len = 0;
        self.hex_search_error = None;

        let query = self.hex.search_query.trim().to_string();
        if query.is_empty() {
            self.hex_search_active = false;
            self.hex_search_progress = (0, 0);
            self.hex_search_rx = None;
            return;
        }

        let Some(needle) = parse_hex_search_query(&query) else {
            self.hex_search_active = false;
            self.hex_search_progress = (0, 0);
            self.hex_search_error = Some("Invalid search query".to_string());
            self.hex_search_rx = None;
            return;
        };
        if needle.is_empty() {
            self.hex_search_active = false;
            self.hex_search_progress = (0, 0);
            self.hex_search_rx = None;
            return;
        }

        let Some(file_id) = self.hex.file_id.clone() else {
            self.hex_search_error = Some("No file selected".to_string());
            self.hex_search_active = false;
            self.hex_search_rx = None;
            return;
        };
        let Some(entry) = self.file_index.iter().find(|f| f.id == file_id).cloned() else {
            self.hex_search_error = Some("Selected file is unavailable".to_string());
            self.hex_search_active = false;
            self.hex_search_rx = None;
            return;
        };

        let file_size = entry.size.unwrap_or(0);
        self.hex_search_progress = (0, file_size);
        self.hex_search_active = true;

        let ctx = self.vfs_context.clone();
        let (tx, rx) = std::sync::mpsc::channel::<HexSearchMessage>();
        std::thread::spawn(move || {
            const CHUNK_SIZE: usize = 1_048_576; // 1 MB
            let overlap = needle.len().saturating_sub(1);
            let total = entry.size.unwrap_or(0);
            let mut hits = Vec::<u64>::new();

            if total == 0 {
                let buf = match read_hex_search_chunk(&entry, ctx.as_deref(), 0, CHUNK_SIZE * 8) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = tx.send(HexSearchMessage::Error(e));
                        return;
                    }
                };
                collect_hits(&buf, &needle, 0, &mut hits);
                let _ = tx.send(HexSearchMessage::Progress {
                    scanned: buf.len() as u64,
                    total: buf.len() as u64,
                });
                let _ = tx.send(HexSearchMessage::Done {
                    hits,
                    match_len: needle.len(),
                });
                return;
            }

            let mut offset = 0u64;
            while offset < total {
                let remaining = total.saturating_sub(offset);
                let base_len =
                    usize::try_from(remaining.min(CHUNK_SIZE as u64)).unwrap_or(CHUNK_SIZE);
                let read_len = base_len.saturating_add(overlap);
                let buf = match read_hex_search_chunk(&entry, ctx.as_deref(), offset, read_len) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = tx.send(HexSearchMessage::Error(e));
                        return;
                    }
                };

                if buf.is_empty() {
                    break;
                }

                let can_overlap = offset.saturating_add(buf.len() as u64) < total;
                let scan_len = if can_overlap {
                    buf.len().saturating_sub(overlap)
                } else {
                    buf.len()
                };
                if scan_len > 0 {
                    collect_hits(&buf[..scan_len], &needle, offset, &mut hits);
                }

                let scanned = (offset.saturating_add(base_len as u64)).min(total);
                let _ = tx.send(HexSearchMessage::Progress { scanned, total });

                if base_len == 0 {
                    break;
                }
                offset = offset.saturating_add(base_len as u64);
            }

            let _ = tx.send(HexSearchMessage::Done {
                hits,
                match_len: needle.len(),
            });
        });

        self.hex_search_rx = Some(rx);
    }

    pub fn bookmarks_for_file(&self, file_id: &str) -> Vec<&Bookmark> {
        self.bookmarks
            .iter()
            .filter(|b| b.file_id.as_deref() == Some(file_id))
            .collect()
    }

    pub fn bookmark_for_file_mut(
        &mut self,
        file_id: &str,
        examiner: &str,
    ) -> Option<&mut Bookmark> {
        self.bookmarks
            .iter_mut()
            .find(|b| b.file_id.as_deref() == Some(file_id) && b.examiner == examiner)
    }

    pub fn bookmark_for_registry_mut(
        &mut self,
        registry_path: &str,
        examiner: &str,
    ) -> Option<&mut Bookmark> {
        self.bookmarks
            .iter_mut()
            .find(|b| b.registry_path.as_deref() == Some(registry_path) && b.examiner == examiner)
    }

    pub fn hashed_count(&self) -> usize {
        self.hashed_files_count
    }

    pub fn flagged_count(&self) -> usize {
        self.flagged_files_count
    }

    pub fn carved_count(&self) -> usize {
        self.carved_files_count
    }

    pub fn mark_filter_dirty(&mut self) {
        self.filter_dirty = true;
        self.filter_last_edit = Some(std::time::Instant::now());
    }

    pub fn refresh_filtered_files(&mut self) {
        if !self.filter_dirty {
            return;
        }
        if let Some(last) = self.filter_last_edit {
            if last.elapsed() < std::time::Duration::from_millis(300) {
                return;
            }
        }
        self.rebuild_filtered_files_now();
    }

    pub fn rebuild_filtered_files_now(&mut self) {
        let filter_lc = self.file_filter.to_lowercase();
        self.filtered_file_indices.clear();
        self.filtered_file_indices.reserve(self.file_index.len());

        for (idx, f) in self.file_index.iter().enumerate() {
            if f.is_dir {
                continue;
            }
            let include = if filter_lc.is_empty() {
                true
            } else if filter_lc.starts_with("$search:") {
                // Global search mode — use precomputed results
                self.global_search_results.contains(&idx)
            } else if filter_lc == "$deleted" {
                f.is_deleted
            } else if filter_lc == "$suspicious" {
                f.hash_flag.as_deref() == Some("KnownBad") || f.is_deleted
            } else if filter_lc == "knownbad" {
                f.hash_flag.as_deref() == Some("KnownBad")
            } else {
                let path_lc = f.path.to_lowercase();
                f.parent_path.to_lowercase() == filter_lc
                    || path_lc.starts_with(&filter_lc)
                    || f.evidence_id.to_lowercase() == filter_lc
                    || f.name.to_lowercase().contains(&filter_lc)
                    || path_lc.contains(&filter_lc)
            };
            if include {
                self.filtered_file_indices.push(idx);
            }
        }

        self.file_table_state.filter = self.file_filter.clone();
        self.file_table_state.total_rows = self.filtered_file_indices.len();
        self.file_table_state.sort_dirty = true;
        self.filter_dirty = false;
        self.filter_last_edit = None;
    }
}

fn parse_hex_search_query(query: &str) -> Option<Vec<u8>> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Some(Vec::new());
    }

    if trimmed.contains(' ') {
        let mut bytes = Vec::new();
        for token in trimmed.split_whitespace() {
            if token.is_empty() || token.len() > 2 {
                return None;
            }
            let b = u8::from_str_radix(token, 16).ok()?;
            bytes.push(b);
        }
        return Some(bytes);
    }

    Some(trimmed.as_bytes().to_vec())
}

fn read_hex_search_chunk(
    entry: &FileEntry,
    ctx: Option<&crate::evidence::vfs_context::VfsReadContext>,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if let Some(ctx) = ctx {
        return ctx
            .read_range(entry, offset, len)
            .map_err(|e| e.to_string());
    }
    Err("VFS read context unavailable".to_string())
}

fn collect_hits(haystack: &[u8], needle: &[u8], base_offset: u64, out: &mut Vec<u64>) {
    if needle.is_empty() || haystack.len() < needle.len() {
        return;
    }
    for i in 0..=(haystack.len() - needle.len()) {
        if haystack[i..i + needle.len()] == *needle {
            out.push(base_offset.saturating_add(i as u64));
        }
    }
}

fn hex_window_len(file_size: u64, window_offset: u64) -> usize {
    if file_size == 0 {
        return HEX_WINDOW_SIZE;
    }
    let remaining = file_size.saturating_sub(window_offset);
    usize::try_from(remaining.min(HEX_WINDOW_SIZE as u64)).unwrap_or(HEX_WINDOW_SIZE)
}

fn hex_required_page_offsets(window_offset: u64, window_len: usize) -> Vec<u64> {
    if window_len == 0 {
        return Vec::new();
    }

    let page_size = HEX_PAGE_SIZE as u64;
    let first = (window_offset / page_size).saturating_mul(page_size);
    let last_byte = window_offset
        .saturating_add(window_len as u64)
        .saturating_sub(1);
    let last = (last_byte / page_size).saturating_mul(page_size);
    let mut pages = Vec::new();
    let mut current = first;
    while current <= last {
        pages.push(current);
        current = current.saturating_add(page_size);
        if current == 0 {
            break;
        }
    }
    pages
}

fn read_hex_page(
    entry: &FileEntry,
    ctx: Option<&crate::evidence::vfs_context::VfsReadContext>,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, String> {
    read_hex_search_chunk(entry, ctx, offset, len)
}

fn normalize_path_for_guard(path: &std::path::Path) -> Option<String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let canonical = std::fs::canonicalize(&absolute).unwrap_or(absolute);
    Some(
        canonical
            .to_string_lossy()
            .replace('\\', "/")
            .to_lowercase(),
    )
}

pub fn verify_audit_chain(entries: &[AuditEntry]) -> ChainVerifyResult {
    if entries.is_empty() {
        return ChainVerifyResult::Verified { count: 0 };
    }

    let mut ordered: Vec<&AuditEntry> = entries.iter().collect();
    ordered.sort_by_key(|e| e.sequence);

    let mut prev_hash = "0".repeat(64);
    for entry in ordered {
        let recomputed = compute_audit_entry_hash(
            entry.sequence,
            &entry.timestamp_utc,
            &entry.examiner,
            &entry.action,
            &entry.detail,
            entry.evidence_id.as_deref(),
            &entry.prev_hash,
        );

        if entry.entry_hash != recomputed {
            return ChainVerifyResult::Broken {
                sequence: entry.sequence,
                detail: "entry hash mismatch".to_string(),
            };
        }

        if entry.prev_hash != prev_hash {
            return ChainVerifyResult::Broken {
                sequence: entry.sequence,
                detail: "prev_hash does not match previous entry".to_string(),
            };
        }

        prev_hash = entry.entry_hash.clone();
    }

    ChainVerifyResult::Verified {
        count: entries.len(),
    }
}

fn compute_audit_entry_hash(
    sequence: u64,
    timestamp_utc: &str,
    examiner: &str,
    action: &str,
    detail: &str,
    evidence_id: Option<&str>,
    prev_hash: &str,
) -> String {
    use sha2::Digest;
    let data = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        sequence,
        timestamp_utc,
        examiner,
        action,
        detail,
        evidence_id.unwrap_or(""),
        prev_hash
    );
    let mut hasher = sha2::Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn diff_evidence(index: &[FileEntry], id_a: &str, id_b: &str) -> EvidenceDiff {
    use std::collections::HashMap;

    fn canonical_path(path: &str) -> String {
        path.replace('\\', "/").to_lowercase()
    }

    let mut map_a: HashMap<String, &FileEntry> = HashMap::new();
    let mut map_b: HashMap<String, &FileEntry> = HashMap::new();

    for entry in index {
        if entry.is_dir {
            continue;
        }
        let key = canonical_path(&entry.path);
        if entry.evidence_id == id_a {
            map_a.entry(key).or_insert(entry);
        } else if entry.evidence_id == id_b {
            map_b.entry(key).or_insert(entry);
        }
    }

    let mut only_in_a = Vec::new();
    let mut only_in_b = Vec::new();
    let mut modified = Vec::new();
    let mut identical = Vec::new();

    for (path, a) in &map_a {
        match map_b.get(path) {
            None => only_in_a.push((*a).clone()),
            Some(b) => {
                let same = if let (Some(sha_a), Some(sha_b)) = (&a.sha256, &b.sha256) {
                    sha_a.eq_ignore_ascii_case(sha_b)
                } else {
                    a.size == b.size && a.modified_utc == b.modified_utc
                };
                if same {
                    identical.push((*a).clone());
                } else {
                    modified.push(((*a).clone(), (**b).clone()));
                }
            }
        }
    }

    for (path, b) in &map_b {
        if !map_a.contains_key(path) {
            only_in_b.push((*b).clone());
        }
    }

    EvidenceDiff {
        evidence_a_id: id_a.to_string(),
        evidence_b_id: id_b.to_string(),
        only_in_a,
        only_in_b,
        modified,
        identical,
        generated_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::{AppState, EvidenceSource};
    use chrono::Utc;

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "strata_state_test_{}_{}",
            label,
            uuid::Uuid::new_v4()
        ))
    }

    #[test]
    fn output_guard_blocks_exact_evidence_file() {
        let root = temp_path("file");
        let evidence_dir = root.join("evidence");
        let _ = std::fs::create_dir_all(&evidence_dir);
        let evidence_path = evidence_dir.join("sample.E01");
        let _ = std::fs::write(&evidence_path, b"ewf");

        let mut state = AppState::default();
        state.evidence_sources.push(EvidenceSource {
            id: "ev1".to_string(),
            path: evidence_path.to_string_lossy().to_string(),
            format: "E01".to_string(),
            sha256: None,
            hash_verified: false,
            loaded_utc: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            size_bytes: Some(3),
        });

        assert!(state
            .ensure_output_path_safe(evidence_path.as_path())
            .is_err());
        let _ = std::fs::remove_file(&evidence_path);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn output_guard_blocks_paths_within_evidence_directory_source() {
        let root = temp_path("dir");
        let evidence_root = root.join("mounted");
        let nested = evidence_root.join("Windows/System32");
        let _ = std::fs::create_dir_all(&nested);
        let output_in_evidence = nested.join("report.csv");
        let _ = std::fs::write(&output_in_evidence, b"seed");

        let mut state = AppState::default();
        state.evidence_sources.push(EvidenceSource {
            id: "ev2".to_string(),
            path: evidence_root.to_string_lossy().to_string(),
            format: "Directory".to_string(),
            sha256: None,
            hash_verified: false,
            loaded_utc: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            size_bytes: None,
        });

        assert!(state
            .ensure_output_path_safe(output_in_evidence.as_path())
            .is_err());
        let _ = std::fs::remove_file(&output_in_evidence);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn output_guard_allows_external_output_path() {
        let root = temp_path("safe");
        let evidence_root = root.join("evidence");
        let export_root = root.join("export");
        let _ = std::fs::create_dir_all(&evidence_root);
        let _ = std::fs::create_dir_all(&export_root);

        let mut state = AppState::default();
        state.evidence_sources.push(EvidenceSource {
            id: "ev3".to_string(),
            path: evidence_root.to_string_lossy().to_string(),
            format: "Directory".to_string(),
            sha256: None,
            hash_verified: false,
            loaded_utc: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            size_bytes: None,
        });

        let output_path = export_root.join("timeline.csv");
        assert!(state.ensure_output_path_safe(output_path.as_path()).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }
}
