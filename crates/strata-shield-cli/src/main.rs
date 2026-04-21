use clap::{Parser, Subcommand};
use forensic_engine::case::add_to_notes::{add_to_notes, AddToNotesMode, AddToNotesRequest};
use forensic_engine::case::database::CaseDatabase;
use forensic_engine::case::examiner_presets::{
    get_examiner_preset, init_case_schema, init_default_presets, list_examiner_presets,
    set_auto_start_preset, start_examination,
};
use forensic_engine::case::replay::{CaseReplay, ReplayOptions, ReplayStatus};
use forensic_engine::case::triage_session::{TriageSessionOptions, TriageSessionStatus};
use forensic_engine::case::verify::{
    check_export_guard, verify_case, write_verification_artifacts, ExportOptions,
    VerificationReport, VerificationStatus, VerifyOptions,
};
use forensic_engine::case::watchpoints::{
    clear_integrity_violations, enable_integrity_watchpoints, get_integrity_watchpoints_enabled,
    list_integrity_violations,
};
use forensic_engine::classification::{
    build_execution_correlations, build_persistence_correlations_with_amcache,
    collect_all_shortcuts, get_av_products, get_defender_exclusions,
    get_defender_quarantined_items, get_defender_scan_history, get_defender_status,
    macos_catalog_specs, parse_all_macos_catalog_artifacts, parse_browser_records_from_path,
    parse_jumplist_entries_from_path, parse_lnk_shortcuts_from_path, parse_macos_catalog_artifact,
    parse_powershell_events_file, parse_powershell_history_file,
    parse_powershell_modules_inventory, parse_powershell_script_log_file,
    parse_powershell_transcripts_dir, parse_prefetch_records_from_path,
    parse_rdp_records_from_path, parse_restore_shadow_records_from_path, parse_scheduled_tasks_xml,
    parse_security_log_with_metadata, parse_srum_records_with_metadata,
    parse_system_log_with_metadata, parse_timeline_correlation_qa_records_from_path,
    parse_usb_records_from_path, parse_user_activity_mru_records_from_path,
    parseautomaticdestinations, scan_prefetch_directory, MacosCatalogFormat,
};
use rusqlite::params;
use serde::Deserialize;

use std::env;
use std::path::{Path, PathBuf};

pub mod commands;
pub mod envelope;
use envelope::*;

pub const CLI_JSON_INPUT_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const CLI_OVERRIDE_JSON_MAX_BYTES: u64 = 1024 * 1024;
pub const MACOS_CATALOG_DEFAULT_LIMIT: usize = 200;
pub const MACOS_CATALOG_MAX_LIMIT: usize = 5000;

pub fn read_json_file_with_limit<T: serde::de::DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
) -> Result<T, String> {
    let meta = strata_fs::metadata(path)
        .map_err(|e| format!("Failed to read metadata for {}: {}", path.display(), e))?;
    if meta.len() > max_bytes {
        return Err(format!(
            "JSON file is too large ({} bytes > {} bytes): {}",
            meta.len(),
            max_bytes,
            path.display()
        ));
    }

    let data = strata_fs::read(path)
        .map_err(|e| format!("Failed to read JSON file {}: {}", path.display(), e))?;
    serde_json::from_slice::<T>(&data)
        .map_err(|e| format!("Failed to parse JSON file {}: {}", path.display(), e))
}

fn open_case_db(path: &PathBuf) -> rusqlite::Connection {
    let conn = match rusqlite::Connection::open(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error opening database: {}", e);
            std::process::exit(1);
        }
    };
    if let Err(e) = init_case_schema(&conn) {
        eprintln!("Warning: Could not initialize case schema: {}", e);
    }
    conn
}

#[allow(dead_code)]
struct Args {
    image_path: PathBuf,
    output_json: Option<PathBuf>,
    output_csv: Option<PathBuf>,
    timeline_file: Option<PathBuf>,
    summary_file: Option<PathBuf>,
    enumerate_mft: bool,
    enumerate_mft_count: u32,
    timeline: bool,
    extract_strings: bool,
    detect_types: bool,
    carve: bool,
    tree: bool,
    tree_depth: u32,
    analysis: bool,
}

#[allow(dead_code)]
#[derive(Debug)]
struct VerifyArgs {
    case_id: String,
    db_path: PathBuf,
    sample: Option<u64>,
    strict_fts: bool,
}

fn print_help_and_exit() {
    println!("Forensic Analysis Engine v{}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Usage: forensic_cli <command> [options]");
    println!();
    println!("Commands:");
    println!("  verify                   Run case verification");
    println!("  export                   Export case with verification guard");
    println!("  verify-export            Run verification then export in one step");
    println!("  replay                   Run case replay (stability test)");
    println!("  replay-verify            Run replay then verification");
    println!("  watchpoints              Enable/disable integrity watchpoints");
    println!("  violations               List integrity violations");
    println!("  timeline                 List merged case timeline events");
    println!("  artifacts                Query case artifact summary from database");
    println!("  hashset                  Hash set management (list, stats)");
    println!("  srum                     Parse SRUM export records (JSON/CSV)");
    println!(
        "  evtx-security            Parse Security.evtx (or XML exports) with semantic summary"
    );
    println!("  evtx-sysmon              Parse Sysmon.evtx (or XML exports) with semantic summary");
    println!("  powershell-artifacts     Parse PowerShell history/log/event artifacts");
    println!("  registry-core-user-hives Parse core user-hive registry artifacts");
    println!("  registry-persistence     Correlate registry persistence signals");
    println!("  shimcache-deep           Parse shimcache/appcompat entries from registry exports");
    println!("  amcache-deep             Parse Amcache file entries from registry exports");
    println!("  bam-dam-activity         Parse BAM/DAM execution activity from registry exports");
    println!("  services-drivers-artifacts Parse services/drivers registry artifacts");
    println!("  scheduled-tasks-artifacts Parse scheduled task XML artifacts");
    println!("  wmi-persistence-activity Parse WMI persistence/activity artifact exports");
    println!("  ntfs-mft-fidelity        Parse NTFS MFT artifact exports with normalized fields");
    println!(
        "  usn-journal-fidelity     Parse USN journal artifact exports with normalized fields"
    );
    println!("  ntfs-logfile-signals     Parse NTFS LogFile signals with normalized fields");
    println!("  recycle-bin-artifacts    Parse Recycle Bin/deletion artifacts from exports");
    println!("  prefetch-fidelity        Parse Prefetch artifacts from directory or exports");
    println!("  jumplist-fidelity        Parse Jump List artifacts from binary/json/csv/text");
    println!(
        "  lnk-shortcut-fidelity    Parse .lnk shortcut artifacts from file/directory/exports"
    );
    println!(
        "  browser-forensics        Parse browser history artifacts from sqlite/json/csv/text"
    );
    println!("  rdp-remote-access        Parse RDP/remote access artifacts from exports");
    println!("  usb-device-history       Parse USB/device history artifacts from exports");
    println!("  restore-shadow-copies    Parse restore point / shadow copy artifact exports");
    println!("  user-activity-mru        Parse user activity + MRU artifact exports");
    println!("  timeline-correlation-qa  Parse normalized timeline correlation QA/perf exports");
    println!("  defender-artifacts       Parse Windows Defender and Defender Endpoint artifacts");
    println!("  execution-correlation    Correlate prefetch/jumplist/shortcut execution traces");
    println!("  recent-execution         Alias of execution-correlation (same options/output)");
    println!("  violations-clear         Clear integrity violations");
    println!("  triage-session           Run full triage session with defensibility bundle");
    println!("  add-to-notes             Add selection to notes (no typing required)");
    println!("  presets                  List available examiner presets");
    println!("  examine                  Run examination with preset");
    println!("  case                     Case management commands");
    println!("  ingest                   Ingest diagnostics and matrix tools");
    println!("  capabilities             Show capability registry");
    println!("  macos-catalog            Parse/list macOS artifact catalog sources");
    println!("  doctor                  Run diagnostics and health checks");
    println!("  smoke-test              Run quick validation test on an image");
    println!("  <image>                  Analyze disk image (default command)");
    println!();
    println!("Image Analysis Options:");
    println!("  --json <file>        Export audit log to JSON file");
    println!("  --csv <file>         Export audit log to CSV file");
    println!("  --timeline <file>   Export timeline to CSV file");
    println!("  --summary <file>    Export summary report to text file");
    println!("  --mft [count]       Enumerate NTFS MFT records (default: 1000)");
    println!("  --timeline-console  Show timeline in console (implies --mft)");
    println!("  --strings           Extract strings from image");
    println!("  --detect-types      Detect file types by signature");
    println!("  --carve            Run signature-based carving");
    println!("  --tree [depth]     Walk NTFS directory tree (default depth: 3)");
    println!("  --analysis         Show timeline analysis");
    println!();
    println!("Verify Command Options:");
    println!("  --case <id>        Case ID to verify");
    println!("  --db <path>        Path to case database");
    println!("  --sample <N>       Sample last N events for hash chain check");
    println!("  --strict-fts       Fail if FTS queue is not empty");
    println!("  --json-result <file>  Write JSON result envelope to file");
    println!("  --quiet            Suppress console output");
    println!();
    println!("Export Command Options:");
    println!("  --case <id>        Case ID to export");
    println!("  --db <path>        Path to case database");
    println!("  --output <dir>     Output directory (default: ./export_<case_id>)");
    println!("  --no-verify        Skip verification requirement");
    println!("  --strict           Fail on warnings");
    println!("  --max-age <sec>    Maximum age of verification report in seconds");
    println!();
    println!("Verify-Export Command Options:");
    println!("  --case <id>        Case ID");
    println!("  --db <path>        Path to case database");
    println!("  --output <dir>     Output directory");
    println!("  --sample <N>       Sample last N events for verification");
    println!("  --strict           Fail on warnings");
    println!("  --max-age <sec>    Maximum age of verification report");
    println!();
    println!("Replay Command Options:");
    println!("  --case <id>        Case ID");
    println!("  --db <path>        Path to case database");
    println!("  --sample <N>       Sample N rows per table for fingerprint");
    println!("  --no-fts          Skip FTS rebuild");
    println!("  --no-readmodels    Skip read model rebuild");
    println!("  --optimize         Run database optimize after replay");
    println!("  --fts-batch <N>    FTS queue batch size");
    println!("  --json-result <file>  Write JSON result envelope to file");
    println!("  --quiet            Suppress console output");
    println!();
    println!("Replay-Verify Command Options:");
    println!("  --case <id>        Case ID");
    println!("  --db <path>        Path to case database");
    println!("  --sample <N>       Sample N rows for verification");
    println!("  --strict           Fail on verification warnings");
    println!();
    println!("Watchpoints Command Options:");
    println!("  --case <id>        Case ID");
    println!("  --db <path>        Path to case database");
    println!("  --enable           Enable integrity watchpoints");
    println!("  --disable          Disable integrity watchpoints");
    println!("  --status           Show watchpoint status (default)");
    println!("  --json-result <file>  Write JSON result envelope to file");
    println!("  --quiet            Suppress console output");
    println!();
    println!("Violations Command Options:");
    println!("  --case <id>        Case ID");
    println!("  --db <path>        Path to case database");
    println!("  --since <utc>      Filter violations since UTC timestamp");
    println!("  --limit <N>        Limit results (default: 50)");
    println!("  --json-result <file>  Write JSON result envelope to file");
    println!("  --quiet            Suppress console output");
    println!();
    println!("Timeline Command Options:");
    println!("  --case <id>        Case ID");
    println!("  --db <path>        Path to case database");
    println!("  --from <utc>       Filter events at/after UTC timestamp");
    println!("  --to <utc>         Filter events at/before UTC timestamp");
    println!("  --limit <N>        Limit results (default: 200, max: 2000)");
    println!("  --cursor <token>   Pagination cursor token from prior response");
    println!("  --severity <level> Filter by severity: info|warn|error");
    println!("  --event-type <name> Filter by event_type contains text");
    println!("  --contains <text>  Filter by summary/details text contains");
    println!("  --source <name>    Source filter: all|activity|evidence|violations|execution|prefetch|jumplist|lnk-shortcuts|browser-forensics|rdp-remote-access|usb-device-history|restore-shadow-copies|user-activity-mru|timeline-correlation-qa|srum|evtx-security|evtx-sysmon|powershell|registry-user-hives|registry-persistence|shimcache|amcache|bam-dam|services-drivers|scheduled-tasks|wmi-persistence|ntfs-mft|usn-journal|ntfs-logfile|recycle-bin|defender-artifacts");
    println!("  --srum-input <path>  Timeline source: SRUM export file (JSON/CSV)");
    println!("  --evtx-security-input <path>  Timeline source: Security.evtx or XML export");
    println!("  --evtx-sysmon-input <path>  Timeline source: Sysmon.evtx or XML export");
    println!("  --powershell-history <path>  Timeline source: ConsoleHost_history.txt");
    println!("  --powershell-script-log <path> Timeline source: script_block.log");
    println!("  --powershell-events <path>   Timeline source: ps_events.json");
    println!("  --powershell-transcripts-dir <path> Timeline source: transcript directory");
    println!("  --runmru-reg <path>    Timeline source: RunMRU .reg export");
    println!("  --opensave-reg <path>  Timeline source: OpenSaveMRU .reg export");
    println!("  --userassist-reg <path> Timeline source: UserAssist .reg export");
    println!("  --recentdocs-reg <path> Timeline source: RecentDocs .reg export");
    println!("  --autorun-reg <path>   Timeline source: Autorun .reg export");
    println!("  --bam-reg <path>       Timeline source: BAM/DAM .reg export");
    println!("  --amcache-reg <path>   Timeline source: Amcache .reg export");
    println!("  --shimcache-reg <path> Timeline source: AppCompat/ShimCache .reg export");
    println!("  --services-reg <path> Timeline source: services/drivers .reg export");
    println!("  --tasks-root <path>    Timeline source: Scheduled tasks root");
    println!("  --wmi-persist-input <path> Timeline source: WMI persistence export");
    println!("  --wmi-traces-input <path>  Timeline source: WMI traces export");
    println!("  --wmi-instances-input <path> Timeline source: WMI instances export");
    println!("  --mft-input <path>     Timeline source: MFT export (binary/json/csv/text)");
    println!("  --usn-input <path>     Timeline source: USN export (json/csv/text)");
    println!("  --logfile-input <path> Timeline source: NTFS LogFile export (binary/json/text)");
    println!("  --recycle-input <path> Timeline source: Recycle Bin export (json/csv/text)");
    println!("  --defender-input <path> Timeline source: Defender artifacts JSON/envelope");
    println!("  --prefetch-input <path> Timeline source: Prefetch export (dir/.pf/json/csv/text)");
    println!(
        "  --jumplist-input <path> Timeline source: Jump List export (auto/custom/json/csv/text)"
    );
    println!("  --lnk-input <path>      Timeline source: LNK export (dir/.lnk/json/csv/text)");
    println!("  --browser-input <path>  Timeline source: Browser export (sqlite/json/csv/text)");
    println!("  --rdp-input <path>      Timeline source: RDP export (json/csv/text)");
    println!("  --usb-input <path>      Timeline source: USB export (json/csv/text)");
    println!(
        "  --restore-shadow-input <path> Timeline source: restore/shadow export (json/csv/text)"
    );
    println!(
        "  --user-activity-input <path> Timeline source: user activity/MRU export (json/csv/text)"
    );
    println!(
        "  --timeline-correlation-input <path> Timeline source: timeline correlation QA export (json/csv/text)"
    );
    println!("  --prefetch-dir <path>  Execution source: Prefetch directory");
    println!("  --jumplist-path <path> Execution source: Jump List source path");
    println!("  --shortcuts-base <path> Execution source: shortcut base directory");
    println!("  --json             Print merged timeline payload as JSON");
    println!("  --json-result <file>  Write JSON result envelope to file");
    println!("  --quiet            Suppress console output");
    println!();
    println!("Defender-Artifacts Command Options:");
    println!(
        "  --limit <N>          Limit records returned per collection (default: 200, max: 5000)"
    );
    println!("  --json               Print command payload as JSON");
    println!("  --json-result <file> Write JSON result envelope to file");
    println!("  --quiet              Suppress console summary output");
    println!("  --help               Show command help");
    println!();
    println!("Registry-Persistence Command Options:");
    println!("  --autorun-reg <path> Path to autorun .reg export (default: exports/autorun.reg)");
    println!("  --bam-reg <path>     Path to BAM/DAM .reg export (default: exports/bam.reg)");
    println!("  --amcache-reg <path> Path to Amcache .reg export (default: exports/amcache.reg)");
    println!("  --tasks-root <path>  Root directory containing task XML files");
    println!("  --limit <N>          Limit results (default: 200, max: 5000)");
    println!("  --json               Print command payload as JSON");
    println!("  --json-result <file> Write JSON result envelope to file");
    println!("  --quiet              Suppress console output");
    println!();
    println!("Registry-Core-User-Hives Command Options:");
    println!("  --runmru-reg <path>      RunMRU .reg export path (default: exports/runmru.reg)");
    println!("  --opensave-reg <path>    OpenSaveMRU .reg export path (default: exports/mru2.reg)");
    println!(
        "  --userassist-reg <path>  UserAssist .reg export path (default: exports/userassist.reg)"
    );
    println!(
        "  --recentdocs-reg <path>  RecentDocs .reg export path (default: exports/recentdocs.reg)"
    );
    println!("  --limit <N>              Limit results (default: 200, max: 5000)");
    println!("  --json                   Print command payload as JSON");
    println!("  --json-result <file>     Write JSON result envelope to file");
    println!("  --quiet                  Suppress console output");
    println!();
    println!("ShimCache-Deep Command Options:");
    println!("  --appcompat-reg <path>  AppCompat/ShimCache .reg export path (default: exports/appcompat.reg)");
    println!("  --limit <N>             Limit results (default: 200, max: 5000)");
    println!("  --json                  Print command payload as JSON");
    println!("  --json-result <file>    Write JSON result envelope to file");
    println!("  --quiet                 Suppress console output");
    println!();
    println!("Execution-Correlation Command Options:");
    println!("  --prefetch-dir <path>  Prefetch directory (default: C:\\Windows\\Prefetch)");
    println!(
        "  --jumplist-path <path> Jump List source (default: %APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations)"
    );
    println!(
        "  --shortcuts-base <path> Base user directory for .lnk traversal (default: %USERPROFILE%)"
    );
    println!("  --prefetch-input <path> Optional Prefetch input alias (dir/.pf/json/csv/text)");
    println!("  --jumplist-input <path> Optional Jump List input alias (file/dir/json/csv/text)");
    println!("  --lnk-input <path>      Optional LNK input (file/dir/json/csv/text)");
    println!("  --browser-input <path>  Optional Browser input (sqlite/json/csv/text)");
    println!("  --rdp-input <path>      Optional RDP input (json/csv/text)");
    println!("  --usb-input <path>      Optional USB input (json/csv/text)");
    println!("  --restore-shadow-input <path> Optional restore/shadow input (json/csv/text)");
    println!("  --user-activity-input <path> Optional user-activity/MRU input (json/csv/text)");
    println!("  --timeline-correlation-input <path> Optional timeline correlation QA input (json/csv/text)");
    println!("  --srum-input <path>     Optional SRUM export file (JSON/CSV)");
    println!("  --evtx-security-input <path> Optional Security.evtx/XML export");
    println!("  --evtx-sysmon-input <path> Optional Sysmon.evtx/XML export");
    println!("  --powershell-history <path> Optional ConsoleHost_history.txt");
    println!("  --powershell-script-log <path> Optional script_block.log");
    println!("  --powershell-events <path> Optional ps_events.json");
    println!("  --runmru-reg <path>      Optional RunMRU .reg export");
    println!("  --opensave-reg <path>    Optional OpenSaveMRU .reg export");
    println!("  --userassist-reg <path>  Optional UserAssist .reg export");
    println!("  --recentdocs-reg <path>  Optional RecentDocs .reg export");
    println!("  --autorun-reg <path>     Optional autorun .reg export");
    println!("  --bam-reg <path>         Optional BAM/DAM .reg export");
    println!("  --amcache-reg <path>     Optional Amcache .reg export");
    println!("  --shimcache-reg <path>   Optional AppCompat/ShimCache .reg export");
    println!("  --services-reg <path>    Optional services/drivers .reg export");
    println!("  --tasks-root <path>      Optional task XML root");
    println!("  --wmi-persist-input <path> Optional WMI persistence export");
    println!("  --wmi-traces-input <path>  Optional WMI traces export");
    println!("  --wmi-instances-input <path> Optional WMI instances export");
    println!("  --mft-input <path>       Optional MFT export input");
    println!("  --usn-input <path>       Optional USN export input");
    println!("  --logfile-input <path>   Optional NTFS LogFile export input");
    println!("  --recycle-input <path>   Optional Recycle Bin export input");
    println!("  --limit <N>            Limit results (default: 200, max: 5000)");
    println!("  --json                 Print command payload as JSON");
    println!("  --json-result <file>   Write JSON result envelope to file");
    println!("  --quiet                Suppress console output");
    println!();
    println!("SRUM Command Options:");
    println!("  --input <path>       SRUM export file path (JSON/CSV)");
    println!("  --limit <N>          Limit results (default: 200, max: 5000)");
    println!("  --json               Print command payload as JSON");
    println!("  --json-result <file> Write JSON result envelope to file");
    println!("  --quiet              Suppress console output");
    println!();
    println!("EVTX-Security Command Options:");
    println!("  --input <path>       Security.evtx or EVTX XML export path");
    println!("  --limit <N>          Limit results (default: 200, max: 5000)");
    println!("  --json               Print command payload as JSON");
    println!("  --json-result <file> Write JSON result envelope to file");
    println!("  --quiet              Suppress console output");
    println!();
    println!("EVTX-Sysmon Command Options:");
    println!("  --input <path>       Sysmon.evtx or EVTX XML export path");
    println!("  --limit <N>          Limit results (default: 200, max: 5000)");
    println!("  --json               Print command payload as JSON");
    println!("  --json-result <file> Write JSON result envelope to file");
    println!("  --quiet              Suppress console output");
    println!();
    println!("PowerShell-Artifacts Command Options:");
    println!("  --history <path>        ConsoleHost_history.txt path");
    println!("  --script-log <path>     Script block log path");
    println!("  --events <path>         PowerShell events JSON path");
    println!("  --transcripts-dir <path> Transcript directory path");
    println!("  --modules <path>        Module inventory path");
    println!("  --limit <N>             Limit records (default: 200, max: 5000)");
    println!("  --json                  Print command payload as JSON");
    println!("  --json-result <file>    Write JSON result envelope to file");
    println!("  --quiet                 Suppress console output");
    println!();
    println!("Amcache-Deep Command Options:");
    println!("  --amcache-reg <path>   Amcache .reg export path (default: exports/amcache.reg)");
    println!("  --input <path>         Alias for --amcache-reg");
    println!("  --limit <N>            Limit records (default: 200, max: 5000)");
    println!("  --json                 Print command payload as JSON");
    println!("  --json-result <file>   Write JSON result envelope to file");
    println!("  --quiet                Suppress console output");
    println!();
    println!("BAM-DAM-Activity Command Options:");
    println!("  --bam-reg <path>       BAM/DAM .reg export path (default: exports/bam.reg)");
    println!("  --input <path>         Alias for --bam-reg");
    println!("  --limit <N>            Limit records (default: 200, max: 5000)");
    println!("  --json                 Print command payload as JSON");
    println!("  --json-result <file>   Write JSON result envelope to file");
    println!("  --quiet                Suppress console output");
    println!();
    println!("Services-Drivers-Artifacts Command Options:");
    println!("  --services-reg <path>  Services/Drivers .reg export path (default: exports/services.reg)");
    println!("  --input <path>         Alias for --services-reg");
    println!("  --limit <N>            Limit records (default: 200, max: 5000)");
    println!("  --json                 Print command payload as JSON");
    println!("  --json-result <file>   Write JSON result envelope to file");
    println!("  --quiet                Suppress console output");
    println!();
    println!("Scheduled-Tasks-Artifacts Command Options:");
    println!("  --tasks-root <path>    Root directory for task XML files (default: exports/tasks)");
    println!("  --input <path>         Alias for --tasks-root");
    println!("  --limit <N>            Limit records (default: 200, max: 5000)");
    println!("  --json                 Print command payload as JSON");
    println!("  --json-result <file>   Write JSON result envelope to file");
    println!("  --quiet                Suppress console output");
    println!();
    println!("WMI-Persistence-Activity Command Options:");
    println!("  --persist-input <path>   WMI persistence export path (default: artifacts/wmi/persistence.json)");
    println!(
        "  --traces-input <path>    WMI trace export path (default: artifacts/wmi/traces.json)"
    );
    println!("  --instances-input <path> WMI instances export path (default: artifacts/wmi/instances.json)");
    println!("  --limit <N>              Limit records (default: 200, max: 5000)");
    println!("  --json                   Print command payload as JSON");
    println!("  --json-result <file>     Write JSON result envelope to file");
    println!("  --quiet                  Suppress console output");
    println!();
    println!("NTFS-MFT-Fidelity Command Options:");
    println!("  --mft-input <path>       MFT export input path (default: exports/mft.json)");
    println!("  --input <path>           Alias for --mft-input");
    println!("  --limit <N>              Limit records (default: 200, max: 5000)");
    println!("  --json                   Print command payload as JSON");
    println!("  --json-result <file>     Write JSON result envelope to file");
    println!("  --quiet                  Suppress console output");
    println!();
    println!("USN-Journal-Fidelity Command Options:");
    println!("  --usn-input <path>       USN export input path (default: exports/usnjrnl.csv)");
    println!("  --input <path>           Alias for --usn-input");
    println!("  --limit <N>              Limit records (default: 200, max: 5000)");
    println!("  --json                   Print command payload as JSON");
    println!("  --json-result <file>     Write JSON result envelope to file");
    println!("  --quiet                  Suppress console output");
    println!();
    println!("macOS-Catalog Command Options:");
    println!("  --list             List available macOS catalog artifact keys");
    println!("  --key <id>         Parse only one artifact key");
    println!("  --limit <N>        Limit records returned (default: 200, max: 5000)");
    println!("  --json             Print command payload as JSON");
    println!("  --json-result <file>  Write JSON result envelope to file");
    println!("  --quiet            Suppress console output");
    println!();
    println!("Violations-Clear Command Options:");
    println!("  --case <id>        Case ID");
    println!("  --db <path>        Path to case database");
    println!("  --json-result <file>  Write JSON result envelope to file");
    println!("  --quiet            Suppress console output");
    println!();
    println!("Presets Command Options:");
    println!("  list                List all available examiner presets");
    println!("  show --name <name> Show details of a specific preset");
    println!();
    println!("Examine Command Options:");
    println!("  --case <id>        Case ID (required)");
    println!("  --db <path>        Path to case database");
    println!("  --preset <name>   Preset name (Strict Examiner, Standard Examiner, Fast Triage)");
    println!("  --override-json <path> JSON file with option overrides");
    println!("  --json-result <file>  Write JSON result envelope to file");
    println!("  --quiet            Suppress console output");
    println!("  --help             Show this help message");
    println!();
    println!("Case Command Options:");
    println!("  init                Initialize a new case database");
    println!("    --case <id>      Case ID (required)");
    println!("    --db <path>     Path to case database");
    println!("  set-auto-preset    Set auto-start examination preset");
    println!("    --case <id>      Case ID (required)");
    println!("    --db <path>     Path to case database");
    println!("    --preset <name> Preset name or 'none' to clear");
    println!();
    println!("Doctor Command Options:");
    println!("  --bundle <dir>     Generate diagnostics bundle");
    println!("  --verbose          Verbose output");
    println!();
    println!("Smoke-Test Command Options:");
    println!("  --image <path>      Path to image file (required)");
    println!("  --out <dir>         Output directory (default: .\\exports\\smoke_test)");
    println!("  --mft <count>       MFT record count (default: 50)");
    println!("  --no-timeline       Skip timeline CSV generation");
    println!("  --no-audit         Skip audit JSON generation");
    println!("  --quiet             Only print final one-line status");
    println!("  --json-summary <path> Path for summary JSON (default: <out>\\smoke_summary.json)");
    println!();
    println!("Triage-Session Command Options:");
    println!("  --case <id>        Case ID (required)");
    println!("  --db <path>        Path to case database");
    println!("  --name <name>      Session name (optional)");
    println!("  --no-watchpoints   Disable integrity watchpoints");
    println!("  --no-replay       Skip replay step");
    println!("  --no-verify       Skip verify step");
    println!("  --strict           Fail on warnings and violations");
    println!("  --bundle-dir <dir> Bundle output directory (default: exports/defensibility)");
    println!("  --no-bundle       Skip bundle export");
    println!("  --sample <N>       Sample size for replay/verify");
    println!("  --json-result <file>  Write JSON result envelope to file");
    println!("  --quiet            Suppress console output");
    println!("  --help             Show this help message");
    println!();
    println!("Add-to-Notes Command Options:");
    println!("  --case <id>        Case ID (required)");
    println!("  --db <path>        Path to case database");
    println!("  --mode <mode>      Mode: note, exhibits, packet (default: note)");
    println!("  --from-json <path> JSON file with SelectionContext + items (required)");
    println!("  --screenshot <path> Optional screenshot path to link");
    println!("  --tag <tag>        Tag to add (can be repeated)");
    println!("  --explain           Run explain on created exhibits");
    println!("  --max-items <N>     Maximum items (default: 200)");
    println!("  --help             Show this help message");
    println!();
    println!("Examples:");
    println!("  forensic_cli disk.img --json audit.json --summary report.txt --mft 5000");
    println!("  forensic_cli verify --case case123 --db ./cases/case123.sqlite");
    println!("  forensic_cli export --case case123 --db ./cases/case123.sqlite");
    println!("  forensic_cli verify-export --case case123 --db ./cases/case123.sqlite");
    println!("  forensic_cli replay --case case123 --db ./cases/case123.sqlite");
    println!("  forensic_cli replay-verify --case case123 --db ./cases/case123.sqlite");
    println!("  forensic_cli watchpoints --case case123 --db ./cases/case123.sqlite --enable");
    println!("  forensic_cli violations --case case123 --db ./cases/case123.sqlite");
    println!(
        "  forensic_cli timeline --case case123 --db ./cases/case123.sqlite --limit 200 --json"
    );
    println!(
        "  forensic_cli registry-persistence --autorun-reg ./exports/autorun.reg --bam-reg ./exports/bam.reg --json"
    );
    println!(
        "  forensic_cli registry-persistence --autorun-reg ./exports/autorun.reg --bam-reg ./exports/bam.reg --amcache-reg ./exports/amcache.reg --json"
    );
    println!(
        "  forensic_cli registry-core-user-hives --runmru-reg ./exports/runmru.reg --opensave-reg ./exports/mru2.reg --userassist-reg ./exports/userassist.reg --json"
    );
    println!("  forensic_cli shimcache-deep --appcompat-reg ./exports/appcompat.reg --json");
    println!("  forensic_cli amcache-deep --amcache-reg ./exports/amcache.reg --json");
    println!("  forensic_cli bam-dam-activity --bam-reg ./exports/bam.reg --json");
    println!(
        "  forensic_cli services-drivers-artifacts --services-reg ./exports/services.reg --json"
    );
    println!("  forensic_cli scheduled-tasks-artifacts --tasks-root ./exports/tasks --json");
    println!(
        "  forensic_cli wmi-persistence-activity --persist-input ./artifacts/wmi/persistence.json --json"
    );
    println!("  forensic_cli ntfs-mft-fidelity --mft-input ./exports/mft.json --json");
    println!("  forensic_cli usn-journal-fidelity --usn-input ./exports/usnjrnl.csv --json");
    println!("  forensic_cli ntfs-logfile-signals --input ./exports/logfile.bin --json");
    println!("  forensic_cli recycle-bin-artifacts --input ./exports/recycle.json --json");
    println!("  forensic_cli prefetch-fidelity --input ./exports/prefetch.json --json");
    println!("  forensic_cli jumplist-fidelity --input ./exports/jumplist.json --json");
    println!("  forensic_cli lnk-shortcut-fidelity --input ./exports/shortcuts.json --json");
    println!("  forensic_cli browser-forensics --input ./exports/browser.json --json");
    println!("  forensic_cli rdp-remote-access --input ./exports/rdp.csv --json");
    println!("  forensic_cli usb-device-history --input ./exports/usb.json --json");
    println!("  forensic_cli restore-shadow-copies --input ./exports/restore_shadow.json --json");
    println!("  forensic_cli user-activity-mru --input ./exports/user_activity_mru.json --json");
    println!("  forensic_cli timeline-correlation-qa --input ./exports/timeline_correlation_qa.json --json");
    println!("  forensic_cli defender-artifacts --json");
    println!("  forensic_cli execution-correlation --prefetch-dir C:\\Windows\\Prefetch --defender-input ./exports/defender_artifacts.json --json");
    println!("  forensic_cli recent-execution --prefetch-dir C:\\Windows\\Prefetch --json");
    println!("  forensic_cli srum --input ./exports/srum.json --json");
    println!("  forensic_cli timeline --case case123 --db ./cases/case123.sqlite --source evtx-security --evtx-security-input ./exports/Security.evtx --json");
    println!("  forensic_cli timeline --case case123 --db ./cases/case123.sqlite --source defender-artifacts --defender-input ./exports/defender_artifacts.json --json");
    println!("  forensic_cli evtx-security --input ./exports/Security.evtx --json");
    println!("  forensic_cli evtx-sysmon --input ./exports/Sysmon.evtx --json");
    println!("  forensic_cli powershell-artifacts --history ./artifacts/powershell/ConsoleHost_history.txt --json");
    println!("  forensic_cli macos-catalog --list --json");
    println!("  forensic_cli add-to-notes --case case123 --db ./cases/case123.sqlite --mode exhibits --from-json selection.json");
    println!("  forensic_cli doctor --verbose");
    std::process::exit(0);
}

#[allow(dead_code)]
#[derive(Debug)]
struct ExportArgs {
    case_id: String,
    db_path: PathBuf,
    output_dir: PathBuf,
    no_verify: bool,
    strict: bool,
    max_age: Option<u64>,
}

const TIMELINE_DEFAULT_LIMIT: usize = 200;
const TIMELINE_MAX_LIMIT: usize = 2000;
const TIMELINE_PAGE_SIZE: usize = 500;
const TIMELINE_MAX_SCAN_PER_SOURCE: usize = 10_000;
const TIMELINE_SCAN_MULTIPLIER: usize = 20;
const REGISTRY_PERSISTENCE_DEFAULT_LIMIT: usize = 200;
const REGISTRY_PERSISTENCE_MAX_LIMIT: usize = 5000;
const EXECUTION_CORRELATION_DEFAULT_LIMIT: usize = 200;
const EXECUTION_CORRELATION_MAX_LIMIT: usize = 5000;
const SRUM_DEFAULT_LIMIT: usize = 200;
const SRUM_MAX_LIMIT: usize = 5000;
const EVTX_SECURITY_DEFAULT_LIMIT: usize = 200;
const EVTX_SECURITY_MAX_LIMIT: usize = 5000;
const EVTX_SYSMON_DEFAULT_LIMIT: usize = 200;
const EVTX_SYSMON_MAX_LIMIT: usize = 5000;
const POWERSHELL_DEFAULT_LIMIT: usize = 200;
const POWERSHELL_MAX_LIMIT: usize = 5000;
const REGISTRY_CORE_HIVES_DEFAULT_LIMIT: usize = 200;
const REGISTRY_CORE_HIVES_MAX_LIMIT: usize = 5000;
const SHIMCACHE_DEEP_DEFAULT_LIMIT: usize = 200;
const SHIMCACHE_DEEP_MAX_LIMIT: usize = 5000;
const AMCACHE_DEEP_DEFAULT_LIMIT: usize = 200;
const AMCACHE_DEEP_MAX_LIMIT: usize = 5000;
const BAM_DAM_ACTIVITY_DEFAULT_LIMIT: usize = 200;
const BAM_DAM_ACTIVITY_MAX_LIMIT: usize = 5000;
const SERVICES_DRIVERS_DEFAULT_LIMIT: usize = 200;
const SERVICES_DRIVERS_MAX_LIMIT: usize = 5000;
const SCHEDULED_TASKS_DEFAULT_LIMIT: usize = 200;
const SCHEDULED_TASKS_MAX_LIMIT: usize = 5000;
const WMI_PERSISTENCE_DEFAULT_LIMIT: usize = 200;
const WMI_PERSISTENCE_MAX_LIMIT: usize = 5000;
const NTFS_MFT_FIDELITY_DEFAULT_LIMIT: usize = 200;
const NTFS_MFT_FIDELITY_MAX_LIMIT: usize = 5000;
const USN_JOURNAL_FIDELITY_DEFAULT_LIMIT: usize = 200;
const USN_JOURNAL_FIDELITY_MAX_LIMIT: usize = 5000;
const NTFS_LOGFILE_SIGNALS_DEFAULT_LIMIT: usize = 200;
const NTFS_LOGFILE_SIGNALS_MAX_LIMIT: usize = 5000;
const RECYCLE_BIN_ARTIFACTS_DEFAULT_LIMIT: usize = 200;
const RECYCLE_BIN_ARTIFACTS_MAX_LIMIT: usize = 5000;
const PREFETCH_FIDELITY_DEFAULT_LIMIT: usize = 200;
const PREFETCH_FIDELITY_MAX_LIMIT: usize = 5000;
const JUMPLIST_FIDELITY_DEFAULT_LIMIT: usize = 200;
const JUMPLIST_FIDELITY_MAX_LIMIT: usize = 5000;
const LNK_SHORTCUT_FIDELITY_DEFAULT_LIMIT: usize = 200;
const LNK_SHORTCUT_FIDELITY_MAX_LIMIT: usize = 5000;
const BROWSER_FORENSICS_DEFAULT_LIMIT: usize = 200;
const BROWSER_FORENSICS_MAX_LIMIT: usize = 5000;
const RDP_REMOTE_ACCESS_DEFAULT_LIMIT: usize = 200;
const RDP_REMOTE_ACCESS_MAX_LIMIT: usize = 5000;
const USB_DEVICE_HISTORY_DEFAULT_LIMIT: usize = 200;
const USB_DEVICE_HISTORY_MAX_LIMIT: usize = 5000;
const RESTORE_SHADOW_COPIES_DEFAULT_LIMIT: usize = 200;
const RESTORE_SHADOW_COPIES_MAX_LIMIT: usize = 5000;
const USER_ACTIVITY_MRU_DEFAULT_LIMIT: usize = 200;
const USER_ACTIVITY_MRU_MAX_LIMIT: usize = 5000;
const TIMELINE_CORRELATION_QA_DEFAULT_LIMIT: usize = 200;
const TIMELINE_CORRELATION_QA_MAX_LIMIT: usize = 5000;
const DEFENDER_ARTIFACTS_DEFAULT_LIMIT: usize = 200;
const DEFENDER_ARTIFACTS_MAX_LIMIT: usize = 5000;

#[derive(Debug, Clone, Copy)]
enum TimelineSourceFilter {
    All,
    Activity,
    Evidence,
    Violations,
    Execution,
    Prefetch,
    JumpList,
    LnkShortcuts,
    BrowserForensics,
    RdpRemoteAccess,
    UsbDeviceHistory,
    RestoreShadowCopies,
    UserActivityMru,
    TimelineCorrelationQa,
    Srum,
    EvtxSecurity,
    EvtxSysmon,
    Powershell,
    RegistryUserHives,
    RegistryPersistence,
    Shimcache,
    Amcache,
    BamDam,
    ServicesDrivers,
    ScheduledTasks,
    WmiPersistence,
    NtfsMft,
    UsnJournal,
    NtfsLogFile,
    RecycleBin,
    DefenderArtifacts,
}

impl TimelineSourceFilter {
    fn parse(value: &str) -> Option<Self> {
        match value.to_lowercase().as_str() {
            "all" => Some(Self::All),
            "activity" => Some(Self::Activity),
            "evidence" => Some(Self::Evidence),
            "violations" => Some(Self::Violations),
            "execution" => Some(Self::Execution),
            "prefetch" => Some(Self::Prefetch),
            "jumplist" => Some(Self::JumpList),
            "lnk-shortcuts" => Some(Self::LnkShortcuts),
            "browser-forensics" => Some(Self::BrowserForensics),
            "rdp-remote-access" => Some(Self::RdpRemoteAccess),
            "usb-device-history" => Some(Self::UsbDeviceHistory),
            "restore-shadow-copies" => Some(Self::RestoreShadowCopies),
            "user-activity-mru" => Some(Self::UserActivityMru),
            "timeline-correlation-qa" => Some(Self::TimelineCorrelationQa),
            "srum" => Some(Self::Srum),
            "evtx-security" => Some(Self::EvtxSecurity),
            "evtx-sysmon" => Some(Self::EvtxSysmon),
            "powershell" => Some(Self::Powershell),
            "registry-user-hives" => Some(Self::RegistryUserHives),
            "registry-persistence" => Some(Self::RegistryPersistence),
            "shimcache" => Some(Self::Shimcache),
            "amcache" => Some(Self::Amcache),
            "bam-dam" => Some(Self::BamDam),
            "services-drivers" => Some(Self::ServicesDrivers),
            "scheduled-tasks" => Some(Self::ScheduledTasks),
            "wmi-persistence" => Some(Self::WmiPersistence),
            "ntfs-mft" => Some(Self::NtfsMft),
            "usn-journal" => Some(Self::UsnJournal),
            "ntfs-logfile" => Some(Self::NtfsLogFile),
            "recycle-bin" => Some(Self::RecycleBin),
            "defender-artifacts" => Some(Self::DefenderArtifacts),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Activity => "activity",
            Self::Evidence => "evidence",
            Self::Violations => "violations",
            Self::Execution => "execution",
            Self::Prefetch => "prefetch",
            Self::JumpList => "jumplist",
            Self::LnkShortcuts => "lnk-shortcuts",
            Self::BrowserForensics => "browser-forensics",
            Self::RdpRemoteAccess => "rdp-remote-access",
            Self::UsbDeviceHistory => "usb-device-history",
            Self::RestoreShadowCopies => "restore-shadow-copies",
            Self::UserActivityMru => "user-activity-mru",
            Self::TimelineCorrelationQa => "timeline-correlation-qa",
            Self::Srum => "srum",
            Self::EvtxSecurity => "evtx-security",
            Self::EvtxSysmon => "evtx-sysmon",
            Self::Powershell => "powershell",
            Self::RegistryUserHives => "registry-user-hives",
            Self::RegistryPersistence => "registry-persistence",
            Self::Shimcache => "shimcache",
            Self::Amcache => "amcache",
            Self::BamDam => "bam-dam",
            Self::ServicesDrivers => "services-drivers",
            Self::ScheduledTasks => "scheduled-tasks",
            Self::WmiPersistence => "wmi-persistence",
            Self::NtfsMft => "ntfs-mft",
            Self::UsnJournal => "usn-journal",
            Self::NtfsLogFile => "ntfs-logfile",
            Self::RecycleBin => "recycle-bin",
            Self::DefenderArtifacts => "defender-artifacts",
        }
    }

    fn includes_activity(&self) -> bool {
        matches!(self, Self::All | Self::Activity)
    }

    fn includes_evidence(&self) -> bool {
        matches!(self, Self::All | Self::Evidence)
    }

    fn includes_violations(&self) -> bool {
        matches!(self, Self::All | Self::Violations)
    }

    fn includes_execution(&self) -> bool {
        matches!(self, Self::All | Self::Execution)
    }

    fn includes_prefetch(&self) -> bool {
        matches!(self, Self::All | Self::Prefetch)
    }

    fn includes_jumplist(&self) -> bool {
        matches!(self, Self::All | Self::JumpList)
    }

    fn includes_lnk_shortcuts(&self) -> bool {
        matches!(self, Self::All | Self::LnkShortcuts)
    }

    fn includes_browser_forensics(&self) -> bool {
        matches!(self, Self::All | Self::BrowserForensics)
    }

    fn includes_rdp_remote_access(&self) -> bool {
        matches!(self, Self::All | Self::RdpRemoteAccess)
    }

    fn includes_usb_device_history(&self) -> bool {
        matches!(self, Self::All | Self::UsbDeviceHistory)
    }

    fn includes_restore_shadow_copies(&self) -> bool {
        matches!(self, Self::All | Self::RestoreShadowCopies)
    }

    fn includes_user_activity_mru(&self) -> bool {
        matches!(self, Self::All | Self::UserActivityMru)
    }

    fn includes_timeline_correlation_qa(&self) -> bool {
        matches!(self, Self::All | Self::TimelineCorrelationQa)
    }

    fn includes_srum(&self) -> bool {
        matches!(self, Self::All | Self::Srum)
    }

    fn includes_evtx_security(&self) -> bool {
        matches!(self, Self::All | Self::EvtxSecurity)
    }

    fn includes_evtx_sysmon(&self) -> bool {
        matches!(self, Self::All | Self::EvtxSysmon)
    }

    fn includes_powershell(&self) -> bool {
        matches!(self, Self::All | Self::Powershell)
    }

    fn includes_registry_user_hives(&self) -> bool {
        matches!(self, Self::All | Self::RegistryUserHives)
    }

    fn includes_registry_persistence(&self) -> bool {
        matches!(self, Self::All | Self::RegistryPersistence)
    }

    fn includes_shimcache(&self) -> bool {
        matches!(self, Self::All | Self::Shimcache)
    }

    fn includes_amcache(&self) -> bool {
        matches!(self, Self::All | Self::Amcache)
    }

    fn includes_bam_dam(&self) -> bool {
        matches!(self, Self::All | Self::BamDam)
    }

    fn includes_services_drivers(&self) -> bool {
        matches!(self, Self::All | Self::ServicesDrivers)
    }

    fn includes_scheduled_tasks(&self) -> bool {
        matches!(self, Self::All | Self::ScheduledTasks)
    }

    fn includes_wmi_persistence(&self) -> bool {
        matches!(self, Self::All | Self::WmiPersistence)
    }

    fn includes_ntfs_mft(&self) -> bool {
        matches!(self, Self::All | Self::NtfsMft)
    }

    fn includes_usn_journal(&self) -> bool {
        matches!(self, Self::All | Self::UsnJournal)
    }

    fn includes_ntfs_logfile(&self) -> bool {
        matches!(self, Self::All | Self::NtfsLogFile)
    }

    fn includes_recycle_bin(&self) -> bool {
        matches!(self, Self::All | Self::RecycleBin)
    }

    fn includes_defender_artifacts(&self) -> bool {
        matches!(self, Self::All | Self::DefenderArtifacts)
    }
}

#[derive(serde::Serialize, Clone)]
struct TimelineMergedEvent {
    id: String,
    source: String,
    timestamp_utc: String,
    timestamp_unix: i64,
    event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_category: Option<String>,
    summary: String,
    severity: String,
    case_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    table_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_record_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_json: Option<String>,
}

fn dedupe_timeline_events(events: Vec<TimelineMergedEvent>) -> Vec<TimelineMergedEvent> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut deduped: Vec<TimelineMergedEvent> = Vec::with_capacity(events.len());

    for event in events {
        let dedupe_key = format!(
            "{}|{}|{}|{}|{}",
            event.source, event.id, event.timestamp_unix, event.event_type, event.summary
        );
        if seen.insert(dedupe_key) {
            deduped.push(event);
        }
    }

    deduped
}

fn parse_utc_to_unix_seconds(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.timestamp());
    }

    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        let dt = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc);
        return Some(dt.timestamp());
    }

    trimmed.parse::<i64>().ok()
}

fn unix_seconds_to_utc(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}

fn timeline_scan_limit(limit: usize) -> usize {
    std::cmp::max(
        limit.saturating_mul(TIMELINE_SCAN_MULTIPLIER),
        TIMELINE_PAGE_SIZE,
    )
    .min(TIMELINE_MAX_SCAN_PER_SOURCE)
}

fn json_value_to_unix_seconds(value: &serde_json::Value) -> Option<i64> {
    if let Some(v) = value.as_i64() {
        return Some(v);
    }
    if let Some(v) = value.as_u64() {
        return i64::try_from(v).ok();
    }
    value.as_str().and_then(parse_utc_to_unix_seconds)
}

fn json_field_unix_seconds(
    row: &serde_json::Value,
    unix_field: &str,
    utc_field: &str,
) -> Option<i64> {
    row.get(unix_field)
        .and_then(json_value_to_unix_seconds)
        .or_else(|| row.get(utc_field).and_then(json_value_to_unix_seconds))
}

fn merge_latest_unix(existing: Option<i64>, candidate: Option<i64>) -> Option<i64> {
    match (existing, candidate) {
        (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn increment_executable_counter(
    index: &mut std::collections::HashMap<String, (u32, Option<i64>)>,
    exe_name: String,
    ts: Option<i64>,
) {
    let entry = index.entry(exe_name).or_insert((0, None));
    entry.0 = entry.0.saturating_add(1);
    entry.1 = merge_latest_unix(entry.1, ts);
}

fn normalize_context_observation(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"');
    if trimmed.is_empty()
        || trimmed == "-"
        || trimmed.eq_ignore_ascii_case("n/a")
        || trimmed.eq_ignore_ascii_case("unknown")
        || trimmed.eq_ignore_ascii_case("null")
    {
        return None;
    }
    Some(trimmed.to_string())
}

fn add_context_observation(
    index: &mut std::collections::HashMap<String, std::collections::BTreeSet<String>>,
    exe_name: &str,
    value: Option<&str>,
) {
    let Some(value) = value.and_then(normalize_context_observation) else {
        return;
    };
    index.entry(exe_name.to_string()).or_default().insert(value);
}

fn add_context_observations_from_event_data(
    index: &mut std::collections::HashMap<String, std::collections::BTreeSet<String>>,
    exe_name: &str,
    event_data: &std::collections::BTreeMap<String, String>,
    keys: &[&str],
) {
    for key in keys {
        add_context_observation(index, exe_name, event_data.get(*key).map(String::as_str));
    }
}

fn collect_context_observations(
    index: &std::collections::HashMap<String, std::collections::BTreeSet<String>>,
    exe_name: &str,
) -> Vec<String> {
    index
        .get(exe_name)
        .map(|values| values.iter().take(16).cloned().collect::<Vec<_>>())
        .unwrap_or_default()
}

fn executable_name_from_json_fields(row: &serde_json::Value, fields: &[&str]) -> Option<String> {
    for field in fields {
        if let Some(text) = row.get(*field).and_then(|v| v.as_str()) {
            if let Some(exe) =
                executable_name_from_hint(text).or_else(|| executable_name_from_command_text(text))
            {
                return Some(exe);
            }
        }
    }
    None
}

fn load_defender_artifacts_payload(
    path: &Path,
) -> Result<(serde_json::Value, Option<String>), String> {
    let root: serde_json::Value = read_json_file_with_limit(path, CLI_JSON_INPUT_MAX_BYTES)?;
    let envelope_mode = root
        .as_object()
        .map(|obj| obj.contains_key("command") || obj.contains_key("tool_version"))
        .unwrap_or(false);

    let envelope_note = if envelope_mode {
        let status = root
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if let Some(err) = root.get("error").and_then(|v| v.as_str()) {
            Some(format!("Defender envelope status '{}': {}", status, err))
        } else {
            root.get("warning")
                .and_then(|v| v.as_str())
                .map(|w| format!("Defender envelope status '{}': {}", status, w))
                .or_else(|| {
                    if status.eq_ignore_ascii_case("error") {
                        Some(
                            "Defender envelope status is 'error' with parseable payload"
                                .to_string(),
                        )
                    } else {
                        None
                    }
                })
        }
    } else {
        None
    };

    let payload = if envelope_mode {
        root.get("data")
            .cloned()
            .ok_or_else(|| "Defender envelope missing data payload".to_string())?
    } else {
        root
    };

    if !payload.is_object() {
        return Err(format!(
            "Defender payload must be a JSON object in {}",
            path.display()
        ));
    }

    Ok((payload, envelope_note))
}

fn run_hashset_list(args: commands::hashset::HashsetCommonArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();
    let case_id = args.case.unwrap_or_else(|| {
        eprintln!("Error: --case <id> required");
        std::process::exit(EXIT_VALIDATION);
    });

    let db_path = args.db.unwrap_or_else(|| {
        eprintln!("Error: --db <path> required");
        std::process::exit(EXIT_VALIDATION);
    });
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let conn = open_case_db(&db_path);

    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cases'",
            [],
            |row| row.get::<_, i32>(0),
        )
        .unwrap_or(0)
        > 0;

    let mut data_obj = serde_json::Map::new();
    data_obj.insert("case_id".to_string(), serde_json::json!(case_id));
    data_obj.insert(
        "db_path".to_string(),
        serde_json::json!(db_path.to_string_lossy().to_string()),
    );
    data_obj.insert("hashset_loaded".to_string(), serde_json::json!(false));
    data_obj.insert("nsrl_loaded".to_string(), serde_json::json!(false));
    data_obj.insert("custom_loaded".to_string(), serde_json::json!(false));
    data_obj.insert("known_good_count".to_string(), serde_json::json!(0));
    data_obj.insert("known_bad_count".to_string(), serde_json::json!(0));
    data_obj.insert(
        "os_artifact_patterns".to_string(),
        serde_json::json!([
            "pagefile.sys",
            "hiberfil.sys",
            "swapfile.sys",
            "$mft",
            "$bitmap",
            "$boot",
            "thumbs.db",
            "desktop.ini",
            "ntuser.dat",
            "ntuser.ini"
        ]),
    );

    let mut warnings = Vec::new();
    if !table_exists {
        warnings.push(
            "Case database schema not initialized. Use CaseDatabase::create() for full schema."
                .to_string(),
        );
    }
    warnings.push("Hash sets are not currently persisted to case database. This is a read-only status command.".to_string());

    data_obj.insert(
        "warning".to_string(),
        serde_json::json!(warnings.join("; ")),
    );

    let data = serde_json::Value::Object(data_obj);

    if json_output {
        if !quiet {
            println!(
                "{}",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            );
        }
    } else if !quiet {
        println!("=== Hash Set Status ===");
        println!("Case: {}", case_id);
        println!("Hash Sets Loaded: false");
        println!("NSRL Loaded: false");
        println!("Custom Loaded: false");
        println!("Known Good: 0");
        println!("Known Bad: 0");
        println!();
        for warning in &warnings {
            println!("Warning: {}", warning);
        }
    }

    if let Some(ref json_path) = json_result_path {
        let envelope = CliResultEnvelope::new(
            "hashset list",
            original_args,
            EXIT_OK,
            start_time.elapsed().as_millis() as u64,
        )
        .with_data(data)
        .warn(
            warnings
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        );

        let _ = envelope.write_to_file(json_path);
    }

    std::process::exit(EXIT_OK);
}

fn run_hashset_stats(args: commands::hashset::HashsetCommonArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();
    let case_id = args.case.unwrap_or_else(|| {
        eprintln!("Error: --case <id> required");
        std::process::exit(EXIT_VALIDATION);
    });

    let db_path = args.db.unwrap_or_else(|| {
        eprintln!("Error: --db <path> required");
        std::process::exit(EXIT_VALIDATION);
    });
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let conn = open_case_db(&db_path);

    let mut warnings = Vec::new();

    let files_hashed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM file_table_rows WHERE case_id = ?1 AND hash_sha256 IS NOT NULL",
            rusqlite::params![&case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let evidence_rows_with_hashes: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM evidence WHERE case_id = ?1 AND hash_sha256 IS NOT NULL",
            rusqlite::params![&case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let exhibits_with_hashes: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM exhibits WHERE case_id = ?1 AND hash_sha256 IS NOT NULL",
            rusqlite::params![&case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let carved_files_with_hashes: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM carved_files WHERE case_id = ?1",
            rusqlite::params![&case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let file_table_rows_with_hashes: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM file_table_rows WHERE case_id = ?1 AND hash_sha256 IS NOT NULL",
            rusqlite::params![&case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let total_files_in_case: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM file_table_rows WHERE case_id = ?1",
            rusqlite::params![&case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    warnings
        .push("Match counts unavailable: no hash sets are persisted to case database.".to_string());

    let mut data_obj = serde_json::Map::new();
    data_obj.insert("case_id".to_string(), serde_json::json!(case_id));
    data_obj.insert(
        "db_path".to_string(),
        serde_json::json!(db_path.to_string_lossy().to_string()),
    );
    data_obj.insert("files_hashed".to_string(), serde_json::json!(files_hashed));
    data_obj.insert(
        "evidence_rows_with_hashes".to_string(),
        serde_json::json!(evidence_rows_with_hashes),
    );
    data_obj.insert(
        "exhibits_with_hashes".to_string(),
        serde_json::json!(exhibits_with_hashes),
    );
    data_obj.insert(
        "carved_files_with_hashes".to_string(),
        serde_json::json!(carved_files_with_hashes),
    );
    data_obj.insert(
        "file_table_rows_with_hashes".to_string(),
        serde_json::json!(file_table_rows_with_hashes),
    );
    data_obj.insert(
        "total_files_in_case".to_string(),
        serde_json::json!(total_files_in_case),
    );
    data_obj.insert("hashsets_loaded".to_string(), serde_json::json!(false));
    data_obj.insert("known_good_matches".to_string(), serde_json::json!(null));
    data_obj.insert("known_bad_matches".to_string(), serde_json::json!(null));
    data_obj.insert(
        "unmatched_count".to_string(),
        serde_json::json!(total_files_in_case - files_hashed),
    );

    let mut category_breakdown = serde_json::Map::new();
    category_breakdown.insert("known_good".to_string(), serde_json::json!(null));
    category_breakdown.insert("known_bad".to_string(), serde_json::json!(null));
    category_breakdown.insert("os_artifact".to_string(), serde_json::json!(null));
    category_breakdown.insert("unknown".to_string(), serde_json::json!(files_hashed));
    data_obj.insert(
        "category_breakdown".to_string(),
        serde_json::Value::Object(category_breakdown),
    );

    data_obj.insert(
        "warning".to_string(),
        serde_json::json!(warnings.join("; ")),
    );

    let data = serde_json::Value::Object(data_obj);

    if json_output {
        if !quiet {
            println!(
                "{}",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            );
        }
    } else if !quiet {
        println!("=== Hash Set Statistics ===");
        println!("Case: {}", case_id);
        println!("Files with SHA256: {}", files_hashed);
        println!("Evidence with hashes: {}", evidence_rows_with_hashes);
        println!("Exhibits with hashes: {}", exhibits_with_hashes);
        println!("Carved files: {}", carved_files_with_hashes);
        println!(
            "File table rows with hashes: {}",
            file_table_rows_with_hashes
        );
        println!("Total files in case: {}", total_files_in_case);
        println!("Hash sets loaded: false");
        println!("Known good matches: N/A (no hash sets loaded)");
        println!("Known bad matches: N/A (no hash sets loaded)");
        println!();
        for warning in &warnings {
            println!("Warning: {}", warning);
        }
    }

    if let Some(ref json_path) = json_result_path {
        let envelope = CliResultEnvelope::new(
            "hashset stats",
            original_args,
            EXIT_OK,
            start_time.elapsed().as_millis() as u64,
        )
        .with_data(data)
        .warn(
            warnings
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        );

        let _ = envelope.write_to_file(json_path);
    }

    std::process::exit(EXIT_OK);
}

fn run_hashset_match(args: commands::hashset::HashsetMatchArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();
    let case_id = args.case.unwrap_or_else(|| {
        eprintln!("Error: --case <id> required");
        std::process::exit(EXIT_VALIDATION);
    });
    let db_path = args.db.unwrap_or_else(|| {
        eprintln!("Error: --db <path> required");
        std::process::exit(EXIT_VALIDATION);
    });
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;
    let limit = args.limit.clamp(1, 10_000);

    let mut warnings = Vec::new();
    if args.nsrl.is_none() && args.known_good.is_none() && args.known_bad.is_none() {
        warnings.push("No hashset inputs provided; matching will be empty".to_string());
    }
    let nsrl_path = args.nsrl.clone();
    let known_good_path = args.known_good.clone();
    let known_bad_path = args.known_bad.clone();

    let mut known_good = forensic_engine::hashset::HashSetDB::new();
    let mut known_bad = forensic_engine::hashset::HashSetDB::new();

    // load helpers
    let load_lines_or_csv =
        |path: &PathBuf| -> Result<forensic_engine::hashset::HashSetDB, String> {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            if ext == "csv" {
                forensic_engine::hashset::HashSetDB::load_nsrl_hashes(path)
                    .map_err(|e| format!("Failed to load CSV {}: {}", path.display(), e))
            } else {
                forensic_engine::hashset::HashSetDB::load_from_file(path)
                    .map_err(|e| format!("Failed to load hash list {}: {}", path.display(), e))
            }
        };

    if let Some(ref nsrl) = nsrl_path {
        match load_lines_or_csv(nsrl) {
            Ok(db) => known_good.merge(db),
            Err(e) => warnings.push(e),
        }
    }
    if let Some(ref kg) = known_good_path {
        match load_lines_or_csv(kg) {
            Ok(db) => known_good.merge(db),
            Err(e) => warnings.push(e),
        }
    }
    if let Some(ref kb) = known_bad_path {
        match load_lines_or_csv(kb) {
            Ok(db) => known_bad.merge(db),
            Err(e) => warnings.push(e),
        }
    }

    let conn = open_case_db(&db_path);

    let mut known_good_matches = 0usize;
    let mut known_bad_matches = 0usize;
    let mut sampled = Vec::new();

    let mut stmt = conn
        .prepare(
            "SELECT path, hash_sha256, size_bytes FROM file_table_rows WHERE case_id = ?1 AND hash_sha256 IS NOT NULL",
        )
        .unwrap_or_else(|e| {
            eprintln!("DB error: {}", e);
            std::process::exit(EXIT_ERROR);
        });

    let rows = stmt
        .query_map(rusqlite::params![&case_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2).ok(),
            ))
        })
        .unwrap_or_else(|e| {
            eprintln!("DB read error: {}", e);
            std::process::exit(EXIT_ERROR);
        });

    for row in rows.flatten() {
        let (path, sha256, size_opt) = row;
        let mut category = "unknown";
        if known_bad.contains_sha256(&sha256) {
            known_bad_matches += 1;
            category = "known_bad";
        } else if known_good.contains_sha256(&sha256) {
            known_good_matches += 1;
            category = "known_good";
        }
        if category != "unknown" && sampled.len() < limit {
            sampled.push(serde_json::json!({
                "path": path,
                "sha256": sha256,
                "size_bytes": size_opt,
                "category": category,
            }));
        }
    }

    let total_hashed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM file_table_rows WHERE case_id = ?1 AND hash_sha256 IS NOT NULL",
            rusqlite::params![&case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let data = serde_json::json!({
        "case_id": case_id,
        "db_path": db_path.to_string_lossy().to_string(),
        "inputs": {
            "nsrl": nsrl_path
                .as_ref()
                .map(|p: &PathBuf| p.to_string_lossy().to_string()),
            "known_good": known_good_path
                .as_ref()
                .map(|p: &PathBuf| p.to_string_lossy().to_string()),
            "known_bad": known_bad_path
                .as_ref()
                .map(|p: &PathBuf| p.to_string_lossy().to_string()),
        },
        "hash_counts": {
            "known_good_loaded": known_good.count(),
            "known_bad_loaded": known_bad.count(),
        },
        "match_counts": {
            "known_good": known_good_matches,
            "known_bad": known_bad_matches,
            "total_hashed": total_hashed,
        },
        "samples": sampled,
        "limit": limit
    });

    if json_output && !quiet {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else if !quiet {
        println!("=== Hashset Match ===");
        println!("Known-good loaded: {}", known_good.count());
        println!("Known-bad loaded: {}", known_bad.count());
        println!("Known-good matches: {}", known_good_matches);
        println!("Known-bad matches: {}", known_bad_matches);
    }

    if let Some(path) = json_result_path {
        let mut envelope = CliResultEnvelope::new(
            "hashset match",
            original_args,
            EXIT_OK,
            start_time.elapsed().as_millis() as u64,
        )
        .with_data(data);
        if !warnings.is_empty() {
            envelope = envelope.warn(warnings.join("; "));
        }
        let _ = envelope.write_to_file(&path);
    }
}

fn default_jumplist_path() -> PathBuf {
    if let Ok(appdata) = env::var("APPDATA") {
        return PathBuf::from(appdata)
            .join("Microsoft")
            .join("Windows")
            .join("Recent")
            .join("AutomaticDestinations");
    }
    if let Ok(userprofile) = env::var("USERPROFILE") {
        return PathBuf::from(userprofile)
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("Recent")
            .join("AutomaticDestinations");
    }
    PathBuf::from("evidence").join("jumplist")
}

fn default_shortcuts_base() -> PathBuf {
    env::var("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\Users\\Default"))
}

fn default_srum_path() -> PathBuf {
    PathBuf::from("artifacts").join("srum").join("srum.json")
}

fn default_evtx_security_path() -> PathBuf {
    PathBuf::from("artifacts")
        .join("security")
        .join("Security.evtx")
}

fn default_evtx_sysmon_path() -> PathBuf {
    PathBuf::from("artifacts")
        .join("security")
        .join("Sysmon.evtx")
}

fn default_powershell_history_path() -> PathBuf {
    if let Ok(user_profile) = env::var("USERPROFILE") {
        return PathBuf::from(user_profile)
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("PowerShell")
            .join("PSReadLine")
            .join("ConsoleHost_history.txt");
    }
    PathBuf::from("artifacts")
        .join("powershell")
        .join("ConsoleHost_history.txt")
}

fn default_powershell_script_log_path() -> PathBuf {
    PathBuf::from("artifacts")
        .join("powershell")
        .join("script_block.log")
}

fn default_powershell_events_path() -> PathBuf {
    PathBuf::from("artifacts")
        .join("powershell")
        .join("ps_events.json")
}

fn default_powershell_transcripts_dir() -> PathBuf {
    PathBuf::from("artifacts")
        .join("powershell")
        .join("Transcripts")
}

fn default_powershell_modules_path() -> PathBuf {
    PathBuf::from("artifacts")
        .join("powershell")
        .join("modules.txt")
}

fn executable_name_from_hint(value: &str) -> Option<String> {
    let normalized = value.trim().trim_matches('"').replace('/', "\\");
    if normalized.is_empty() {
        return None;
    }

    let candidate = normalized
        .rsplit('\\')
        .next()
        .unwrap_or(normalized.as_str())
        .trim()
        .trim_end_matches([';', ',', ')']);
    let lowered = candidate.to_ascii_lowercase();
    let is_executable = [
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".com", ".msi", ".scr",
    ]
    .iter()
    .any(|ext| lowered.ends_with(ext));
    if is_executable {
        Some(lowered)
    } else {
        None
    }
}

fn executable_name_from_command_text(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        return None;
    }
    for token in value.split_whitespace() {
        let candidate = token.trim_matches(|c: char| {
            c == '"'
                || c == '\''
                || c == ','
                || c == ';'
                || c == '('
                || c == ')'
                || c == '['
                || c == ']'
        });
        if let Some(exe) = executable_name_from_hint(candidate) {
            return Some(exe);
        }
    }
    executable_name_from_hint(value)
}

fn powershell_severity(value: &str) -> &'static str {
    let lower = value.to_ascii_lowercase();
    if lower.contains("invoke-expression")
        || lower.contains(" downloadstring")
        || lower.contains("frombase64string")
        || lower.contains(" -enc")
        || lower.contains(" -encodedcommand")
        || lower.contains("iex ")
    {
        "warn"
    } else {
        "info"
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PowershellInputShape {
    Missing,
    Directory,
    Empty,
    JsonArray,
    JsonObject,
    PipeDelimited,
    CsvDelimited,
    LineText,
    Unknown,
}

impl PowershellInputShape {
    fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Directory => "directory",
            Self::Empty => "empty",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::PipeDelimited => "pipe-delimited",
            Self::CsvDelimited => "csv-delimited",
            Self::LineText => "line-text",
            Self::Unknown => "unknown",
        }
    }
}

fn detect_powershell_input_shape(path: &Path, expect_directory: bool) -> PowershellInputShape {
    if !path.exists() {
        return PowershellInputShape::Missing;
    }
    if path.is_dir() {
        return PowershellInputShape::Directory;
    }
    if expect_directory {
        return PowershellInputShape::Unknown;
    }

    let Ok(bytes) = strata_fs::read(path) else {
        return PowershellInputShape::Unknown;
    };
    if bytes.is_empty() {
        return PowershellInputShape::Empty;
    }

    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return PowershellInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return PowershellInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return PowershellInputShape::JsonObject;
    }
    let first_line = trimmed.lines().next().unwrap_or(trimmed);
    if first_line.contains('|') {
        return PowershellInputShape::PipeDelimited;
    }
    if first_line.contains(',') {
        return PowershellInputShape::CsvDelimited;
    }
    PowershellInputShape::LineText
}

fn powershell_record_dedupe_key(row: &serde_json::Value) -> String {
    let source = row
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let timestamp = row
        .get("timestamp_unix")
        .and_then(|v| v.as_i64())
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".to_string());
    let primary = row
        .get("command")
        .or_else(|| row.get("script_path"))
        .or_else(|| row.get("script"))
        .or_else(|| row.get("path"))
        .or_else(|| row.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let secondary = row
        .get("parameters")
        .or_else(|| row.get("result"))
        .or_else(|| row.get("version"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    format!("{source}|{timestamp}|{primary}|{secondary}")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RegistryInputShape {
    Missing,
    Empty,
    RegExportText,
    JsonArray,
    JsonObject,
    LineText,
    Unknown,
}

impl RegistryInputShape {
    fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::RegExportText => "reg-export-text",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::LineText => "line-text",
            Self::Unknown => "unknown",
        }
    }
}

fn detect_registry_input_shape(path: &Path) -> RegistryInputShape {
    if !path.exists() {
        return RegistryInputShape::Missing;
    }
    let Ok(bytes) = strata_fs::read(path) else {
        return RegistryInputShape::Unknown;
    };
    if bytes.is_empty() {
        return RegistryInputShape::Empty;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return RegistryInputShape::Empty;
    }
    if trimmed.starts_with("Windows Registry Editor") || trimmed.starts_with('[') {
        return RegistryInputShape::RegExportText;
    }
    if trimmed.starts_with('{') {
        return RegistryInputShape::JsonObject;
    }
    if trimmed.starts_with('[') {
        return RegistryInputShape::JsonArray;
    }
    RegistryInputShape::LineText
}

fn parse_registry_text_fallback(path: &Path, source: &str) -> Vec<serde_json::Value> {
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('[')
            || trimmed.starts_with(';')
            || trimmed.starts_with("Windows Registry Editor")
        {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().trim_matches('"');
            let value = v.trim().trim_matches('"');
            if key.is_empty() && value.is_empty() {
                continue;
            }
            out.push(serde_json::json!({
                "source": source,
                "event_type": "registry-value",
                "timestamp_unix": serde_json::Value::Null,
                "timestamp_utc": serde_json::Value::Null,
                "timestamp_precision": "none",
                "severity": "info",
                "key": key,
                "value": value,
                "executable_name": executable_name_from_command_text(value)
                    .or_else(|| executable_name_from_hint(value))
            }));
        }
    }
    out
}

#[derive(Debug, Deserialize)]
struct SelectionJsonInput {
    context: forensic_engine::case::exhibit_packet::SelectionContext,
    items: Vec<forensic_engine::case::exhibit_packet::SelectionItem>,
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[allow(dead_code)]
fn unix_time_to_string(ts: i64) -> String {
    if ts <= 0 {
        return "N/A".to_string();
    }
    let secs = ts / 10_000_000;
    let nanos = (ts % 10_000_000) as u32 * 100;
    if let Some(t) = std::time::UNIX_EPOCH.checked_add(std::time::Duration::new(secs as u64, nanos))
    {
        let datetime: time::OffsetDateTime = t.into();
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            datetime.year(),
            datetime.month(),
            datetime.day(),
            datetime.hour(),
            datetime.minute(),
            datetime.second()
        )
    } else {
        format!("{}", ts)
    }
}

#[allow(dead_code)]
fn run_smoke_test_help() {
    println!("Usage: forensic-cli smoke-test [options]");
    println!();
    println!("Options:");
    println!("  --image <path>      Path to image file (required)");
    println!("  --out <dir>         Output directory (default: .\\exports\\smoke_test)");
    println!("  --mft <count>       MFT record count (default: 50)");
    println!("  --no-timeline       Skip timeline CSV generation");
    println!("  --no-audit         Skip audit JSON generation");
    println!("  --quiet            Only print final one-line status");
    println!("  --json-summary <path> Path for summary JSON");
    println!("  --help, -h         Show this help message");
    std::process::exit(0);
}

#[derive(serde::Serialize)]
struct SmokeTestResult {
    tool_version: String,
    timestamp_utc: String,
    platform: String,
    image_path: String,
    out_dir: String,
    mft_count: u32,
    timeline_enabled: bool,
    audit_enabled: bool,
    did_open_image: bool,
    evidence_size_bytes: u64,
    bytes_actually_read: u64,
    sample_sha256: Option<String>,
    container_type: Option<String>,
    filesystem_detected: Option<String>,
    mft_records_attempted: u32,
    mft_records_emitted: u32,
    analysis_mode: String,
    analysis_valid: bool,
    warning: Option<String>,
    outputs: SmokeTestOutputs,
    sizes: SmokeTestSizes,
    elapsed_ms: u64,
    status: String,
    error: Option<String>,
}

#[derive(serde::Serialize)]
struct SmokeTestOutputs {
    #[serde(rename = "summary_txt")]
    summary_txt: Option<String>,
    #[serde(rename = "timeline_csv")]
    timeline_csv: Option<String>,
    #[serde(rename = "audit_json")]
    audit_json: Option<String>,
    #[serde(rename = "json_summary")]
    json_summary: Option<String>,
}

#[derive(serde::Serialize)]
struct SmokeTestSizes {
    #[serde(rename = "summary_txt")]
    summary_txt: u64,
    #[serde(rename = "timeline_csv")]
    timeline_csv: u64,
    #[serde(rename = "audit_json")]
    audit_json: u64,
    #[serde(rename = "json_summary")]
    json_summary: u64,
}

#[derive(Parser, Debug)]
#[command(name = "forensic_cli", version, about = "Strata Shield Forensic CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum Commands {
    Verify(commands::verify::VerifyArgs),
    Export(commands::export::ExportArgs),
    VerifyExport(commands::verify_export::VerifyExportArgs),
    Replay(commands::replay::ReplayArgs),
    ReplayVerify(commands::replay_verify::ReplayVerifyArgs),
    Watchpoints(commands::watchpoints::WatchpointsArgs),
    Violations(commands::violations::ViolationsArgs),
    Timeline(commands::timeline::TimelineArgs),
    Artifacts(commands::artifacts::ArtifactsArgs),
    Hashset(commands::hashset::HashsetArgs),
    Srum(commands::srum::SrumArgs),
    EvtxSecurity(commands::evtx_security::EvtxSecurityArgs),
    EvtxSysmon(commands::evtx_sysmon::EvtxSysmonArgs),
    PowershellArtifacts(commands::powershell_artifacts::PowershellArgs),
    RegistryCoreUserHives(commands::registry_core_user_hives::RegistryCoreUserHivesArgs),
    RegistryPersistence(commands::registry_persistence::RegistryPersistenceArgs),
    ShimcacheDeep(commands::shimcache_deep::ShimcacheDeepArgs),
    AmcacheDeep(commands::amcache_deep::AmcacheDeepArgs),
    BamDamActivity(commands::bam_dam_activity::BamDamActivityArgs),
    ServicesDriversArtifacts(commands::services_drivers_artifacts::ServicesDriversArgs),
    ScheduledTasksArtifacts(commands::scheduled_tasks_artifacts::ScheduledTasksArtifactsArgs),
    WmiPersistenceActivity(commands::wmi_persistence_activity::WmiArgs),
    NtfsMftFidelity(commands::ntfs_mft_fidelity::NtfsMftFidelityArgs),
    UsnJournalFidelity(commands::usn_journal_fidelity::UsnJournalFidelityArgs),
    NtfsLogfileSignals(commands::ntfs_logfile_signals::NtfsLogfileSignalsArgs),
    RecycleBinArtifacts(commands::recycle_bin_artifacts::RecycleBinArtifactsArgs),
    PrefetchFidelity(commands::prefetch_fidelity::PrefetchFidelityArgs),
    JumplistFidelity(commands::jumplist_fidelity::JumplistFidelityArgs),
    LnkShortcutFidelity(commands::lnk_shortcut_fidelity::LnkShortcutFidelityArgs),
    BrowserForensics(commands::browser_forensics::BrowserForensicsArgs),
    RdpRemoteAccess(commands::rdp_remote_access::RdpRemoteAccessArgs),
    UsbDeviceHistory(commands::usb_device_history::UsbDeviceHistoryArgs),
    RestoreShadowCopies(commands::restore_shadow_copies::RestoreShadowCopiesArgs),
    UserActivityMru(commands::user_activity_mru::UserActivityMruArgs),
    TimelineCorrelationQa(commands::timeline_correlation_qa::TimelineCorrelationQaArgs),
    DefenderArtifacts(commands::defender_artifacts::DefenderArgs),
    ExecutionCorrelation(commands::execution_correlation::ExecutionCorrelationArgs),
    RecentExecution(commands::execution_correlation::ExecutionCorrelationArgs),
    ViolationsClear(commands::violations_clear::ViolationsClearArgs),
    Presets(commands::presets::PresetsArgs),
    Capabilities(commands::capabilities::CapabilitiesArgs),
    MacosCatalog(commands::macos_catalog::MacosCatalogArgs),
    OpenEvidence(commands::open_evidence::OpenEvidenceArgs),
    Examine(commands::examine::ExamineArgs),
    Case(commands::case::CaseArgs),
    Ingest(commands::ingest::IngestArgs),
    Doctor(commands::doctor::DoctorArgs),
    TriageSession(commands::triage_session::TriageSessionArgs),
    AddToNotes(commands::add_to_notes::AddToNotesArgs),
    Ioc(commands::ioc::IocArgs),
    Search(commands::search::SearchArgs),
    Strings(commands::strings::StringsArgs),
    Carve(commands::carve::CarveArgs),
    Unallocated(commands::unallocated::UnallocatedArgs),
    Filetable(commands::filetable::FiletableArgs),
    Worker(commands::worker::WorkerArgs),
    /// Generate a court-ready examiner report from a Strata case directory.
    Report(commands::report::ReportArgs),
    ReportSkeleton(commands::report_skeleton::ReportSkeletonArgs),
    Score(commands::score::ScoreArgs),
    SmokeTest(commands::smoke_test::SmokeTestArgs),
    Image(commands::image::ImageArgs),
    #[command(external_subcommand)]
    External(Vec<String>),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let original_args: Vec<String> = std::env::args().skip(1).collect();
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify(args) => commands::verify::execute(args, original_args),
        Commands::Export(args) => commands::export::execute(args),
        Commands::VerifyExport(args) => commands::verify_export::execute(args),
        Commands::Replay(args) => commands::replay::execute(args, original_args),
        Commands::ReplayVerify(args) => commands::replay_verify::execute(args),
        Commands::Watchpoints(args) => commands::watchpoints::execute(args, original_args),
        Commands::Violations(args) => commands::violations::execute(args, original_args),
        Commands::Timeline(args) => commands::timeline::execute(args),
        Commands::Artifacts(args) => commands::artifacts::execute(args, original_args),
        Commands::Hashset(args) => commands::hashset::execute(args, original_args),
        Commands::Srum(args) => commands::srum::execute(args),
        Commands::EvtxSecurity(args) => commands::evtx_security::execute(args, original_args),
        Commands::EvtxSysmon(args) => commands::evtx_sysmon::execute(args, original_args),
        Commands::PowershellArtifacts(args) => {
            commands::powershell_artifacts::execute(args, "powershell-artifacts", original_args)
        }
        Commands::RegistryCoreUserHives(args) => commands::registry_core_user_hives::execute(
            args,
            "registry-core-user-hives",
            original_args,
        ),
        Commands::RegistryPersistence(args) => {
            commands::registry_persistence::execute(args, original_args)
        }
        Commands::ShimcacheDeep(args) => commands::shimcache_deep::execute(args),
        Commands::AmcacheDeep(args) => commands::amcache_deep::execute(args),
        Commands::BamDamActivity(args) => commands::bam_dam_activity::execute(args),
        Commands::ServicesDriversArtifacts(args) => commands::services_drivers_artifacts::execute(
            args,
            "services-drivers-artifacts",
            original_args,
        ),
        Commands::ScheduledTasksArtifacts(args) => {
            commands::scheduled_tasks_artifacts::execute(args, original_args)
        }
        Commands::WmiPersistenceActivity(args) => commands::wmi_persistence_activity::execute(
            args,
            "wmi-persistence-activity",
            original_args,
        ),
        Commands::NtfsMftFidelity(args) => {
            commands::ntfs_mft_fidelity::execute(args, original_args)
        }
        Commands::UsnJournalFidelity(args) => {
            commands::usn_journal_fidelity::execute(args, original_args)
        }
        Commands::NtfsLogfileSignals(args) => {
            commands::ntfs_logfile_signals::execute(args, original_args)
        }
        Commands::RecycleBinArtifacts(args) => {
            commands::recycle_bin_artifacts::execute(args, original_args)
        }
        Commands::PrefetchFidelity(args) => {
            commands::prefetch_fidelity::execute(args, original_args)
        }
        Commands::JumplistFidelity(args) => {
            commands::jumplist_fidelity::execute(args, original_args)
        }
        Commands::LnkShortcutFidelity(args) => {
            commands::lnk_shortcut_fidelity::execute(args, original_args)
        }
        Commands::BrowserForensics(args) => {
            commands::browser_forensics::execute(args, original_args)
        }
        Commands::RdpRemoteAccess(args) => {
            commands::rdp_remote_access::execute(args, original_args)
        }
        Commands::UsbDeviceHistory(args) => {
            commands::usb_device_history::execute(args, original_args)
        }
        Commands::RestoreShadowCopies(args) => {
            commands::restore_shadow_copies::execute(args, original_args)
        }
        Commands::UserActivityMru(args) => commands::user_activity_mru::execute(args),
        Commands::TimelineCorrelationQa(args) => {
            commands::timeline_correlation_qa::execute(args, original_args)
        }
        Commands::DefenderArtifacts(args) => {
            commands::defender_artifacts::execute(args, "defender-artifacts", original_args)
        }
        Commands::ExecutionCorrelation(args) => {
            commands::execution_correlation::execute(args, "execution-correlation", original_args)
        }
        Commands::RecentExecution(args) => {
            commands::execution_correlation::execute(args, "recent-execution", original_args)
        }
        Commands::ViolationsClear(args) => commands::violations_clear::execute(args),
        Commands::Presets(args) => commands::presets::execute(args),
        Commands::Capabilities(args) => commands::capabilities::execute(args, original_args),
        Commands::MacosCatalog(args) => commands::macos_catalog::execute(args),
        Commands::OpenEvidence(args) => commands::open_evidence::execute(args),
        Commands::Examine(args) => commands::examine::execute(args, original_args),
        Commands::Case(args) => commands::case::execute(args),
        Commands::Ingest(args) => commands::ingest::execute(args),
        Commands::Doctor(args) => commands::doctor::execute(args, original_args),
        Commands::TriageSession(args) => commands::triage_session::execute(args, original_args),
        Commands::AddToNotes(args) => commands::add_to_notes::execute(args),
        Commands::Ioc(args) => commands::ioc::execute(args),
        Commands::Search(args) => commands::search::execute(args),
        Commands::Strings(args) => commands::strings::execute(args),
        Commands::Carve(args) => commands::carve::execute(args),
        Commands::Unallocated(args) => commands::unallocated::execute(args),
        Commands::Filetable(args) => commands::filetable::execute(args),
        Commands::Worker(args) => commands::worker::execute(args),
        Commands::Report(args) => {
            std::process::exit(commands::report::execute(args));
        }
        Commands::ReportSkeleton(args) => commands::report_skeleton::execute(args),
        Commands::Score(args) => commands::score::execute(args),
        Commands::SmokeTest(args) => commands::smoke_test::execute(args, original_args),
        Commands::Image(args) => commands::image::execute(args),
        Commands::External(values) => {
            if values.is_empty() {
                eprintln!("Error: Missing command. Run with --help for usage.");
                std::process::exit(1);
            }
            let first_arg = values[0].clone();
            if first_arg.ends_with(".E01")
                || first_arg.ends_with(".001")
                || first_arg.ends_with(".dd")
                || first_arg.ends_with(".img")
                || first_arg.ends_with(".raw")
                || std::path::Path::new(&first_arg).exists()
            {
                let mut image_args = vec!["image".to_string()];
                image_args.extend(values);
                let parsed = commands::image::ImageArgs::parse_from(image_args);
                commands::image::execute(parsed);
            } else {
                eprintln!(
                    "Error: Unknown command '{}'. Run with --help for usage.",
                    first_arg
                );
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_json_file_with_limit_parses_small_json() {
        let dir = std::env::temp_dir().join(format!("forensic_cli_json_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("small.json");
        std::fs::write(&path, br#"{"mode":"ok","value":1}"#).unwrap();

        let parsed: serde_json::Value = read_json_file_with_limit(&path, 1024).unwrap();
        assert_eq!(parsed["mode"], "ok");
        assert_eq!(parsed["value"], 1);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_json_file_with_limit_rejects_oversized_json() {
        let dir = std::env::temp_dir().join(format!("forensic_cli_json_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("large.json");

        let large_body = "x".repeat(2048);
        let data = format!(r#"{{"payload":"{}"}}"#, large_body);
        std::fs::write(&path, data).unwrap();

        let result = read_json_file_with_limit::<serde_json::Value>(&path, 128);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too large"));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
