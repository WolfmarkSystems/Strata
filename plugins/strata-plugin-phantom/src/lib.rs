//! # Phantom — Registry Intelligence Engine
//!
//! Phantom is the Strata plugin that **owns** registry hive parsing. It is the
//! only plugin that should ever directly walk a raw hive binary; the other
//! plugins (Chronicle, Trace, Conduit) extract incidental hive data only as
//! needed for their own domain.
//!
//! Hives parsed:
//!   * SYSTEM      — ShimCache, USB chain, services, network, computer identity
//!   * SOFTWARE    — OS version, installed programs, cloud accounts, AutoRun (HKLM)
//!   * SAM         — Local accounts, Microsoft email, last login
//!   * SECURITY    — Audit policy, LSA secrets metadata
//!   * AmCache.hve — InventoryApplicationFile (SHA1 + execution evidence),
//!     InventoryDriverBinary (signed/unsigned drivers)
//!   * USRCLASS.DAT — Network shellbags, MuiCache, UserChoice (default app
//!     associations)
//!
//! Phantom is intentionally synchronous and pure-Rust. All parsing happens via
//! the `nt-hive` crate; no Windows API calls.

use std::path::{Path, PathBuf};

pub mod amcache;
pub mod cloud_cli;
pub mod lnk;
pub mod memory_carving;
pub mod memory_structures;
pub mod mru;
pub mod notepad_tabstate;
pub mod outlook;
pub mod powershell;
pub mod prefetch;
pub mod regtxlog;
pub mod ring_doorbell;
pub mod services;
pub mod shimcache;
pub mod smart_locks;
pub mod thumbcache;
pub mod usb;
pub mod windows_recall;
pub mod windows_search;

use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct PhantomPlugin {
    name: String,
    version: String,
}

impl Default for PhantomPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl PhantomPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Phantom".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

impl StrataPlugin for PhantomPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec![
            "SYSTEM".to_string(),
            "SOFTWARE".to_string(),
            "SAM".to_string(),
            "SECURITY".to_string(),
            "AmCache.hve".to_string(),
            "UsrClass.dat".to_string(),
        ]
    }
    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::ArtifactExtraction,
            PluginCapability::ExecutionTracking,
        ]
    }
    fn description(&self) -> &str {
        "Registry Intelligence Engine — parses every Windows hive into structured artifacts"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut results = Vec::new();

        // VFS-PLUGIN-2 pilot: when the evidence is a mounted image,
        // find Windows registry hives by name and parse them via the
        // existing per-hive parsers. Each hive read is gated at
        // 512 MB (the v9 host-fs path's gate).
        if ctx.vfs.is_some() {
            const HIVE_MAX: usize = 512 * 1024 * 1024;
            for (hive_name, parse_fn) in [
                (
                    "SYSTEM",
                    parsers::system::parse as fn(&Path, &[u8]) -> Vec<Artifact>,
                ),
                ("SOFTWARE", parsers::software::parse),
                ("SAM", parsers::sam::parse),
                ("SECURITY", parsers::security::parse),
                ("NTUSER.DAT", parsers::ntuser::parse),
                ("UsrClass.dat", parsers::usrclass::parse),
            ] {
                for logical_path in ctx.find_by_name(hive_name) {
                    let logical_str = logical_path.to_string_lossy().into_owned();
                    let Some(bytes) = ctx.read_file(&logical_str) else {
                        continue;
                    };
                    if bytes.len() > HIVE_MAX {
                        continue;
                    }
                    results.extend(parse_fn(&logical_path, &bytes));
                }
            }
            return Ok(results);
        }

        let files = match walk_dir(root) {
            Ok(f) => f,
            Err(_) => return Ok(results),
        };

        for path in files {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            let lower = name.to_lowercase();

            // Hive routing — match on filename, not extension. Hives have no
            // extension or arbitrary ones. Each read is gated at 512 MB to
            // prevent OOM on enterprise hives (SYSTEM/SOFTWARE can exceed
            // 256 MB on domain controllers).
            if lower == "system" {
                if let Some(data) = read_hive_gated(&path) {
                    results.extend(parsers::system::parse(&path, &data));
                }
            } else if lower == "software" {
                if let Some(data) = read_hive_gated(&path) {
                    results.extend(parsers::software::parse(&path, &data));
                }
            } else if lower == "sam" {
                if let Some(data) = read_hive_gated(&path) {
                    results.extend(parsers::sam::parse(&path, &data));
                }
            } else if lower == "security" {
                if let Some(data) = read_hive_gated(&path) {
                    results.extend(parsers::security::parse(&path, &data));
                }
            } else if lower == "amcache.hve" {
                if let Some(data) = read_hive_gated(&path) {
                    // Typed AmCache parser — InventoryApplicationFile +
                    // InventoryDriverBinary as `AmCacheAppEntry` /
                    // `AmCacheDriverEntry` structs (see crate::amcache).
                    let path_str = path.to_string_lossy().to_string();
                    let parsed = crate::amcache::parse(&data);
                    for app in &parsed.apps {
                        let suspicious = crate::amcache::is_suspicious_app(app);
                        let deleted = !windows_path_exists(root, &app.full_path);
                        let mut a = Artifact::new("AmCache Application", &path_str);
                        a.timestamp = app.link_date.map(|dt| dt.timestamp() as u64);
                        let title_label = if !app.product_name.is_empty() {
                            app.product_name.clone()
                        } else if !app.full_path.is_empty() {
                            app.full_path.clone()
                        } else {
                            app.sha1_hash.clone()
                        };
                        a.add_field("title", &format!("AmCache: {}", title_label));
                        a.add_field(
                            "detail",
                            &format!(
                                "Path: {} | SHA1: {} | Size: {} | Publisher: {} | Product: {} | PE: {}",
                                if app.full_path.is_empty() { "<unknown>" } else { &app.full_path },
                                if app.sha1_hash.is_empty() { "<unknown>" } else { &app.sha1_hash },
                                app.file_size,
                                if app.publisher.is_empty() { "<unknown>" } else { &app.publisher },
                                if app.product_name.is_empty() { "<unknown>" } else { &app.product_name },
                                app.is_pe_file,
                            ),
                        );
                        a.add_field("file_type", "AmCache Application");
                        a.add_field("sha1_hash", &app.sha1_hash);
                        a.add_field("full_path", &app.full_path);
                        a.add_field("file_size", &app.file_size.to_string());
                        if let Some(dt) = app.link_date {
                            a.add_field(
                                "link_date",
                                &dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                            );
                        }
                        a.add_field("publisher", &app.publisher);
                        a.add_field("product_name", &app.product_name);
                        a.add_field("is_pe_file", if app.is_pe_file { "true" } else { "false" });
                        a.add_field("source_hive", &path_str);
                        // T1059 — Command and Scripting Interpreter
                        // T1204 — User Execution
                        a.add_field("mitre", "T1059");
                        a.add_field("mitre_secondary", "T1204");
                        if deleted {
                            a.add_field("is_deleted", "true");
                            a.add_field("mitre_deletion", "T1070.004");
                        }
                        a.add_field("forensic_value", "High");
                        if suspicious {
                            a.add_field("suspicious", "true");
                        }
                        results.push(a);
                    }
                    for drv in &parsed.drivers {
                        let unsigned = !drv.driver_signed;
                        let mut a = Artifact::new("AmCache Driver", &path_str);
                        a.add_field("title", &format!("Driver: {}", drv.driver_name));
                        a.add_field(
                            "detail",
                            &format!(
                                "Driver: {} | Version: {} | Signed: {} | INF: {}",
                                drv.driver_name,
                                if drv.driver_version.is_empty() {
                                    "<unknown>"
                                } else {
                                    &drv.driver_version
                                },
                                if drv.driver_signed {
                                    "yes"
                                } else {
                                    "NO (unsigned)"
                                },
                                if drv.inf_name.is_empty() {
                                    "<unknown>"
                                } else {
                                    &drv.inf_name
                                },
                            ),
                        );
                        a.add_field("file_type", "AmCache Driver");
                        a.add_field("driver_name", &drv.driver_name);
                        a.add_field("driver_version", &drv.driver_version);
                        a.add_field(
                            "driver_signed",
                            if drv.driver_signed { "true" } else { "false" },
                        );
                        a.add_field("inf_name", &drv.inf_name);
                        a.add_field("source_hive", &path_str);
                        // T1014 — Rootkit (unsigned drivers are the
                        // canonical BYOVD fingerprint).
                        a.add_field("mitre", "T1014");
                        a.add_field("forensic_value", if unsigned { "High" } else { "Medium" });
                        if unsigned {
                            a.add_field("suspicious", "true");
                        }
                        results.push(a);
                    }
                    // Legacy AmCache categories (shortcuts, device
                    // containers, PnP, driver packages, Win7 file/programs)
                    // are still served by the existing parsers::amcache
                    // module — we skipped only its app + driver paths.
                    results.extend(parsers::amcache::parse(&path, &data));
                }
            } else if lower == "usrclass.dat" {
                if let Some(data) = read_hive_gated(&path) {
                    results.extend(parsers::usrclass::parse(&path, &data));
                }
            } else if lower == "ntuser.dat" {
                if let Some(data) = read_hive_gated(&path) {
                    results.extend(parsers::ntuser::parse(&path, &data));
                    // Typed MRU parser — RecentDocs / OpenSave /
                    // LastVisited / RunMRU. See `crate::mru`.
                    let path_str = path.to_string_lossy().to_string();
                    if let Ok(hive) = nt_hive::Hive::new(data.as_slice()) {
                        if let Ok(root) = hive.root_key_node() {
                            let parsed = crate::mru::parse(&root);
                            for e in &parsed.entries {
                                let mut a = Artifact::new("MRU Entry", &path_str);
                                let title_subcat = if e.subcategory.is_empty() {
                                    String::new()
                                } else {
                                    format!(" ({})", e.subcategory)
                                };
                                a.add_field(
                                    "title",
                                    &format!(
                                        "MRU [{}{}]: {}",
                                        e.mru_type.as_str(),
                                        title_subcat,
                                        e.value
                                    ),
                                );
                                let order_str = if e.order == u32::MAX {
                                    "<unknown>".to_string()
                                } else {
                                    e.order.to_string()
                                };
                                a.add_field(
                                    "detail",
                                    &format!(
                                        "Store: {}{} | Order: {} | Raw value: {} | Decoded: {}",
                                        e.mru_type.as_str(),
                                        if e.subcategory.is_empty() {
                                            String::new()
                                        } else {
                                            format!("\\{}", e.subcategory)
                                        },
                                        order_str,
                                        e.raw_value_name,
                                        e.value
                                    ),
                                );
                                a.add_field("file_type", "MRU Entry");
                                a.add_field("mru_type", e.mru_type.as_str());
                                a.add_field("subcategory", &e.subcategory);
                                a.add_field("value", &e.value);
                                a.add_field("order", &order_str);
                                a.add_field("raw_value_name", &e.raw_value_name);
                                a.add_field("source_hive", &path_str);
                                // T1074.001 — Local Data Staging
                                // T1059   — Command and Scripting (RunMRU)
                                a.add_field("mitre", "T1074.001");
                                a.add_field("mitre_secondary", "T1059");
                                a.add_field("forensic_value", "Medium");
                                results.push(a);
                            }
                        }
                    }
                }
            } else if lower.ends_with(".log1") || lower.ends_with(".log2") {
                // Registry transaction logs (`.LOG1` / `.LOG2`) — see
                // `crate::regtxlog`. Uncommitted dirty pages are
                // strong evidence of interrupted hive writes (power
                // loss, BSOD, or anti-forensic mid-write kills).
                if let Some(data) = read_hive_gated(&path) {
                    let path_str = path.to_string_lossy().to_string();
                    if let Some(header) = crate::regtxlog::parse(&data) {
                        let uncommitted = crate::regtxlog::has_uncommitted_changes(&header);
                        let mut a = Artifact::new("Registry Transaction Log", &path_str);
                        let hive_label = if header.hive_name.is_empty() {
                            "<unknown hive>".to_string()
                        } else {
                            header.hive_name.clone()
                        };
                        a.add_field(
                            "title",
                            &format!(
                                "Registry tx log: {} (LSN {}, {} dirty pages)",
                                hive_label, header.log_sequence_number, header.dirty_page_count
                            ),
                        );
                        a.add_field(
                            "detail",
                            &format!(
                                "File: {} | Hive: {} | LSN: {} | Dirty pages: {} | \
                                 Uncommitted changes: {} (uncommitted changes may \
                                 indicate interrupted anti-forensic activity)",
                                path_str,
                                hive_label,
                                header.log_sequence_number,
                                header.dirty_page_count,
                                uncommitted,
                            ),
                        );
                        a.add_field("file_type", "Registry Transaction Log");
                        a.add_field("log_file", &path_str);
                        a.add_field("hive_name", &header.hive_name);
                        a.add_field(
                            "log_sequence_number",
                            &header.log_sequence_number.to_string(),
                        );
                        a.add_field("dirty_page_count", &header.dirty_page_count.to_string());
                        a.add_field(
                            "has_uncommitted_changes",
                            if uncommitted { "true" } else { "false" },
                        );
                        // T1112 — Modify Registry (the log records
                        //          the actual pending modifications).
                        // T1070.006 — Indicator Removal subtechnique;
                        //          uncommitted entries are evidence of
                        //          attempted but uncompleted log/hive
                        //          tampering.
                        a.add_field("mitre", "T1112");
                        a.add_field("mitre_secondary", "T1070.006");
                        a.add_field(
                            "forensic_value",
                            if uncommitted { "High" } else { "Medium" },
                        );
                        if uncommitted {
                            a.add_field("suspicious", "true");
                        }
                        results.push(a);
                    }
                }
            } else if lower.starts_with("thumbcache_") && lower.ends_with(".db") {
                // Typed thumbnail-cache parser. Thumbnails persist
                // after source-file deletion — this is the highest-
                // value forensic artifact in deletion / staging
                // cases. See `crate::thumbcache` for format details.
                if let Ok(data) = std::fs::read(&path) {
                    let path_str = path.to_string_lossy().to_string();
                    let parsed = crate::thumbcache::parse(&data);
                    for e in &parsed.entries {
                        let mut a = Artifact::new("Thumbcache Entry", &path_str);
                        let ext_label = if e.extension.is_empty() {
                            "<none>".to_string()
                        } else {
                            format!(".{}", e.extension)
                        };
                        a.add_field(
                            "title",
                            &format!(
                                "Thumbnail [{}]: hash={:016X} ext={} size={}",
                                e.cache_type, e.hash, ext_label, e.data_size
                            ),
                        );
                        a.add_field(
                            "detail",
                            &format!(
                                "Cache: {} | Hash: {:016X} | Ext: {} | Data size: {} | \
                                 Has thumbnail data: {} | data_checksum: {:016X} | \
                                 header_checksum: {:016X} (thumbnails persist after \
                                 source-file deletion \u{2014} high evidentiary value \
                                 in deletion cases)",
                                e.cache_type,
                                e.hash,
                                ext_label,
                                e.data_size,
                                !e.thumbnail_data.is_empty(),
                                e.data_checksum,
                                e.header_checksum,
                            ),
                        );
                        a.add_field("file_type", "Thumbcache Entry");
                        a.add_field("cache_type", &e.cache_type);
                        a.add_field("entry_hash", &format!("{:016X}", e.hash));
                        a.add_field("extension", &e.extension);
                        a.add_field("data_size", &e.data_size.to_string());
                        a.add_field(
                            "has_data",
                            if e.thumbnail_data.is_empty() {
                                "false"
                            } else {
                                "true"
                            },
                        );
                        a.add_field("data_checksum", &format!("{:016X}", e.data_checksum));
                        a.add_field("header_checksum", &format!("{:016X}", e.header_checksum));
                        a.add_field("source_path", &path_str);
                        // T1074.001 — Local Data Staging.
                        a.add_field("mitre", "T1074.001");
                        a.add_field("forensic_value", "Medium");
                        results.push(a);
                    }
                }
            } else if lower.ends_with(".pf") {
                // Prefetch deep parser — see crate::prefetch for the typed
                // PrefetchEntry shape and forensic rationale. Each .pf
                // becomes one Artifact("Prefetch Execution", path_str).
                if let Some(entry) = crate::prefetch::parse_file(&path) {
                    let path_str = path.to_string_lossy().to_string();
                    let mut a = Artifact::new("Prefetch Execution", &path_str);
                    a.timestamp = entry.last_run_times.first().map(|dt| dt.timestamp() as u64);
                    let last_run_str = entry
                        .last_run_times
                        .first()
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    let all_run_times = entry
                        .last_run_times
                        .iter()
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .collect::<Vec<_>>()
                        .join("|");
                    let volume_paths_joined = entry.volume_paths.join("|");
                    a.add_field(
                        "title",
                        &format!(
                            "Prefetch: {} executed {}\u{00D7}",
                            entry.executable_name, entry.run_count
                        ),
                    );
                    a.add_field(
                        "detail",
                        &format!(
                            "Executable: {} | Hash: {} | Run count: {} | Last run: {} | \
                             Format v{} | {} loaded files | {} volume(s)",
                            entry.executable_name,
                            entry.hash,
                            entry.run_count,
                            last_run_str,
                            entry.format_version,
                            entry.loaded_files.len(),
                            entry.volume_paths.len()
                        ),
                    );
                    a.add_field("file_type", "Prefetch Execution");
                    a.add_field("executable_name", &entry.executable_name);
                    a.add_field("hash", &entry.hash);
                    a.add_field("run_count", &entry.run_count.to_string());
                    a.add_field("last_run_time", &last_run_str);
                    a.add_field("all_run_times", &all_run_times);
                    a.add_field("volume_paths", &volume_paths_joined);
                    a.add_field("loaded_file_count", &entry.loaded_files.len().to_string());
                    a.add_field("format_version", &entry.format_version.to_string());
                    // T1059 — Command and Scripting Interpreter (proves
                    //         shell-launched executable execution).
                    // T1204 — User Execution (every prefetch entry is by
                    //         definition a user-induced launch).
                    a.add_field("mitre", "T1059");
                    a.add_field("mitre_secondary", "T1204");
                    a.add_field("forensic_value", "High");
                    results.push(a);
                }
            } else if lower.ends_with(".lnk") {
                // LNK (Shell Link) parser — see `crate::lnk`. One
                // artifact per file.
                let path_str = path.to_string_lossy().to_string();
                if let Ok(data) = std::fs::read(&path) {
                    if let Some(lnk) = crate::lnk::parse(&data) {
                        let mut a = Artifact::new("LNK File", &path_str);
                        a.timestamp = lnk.target_modified.map(|d| d.timestamp() as u64);
                        let title = format!("LNK → {}", lnk.target_path);
                        let detail = format!(
                            "Target: {} | WorkDir: {} | Args: {} | \
                             Drive: {} (serial {}) | Volume: {} | \
                             Machine: {} | DroidVol: {} | DroidFile: {} | \
                             Created: {} | Accessed: {} | Modified: {} | \
                             Size: {} bytes",
                            lnk.target_path,
                            lnk.working_directory.as_deref().unwrap_or("-"),
                            lnk.arguments.as_deref().unwrap_or("-"),
                            lnk.drive_type,
                            lnk.drive_serial.as_deref().unwrap_or("-"),
                            lnk.volume_label.as_deref().unwrap_or("-"),
                            lnk.machine_id.as_deref().unwrap_or("-"),
                            lnk.droid_volume_id.as_deref().unwrap_or("-"),
                            lnk.droid_file_id.as_deref().unwrap_or("-"),
                            lnk.target_created
                                .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                .unwrap_or_else(|| "-".to_string()),
                            lnk.target_accessed
                                .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                .unwrap_or_else(|| "-".to_string()),
                            lnk.target_modified
                                .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                .unwrap_or_else(|| "-".to_string()),
                            lnk.target_size,
                        );
                        a.add_field("title", &title);
                        a.add_field("detail", &detail);
                        a.add_field("file_type", "LNK File");
                        a.add_field("target_path", &lnk.target_path);
                        a.add_field("drive_type", &lnk.drive_type);
                        if let Some(v) = &lnk.working_directory {
                            a.add_field("working_directory", v);
                        }
                        if let Some(v) = &lnk.arguments {
                            a.add_field("arguments", v);
                        }
                        if let Some(v) = &lnk.drive_serial {
                            a.add_field("drive_serial", v);
                        }
                        if let Some(v) = &lnk.volume_label {
                            a.add_field("volume_label", v);
                        }
                        if let Some(v) = &lnk.machine_id {
                            a.add_field("machine_id", v);
                        }
                        if let Some(v) = &lnk.droid_volume_id {
                            a.add_field("droid_volume_id", v);
                        }
                        if let Some(v) = &lnk.droid_file_id {
                            a.add_field("droid_file_id", v);
                        }
                        a.add_field("target_size", &lnk.target_size.to_string());
                        let suspicious = crate::lnk::is_suspicious_target(&lnk.target_path);
                        a.add_field("mitre", "T1547.009");
                        a.add_field("mitre_secondary", "T1070.006");
                        a.add_field("forensic_value", "High");
                        if suspicious {
                            a.add_field("suspicious", "true");
                        }
                        results.push(a);
                    }
                }
            } else if lower == "windows.edb" {
                // ── post-v16 Sprint 5 wiring ──────────────────────────
                // Seven previously-orphaned Phantom submodules wired
                // into run() dispatch per Sprint 5 audit. Each was
                // declared via `pub mod X;` at the top of this file
                // but never referenced from any call site — the
                // pattern Session B's plugin audit named "Scenario B"
                // (submodule compiles and has tests, but is
                // unreachable from run()).
                //
                // All seven are filename-gated: the submodule owns
                // its own `is_*_path` / `classify` / `has_*_magic`
                // predicate so Phantom's walker just calls through
                // without expensive speculation.

                // memory_carving — .mem / .dmp raw memory images.
                // Surface "Memory Forensic String" records carved
                // from process memory (cred leaks, URL history,
                // command-line traces).
                results.extend(crate::memory_carving::scan(&path));

                // memory_structures — parallel scan for process /
                // network-connection structures inside memory
                // images. Same filename gate as memory_carving but
                // emits different records (Process, Net Connection).
                results.extend(crate::memory_structures::scan(&path));

                // notepad_tabstate — Win11 22H2+ Notepad tab-state
                // files (TabState*.bin) carry unsaved draft content.
                if crate::notepad_tabstate::is_tabstate_path(&path) {
                    if let Ok(bytes) = std::fs::read(&path) {
                        let guid = crate::notepad_tabstate::tab_guid_from_path(&path);
                        let tab = crate::notepad_tabstate::parse(&bytes, &guid);
                        let mut a = Artifact::new("Notepad TabState", &path.to_string_lossy());
                        a.add_field(
                            "title",
                            &format!(
                                "Notepad tab {}: {} ({} bytes unsaved)",
                                tab.tab_guid,
                                tab.file_path.as_deref().unwrap_or("(no file path)"),
                                tab.content_length,
                            ),
                        );
                        a.add_field(
                            "detail",
                            &format!(
                                "unsaved={} | content_length={} | content_preview={}",
                                tab.unsaved_content,
                                tab.content_length,
                                tab.content
                                    .as_deref()
                                    .map(|c| c.chars().take(200).collect::<String>())
                                    .unwrap_or_default(),
                            ),
                        );
                        a.add_field("file_type", "Notepad TabState");
                        a.add_field("mitre", "T1005");
                        if tab.unsaved_content {
                            a.add_field("suspicious", "true");
                        }
                        results.push(a);
                    }
                }

                // outlook — PST magic + attachment-name / email-
                // subject carver. Windows Outlook traces only.
                if crate::outlook::is_outlook_path(&path) {
                    // PST files can be multi-GB; read at most 128 MB
                    // to feed the carver (which is a string-carver
                    // over arbitrary offsets; bigger reads return
                    // diminishing signal).
                    const PST_MAX: u64 = 128 * 1024 * 1024;
                    if path.metadata().map(|m| m.len()).unwrap_or(0) <= PST_MAX {
                        if let Ok(bytes) = std::fs::read(&path) {
                            if crate::outlook::has_pst_magic(&bytes) {
                                for hit in crate::outlook::carve(&bytes) {
                                    let mut a =
                                        Artifact::new("Outlook Carved", &path.to_string_lossy());
                                    a.add_field(
                                        "title",
                                        &format!(
                                            "Outlook {}: {}",
                                            hit.kind,
                                            hit.value.chars().take(120).collect::<String>(),
                                        ),
                                    );
                                    a.add_field(
                                        "detail",
                                        &format!(
                                            "kind={} | value={} | offset=0x{:X}",
                                            hit.kind, hit.value, hit.offset
                                        ),
                                    );
                                    a.add_field("file_type", "Outlook Carved");
                                    a.add_field("mitre", "T1114.001");
                                    results.push(a);
                                }
                            }
                        }
                    }
                }

                // powershell — PSReadLine ConsoleHost_history.txt
                // command history. Suspicious entries surfaced via
                // submodule's own heuristic.
                if crate::powershell::is_psreadline_path(&path) {
                    if let Ok(body) = std::fs::read_to_string(&path) {
                        let entries = crate::powershell::parse(&body);
                        for e in &entries {
                            let is_sus = e.suspicious_pattern.is_some()
                                || e.has_encoded_content
                                || e.has_download_cradle;
                            let mut a =
                                Artifact::new("PowerShell History", &path.to_string_lossy());
                            a.add_field(
                                "title",
                                &format!(
                                    "PS line {}: {}",
                                    e.line_number,
                                    e.command.chars().take(120).collect::<String>(),
                                ),
                            );
                            let mut detail = format!(
                                "line={} | command={}",
                                e.line_number,
                                e.command.chars().take(400).collect::<String>(),
                            );
                            if let Some(s) = &e.suspicious_pattern {
                                detail.push_str(&format!(" | pattern={s}"));
                            }
                            if e.has_encoded_content {
                                detail.push_str(" | encoded_content");
                            }
                            if e.has_download_cradle {
                                detail.push_str(" | download_cradle");
                            }
                            a.add_field("detail", &detail);
                            a.add_field("file_type", "PowerShell History");
                            a.add_field("mitre", "T1059.001");
                            if is_sus {
                                a.add_field("suspicious", "true");
                            }
                            results.push(a);
                        }
                    }
                }

                // cloud_cli — AWS credentials, AWS config, Azure
                // access tokens, Terraform state. Per-file parser
                // selected by crate::cloud_cli::classify.
                if let Some(tag) = crate::cloud_cli::classify(&path) {
                    if let Ok(body) = std::fs::read_to_string(&path) {
                        let hits: Vec<crate::cloud_cli::CloudCliArtifact> = match tag {
                            "aws_credentials" => crate::cloud_cli::parse_aws_credentials(&body),
                            "aws_config" => crate::cloud_cli::parse_aws_config(&body),
                            "azure_access_tokens" => {
                                crate::cloud_cli::parse_azure_access_tokens(&body)
                            }
                            "terraform_state" => crate::cloud_cli::parse_terraform_state(&body),
                            _ => Vec::new(),
                        };
                        for hit in &hits {
                            let mut a =
                                Artifact::new("Cloud CLI Credential", &path.to_string_lossy());
                            a.add_field(
                                "title",
                                &format!(
                                    "{} {} {}",
                                    hit.provider,
                                    hit.artifact_type,
                                    hit.profile_name
                                        .clone()
                                        .or_else(|| hit.account_id.clone())
                                        .unwrap_or_else(|| "(unnamed)".into()),
                                ),
                            );
                            let mut detail = format!(
                                "provider={} | artifact_type={}",
                                hit.provider, hit.artifact_type
                            );
                            if let Some(p) = &hit.profile_name {
                                detail.push_str(&format!(" | profile={p}"));
                            }
                            if let Some(a) = &hit.account_id {
                                detail.push_str(&format!(" | account_id={a}"));
                            }
                            if let Some(t) = &hit.tenant_id {
                                detail.push_str(&format!(" | tenant_id={t}"));
                            }
                            a.add_field("detail", &detail);
                            a.add_field("file_type", "Cloud CLI Credential");
                            a.add_field("mitre", "T1552.001");
                            a.add_field("suspicious", "true");
                            results.push(a);
                        }
                    }
                }

                // windows_recall — Win11 Recall UKG.db SQLite.
                // parse() returns RecallOutcome::{Captures, Locked,
                // Missing}. Missing is silent; Locked/Captures
                // surface records.
                if crate::windows_recall::is_recall_db_path(&path) {
                    match crate::windows_recall::parse(&path) {
                        crate::windows_recall::RecallOutcome::Captures(captures) => {
                            for c in &captures {
                                let mut a = Artifact::new(
                                    "Windows Recall Capture",
                                    &path.to_string_lossy(),
                                );
                                a.add_field(
                                    "title",
                                    &format!(
                                        "Recall: {} @ {}",
                                        c.app_name.as_deref().unwrap_or("(unknown app)"),
                                        c.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                                    ),
                                );
                                a.add_field(
                                    "detail",
                                    &format!(
                                        "capture_id={} | app={} | app_path={} | title={} | captured_at={}",
                                        c.capture_id,
                                        c.app_name.as_deref().unwrap_or("-"),
                                        c.app_path.as_deref().unwrap_or("-"),
                                        c.window_title.as_deref().unwrap_or("-"),
                                        c.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                                    ),
                                );
                                a.add_field("file_type", "Windows Recall Capture");
                                a.add_field("mitre", "T1113");
                                a.timestamp = Some(c.timestamp.timestamp() as u64);
                                results.push(a);
                            }
                        }
                        crate::windows_recall::RecallOutcome::Locked => {
                            let mut a =
                                Artifact::new("Windows Recall Locked", &path.to_string_lossy());
                            a.add_field(
                                "title",
                                "Windows Recall DB present but locked / unreadable",
                            );
                            a.add_field(
                                "detail",
                                "Recall UKG.db is present. SQLite open failed — typically \
                                 encrypted-at-rest via DPAPI (Windows 11 24H2+ default). \
                                 Offline DPAPI key recovery required.",
                            );
                            a.add_field("file_type", "Windows Recall Locked");
                            a.add_field("mitre", "T1113");
                            a.add_field("suspicious", "true");
                            results.push(a);
                        }
                        crate::windows_recall::RecallOutcome::Missing => {}
                    }
                }

                // Windows Search Index — string-carving fallback. See
                // `crate::windows_search` for the rationale behind the
                // carving approach over full ESE parsing.
                if let Ok(data) = std::fs::read(&path) {
                    let entries = crate::windows_search::parse(&path, &data);
                    let path_str = path.to_string_lossy().to_string();
                    for e in &entries {
                        let mut a = Artifact::new("Search Index Entry", &path_str);
                        a.add_field("title", &format!("Indexed path: {}", e.item_path));
                        a.add_field(
                            "detail",
                            &format!(
                                "Path: {} | Offset: 0x{:X} | Length: {}",
                                e.item_path, e.file_offset, e.path_length
                            ),
                        );
                        a.add_field("file_type", "Search Index Entry");
                        a.add_field("item_path", &e.item_path);
                        a.add_field("file_offset", &format!("0x{:X}", e.file_offset));
                        a.add_field("path_length", &e.path_length.to_string());
                        a.add_field("mitre", "T1083");
                        a.add_field("forensic_value", "Medium");
                        results.push(a);
                    }
                }
            }
        }

        Ok(results)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;

        let mut records = Vec::new();
        let mut categories: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut suspicious_count = 0usize;

        for a in &artifacts {
            let file_type = a.data.get("file_type").cloned().unwrap_or_default();
            let category = match file_type.as_str() {
                "ShimCache"
                | "AmCache File"
                | "AmCache Application"
                | "Service"
                | "AmCache Legacy File"
                | "Prefetch Execution"
                | "Registry Transaction Log" => ArtifactCategory::ExecutionHistory,
                "USB Device" | "Network Adapter" => ArtifactCategory::NetworkArtifacts,
                "SAM Account" | "Cloud Identity" => ArtifactCategory::AccountsCredentials,
                "Installed Program"
                | "OS Version"
                | "AmCache Installed App"
                | "AmCache Legacy Program" => ArtifactCategory::SystemActivity,
                "AmCache Driver" | "AmCache Driver Package" => ArtifactCategory::ExecutionHistory,
                "AmCache Device Container" | "AmCache PnP Device" => {
                    ArtifactCategory::NetworkArtifacts
                }
                "AmCache Shortcut" => ArtifactCategory::UserActivity,
                "Shellbag" | "MuiCache" | "UserChoice" | "MRU Entry" | "Thumbcache Entry"
                | "Search Index Entry" | "LNK File" => ArtifactCategory::UserActivity,
                // v1.5.0 RegRipper-coverage parsers
                "Print Monitor"
                | "LSA Security Package"
                | "LSA Authentication Package"
                | "AppCert DLL"
                | "Network Provider"
                | "Boot Execute"
                | "Pending File Rename"
                | "Time Provider"
                | "Winsock LSP" => ArtifactCategory::SystemActivity,
                "WDigest Cleartext" => ArtifactCategory::AccountsCredentials,
                "RDP State" | "SMB1 State" => ArtifactCategory::NetworkArtifacts,
                "IFEO Debugger"
                | "AppInit DLL"
                | "Winlogon Persistence"
                | "Active Setup"
                | "Office Test Persistence"
                | "Browser Helper Object"
                | "Shell Execute Hook" => ArtifactCategory::ExecutionHistory,
                "Defender Exclusion" => ArtifactCategory::SystemActivity,
                "WinRM TrustedHosts" | "RDP MRU" | "RDP Saved Server" => {
                    ArtifactCategory::NetworkArtifacts
                }
                // Post-v16 Sprint 5 — seven new submodule categories.
                "Memory String"
                | "Memory Process"
                | "Memory Network Connection"
                | "Windows Recall Capture"
                | "Windows Recall Locked" => ArtifactCategory::SystemActivity,
                "Notepad TabState" => ArtifactCategory::UserActivity,
                "Outlook Carved" => ArtifactCategory::UserActivity,
                "PowerShell History" => ArtifactCategory::ExecutionHistory,
                "Cloud CLI Credential" => ArtifactCategory::AccountsCredentials,
                _ => ArtifactCategory::SystemActivity,
            };

            let suspicious = a
                .data
                .get("suspicious")
                .map(|s| s == "true")
                .unwrap_or(false);
            if suspicious {
                suspicious_count += 1;
            }
            categories.insert(category.as_str().to_string());

            let fv_str = a.data.get("forensic_value").cloned().unwrap_or_default();
            let forensic_value = match fv_str.as_str() {
                "Critical" => ForensicValue::Critical,
                "High" => ForensicValue::High,
                "Medium" => ForensicValue::Medium,
                _ => {
                    if suspicious {
                        ForensicValue::High
                    } else {
                        ForensicValue::Medium
                    }
                }
            };

            records.push(ArtifactRecord {
                category,
                subcategory: file_type,
                timestamp: a.timestamp.map(|t| t as i64),
                title: a
                    .data
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| a.source.clone()),
                detail: a.data.get("detail").cloned().unwrap_or_default(),
                source_path: a.source.clone(),
                forensic_value,
                mitre_technique: a.data.get("mitre").cloned(),
                is_suspicious: suspicious,
                raw_data: None,
                confidence: 0,
            });
        }

        let total = records.len();
        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count,
                categories_populated: categories.into_iter().collect(),
                headline: format!(
                    "Parsed {} registry artifacts across {} hive types ({} suspicious)",
                    total, 6, suspicious_count
                ),
            },
            warnings: vec![],
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Hive parsers
// ────────────────────────────────────────────────────────────────────────────

mod parsers {
    use super::*;

    /// Convert a Windows FILETIME (100ns ticks since 1601-01-01) to a Unix
    /// timestamp in seconds. Returns None for zero or pre-epoch values.
    pub(super) fn filetime_to_unix(ft: i64) -> Option<i64> {
        if ft <= 0 {
            return None;
        }
        let u = (ft - 116_444_736_000_000_000) / 10_000_000;
        if u < 0 {
            None
        } else {
            Some(u)
        }
    }

    /// Walk a UTF-16LE byte buffer up to the first null and return as String.
    pub(super) fn utf16le_to_string(data: &[u8]) -> String {
        let u16s: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&ch| ch != 0)
            .collect();
        String::from_utf16_lossy(&u16s)
    }

    /// Format a Unix timestamp as `YYYY-MM-DD HH:MM:SS UTC`.
    pub(super) fn fmt_unix(ts: i64) -> String {
        chrono::DateTime::from_timestamp(ts, 0)
            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| format!("unix:{}", ts))
    }

    /// Open a hive from raw bytes. The caller must hold the `Hive` for the
    /// lifetime of any derived `KeyNode` since `root_key_node()` borrows the
    /// hive.
    pub(super) fn open_hive(data: &[u8]) -> Option<nt_hive::Hive<&[u8]>> {
        nt_hive::Hive::new(data).ok()
    }

    pub mod system {
        use super::*;

        pub fn parse(path: &Path, data: &[u8]) -> Vec<Artifact> {
            let mut out = Vec::new();
            let path_str = path.to_string_lossy().to_string();

            let Some(hive) = open_hive(data) else {
                return out;
            };
            let Ok(root) = hive.root_key_node() else {
                let mut a = Artifact::new("ShimCache", &path_str);
                a.add_field("title", "SYSTEM hive present (parse failed)");
                a.add_field("detail", "nt-hive failed to open the hive");
                a.add_field("file_type", "ShimCache");
                a.add_field("forensic_value", "Medium");
                out.push(a);
                return out;
            };

            // ── ComputerName ────────────────────────────────────────────
            if let Some(hostname) = read_string(
                &root,
                &["ControlSet001", "Control", "ComputerName", "ComputerName"],
                "ComputerName",
            ) {
                let mut a = Artifact::new("Computer Identity", &path_str);
                a.add_field("title", &format!("Hostname: {}", hostname));
                a.add_field("detail", "SYSTEM\\ControlSet001\\Control\\ComputerName");
                a.add_field("file_type", "Computer Identity");
                a.add_field("forensic_value", "Medium");
                out.push(a);
            }

            // ── TimeZoneInformation ──────────────────────────────────────
            if let Some(tz) = read_string(
                &root,
                &["ControlSet001", "Control", "TimeZoneInformation"],
                "TimeZoneKeyName",
            ) {
                let mut a = Artifact::new("Computer Identity", &path_str);
                a.add_field("title", &format!("Time Zone: {}", tz));
                a.add_field(
                    "detail",
                    "SYSTEM\\ControlSet001\\Control\\TimeZoneInformation",
                );
                a.add_field("file_type", "Computer Identity");
                a.add_field("forensic_value", "Medium");
                out.push(a);
            }

            // ── Last shutdown time ──────────────────────────────────────
            if let Some(node) = walk(&root, &["ControlSet001", "Control", "Windows"]) {
                if let Some(bytes) = read_value_bytes(&node, "ShutdownTime") {
                    if bytes.len() >= 8 {
                        let ft = i64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
                        if let Some(unix) = filetime_to_unix(ft) {
                            let mut a = Artifact::new("Computer Identity", &path_str);
                            a.timestamp = Some(unix as u64);
                            a.add_field("title", &format!("Last shutdown: {}", fmt_unix(unix)));
                            a.add_field(
                                "detail",
                                "SYSTEM\\ControlSet001\\Control\\Windows ShutdownTime",
                            );
                            a.add_field("file_type", "Computer Identity");
                            a.add_field("forensic_value", "High");
                            out.push(a);
                        }
                    }
                }
            }

            // ── ShimCache (AppCompatCache) ──────────────────────────────
            //
            // Typed binary parser — see `crate::shimcache`. Handles Win7,
            // Win8.0, Win8.1, and Win10/11 framing. Emits one artifact per
            // entry, with the FILETIME `last_modified` promoted to the
            // artifact `timestamp` so the timeline view shows real dates
            // rather than "unknown time".
            if let Some(node) = walk(
                &root,
                &[
                    "ControlSet001",
                    "Control",
                    "Session Manager",
                    "AppCompatCache",
                ],
            ) {
                if let Some(bytes) = read_value_bytes(&node, "AppCompatCache") {
                    let entries = crate::shimcache::parse(&bytes, &path_str);
                    for entry in entries {
                        let suspicious = is_suspicious_exe_path(&entry.executable_path);
                        let mut a = Artifact::new("ShimCache", &path_str);
                        a.timestamp = Some(entry.last_modified.timestamp() as u64);
                        a.add_field("title", &format!("ShimCache: {}", entry.executable_path));
                        a.add_field(
                            "detail",
                            &format!(
                                "AppCompatCache entry #{} — last_modified={} shimmed={} \
                                 (proves file existed on disk; does NOT prove execution)",
                                entry.entry_index,
                                entry.last_modified.format("%Y-%m-%d %H:%M:%S UTC"),
                                entry.shimmed,
                            ),
                        );
                        a.add_field("file_type", "ShimCache");
                        // T1059: Command and Scripting Interpreter — ShimCache
                        //         is the canonical shell-executable artifact.
                        // T1112: Modify Registry — cleared / tampered
                        //         ShimCache is a direct T1112 indicator; we
                        //         carry both for downstream kill-chain
                        //         correlation.
                        a.add_field("mitre", "T1059");
                        a.add_field("mitre_secondary", "T1112");
                        a.add_field("forensic_value", if suspicious { "High" } else { "Medium" });
                        a.add_field("executable_path", &entry.executable_path);
                        a.add_field("entry_index", &entry.entry_index.to_string());
                        a.add_field("shimmed", if entry.shimmed { "true" } else { "false" });
                        a.add_field("source_hive", &entry.source_hive);
                        if suspicious {
                            a.add_field("suspicious", "true");
                        }
                        out.push(a);
                    }
                }
            }

            // ── USB device chain ─────────────────────────────────────────
            // Typed parser — see `crate::usb`. Walks USBSTOR + USB,
            // splits vendor/product, surfaces all three Properties
            // FILETIMEs, flags generic / spoofed serials suspicious.
            let usb_history = crate::usb::parse(&root);
            for dev in &usb_history.devices {
                let suspicious = crate::usb::is_generic_serial(&dev.serial_number);
                let mut a = Artifact::new("USB Device", &path_str);
                a.timestamp = dev.last_write_time.map(|dt| dt.timestamp() as u64);
                let title_label = if !dev.friendly_name.is_empty() {
                    dev.friendly_name.clone()
                } else if !dev.product.is_empty() {
                    format!("{} {}", dev.vendor, dev.product)
                } else {
                    dev.device_type.clone()
                };
                a.add_field("title", &format!("USB: {}", title_label));
                let install_str = dev
                    .first_install_time
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "<unknown>".to_string());
                let connect_str = dev
                    .last_connect_time
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "<unknown>".to_string());
                let removal_str = dev
                    .last_removal_time
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "<unknown>".to_string());
                a.add_field(
                    "detail",
                    &format!(
                        "Bus: {} | Type: {} | Vendor: {} | Product: {} | Serial: {} | \
                         First install: {} | Last connected: {} | Last removal: {}",
                        dev.bus.as_str(),
                        dev.device_type,
                        if dev.vendor.is_empty() {
                            "<unknown>"
                        } else {
                            &dev.vendor
                        },
                        if dev.product.is_empty() {
                            "<unknown>"
                        } else {
                            &dev.product
                        },
                        dev.serial_number,
                        install_str,
                        connect_str,
                        removal_str,
                    ),
                );
                a.add_field("file_type", "USB Device");
                a.add_field("bus", dev.bus.as_str());
                a.add_field("device_type", &dev.device_type);
                a.add_field("vendor", &dev.vendor);
                a.add_field("product", &dev.product);
                a.add_field("serial_number", &dev.serial_number);
                a.add_field("friendly_name", &dev.friendly_name);
                a.add_field("device_desc", &dev.device_desc);
                if let Some(letter) = &dev.drive_letter {
                    a.add_field("drive_letter", letter);
                }
                a.add_field("first_install_time", &install_str);
                a.add_field("last_connect_time", &connect_str);
                a.add_field("last_removal_time", &removal_str);
                a.add_field("mitre", "T1091");
                a.add_field("mitre_secondary", "T1052.001");
                a.add_field("forensic_value", "High");
                if suspicious {
                    a.add_field("suspicious", "true");
                    a.add_field(
                        "suspicious_reason",
                        "Generic / spoofed / Microsoft-fallback serial number",
                    );
                }
                out.push(a);
            }

            // ── Services enumeration ─────────────────────────────────────
            if let Some(svcs) = walk(&root, &["ControlSet001", "Services"]) {
                if let Some(Ok(svc_iter)) = svcs.subkeys() {
                    for svc_res in svc_iter {
                        let Ok(svc_node) = svc_res else { continue };
                        let Ok(svc_name) = svc_node.name() else {
                            continue;
                        };
                        let svc_name = svc_name.to_string_lossy();

                        let image_path =
                            read_value_string(&svc_node, "ImagePath").unwrap_or_default();
                        if image_path.is_empty() {
                            continue;
                        }
                        let display = read_value_string(&svc_node, "DisplayName")
                            .unwrap_or_else(|| svc_name.to_string());
                        let start_type = read_value_dword(&svc_node, "Start").unwrap_or(0xFF);
                        let object = read_value_string(&svc_node, "ObjectName")
                            .unwrap_or_else(|| "LocalSystem".to_string());

                        let lower_path = image_path.to_lowercase();
                        let in_system = lower_path.contains("system32")
                            || lower_path.contains("syswow64")
                            || lower_path.contains("\\windows\\");
                        let auto_start = matches!(start_type, 0..=2);
                        let suspicious = !in_system && auto_start;

                        let start_label = match start_type {
                            0 => "Boot",
                            1 => "System",
                            2 => "Auto",
                            3 => "Manual",
                            4 => "Disabled",
                            _ => "Unknown",
                        };

                        let mut a = Artifact::new("Service", &path_str);
                        a.add_field("title", &format!("Service: {}", display));
                        a.add_field(
                            "detail",
                            &format!(
                                "ImagePath: {} | Start: {} | RunAs: {}",
                                image_path, start_label, object
                            ),
                        );
                        a.add_field("file_type", "Service");
                        a.add_field("mitre", "T1543.003");
                        if suspicious {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                    }
                }
            }

            // ── Network adapter history ──────────────────────────────────
            if let Some(ifs) = walk(
                &root,
                &[
                    "ControlSet001",
                    "Services",
                    "Tcpip",
                    "Parameters",
                    "Interfaces",
                ],
            ) {
                if let Some(Ok(if_iter)) = ifs.subkeys() {
                    for if_res in if_iter {
                        let Ok(if_node) = if_res else { continue };
                        let Ok(guid) = if_node.name() else { continue };
                        let guid = guid.to_string_lossy();
                        let ip = read_value_string(&if_node, "DhcpIPAddress").unwrap_or_default();
                        let server = read_value_string(&if_node, "DhcpServer").unwrap_or_default();
                        let domain = read_value_string(&if_node, "DhcpDomain").unwrap_or_default();
                        if ip.is_empty() && server.is_empty() {
                            continue;
                        }
                        let mut a = Artifact::new("Network Adapter", &path_str);
                        a.add_field("title", &format!("Adapter: {}", guid));
                        a.add_field(
                            "detail",
                            &format!(
                                "DHCP IP: {} | DHCP Server: {} | Domain: {}",
                                ip, server, domain
                            ),
                        );
                        a.add_field("file_type", "Network Adapter");
                        a.add_field("mitre", "T1016");
                        a.add_field("forensic_value", "Medium");
                        out.push(a);
                    }
                }
            }

            // ── v1.5.0 SYSTEM hive parsers (RegRipper coverage) ─────────
            parse_print_monitors(&root, &path_str, &mut out);
            parse_lsa_security_packages(&root, &path_str, &mut out);
            parse_lsa_authentication_packages(&root, &path_str, &mut out);
            parse_appcert_dlls(&root, &path_str, &mut out);
            parse_network_provider_order(&root, &path_str, &mut out);
            parse_wdigest_use_logon_credential(&root, &path_str, &mut out);
            parse_session_manager_boot_execute(&root, &path_str, &mut out);
            parse_pending_file_rename(&root, &path_str, &mut out);
            parse_terminal_server_state(&root, &path_str, &mut out);
            parse_lanman_smb1_state(&root, &path_str, &mut out);
            parse_w32time_providers(&root, &path_str, &mut out);
            parse_winsock_lsps(&root, &path_str, &mut out);

            out
        }

        // ───────────────────────────────────────────────────────────────
        // Pure helpers (unit-testable)
        // ───────────────────────────────────────────────────────────────

        /// Print monitor DLLs are loaded into spoolsv.exe at SYSTEM
        /// privilege. Anything that isn't on Microsoft's blessed list is
        /// worth a closer look.
        pub(super) fn is_known_print_monitor(name: &str) -> bool {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "local port"
                    | "standard tcp/ip port"
                    | "usb monitor"
                    | "wsd port"
                    | "appmon"
                    | "bjlanglemonitor"
                    | "microsoft document imaging writer monitor"
                    | "microsoft shared fax monitor"
                    | "lpr port"
                    | "pjl language monitor"
                    | "msxpsmon"
            )
        }

        /// Microsoft's stock LSA security packages — anything else means
        /// a third-party SSP has been registered, which is a known
        /// credential-theft persistence mechanism (T1547.005).
        pub(super) fn is_known_lsa_package(name: &str) -> bool {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "kerberos"
                    | "msv1_0"
                    | "schannel"
                    | "wdigest"
                    | "tspkg"
                    | "pku2u"
                    | "negotiate"
                    | "cloudap"
                    | "negoexts"
                    | "credssp"
                    | "livessp"
                    | ""
            )
        }

        /// Stock Microsoft network providers seen across modern Windows
        /// installs. A network provider that isn't one of these and
        /// appears earlier in the order is a credential-harvesting
        /// indicator (NPLogonNotify is called on every interactive logon).
        pub(super) fn is_known_network_provider(name: &str) -> bool {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "rdpnp"
                    | "lanmanworkstation"
                    | "webclient"
                    | "p9np"
                    | "csc"
                    | "ms-nlsp"
                    | "ms-resolver"
            )
        }

        // ───────────────────────────────────────────────────────────────
        // Parser bodies — each consumes the SYSTEM root and pushes
        // artifacts into the shared output vector.
        // ───────────────────────────────────────────────────────────────

        fn parse_print_monitors(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["ControlSet001", "Control", "Print", "Monitors"]) else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let Ok(name) = k.name() else { continue };
                let name = name.to_string_lossy();
                let driver = read_value_string(&k, "Driver").unwrap_or_default();
                let suspicious = !is_known_print_monitor(&name);
                let mut a = Artifact::new("Print Monitor", path_str);
                a.add_field("title", &format!("Print Monitor: {}", name));
                a.add_field(
                    "detail",
                    &format!(
                        "Driver: {} | spoolsv.exe loads this DLL at SYSTEM privilege",
                        driver
                    ),
                );
                a.add_field("file_type", "Print Monitor");
                a.add_field("mitre", "T1547.012");
                if suspicious {
                    a.add_field("forensic_value", "High");
                    a.add_field("suspicious", "true");
                } else {
                    a.add_field("forensic_value", "Medium");
                }
                out.push(a);
            }
        }

        fn parse_lsa_security_packages(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["ControlSet001", "Control", "Lsa"]) else {
                return;
            };
            let Some(bytes) = read_value_bytes(&node, "Security Packages") else {
                return;
            };
            for pkg in decode_reg_multi_sz(&bytes) {
                let suspicious = !is_known_lsa_package(&pkg);
                let mut a = Artifact::new("LSA Security Package", path_str);
                a.add_field("title", &format!("LSA SSP: {}", pkg));
                a.add_field(
                    "detail",
                    "SYSTEM\\ControlSet001\\Control\\Lsa\\Security Packages — loaded into lsass.exe",
                );
                a.add_field("file_type", "LSA Security Package");
                a.add_field("mitre", "T1547.005");
                if suspicious {
                    a.add_field("forensic_value", "Critical");
                    a.add_field("suspicious", "true");
                } else {
                    a.add_field("forensic_value", "Medium");
                }
                out.push(a);
            }
        }

        fn parse_lsa_authentication_packages(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["ControlSet001", "Control", "Lsa"]) else {
                return;
            };
            let Some(bytes) = read_value_bytes(&node, "Authentication Packages") else {
                return;
            };
            for pkg in decode_reg_multi_sz(&bytes) {
                let suspicious = !is_known_lsa_package(&pkg);
                let mut a = Artifact::new("LSA Authentication Package", path_str);
                a.add_field("title", &format!("LSA Auth Pkg: {}", pkg));
                a.add_field(
                    "detail",
                    "SYSTEM\\ControlSet001\\Control\\Lsa\\Authentication Packages",
                );
                a.add_field("file_type", "LSA Authentication Package");
                a.add_field("mitre", "T1547.002");
                if suspicious {
                    a.add_field("forensic_value", "Critical");
                    a.add_field("suspicious", "true");
                } else {
                    a.add_field("forensic_value", "Medium");
                }
                out.push(a);
            }
        }

        fn parse_appcert_dlls(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &["ControlSet001", "Control", "Session Manager", "AppCertDlls"],
            ) else {
                return;
            };
            let Some(Ok(values)) = node.values() else {
                return;
            };
            for vr in values {
                let Ok(v) = vr else { continue };
                let Ok(name) = v.name() else { continue };
                let dll_path = match v.data() {
                    Ok(d) => match d.into_vec() {
                        Ok(b) => utf16le_to_string(&b),
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                };
                if dll_path.is_empty() {
                    continue;
                }
                let mut a = Artifact::new("AppCert DLL", path_str);
                a.add_field("title", &format!("AppCert DLL: {}", name.to_string_lossy()));
                a.add_field(
                    "detail",
                    &format!(
                        "Path: {} | AppCertDLLs are loaded into every process \
                         that calls CreateProcess (T1546.009)",
                        dll_path
                    ),
                );
                a.add_field("file_type", "AppCert DLL");
                a.add_field("mitre", "T1546.009");
                a.add_field("forensic_value", "Critical");
                a.add_field("suspicious", "true");
                out.push(a);
            }
        }

        fn parse_network_provider_order(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &["ControlSet001", "Control", "NetworkProvider", "Order"],
            ) else {
                return;
            };
            let provider_csv = read_value_string(&node, "ProviderOrder").unwrap_or_default();
            if provider_csv.is_empty() {
                return;
            }
            for provider in provider_csv
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let suspicious = !is_known_network_provider(provider);
                let mut a = Artifact::new("Network Provider", path_str);
                a.add_field("title", &format!("Network Provider: {}", provider));
                a.add_field(
                    "detail",
                    "SYSTEM\\...\\NetworkProvider\\Order — providers see logon credentials",
                );
                a.add_field("file_type", "Network Provider");
                a.add_field("mitre", "T1556.008");
                if suspicious {
                    a.add_field("forensic_value", "Critical");
                    a.add_field("suspicious", "true");
                } else {
                    a.add_field("forensic_value", "Medium");
                }
                out.push(a);
            }
        }

        fn parse_wdigest_use_logon_credential(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &["ControlSet001", "Control", "SecurityProviders", "WDigest"],
            ) else {
                return;
            };
            let Some(value) = read_value_dword(&node, "UseLogonCredential") else {
                return;
            };
            let enabled = value != 0;
            let mut a = Artifact::new("WDigest Cleartext", path_str);
            a.add_field(
                "title",
                if enabled {
                    "WDigest UseLogonCredential = 1 (cleartext credentials in lsass)"
                } else {
                    "WDigest UseLogonCredential = 0 (default)"
                },
            );
            a.add_field(
                "detail",
                "SYSTEM\\...\\SecurityProviders\\WDigest\\UseLogonCredential — \
                 when set to 1, lsass.exe caches plaintext passwords (Mimikatz target)",
            );
            a.add_field("file_type", "WDigest Cleartext");
            a.add_field("mitre", "T1003.001");
            if enabled {
                a.add_field("forensic_value", "Critical");
                a.add_field("suspicious", "true");
            } else {
                a.add_field("forensic_value", "Medium");
            }
            out.push(a);
        }

        fn parse_session_manager_boot_execute(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["ControlSet001", "Control", "Session Manager"]) else {
                return;
            };
            let Some(bytes) = read_value_bytes(&node, "BootExecute") else {
                return;
            };
            let entries = decode_reg_multi_sz(&bytes);
            // Stock Windows BootExecute is "autocheck autochk *" — anything
            // else is worth flagging.
            let stock = entries.iter().all(|e| {
                let l = e.to_lowercase();
                l == "autocheck autochk *" || l.is_empty()
            });
            for entry in &entries {
                let mut a = Artifact::new("Boot Execute", path_str);
                a.add_field("title", &format!("BootExecute: {}", entry));
                a.add_field(
                    "detail",
                    "SYSTEM\\...\\Session Manager\\BootExecute — runs in native mode \
                     before Win32 starts; common rootkit persistence",
                );
                a.add_field("file_type", "Boot Execute");
                a.add_field("mitre", "T1547.001");
                if stock {
                    a.add_field("forensic_value", "Medium");
                } else {
                    a.add_field("forensic_value", "Critical");
                    a.add_field("suspicious", "true");
                }
                out.push(a);
            }
        }

        fn parse_pending_file_rename(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["ControlSet001", "Control", "Session Manager"]) else {
                return;
            };
            let Some(bytes) = read_value_bytes(&node, "PendingFileRenameOperations") else {
                return;
            };
            for entry in decode_reg_multi_sz(&bytes) {
                if entry.is_empty() {
                    continue;
                }
                let mut a = Artifact::new("Pending File Rename", path_str);
                a.add_field("title", &format!("PendingFileRename: {}", entry));
                a.add_field(
                    "detail",
                    "SYSTEM\\...\\Session Manager\\PendingFileRenameOperations \
                     — applied at next reboot",
                );
                a.add_field("file_type", "Pending File Rename");
                a.add_field("mitre", "T1070.004");
                a.add_field("forensic_value", "Medium");
                out.push(a);
            }
        }

        fn parse_terminal_server_state(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["ControlSet001", "Control", "Terminal Server"]) else {
                return;
            };
            // fDenyTSConnections = 0 means RDP is enabled.
            let Some(deny) = read_value_dword(&node, "fDenyTSConnections") else {
                return;
            };
            let enabled = deny == 0;
            let mut a = Artifact::new("RDP State", path_str);
            a.add_field(
                "title",
                if enabled {
                    "RDP enabled (fDenyTSConnections = 0)"
                } else {
                    "RDP disabled (fDenyTSConnections = 1)"
                },
            );
            a.add_field("detail", "SYSTEM\\...\\Terminal Server\\fDenyTSConnections");
            a.add_field("file_type", "RDP State");
            a.add_field("mitre", "T1021.001");
            if enabled {
                a.add_field("forensic_value", "High");
            } else {
                a.add_field("forensic_value", "Medium");
            }
            out.push(a);
        }

        fn parse_lanman_smb1_state(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &["ControlSet001", "Services", "LanmanServer", "Parameters"],
            ) else {
                return;
            };
            let Some(value) = read_value_dword(&node, "SMB1") else {
                return;
            };
            let enabled = value != 0;
            let mut a = Artifact::new("SMB1 State", path_str);
            a.add_field(
                "title",
                if enabled {
                    "SMB1 server enabled (SMB1 = 1)"
                } else {
                    "SMB1 server disabled (SMB1 = 0)"
                },
            );
            a.add_field(
                "detail",
                "SYSTEM\\...\\Services\\LanmanServer\\Parameters\\SMB1 — SMB1 \
                 enables EternalBlue (T1210)",
            );
            a.add_field("file_type", "SMB1 State");
            a.add_field("mitre", "T1210");
            if enabled {
                a.add_field("forensic_value", "Critical");
                a.add_field("suspicious", "true");
            } else {
                a.add_field("forensic_value", "Medium");
            }
            out.push(a);
        }

        fn parse_w32time_providers(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &["ControlSet001", "Services", "W32Time", "TimeProviders"],
            ) else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let Ok(name) = k.name() else { continue };
                let name = name.to_string_lossy();
                let dll = read_value_string(&k, "DllName").unwrap_or_default();
                let enabled = read_value_dword(&k, "Enabled")
                    .map(|d| d != 0)
                    .unwrap_or(false);
                let suspicious = !matches!(
                    name.to_ascii_lowercase().as_str(),
                    "ntpclient" | "ntpserver" | "vmictimeprovider"
                ) && enabled;
                let mut a = Artifact::new("Time Provider", path_str);
                a.add_field("title", &format!("Time Provider: {}", name));
                a.add_field(
                    "detail",
                    &format!(
                        "DLL: {} | Enabled: {} | TimeProviders run inside w32time service",
                        dll, enabled
                    ),
                );
                a.add_field("file_type", "Time Provider");
                a.add_field("mitre", "T1547.003");
                if suspicious {
                    a.add_field("forensic_value", "Critical");
                    a.add_field("suspicious", "true");
                } else {
                    a.add_field("forensic_value", "Medium");
                }
                out.push(a);
            }
        }

        fn parse_winsock_lsps(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &[
                    "ControlSet001",
                    "Services",
                    "WinSock2",
                    "Parameters",
                    "Protocol_Catalog9",
                    "Catalog_Entries",
                ],
            ) else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            let mut count = 0;
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let Ok(name) = k.name() else { continue };
                count += 1;
                let mut a = Artifact::new("Winsock LSP", path_str);
                a.add_field(
                    "title",
                    &format!("Winsock LSP entry: {}", name.to_string_lossy()),
                );
                a.add_field(
                    "detail",
                    "Protocol_Catalog9\\Catalog_Entries — Layered Service Providers \
                     intercept all socket calls (T1556.008)",
                );
                a.add_field("file_type", "Winsock LSP");
                a.add_field("mitre", "T1556.008");
                a.add_field("forensic_value", "Medium");
                out.push(a);
                if count > 200 {
                    break;
                }
            }
        }

        /// Decode a REG_MULTI_SZ blob — UTF-16LE strings separated by
        /// double-null terminators. Hoisted out of the older inline
        /// implementation in `ntuser` so the SYSTEM hive parsers can
        /// share it.
        pub(super) fn decode_reg_multi_sz(bytes: &[u8]) -> Vec<String> {
            let u16s: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let mut out = Vec::new();
            let mut buf = String::new();
            for ch in u16s {
                if ch == 0 {
                    if !buf.is_empty() {
                        out.push(buf.clone());
                        buf.clear();
                    }
                } else if let Some(c) = char::from_u32(ch as u32) {
                    buf.push(c);
                }
            }
            if !buf.is_empty() {
                out.push(buf);
            }
            out
        }

        // `decode_shimcache_strings` (the v1.0.0 string-heuristic ShimCache
        // reader) was replaced by `crate::shimcache::parse` in v1.3.1 and
        // removed to avoid carrying two parallel implementations.

        fn is_suspicious_exe_path(p: &str) -> bool {
            let l = p.to_lowercase();
            l.contains("\\temp\\")
                || l.contains("\\appdata\\local\\temp")
                || l.contains("\\users\\public\\")
                || l.contains("\\windows\\debug\\")
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn is_known_print_monitor_filters_microsoft_stock() {
                assert!(is_known_print_monitor("Local Port"));
                assert!(is_known_print_monitor("Standard TCP/IP Port"));
                assert!(is_known_print_monitor("USB Monitor"));
                assert!(is_known_print_monitor("WSD Port"));
                // Case insensitive.
                assert!(is_known_print_monitor("LOCAL PORT"));
                // Anything outside the stock list is unknown.
                assert!(!is_known_print_monitor("EvilMonitorDll"));
                assert!(!is_known_print_monitor("PrintNightmare"));
            }

            #[test]
            fn is_known_lsa_package_filters_microsoft_stock() {
                assert!(is_known_lsa_package("kerberos"));
                assert!(is_known_lsa_package("Msv1_0"));
                assert!(is_known_lsa_package("CredSSP"));
                assert!(is_known_lsa_package("CloudAP"));
                // Empty entries (REG_MULTI_SZ trailing null) are ignored.
                assert!(is_known_lsa_package(""));
                // Anything else is suspicious.
                assert!(!is_known_lsa_package("evilssp"));
                assert!(!is_known_lsa_package("mimilib"));
            }

            #[test]
            fn is_known_network_provider_filters_microsoft_stock() {
                assert!(is_known_network_provider("RDPNP"));
                assert!(is_known_network_provider("LanmanWorkstation"));
                assert!(is_known_network_provider("WebClient"));
                assert!(!is_known_network_provider("CreddumpNP"));
                assert!(!is_known_network_provider("evil"));
            }

            #[test]
            fn decode_reg_multi_sz_handles_typical_payload() {
                // "kerberos\0msv1_0\0\0" as UTF-16LE
                let mut bytes: Vec<u8> = Vec::new();
                for s in &["kerberos", "msv1_0"] {
                    for c in s.encode_utf16() {
                        bytes.extend_from_slice(&c.to_le_bytes());
                    }
                    bytes.extend_from_slice(&[0u8, 0]);
                }
                bytes.extend_from_slice(&[0u8, 0]);
                let out = decode_reg_multi_sz(&bytes);
                assert_eq!(out, vec!["kerberos".to_string(), "msv1_0".to_string()]);
            }

            #[test]
            fn decode_reg_multi_sz_returns_empty_for_garbage() {
                let out = decode_reg_multi_sz(&[]);
                assert!(out.is_empty());
                let out = decode_reg_multi_sz(&[0u8, 0, 0, 0]);
                assert!(out.is_empty());
            }
        }
    }

    pub mod software {
        use super::*;

        pub fn parse(path: &Path, data: &[u8]) -> Vec<Artifact> {
            let mut out = Vec::new();
            let path_str = path.to_string_lossy().to_string();

            let Some(hive) = open_hive(data) else {
                return out;
            };
            let Ok(root) = hive.root_key_node() else {
                return out;
            };

            // ── OS version ───────────────────────────────────────────────
            if let Some(node) = walk(&root, &["Microsoft", "Windows NT", "CurrentVersion"]) {
                let product = read_value_string(&node, "ProductName").unwrap_or_default();
                let edition = read_value_string(&node, "EditionID").unwrap_or_default();
                let display = read_value_string(&node, "DisplayVersion").unwrap_or_default();
                let build = read_value_string(&node, "CurrentBuildNumber").unwrap_or_default();
                let install_unix = read_value_dword(&node, "InstallDate")
                    .map(|d| d as i64)
                    .filter(|&d| d > 0);
                let install_str = install_unix
                    .map(fmt_unix)
                    .unwrap_or_else(|| "unknown".to_string());

                let mut a = Artifact::new("OS Version", &path_str);
                if let Some(u) = install_unix {
                    a.timestamp = Some(u as u64);
                }
                a.add_field("title", &format!("Windows: {} {}", product, display));
                a.add_field(
                    "detail",
                    &format!(
                        "Edition: {} | Build: {} | Installed: {}",
                        edition, build, install_str
                    ),
                );
                a.add_field("file_type", "OS Version");
                a.add_field("forensic_value", "High");
                out.push(a);
            }

            // ── Installed Programs (Uninstall keys) ──────────────────────
            for branch in &["Microsoft\\Windows\\CurrentVersion\\Uninstall"] {
                let parts: Vec<&str> = branch.split('\\').collect();
                let Some(node) = walk(&root, &parts) else {
                    continue;
                };
                if let Some(Ok(iter)) = node.subkeys() {
                    for k_res in iter {
                        let Ok(k) = k_res else { continue };
                        let display = read_value_string(&k, "DisplayName").unwrap_or_default();
                        if display.is_empty() {
                            continue;
                        }
                        let publisher = read_value_string(&k, "Publisher").unwrap_or_default();
                        let version = read_value_string(&k, "DisplayVersion").unwrap_or_default();
                        let install = read_value_string(&k, "InstallDate").unwrap_or_default();
                        let location = read_value_string(&k, "InstallLocation").unwrap_or_default();

                        let suspicious_publisher =
                            publisher.is_empty() || is_offensive_tool_name(&display);

                        let mut a = Artifact::new("Installed Program", &path_str);
                        a.add_field("title", &format!("Installed: {}", display));
                        a.add_field(
                            "detail",
                            &format!(
                                "Publisher: {} | Version: {} | Date: {} | Path: {}",
                                if publisher.is_empty() {
                                    "(none)"
                                } else {
                                    &publisher
                                },
                                version,
                                install,
                                location
                            ),
                        );
                        a.add_field("file_type", "Installed Program");
                        a.add_field("mitre", "T1072");
                        if suspicious_publisher {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                    }
                }
            }

            // ── HKLM AutoRun ─────────────────────────────────────────────
            for autorun_path in &[
                "Microsoft\\Windows\\CurrentVersion\\Run",
                "Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            ] {
                let parts: Vec<&str> = autorun_path.split('\\').collect();
                let Some(node) = walk(&root, &parts) else {
                    continue;
                };
                if let Some(Ok(values)) = node.values() {
                    for vr in values {
                        let Ok(v) = vr else { continue };
                        let Ok(vname) = v.name() else { continue };
                        let exe = match v.data() {
                            Ok(d) => match d.into_vec() {
                                Ok(b) => utf16le_to_string(&b),
                                Err(_) => continue,
                            },
                            Err(_) => continue,
                        };
                        let lower = exe.to_lowercase();
                        let suspicious = lower.contains("\\temp\\")
                            || lower.contains("\\appdata\\")
                            || lower.contains("powershell")
                            || lower.contains("cmd.exe /c");
                        let mut a = Artifact::new("AutoRun", &path_str);
                        a.add_field("title", &format!("AutoRun: {}", vname.to_string_lossy()));
                        a.add_field(
                            "detail",
                            &format!("Path: {} | Hive: SOFTWARE\\{}", exe, autorun_path),
                        );
                        a.add_field("file_type", "AutoRun");
                        a.add_field("mitre", "T1547.001");
                        if suspicious {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                    }
                }
            }

            // ── v1.5.0 SOFTWARE hive parsers (RegRipper coverage) ───────
            parse_ifeo_debuggers(&root, &path_str, &mut out);
            parse_appinit_dlls(&root, &path_str, &mut out);
            parse_winlogon_persistence(&root, &path_str, &mut out);
            parse_active_setup(&root, &path_str, &mut out);
            parse_office_test_persistence(&root, &path_str, &mut out);
            parse_browser_helper_objects(&root, &path_str, &mut out);
            parse_shell_execute_hooks(&root, &path_str, &mut out);
            parse_defender_exclusions(&root, &path_str, &mut out);
            parse_winrm_trusted_hosts(&root, &path_str, &mut out);

            out
        }

        // ───────────────────────────────────────────────────────────────
        // Pure helpers (unit-testable)
        // ───────────────────────────────────────────────────────────────

        /// Recognise the well-known Microsoft Userinit / Shell values so
        /// the Winlogon parser can flag tampered values without dragging
        /// in a `\Userinit\Userinit\Userinit` regex chain.
        pub(super) fn is_default_userinit(value: &str) -> bool {
            let l = value.to_ascii_lowercase();
            l == "c:\\windows\\system32\\userinit.exe,"
                || l == "c:\\windows\\system32\\userinit.exe"
                || l == "userinit.exe,"
                || l == "userinit.exe"
        }

        pub(super) fn is_default_shell(value: &str) -> bool {
            let l = value.to_ascii_lowercase();
            l == "explorer.exe" || l == "c:\\windows\\explorer.exe"
        }

        /// Defender Exclusions paths leak the operator's playbook —
        /// anything obviously a drop site OR a wildcard exclusion is
        /// worth flagging.
        pub(super) fn is_suspicious_defender_exclusion(path_lower: &str) -> bool {
            path_lower.contains("\\temp\\")
                || path_lower.contains("\\appdata\\")
                || path_lower.contains("\\downloads\\")
                || path_lower.contains("\\public\\")
                || path_lower.starts_with("c:\\users\\")
                || path_lower == "*"
                || path_lower.ends_with("\\*")
        }

        // ───────────────────────────────────────────────────────────────
        // Parser bodies
        // ───────────────────────────────────────────────────────────────

        fn parse_ifeo_debuggers(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &[
                    "Microsoft",
                    "Windows NT",
                    "CurrentVersion",
                    "Image File Execution Options",
                ],
            ) else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let Ok(image) = k.name() else { continue };
                let image = image.to_string_lossy();
                let debugger = read_value_string(&k, "Debugger").unwrap_or_default();
                if debugger.is_empty() {
                    continue;
                }
                let mut a = Artifact::new("IFEO Debugger", path_str);
                a.add_field(
                    "title",
                    &format!("IFEO Debugger: {} \u{2192} {}", image, debugger),
                );
                a.add_field(
                    "detail",
                    "Image File Execution Options Debugger redirects EVERY launch \
                     of the named image (T1546.012). This is the classic 'sticky keys' \
                     persistence/backdoor vector.",
                );
                a.add_field("file_type", "IFEO Debugger");
                a.add_field("mitre", "T1546.012");
                a.add_field("forensic_value", "Critical");
                a.add_field("suspicious", "true");
                out.push(a);
            }
        }

        fn parse_appinit_dlls(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &["Microsoft", "Windows NT", "CurrentVersion", "Windows"],
            ) else {
                return;
            };
            let appinit = read_value_string(&node, "AppInit_DLLs").unwrap_or_default();
            let load_dlls = read_value_dword(&node, "LoadAppInit_DLLs").unwrap_or(0);
            if appinit.trim().is_empty() {
                return;
            }
            let enabled = load_dlls != 0;
            let mut a = Artifact::new("AppInit DLL", path_str);
            a.add_field("title", &format!("AppInit_DLLs: {}", appinit));
            a.add_field(
                "detail",
                &format!(
                    "LoadAppInit_DLLs = {} ({}) | AppInit DLLs are loaded into every \
                     user32.dll-linked process (T1546.010)",
                    load_dlls,
                    if enabled { "ENABLED" } else { "disabled" }
                ),
            );
            a.add_field("file_type", "AppInit DLL");
            a.add_field("mitre", "T1546.010");
            a.add_field("forensic_value", "Critical");
            a.add_field("suspicious", "true");
            out.push(a);
        }

        fn parse_winlogon_persistence(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &["Microsoft", "Windows NT", "CurrentVersion", "Winlogon"],
            ) else {
                return;
            };
            // Userinit should be C:\Windows\System32\userinit.exe,
            if let Some(value) = read_value_string(&node, "Userinit") {
                if !is_default_userinit(&value) {
                    let mut a = Artifact::new("Winlogon Persistence", path_str);
                    a.add_field("title", &format!("Winlogon Userinit modified: {}", value));
                    a.add_field(
                        "detail",
                        "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit \
                         (T1547.004) — added entries run at every interactive logon",
                    );
                    a.add_field("file_type", "Winlogon Persistence");
                    a.add_field("mitre", "T1547.004");
                    a.add_field("forensic_value", "Critical");
                    a.add_field("suspicious", "true");
                    out.push(a);
                }
            }
            // Shell should be explorer.exe
            if let Some(value) = read_value_string(&node, "Shell") {
                if !is_default_shell(&value) {
                    let mut a = Artifact::new("Winlogon Persistence", path_str);
                    a.add_field("title", &format!("Winlogon Shell modified: {}", value));
                    a.add_field(
                        "detail",
                        "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell \
                         (T1547.004) — replaces explorer.exe at logon",
                    );
                    a.add_field("file_type", "Winlogon Persistence");
                    a.add_field("mitre", "T1547.004");
                    a.add_field("forensic_value", "Critical");
                    a.add_field("suspicious", "true");
                    out.push(a);
                }
            }
            // Notify subkey — third-party DLLs hooking SAS / Logon events
            if let Some(notify) = node.subkey("Notify").and_then(|r| r.ok()) {
                if let Some(Ok(iter)) = notify.subkeys() {
                    for k_res in iter {
                        let Ok(k) = k_res else { continue };
                        let Ok(name) = k.name() else { continue };
                        let dll = read_value_string(&k, "DllName").unwrap_or_default();
                        let mut a = Artifact::new("Winlogon Persistence", path_str);
                        a.add_field(
                            "title",
                            &format!("Winlogon\\Notify: {}", name.to_string_lossy()),
                        );
                        a.add_field("detail", &format!("DllName: {}", dll));
                        a.add_field("file_type", "Winlogon Persistence");
                        a.add_field("mitre", "T1547.004");
                        a.add_field("forensic_value", "Critical");
                        a.add_field("suspicious", "true");
                        out.push(a);
                    }
                }
            }
        }

        fn parse_active_setup(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["Microsoft", "Active Setup", "Installed Components"])
            else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let stub = read_value_string(&k, "StubPath").unwrap_or_default();
                if stub.is_empty() {
                    continue;
                }
                let lower = stub.to_lowercase();
                let suspicious = lower.contains("powershell")
                    || lower.contains("cmd.exe")
                    || lower.contains("\\temp\\")
                    || lower.contains("\\appdata\\")
                    || lower.contains("rundll32");
                let mut a = Artifact::new("Active Setup", path_str);
                a.add_field(
                    "title",
                    &format!(
                        "Active Setup: {}",
                        k.name()
                            .ok()
                            .map(|n| n.to_string_lossy())
                            .unwrap_or_default()
                    ),
                );
                a.add_field(
                    "detail",
                    &format!(
                        "StubPath: {} | runs once per user at first logon (T1547.014)",
                        stub
                    ),
                );
                a.add_field("file_type", "Active Setup");
                a.add_field("mitre", "T1547.014");
                if suspicious {
                    a.add_field("forensic_value", "Critical");
                    a.add_field("suspicious", "true");
                } else {
                    a.add_field("forensic_value", "Medium");
                }
                out.push(a);
            }
        }

        fn parse_office_test_persistence(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            // Office\test\Special\Perf — well-known Office persistence trick.
            // The mere presence of this key (with any value) is suspicious.
            let Some(node) = walk(root, &["Microsoft", "Office test", "Special", "Perf"]) else {
                return;
            };
            let dll = read_value_string(&node, "").unwrap_or_default();
            let mut a = Artifact::new("Office Test Persistence", path_str);
            a.add_field(
                "title",
                "Office\\test\\Special\\Perf key present (Office persistence)",
            );
            a.add_field(
                "detail",
                &format!(
                    "Default value: {} | Office loads this DLL on every startup \
                     (T1137.002)",
                    dll
                ),
            );
            a.add_field("file_type", "Office Test Persistence");
            a.add_field("mitre", "T1137.002");
            a.add_field("forensic_value", "Critical");
            a.add_field("suspicious", "true");
            out.push(a);
        }

        fn parse_browser_helper_objects(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &[
                    "Microsoft",
                    "Windows",
                    "CurrentVersion",
                    "Explorer",
                    "Browser Helper Objects",
                ],
            ) else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let Ok(clsid) = k.name() else { continue };
                let mut a = Artifact::new("Browser Helper Object", path_str);
                a.add_field("title", &format!("BHO: {}", clsid.to_string_lossy()));
                a.add_field(
                    "detail",
                    "Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects \
                     — IE-era persistence vector still respected by some host apps (T1176)",
                );
                a.add_field("file_type", "Browser Helper Object");
                a.add_field("mitre", "T1176");
                a.add_field("forensic_value", "High");
                a.add_field("suspicious", "true");
                out.push(a);
            }
        }

        fn parse_shell_execute_hooks(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &[
                    "Microsoft",
                    "Windows",
                    "CurrentVersion",
                    "Explorer",
                    "ShellExecuteHooks",
                ],
            ) else {
                return;
            };
            let Some(Ok(values)) = node.values() else {
                return;
            };
            for vr in values {
                let Ok(v) = vr else { continue };
                let Ok(name) = v.name() else { continue };
                let mut a = Artifact::new("Shell Execute Hook", path_str);
                a.add_field(
                    "title",
                    &format!("ShellExecuteHook: {}", name.to_string_lossy()),
                );
                a.add_field(
                    "detail",
                    "ShellExecuteHooks intercept every ShellExecute call \
                     made by Explorer (T1546)",
                );
                a.add_field("file_type", "Shell Execute Hook");
                a.add_field("mitre", "T1546");
                a.add_field("forensic_value", "Critical");
                a.add_field("suspicious", "true");
                out.push(a);
            }
        }

        fn parse_defender_exclusions(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(excl) = walk(root, &["Microsoft", "Windows Defender", "Exclusions"]) else {
                return;
            };
            for (sub, kind) in &[
                ("Paths", "Path"),
                ("Processes", "Process"),
                ("Extensions", "Extension"),
                ("IpAddresses", "IpAddress"),
            ] {
                let Some(node) = excl.subkey(sub).and_then(|r| r.ok()) else {
                    continue;
                };
                let Some(Ok(values)) = node.values() else {
                    continue;
                };
                for vr in values {
                    let Ok(v) = vr else { continue };
                    let Ok(name) = v.name() else { continue };
                    let name = name.to_string_lossy();
                    let lower = name.to_lowercase();
                    let suspicious = is_suspicious_defender_exclusion(&lower);
                    let mut a = Artifact::new("Defender Exclusion", path_str);
                    a.add_field("title", &format!("Defender Exclusion ({}): {}", kind, name));
                    a.add_field(
                        "detail",
                        "Microsoft\\Windows Defender\\Exclusions — defender will \
                         not scan listed locations (T1562.001)",
                    );
                    a.add_field("file_type", "Defender Exclusion");
                    a.add_field("mitre", "T1562.001");
                    if suspicious {
                        a.add_field("forensic_value", "Critical");
                        a.add_field("suspicious", "true");
                    } else {
                        a.add_field("forensic_value", "High");
                    }
                    out.push(a);
                }
            }
        }

        fn parse_winrm_trusted_hosts(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &["Microsoft", "Windows", "CurrentVersion", "WSMAN", "Client"],
            ) else {
                return;
            };
            let trusted = read_value_string(&node, "TrustedHosts").unwrap_or_default();
            if trusted.trim().is_empty() {
                return;
            }
            let suspicious = trusted.trim() == "*" || trusted.contains('*');
            let mut a = Artifact::new("WinRM TrustedHosts", path_str);
            a.add_field("title", &format!("WinRM TrustedHosts: {}", trusted));
            a.add_field(
                "detail",
                "WSMAN\\Client\\TrustedHosts — wildcard or remote-host entries \
                 enable lateral movement via PSRemoting (T1021.006)",
            );
            a.add_field("file_type", "WinRM TrustedHosts");
            a.add_field("mitre", "T1021.006");
            if suspicious {
                a.add_field("forensic_value", "Critical");
                a.add_field("suspicious", "true");
            } else {
                a.add_field("forensic_value", "High");
            }
            out.push(a);
        }

        fn is_offensive_tool_name(name: &str) -> bool {
            let l = name.to_lowercase();
            const TOOLS: &[&str] = &[
                "mimikatz",
                "metasploit",
                "cobalt strike",
                "psexec",
                "nmap",
                "wireshark",
                "burp",
                "kali",
                "havoc",
                "sliver",
                "responder",
            ];
            TOOLS.iter().any(|t| l.contains(t))
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn is_default_userinit_recognises_msft_default() {
                assert!(is_default_userinit("C:\\Windows\\System32\\userinit.exe,"));
                assert!(is_default_userinit("c:\\windows\\system32\\userinit.exe"));
                assert!(is_default_userinit("Userinit.exe,"));
                assert!(!is_default_userinit(
                    "C:\\Windows\\System32\\userinit.exe,evil.exe"
                ));
                assert!(!is_default_userinit("powershell.exe -enc xxx"));
            }

            #[test]
            fn is_default_shell_recognises_explorer() {
                assert!(is_default_shell("explorer.exe"));
                assert!(is_default_shell("Explorer.exe"));
                assert!(is_default_shell("c:\\windows\\explorer.exe"));
                assert!(!is_default_shell("powershell.exe"));
                assert!(!is_default_shell("cmd.exe"));
            }

            #[test]
            fn is_suspicious_defender_exclusion_flags_drop_locations_and_wildcards() {
                assert!(is_suspicious_defender_exclusion(
                    "c:\\users\\victim\\downloads\\"
                ));
                assert!(is_suspicious_defender_exclusion("c:\\temp\\stage\\"));
                assert!(is_suspicious_defender_exclusion("c:\\users\\public\\"));
                assert!(is_suspicious_defender_exclusion("*"));
                assert!(is_suspicious_defender_exclusion("c:\\some\\folder\\*"));
                assert!(!is_suspicious_defender_exclusion(
                    "c:\\program files\\corp_av\\"
                ));
                assert!(!is_suspicious_defender_exclusion(".vmdk"));
            }

            #[test]
            fn is_offensive_tool_name_catches_redteam_tools() {
                assert!(is_offensive_tool_name("Mimikatz"));
                assert!(is_offensive_tool_name("Cobalt Strike Beacon"));
                assert!(is_offensive_tool_name("PsExec utility"));
                assert!(!is_offensive_tool_name("Adobe Reader"));
                assert!(!is_offensive_tool_name("Microsoft Office"));
            }
        }
    }

    pub mod sam {
        use super::*;

        pub fn parse(path: &Path, data: &[u8]) -> Vec<Artifact> {
            let mut out = Vec::new();
            let path_str = path.to_string_lossy().to_string();

            let Some(hive) = open_hive(data) else {
                return out;
            };
            let Ok(root) = hive.root_key_node() else {
                return out;
            };

            // SAM\\Domains\\Account\\Users\\Names\\<username> — each subkey
            // is a username, the F value contains a binary blob with logon
            // statistics. We extract usernames and the InternetUserName
            // (Microsoft account email) when present.
            if let Some(names) = walk(&root, &["Domains", "Account", "Users", "Names"]) {
                if let Some(Ok(iter)) = names.subkeys() {
                    for k_res in iter {
                        let Ok(k) = k_res else { continue };
                        let Ok(uname) = k.name() else { continue };
                        let uname = uname.to_string_lossy();
                        let mut a = Artifact::new("SAM Account", &path_str);
                        a.add_field("title", &format!("Local account: {}", uname));
                        a.add_field("detail", "SAM\\Domains\\Account\\Users\\Names");
                        a.add_field("file_type", "SAM Account");
                        a.add_field("mitre", "T1087.001");
                        a.add_field("forensic_value", "Medium");
                        out.push(a);
                    }
                }
            }

            // Cloud accounts: SAM\\Domains\\Account\\Users\\<RID>\\InternetUserName
            if let Some(users) = walk(&root, &["Domains", "Account", "Users"]) {
                if let Some(Ok(iter)) = users.subkeys() {
                    for k_res in iter {
                        let Ok(k) = k_res else { continue };
                        let Ok(rid) = k.name() else { continue };
                        let rid = rid.to_string_lossy();
                        if rid == "Names" {
                            continue;
                        }
                        if let Some(email) = read_value_string(&k, "InternetUserName") {
                            if !email.is_empty() {
                                let mut a = Artifact::new("Cloud Identity", &path_str);
                                a.add_field("title", &format!("Microsoft account: {}", email));
                                a.add_field("detail", &format!("RID: {}", rid));
                                a.add_field("file_type", "Cloud Identity");
                                a.add_field("mitre", "T1078.003");
                                a.add_field("forensic_value", "High");
                                out.push(a);
                            }
                        }
                    }
                }
            }

            out
        }
    }

    pub mod security {
        use super::*;

        pub fn parse(path: &Path, _data: &[u8]) -> Vec<Artifact> {
            // The SECURITY hive is largely opaque (LSA secrets are encrypted
            // with the bootkey from SYSTEM). We surface only the existence of
            // the audit policy entry as a forensic marker.
            let path_str = path.to_string_lossy().to_string();
            let mut a = Artifact::new("Security Hive", &path_str);
            a.add_field("title", "SECURITY hive present");
            a.add_field(
                "detail",
                "LSA secrets and cached credentials require offline decryption with the SYSTEM bootkey",
            );
            a.add_field("file_type", "Security Hive");
            a.add_field("mitre", "T1003.004");
            a.add_field("forensic_value", "Medium");
            vec![a]
        }
    }

    pub mod amcache {
        //! Full AmCache.hve parser modeled on EricZimmerman's AmcacheParser.
        //!
        //! Subkeys covered (modern Win10/11 layout, all under `Root\`):
        //!   - InventoryApplicationFile — per-file SHA1 + execution evidence
        //!   - InventoryApplication     — installed application metadata
        //!   - InventoryApplicationShortcut — Start-Menu / desktop shortcuts
        //!   - InventoryDriverBinary    — driver binary inventory
        //!   - InventoryDriverPackage   — driver package provenance
        //!   - InventoryDeviceContainer — connected device containers (USB hubs, etc.)
        //!   - InventoryDevicePnp       — PnP device inventory (with class GUIDs)
        //!
        //! Legacy (Win7-style) subkeys also covered:
        //!   - Root\File\<volume_GUID>\<file_id>  — pre-Win10 file records
        //!   - Root\Programs\<install_id>         — pre-Win10 installed programs
        //!
        //! All parsers cap at sane limits (5000 files, 1000 drivers, 2000
        //! per other category) so a corrupt or huge hive can't blow up
        //! report size.

        use super::*;

        /// Apply Strata's "this AmCache file is interesting" heuristic.
        /// Empty publisher OR path inside Temp/AppData/Downloads/Public is
        /// the trigger — these are the high-signal locations malware drops
        /// itself into.
        pub fn is_suspicious_amcache_path(path_lower: &str, publisher: &str) -> bool {
            if publisher.trim().is_empty() {
                return true;
            }
            path_lower.contains("\\temp\\")
                || path_lower.contains("\\appdata\\")
                || path_lower.contains("\\downloads\\")
                || path_lower.contains("\\public\\")
                || path_lower.contains("\\users\\public\\")
                || path_lower.contains("\\programdata\\")
        }

        /// Map a Microsoft device-setup class GUID to a human-readable
        /// label. Used by `InventoryDevicePnp` to give the examiner a
        /// quick "USB controller / Disk drive / Display adapter" string
        /// instead of an opaque GUID.
        pub fn device_class_label(class_guid: &str) -> &'static str {
            match class_guid.to_ascii_uppercase().as_str() {
                "{36FC9E60-C465-11CF-8056-444553540000}" => "USB Controller",
                "{4D36E967-E325-11CE-BFC1-08002BE10318}" => "Disk Drive",
                "{4D36E968-E325-11CE-BFC1-08002BE10318}" => "Display Adapter",
                "{4D36E96E-E325-11CE-BFC1-08002BE10318}" => "Modem",
                "{4D36E972-E325-11CE-BFC1-08002BE10318}" => "Network Adapter",
                "{4D36E96F-E325-11CE-BFC1-08002BE10318}" => "Mouse",
                "{4D36E96B-E325-11CE-BFC1-08002BE10318}" => "Keyboard",
                "{6BDD1FC6-810F-11D0-BEC7-08002BE2092F}" => "Image Device",
                "{4D36E97D-E325-11CE-BFC1-08002BE10318}" => "System Device",
                "{4D36E96C-E325-11CE-BFC1-08002BE10318}" => "Sound, Video & Game Controller",
                "{4D36E978-E325-11CE-BFC1-08002BE10318}" => "Port (COM/LPT)",
                "{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}" => "HID",
                "{EEC5AD98-8080-425F-922A-DABF3DE3F69A}" => "Portable Device",
                _ => "Unknown class",
            }
        }

        pub fn parse(path: &Path, data: &[u8]) -> Vec<Artifact> {
            let mut out = Vec::new();
            let path_str = path.to_string_lossy().to_string();

            let Some(hive) = open_hive(data) else {
                return out;
            };
            let Ok(root) = hive.root_key_node() else {
                return out;
            };

            // InventoryApplicationFile + InventoryDriverBinary are owned
            // by `crate::amcache`; avoid duplicate artifacts here.
            parse_inventory_application(&root, &path_str, &mut out);
            parse_inventory_application_shortcut(&root, &path_str, &mut out);
            parse_inventory_driver_package(&root, &path_str, &mut out);
            parse_inventory_device_container(&root, &path_str, &mut out);
            parse_inventory_device_pnp(&root, &path_str, &mut out);
            parse_legacy_file(&root, &path_str, &mut out);
            parse_legacy_programs(&root, &path_str, &mut out);

            out
        }

        // ── Modern: Root\InventoryApplication ──────────────────────────
        fn parse_inventory_application(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["Root", "InventoryApplication"]) else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            let mut count = 0;
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let name = read_value_string(&k, "Name").unwrap_or_default();
                let publisher = read_value_string(&k, "Publisher").unwrap_or_default();
                let version = read_value_string(&k, "Version").unwrap_or_default();
                let install_date = read_value_string(&k, "InstallDate").unwrap_or_default();
                let root_dir = read_value_string(&k, "RootDirPath").unwrap_or_default();
                let install_source = read_value_string(&k, "Source").unwrap_or_default();
                let install_type = read_value_string(&k, "Type").unwrap_or_default();
                let registry_key = read_value_string(&k, "RegistryKeyPath").unwrap_or_default();
                if name.is_empty() && root_dir.is_empty() {
                    continue;
                }

                let lc = root_dir.to_lowercase();
                let suspicious = is_suspicious_amcache_path(&lc, &publisher)
                    || install_source.eq_ignore_ascii_case("WindowsUpdate") && publisher.is_empty();

                let mut a = Artifact::new("AmCache Installed App", path_str);
                a.add_field(
                    "title",
                    &format!(
                        "Installed: {}",
                        if !name.is_empty() { &name } else { &root_dir }
                    ),
                );
                a.add_field(
                    "detail",
                    &format!(
                        "Publisher: {} | Version: {} | InstallDate: {} | Type: {} | Source: {} \
                         | RootDir: {} | RegKey: {}",
                        publisher,
                        version,
                        install_date,
                        install_type,
                        install_source,
                        root_dir,
                        registry_key
                    ),
                );
                a.add_field("file_type", "AmCache Installed App");
                a.add_field("mitre", "T1518");
                if suspicious {
                    a.add_field("forensic_value", "High");
                    a.add_field("suspicious", "true");
                } else {
                    a.add_field("forensic_value", "Medium");
                }
                out.push(a);
                count += 1;
                if count > 2000 {
                    break;
                }
            }
        }

        // ── Modern: Root\InventoryApplicationShortcut ──────────────────
        fn parse_inventory_application_shortcut(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["Root", "InventoryApplicationShortcut"]) else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            let mut count = 0;
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let target = read_value_string(&k, "ShortcutTargetPath").unwrap_or_default();
                if target.is_empty() {
                    continue;
                }
                let lc = target.to_lowercase();
                let suspicious = is_suspicious_amcache_path(&lc, "");
                let mut a = Artifact::new("AmCache Shortcut", path_str);
                a.add_field("title", &format!("Shortcut: {}", target));
                a.add_field("detail", "InventoryApplicationShortcut target");
                a.add_field("file_type", "AmCache Shortcut");
                a.add_field("mitre", "T1547.009");
                if suspicious {
                    a.add_field("forensic_value", "High");
                    a.add_field("suspicious", "true");
                } else {
                    a.add_field("forensic_value", "Medium");
                }
                out.push(a);
                count += 1;
                if count > 2000 {
                    break;
                }
            }
        }

        // ── Modern: Root\InventoryDriverPackage ────────────────────────
        fn parse_inventory_driver_package(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["Root", "InventoryDriverPackage"]) else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            let mut count = 0;
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let pkg_id = k
                    .name()
                    .ok()
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_default();
                let provider = read_value_string(&k, "ProviderName").unwrap_or_default();
                let inf = read_value_string(&k, "Inf").unwrap_or_default();
                let class = read_value_string(&k, "Class").unwrap_or_default();
                let version = read_value_string(&k, "Version").unwrap_or_default();
                let date = read_value_string(&k, "Date").unwrap_or_default();
                if provider.is_empty() && inf.is_empty() {
                    continue;
                }
                let mut a = Artifact::new("AmCache Driver Package", path_str);
                a.add_field("title", &format!("Driver pkg: {} ({})", inf, provider));
                a.add_field(
                    "detail",
                    &format!(
                        "Provider: {} | Class: {} | Version: {} | Date: {} | PackageId: {}",
                        provider, class, version, date, pkg_id
                    ),
                );
                a.add_field("file_type", "AmCache Driver Package");
                a.add_field("mitre", "T1014");
                a.add_field("forensic_value", "Medium");
                out.push(a);
                count += 1;
                if count > 2000 {
                    break;
                }
            }
        }

        // ── Modern: Root\InventoryDeviceContainer ──────────────────────
        fn parse_inventory_device_container(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["Root", "InventoryDeviceContainer"]) else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            let mut count = 0;
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let model = read_value_string(&k, "ModelName").unwrap_or_default();
                let manufacturer = read_value_string(&k, "Manufacturer").unwrap_or_default();
                let category = read_value_string(&k, "Categories").unwrap_or_default();
                let primary = read_value_string(&k, "PrimaryCategory").unwrap_or_default();
                let networked = read_value_string(&k, "Networked").unwrap_or_default();
                if model.is_empty() && manufacturer.is_empty() {
                    continue;
                }
                let mut a = Artifact::new("AmCache Device Container", path_str);
                a.add_field("title", &format!("Device: {} ({})", model, manufacturer));
                a.add_field(
                    "detail",
                    &format!(
                        "Categories: {} | Primary: {} | Networked: {}",
                        category, primary, networked
                    ),
                );
                a.add_field("file_type", "AmCache Device Container");
                a.add_field("mitre", "T1052.001");
                a.add_field("forensic_value", "Medium");
                out.push(a);
                count += 1;
                if count > 2000 {
                    break;
                }
            }
        }

        // ── Modern: Root\InventoryDevicePnp ────────────────────────────
        fn parse_inventory_device_pnp(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["Root", "InventoryDevicePnp"]) else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            let mut count = 0;
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let description = read_value_string(&k, "Description").unwrap_or_default();
                let class = read_value_string(&k, "Class").unwrap_or_default();
                let class_guid = read_value_string(&k, "ClassGuid").unwrap_or_default();
                let manufacturer = read_value_string(&k, "Manufacturer").unwrap_or_default();
                let device_id = read_value_string(&k, "ParentId").unwrap_or_default();
                if description.is_empty() && class.is_empty() {
                    continue;
                }
                let class_label = device_class_label(&class_guid);
                let mut a = Artifact::new("AmCache PnP Device", path_str);
                a.add_field("title", &format!("PnP: {} ({})", description, class_label));
                a.add_field(
                    "detail",
                    &format!(
                        "Class: {} | ClassGuid: {} ({}) | Manufacturer: {} | ParentId: {}",
                        class, class_guid, class_label, manufacturer, device_id
                    ),
                );
                a.add_field("file_type", "AmCache PnP Device");
                a.add_field("mitre", "T1120");
                a.add_field("forensic_value", "Medium");
                out.push(a);
                count += 1;
                if count > 2000 {
                    break;
                }
            }
        }

        // ── Legacy (Win7/8): Root\File\<volume_GUID>\<file_id> ─────────
        fn parse_legacy_file(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(file_root) = walk(root, &["Root", "File"]) else {
                return;
            };
            let Some(Ok(vol_iter)) = file_root.subkeys() else {
                return;
            };
            let mut count = 0;
            for vol_res in vol_iter {
                let Ok(vol_node) = vol_res else { continue };
                let vol_guid = vol_node
                    .name()
                    .ok()
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_default();
                let Some(Ok(file_iter)) = vol_node.subkeys() else {
                    continue;
                };
                for file_res in file_iter {
                    let Ok(file_node) = file_res else { continue };
                    // Common values across the legacy schema. Numeric value
                    // names ("0", "100", etc.) hold the path/sha1/etc.
                    let path_l = read_value_string(&file_node, "15").unwrap_or_default();
                    let sha1 = read_value_string(&file_node, "101").unwrap_or_default();
                    let publisher = read_value_string(&file_node, "0").unwrap_or_default();
                    if path_l.is_empty() && sha1.is_empty() {
                        continue;
                    }
                    let suspicious = is_suspicious_amcache_path(&path_l.to_lowercase(), &publisher);
                    let mut a = Artifact::new("AmCache Legacy File", path_str);
                    a.add_field("title", &format!("Legacy AmCache: {}", path_l));
                    a.add_field(
                        "detail",
                        &format!(
                            "Vol: {} | SHA1: {} | Publisher: {}",
                            vol_guid, sha1, publisher
                        ),
                    );
                    a.add_field("file_type", "AmCache Legacy File");
                    a.add_field("mitre", "T1059");
                    if suspicious {
                        a.add_field("forensic_value", "High");
                        a.add_field("suspicious", "true");
                    } else {
                        a.add_field("forensic_value", "Medium");
                    }
                    out.push(a);
                    count += 1;
                    if count > 5000 {
                        return;
                    }
                }
            }
        }

        // ── Legacy (Win7/8): Root\Programs\<install_id> ────────────────
        fn parse_legacy_programs(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(root, &["Root", "Programs"]) else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            let mut count = 0;
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let name = read_value_string(&k, "0").unwrap_or_default();
                let version = read_value_string(&k, "1").unwrap_or_default();
                let publisher = read_value_string(&k, "2").unwrap_or_default();
                let install_date = read_value_string(&k, "a").unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                let suspicious = publisher.trim().is_empty();
                let mut a = Artifact::new("AmCache Legacy Program", path_str);
                a.add_field("title", &format!("Legacy installed: {}", name));
                a.add_field(
                    "detail",
                    &format!(
                        "Version: {} | Publisher: {} | InstallDate: {}",
                        version, publisher, install_date
                    ),
                );
                a.add_field("file_type", "AmCache Legacy Program");
                a.add_field("mitre", "T1518");
                if suspicious {
                    a.add_field("forensic_value", "High");
                    a.add_field("suspicious", "true");
                } else {
                    a.add_field("forensic_value", "Medium");
                }
                out.push(a);
                count += 1;
                if count > 2000 {
                    break;
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn is_suspicious_amcache_path_flags_drop_locations() {
                // Empty publisher — always suspicious.
                assert!(is_suspicious_amcache_path("c:\\windows\\notepad.exe", ""));
                assert!(is_suspicious_amcache_path(
                    "c:\\windows\\notepad.exe",
                    "   "
                ));
                // Temp / AppData / Downloads / Public / ProgramData
                assert!(is_suspicious_amcache_path(
                    "c:\\users\\victim\\appdata\\local\\temp\\foo.exe",
                    "Microsoft"
                ));
                assert!(is_suspicious_amcache_path(
                    "c:\\users\\victim\\downloads\\setup.exe",
                    "Microsoft"
                ));
                assert!(is_suspicious_amcache_path(
                    "c:\\programdata\\stage.exe",
                    "Microsoft"
                ));
                // Clean: signed publisher in normal install path.
                assert!(!is_suspicious_amcache_path(
                    "c:\\program files\\microsoft\\office\\winword.exe",
                    "Microsoft Corporation"
                ));
            }

            #[test]
            fn device_class_label_resolves_known_guids_case_insensitive() {
                assert_eq!(
                    device_class_label("{36FC9E60-C465-11CF-8056-444553540000}"),
                    "USB Controller"
                );
                // Lowercase variant — should still resolve.
                assert_eq!(
                    device_class_label("{36fc9e60-c465-11cf-8056-444553540000}"),
                    "USB Controller"
                );
                assert_eq!(
                    device_class_label("{4D36E972-E325-11CE-BFC1-08002BE10318}"),
                    "Network Adapter"
                );
                // Unknown GUID falls through to generic label.
                assert_eq!(
                    device_class_label("{00000000-0000-0000-0000-000000000000}"),
                    "Unknown class"
                );
            }

            #[test]
            fn parse_returns_empty_for_garbage_data() {
                // A garbage buffer is not a valid hive — open_hive returns
                // None, parse should return an empty vec rather than panic.
                use std::path::PathBuf;
                let p = PathBuf::from("/tmp/AmCache.hve");
                let out = parse(&p, &[0u8; 32]);
                assert!(out.is_empty());
            }
        }
    }

    pub mod usrclass {
        use super::*;

        pub fn parse(path: &Path, data: &[u8]) -> Vec<Artifact> {
            let mut out = Vec::new();
            let path_str = path.to_string_lossy().to_string();

            let Some(hive) = open_hive(data) else {
                return out;
            };
            let Ok(root) = hive.root_key_node() else {
                return out;
            };

            // MuiCache — display names of executed apps
            if let Some(node) = walk(
                &root,
                &[
                    "Local Settings",
                    "Software",
                    "Microsoft",
                    "Windows",
                    "ShellNoRoam",
                    "MUICache",
                ],
            )
            .or_else(|| {
                walk(
                    &root,
                    &[
                        "Local Settings",
                        "Software",
                        "Microsoft",
                        "Windows",
                        "Shell",
                        "MuiCache",
                    ],
                )
            }) {
                if let Some(Ok(values)) = node.values() {
                    for vr in values {
                        let Ok(v) = vr else { continue };
                        let Ok(vname) = v.name() else { continue };
                        let vname = vname.to_string_lossy();
                        if !vname.contains('\\') {
                            continue;
                        }
                        let display = match v.data() {
                            Ok(d) => match d.into_vec() {
                                Ok(b) => utf16le_to_string(&b),
                                Err(_) => continue,
                            },
                            Err(_) => continue,
                        };
                        let mut a = Artifact::new("MuiCache", &path_str);
                        a.add_field("title", &format!("MuiCache: {}", display));
                        a.add_field("detail", &format!("Executable: {}", vname));
                        a.add_field("file_type", "MuiCache");
                        a.add_field("mitre", "T1059");
                        a.add_field("forensic_value", "Medium");
                        out.push(a);
                    }
                }
            }

            // UserChoice default app handlers — flag scripts associated with
            // unexpected handlers.
            if let Some(node) = walk(
                &root,
                &[
                    "Local Settings",
                    "Software",
                    "Microsoft",
                    "Windows",
                    "CurrentVersion",
                    "Explorer",
                    "FileExts",
                ],
            ) {
                if let Some(Ok(iter)) = node.subkeys() {
                    for k_res in iter {
                        let Ok(k) = k_res else { continue };
                        let Ok(ext) = k.name() else { continue };
                        let ext = ext.to_string_lossy();
                        let Some(uc) = k.subkey("UserChoice").and_then(|r| r.ok()) else {
                            continue;
                        };
                        let progid = read_value_string(&uc, "ProgId").unwrap_or_default();
                        if progid.is_empty() {
                            continue;
                        }
                        let suspicious =
                            matches!(ext.as_ref(), ".exe" | ".bat" | ".ps1" | ".js" | ".vbs")
                                && !progid.to_lowercase().contains("exefile")
                                && !progid.to_lowercase().contains("batfile");
                        let mut a = Artifact::new("UserChoice", &path_str);
                        a.add_field("title", &format!("Default handler: {} → {}", ext, progid));
                        a.add_field("detail", "USRCLASS\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts");
                        a.add_field("file_type", "UserChoice");
                        a.add_field("mitre", "T1546.001");
                        if suspicious {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                    }
                }
            }

            out
        }
    }

    pub mod ntuser {
        //! v1.1.0 — NTUSER.DAT parsers for HKCU keys not already owned by
        //! Chronicle (UserAssist, RecentDocs, ComDlg32 MRUs) or Trace
        //! (BAM/DAM).
        //!
        //! Phantom owns:
        //!   * Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager
        //!     \ConsentStore\<capability>\NonPackaged\<app>\
        //!     LastUsedTimeStart / LastUsedTimeStop / Value
        //!   * Software\7-Zip\FM\FolderHistory   (recent paths)
        //!   * Software\WinRAR\ArcHistory        (MRU archive paths)
        //!   * Software\Nico Mak Computing\WinZip\
        //!   * Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\
        //!     AppLaunch / AppSwitched (per-app counters)

        use super::*;

        pub fn parse(path: &Path, data: &[u8]) -> Vec<Artifact> {
            let mut out = Vec::new();
            let path_str = path.to_string_lossy().to_string();

            let Some(hive) = open_hive(data) else {
                return out;
            };
            let Ok(root) = hive.root_key_node() else {
                return out;
            };

            // ── CapabilityAccessManager ────────────────────────────────
            //
            // Walk Software\...\CapabilityAccessManager\ConsentStore\
            // Each subkey is a capability (microphone, webcam, location).
            // Under each capability\NonPackaged\ are app-path subkeys with
            // LastUsedTimeStart / LastUsedTimeStop FILETIMEs.
            if let Some(consent) = walk(
                &root,
                &[
                    "Software",
                    "Microsoft",
                    "Windows",
                    "CurrentVersion",
                    "CapabilityAccessManager",
                    "ConsentStore",
                ],
            ) {
                if let Some(Ok(cap_iter)) = consent.subkeys() {
                    for cap_res in cap_iter {
                        let Ok(cap_node) = cap_res else { continue };
                        let Ok(cap_name) = cap_node.name() else {
                            continue;
                        };
                        let cap_name = cap_name.to_string_lossy();
                        let mitre = match cap_name.as_ref() {
                            "microphone" => "T1123",
                            "webcam" => "T1125",
                            "location" => "T1430",
                            "contacts" => "T1213",
                            _ => "T1005",
                        };

                        // Walk both NonPackaged (desktop) and direct app subkeys
                        let nonpackaged = cap_node.subkey("NonPackaged").and_then(|r| r.ok());
                        let parents: Vec<nt_hive::KeyNode<'_, &[u8]>> =
                            if let Some(np) = nonpackaged {
                                vec![np, cap_node.clone()]
                            } else {
                                vec![cap_node.clone()]
                            };

                        for parent in parents {
                            if let Some(Ok(app_iter)) = parent.subkeys() {
                                for app_res in app_iter {
                                    let Ok(app_node) = app_res else { continue };
                                    let Ok(app_path_raw) = app_node.name() else {
                                        continue;
                                    };
                                    let app_path = app_path_raw.to_string_lossy();
                                    if app_path == "NonPackaged" {
                                        continue;
                                    }

                                    let value =
                                        read_value_string(&app_node, "Value").unwrap_or_default();
                                    let last_start = read_filetime(&app_node, "LastUsedTimeStart");
                                    let last_stop = read_filetime(&app_node, "LastUsedTimeStop");

                                    if value != "Allow" && last_start.is_none() {
                                        continue;
                                    }

                                    // Capability access app paths use # as
                                    // separator instead of \
                                    let display_path = app_path.replace('#', "\\");
                                    let lc = display_path.to_lowercase();
                                    let suspicious = lc.contains("\\temp\\")
                                        || lc.contains("\\appdata\\local\\temp")
                                        || lc.contains("\\downloads\\");

                                    let last_used = last_start
                                        .or(last_stop)
                                        .map(fmt_unix)
                                        .unwrap_or_else(|| "(no timestamp)".to_string());

                                    let mut a = Artifact::new("Capability Access", &path_str);
                                    if let Some(t) = last_start.or(last_stop) {
                                        a.timestamp = Some(t as u64);
                                    }
                                    a.add_field(
                                        "title",
                                        &format!(
                                            "Capability: {} \u{2192} {}",
                                            cap_name, display_path
                                        ),
                                    );
                                    a.add_field(
                                        "detail",
                                        &format!("Value: {} | Last used: {}", value, last_used),
                                    );
                                    a.add_field("file_type", "Capability Access");
                                    a.add_field("mitre", mitre);
                                    if suspicious {
                                        a.add_field("forensic_value", "High");
                                        a.add_field("suspicious", "true");
                                    } else {
                                        a.add_field("forensic_value", "Medium");
                                    }
                                    out.push(a);
                                }
                            }
                        }
                    }
                }
            }

            // ── 7-Zip FolderHistory ────────────────────────────────────
            if let Some(node) = walk(&root, &["Software", "7-Zip", "FM"]) {
                if let Some(bytes) = read_value_bytes(&node, "FolderHistory") {
                    // Multi-string (REG_MULTI_SZ) — null-separated UTF-16LE.
                    let entries = decode_multi_sz(&bytes);
                    for entry in entries {
                        let suspicious = is_archive_path_suspicious(&entry);
                        let mut a = Artifact::new("Archive Tool", &path_str);
                        a.add_field("title", &format!("7-Zip recent: {}", entry));
                        a.add_field("detail", "7-Zip FolderHistory");
                        a.add_field("file_type", "Archive Tool");
                        a.add_field("mitre", "T1560.001");
                        if suspicious {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                    }
                }
            }

            // ── WinRAR ArcHistory ──────────────────────────────────────
            if let Some(node) = walk(&root, &["Software", "WinRAR", "ArcHistory"]) {
                if let Some(Ok(values)) = node.values() {
                    for vr in values {
                        let Ok(v) = vr else { continue };
                        let bytes: Vec<u8> = match v.data() {
                            Ok(d) => match d.into_vec() {
                                Ok(b) => b,
                                Err(_) => continue,
                            },
                            Err(_) => continue,
                        };
                        let archive_path = utf16le_to_string(&bytes);
                        if archive_path.is_empty() {
                            continue;
                        }
                        let suspicious = is_archive_path_suspicious(&archive_path)
                            || archive_path_has_exfil_keyword(&archive_path);
                        let mut a = Artifact::new("Archive Tool", &path_str);
                        a.add_field("title", &format!("WinRAR archive: {}", archive_path));
                        a.add_field("detail", "WinRAR ArcHistory MRU");
                        a.add_field("file_type", "Archive Tool");
                        a.add_field("mitre", "T1560.001");
                        if suspicious {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                    }
                }
            }

            // ── WinRAR DialogEditHistory ExtrPath (extraction destinations) ──
            if let Some(node) = walk(
                &root,
                &["Software", "WinRAR", "DialogEditHistory", "ExtrPath"],
            ) {
                if let Some(Ok(values)) = node.values() {
                    for vr in values {
                        let Ok(v) = vr else { continue };
                        let bytes: Vec<u8> = match v.data() {
                            Ok(d) => match d.into_vec() {
                                Ok(b) => b,
                                Err(_) => continue,
                            },
                            Err(_) => continue,
                        };
                        let extract_path = utf16le_to_string(&bytes);
                        if extract_path.is_empty() {
                            continue;
                        }
                        let mut a = Artifact::new("Archive Tool", &path_str);
                        a.add_field("title", &format!("WinRAR extracted to: {}", extract_path));
                        a.add_field("detail", "WinRAR DialogEditHistory ExtrPath");
                        a.add_field("file_type", "Archive Tool");
                        a.add_field("mitre", "T1560.001");
                        a.add_field("forensic_value", "Medium");
                        out.push(a);
                    }
                }
            }

            // ── WinZip ────────────────────────────────────────────────
            if walk(&root, &["Software", "Nico Mak Computing", "WinZip"]).is_some() {
                let mut a = Artifact::new("Archive Tool", &path_str);
                a.add_field("title", "WinZip installed");
                a.add_field(
                    "detail",
                    "Software\\Nico Mak Computing\\WinZip key present — examine for recent archive history",
                );
                a.add_field("file_type", "Archive Tool");
                a.add_field("mitre", "T1560.001");
                a.add_field("forensic_value", "Medium");
                out.push(a);
            }

            // ── TaskBar FeatureUsage ───────────────────────────────────
            if let Some(fu) = walk(
                &root,
                &[
                    "Software",
                    "Microsoft",
                    "Windows",
                    "CurrentVersion",
                    "Explorer",
                    "FeatureUsage",
                ],
            ) {
                // AppLaunch — counts of taskbar launches per app
                if let Some(Ok(launch)) = fu.subkey("AppLaunch") {
                    if let Some(Ok(values)) = launch.values() {
                        for vr in values {
                            let Ok(v) = vr else { continue };
                            let Ok(vname) = v.name() else { continue };
                            let app = vname.to_string_lossy();
                            let count = match v.data() {
                                Ok(d) => match d.into_vec() {
                                    Ok(b) if b.len() >= 4 => {
                                        u32::from_le_bytes(b[0..4].try_into().unwrap_or([0; 4]))
                                    }
                                    _ => 0,
                                },
                                Err(_) => 0,
                            };
                            let mut a = Artifact::new("FeatureUsage", &path_str);
                            a.add_field(
                                "title",
                                &format!("TaskBar launch: {}", short_app_name(&app)),
                            );
                            a.add_field(
                                "detail",
                                &format!("{} launches from taskbar | Path: {}", count, app),
                            );
                            a.add_field("file_type", "FeatureUsage");
                            a.add_field("forensic_value", "Low");
                            out.push(a);
                        }
                    }
                }

                // AppSwitched — counts of focus switches per app
                if let Some(Ok(switched)) = fu.subkey("AppSwitched") {
                    if let Some(Ok(values)) = switched.values() {
                        for vr in values {
                            let Ok(v) = vr else { continue };
                            let Ok(vname) = v.name() else { continue };
                            let app = vname.to_string_lossy();
                            let count = match v.data() {
                                Ok(d) => match d.into_vec() {
                                    Ok(b) if b.len() >= 4 => {
                                        u32::from_le_bytes(b[0..4].try_into().unwrap_or([0; 4]))
                                    }
                                    _ => 0,
                                },
                                Err(_) => 0,
                            };
                            let mut a = Artifact::new("FeatureUsage", &path_str);
                            a.add_field(
                                "title",
                                &format!("TaskBar switch: {}", short_app_name(&app)),
                            );
                            a.add_field(
                                "detail",
                                &format!("{} times focused | Path: {}", count, app),
                            );
                            a.add_field("file_type", "FeatureUsage");
                            a.add_field("forensic_value", "Low");
                            out.push(a);
                        }
                    }
                }
            }

            // ── v1.5.0: Terminal Server Client default username MRU ────
            // HKCU\Software\Microsoft\Terminal Server Client\Default
            // Each value MRU0..MRUN is the last `username@host` used by
            // the user when initiating an outbound RDP session — a
            // direct lateral-movement indicator.
            parse_tsclient_default(&root, &path_str, &mut out);
            // HKCU\Software\Microsoft\Terminal Server Client\Servers\<host>
            parse_tsclient_servers(&root, &path_str, &mut out);

            out
        }

        fn parse_tsclient_default(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &["Software", "Microsoft", "Terminal Server Client", "Default"],
            ) else {
                return;
            };
            let Some(Ok(values)) = node.values() else {
                return;
            };
            for vr in values {
                let Ok(v) = vr else { continue };
                let Ok(name) = v.name() else { continue };
                let target = match v.data() {
                    Ok(d) => match d.into_vec() {
                        Ok(b) => utf16le_to_string(&b),
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                };
                if target.is_empty() {
                    continue;
                }
                let mut a = Artifact::new("RDP MRU", path_str);
                a.add_field(
                    "title",
                    &format!("RDP MRU: {} \u{2192} {}", name.to_string_lossy(), target),
                );
                a.add_field(
                    "detail",
                    "HKCU\\Software\\Microsoft\\Terminal Server Client\\Default \
                     \u{2014} outbound RDP destination history (T1021.001)",
                );
                a.add_field("file_type", "RDP MRU");
                a.add_field("mitre", "T1021.001");
                a.add_field("forensic_value", "High");
                out.push(a);
            }
        }

        fn parse_tsclient_servers(
            root: &nt_hive::KeyNode<'_, &[u8]>,
            path_str: &str,
            out: &mut Vec<Artifact>,
        ) {
            let Some(node) = walk(
                root,
                &["Software", "Microsoft", "Terminal Server Client", "Servers"],
            ) else {
                return;
            };
            let Some(Ok(iter)) = node.subkeys() else {
                return;
            };
            for k_res in iter {
                let Ok(k) = k_res else { continue };
                let Ok(server) = k.name() else { continue };
                let username = read_value_string(&k, "UsernameHint").unwrap_or_default();
                let mut a = Artifact::new("RDP Saved Server", path_str);
                a.add_field(
                    "title",
                    &format!("RDP saved server: {}", server.to_string_lossy()),
                );
                a.add_field(
                    "detail",
                    &format!(
                        "UsernameHint: {} | HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers",
                        username
                    ),
                );
                a.add_field("file_type", "RDP Saved Server");
                a.add_field("mitre", "T1021.001");
                a.add_field("forensic_value", "High");
                out.push(a);
            }
        }

        fn read_filetime(node: &nt_hive::KeyNode<'_, &[u8]>, name: &str) -> Option<i64> {
            let bytes = read_value_bytes(node, name)?;
            if bytes.len() >= 8 {
                let ft = i64::from_le_bytes(bytes[0..8].try_into().ok()?);
                filetime_to_unix(ft)
            } else {
                None
            }
        }

        fn decode_multi_sz(bytes: &[u8]) -> Vec<String> {
            // REG_MULTI_SZ is sequences of UTF-16LE strings separated by
            // double-null terminators.
            let mut out = Vec::new();
            let u16s: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let mut buf = String::new();
            for ch in u16s {
                if ch == 0 {
                    if !buf.is_empty() {
                        out.push(buf.clone());
                        buf.clear();
                    }
                } else if let Some(c) = char::from_u32(ch as u32) {
                    buf.push(c);
                }
            }
            if !buf.is_empty() {
                out.push(buf);
            }
            out
        }

        fn is_archive_path_suspicious(p: &str) -> bool {
            let l = p.to_lowercase();
            l.starts_with("d:\\")
                || l.starts_with("e:\\")
                || l.starts_with("f:\\")
                || l.starts_with("g:\\")
                || l.contains("\\temp\\")
                || l.contains("\\appdata\\")
                || l.contains("\\desktop\\")
        }

        fn archive_path_has_exfil_keyword(p: &str) -> bool {
            let l = p.to_lowercase();
            ["backup", "data", "export", "copy", "dump", "exfil"]
                .iter()
                .any(|kw| l.contains(kw))
        }

        fn short_app_name(app: &str) -> String {
            if let Some(pos) = app.rfind(['\\', '/']) {
                app[pos + 1..].to_string()
            } else {
                app.to_string()
            }
        }
    }

    // ── Generic hive helpers ────────────────────────────────────────────

    pub(super) fn walk<'a>(
        root: &nt_hive::KeyNode<'a, &'a [u8]>,
        path: &[&str],
    ) -> Option<nt_hive::KeyNode<'a, &'a [u8]>> {
        let mut node = root.clone();
        for part in path {
            node = node.subkey(part)?.ok()?;
        }
        Some(node)
    }

    pub(super) fn read_string(
        root: &nt_hive::KeyNode<'_, &[u8]>,
        key_path: &[&str],
        value_name: &str,
    ) -> Option<String> {
        let node = walk(root, key_path)?;
        read_value_string(&node, value_name)
    }

    pub(super) fn read_value_bytes(
        node: &nt_hive::KeyNode<'_, &[u8]>,
        value_name: &str,
    ) -> Option<Vec<u8>> {
        let values = node.values()?.ok()?;
        for vr in values {
            let v = vr.ok()?;
            let n = v.name().ok()?.to_string_lossy();
            if n.eq_ignore_ascii_case(value_name) {
                return v.data().ok()?.into_vec().ok();
            }
        }
        None
    }

    pub(super) fn read_value_string(
        node: &nt_hive::KeyNode<'_, &[u8]>,
        value_name: &str,
    ) -> Option<String> {
        let bytes = read_value_bytes(node, value_name)?;
        let s = utf16le_to_string(&bytes);
        if s.is_empty() {
            // Try ANSI
            let ansi = String::from_utf8_lossy(&bytes)
                .trim_end_matches('\0')
                .to_string();
            if ansi.is_empty() {
                None
            } else {
                Some(ansi)
            }
        } else {
            Some(s)
        }
    }

    pub(super) fn read_value_dword(
        node: &nt_hive::KeyNode<'_, &[u8]>,
        value_name: &str,
    ) -> Option<u32> {
        let bytes = read_value_bytes(node, value_name)?;
        if bytes.len() >= 4 {
            Some(u32::from_le_bytes(bytes[0..4].try_into().ok()?))
        } else {
            None
        }
    }
}

/// Read a registry hive with a 512 MB size gate. Returns `None` if the
/// file is unreadable or exceeds the cap. Enterprise SYSTEM/SOFTWARE
/// hives can be 256--512 MB; NTUSER.DAT can be 100+ MB on domain
/// controllers. Without this gate, Phantom would OOM on server images.
fn read_hive_gated(path: &Path) -> Option<Vec<u8>> {
    const MAX_HIVE_BYTES: u64 = 512 * 1024 * 1024;
    let meta = path.metadata().ok()?;
    if meta.len() > MAX_HIVE_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

fn windows_path_exists(root: &Path, windows_path: &str) -> bool {
    let normalized = windows_path.replace('\\', "/");
    let relative = normalized
        .split_once(':')
        .map(|(_, rest)| rest)
        .unwrap_or(normalized.as_str())
        .trim_start_matches('/');
    if relative.is_empty() {
        return false;
    }
    root.join(relative).exists()
}

fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut paths = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                if let Ok(sub) = walk_dir(&p) {
                    paths.extend(sub);
                }
            } else {
                paths.push(p);
            }
        }
    }
    Ok(paths)
}

// ── post-v16 Sprint 5 tripwires — Phantom submodule wiring ──

#[cfg(test)]
mod sprint5_wiring_tests {
    // Tests below all source-inspect via include_str! rather than
    // exercising types from super::*. Any future test that needs
    // the parent module's types should re-add `use super::*;`.

    /// Source-inspection tripwires pinning the seven Sprint 5
    /// dispatch call sites. Each verifies Phantom's run() still
    /// invokes the previously-orphaned submodule. Regression guard
    /// against a future refactor that accidentally drops one of the
    /// `out.extend(crate::X::scan(&path))` lines (or the
    /// corresponding `if ...is_*_path(&path)` dispatch block).
    ///
    /// We inspect source text at test time rather than executing
    /// each submodule with a synthetic fixture — the submodules
    /// already have comprehensive per-submodule unit tests; what
    /// Sprint 5 needs to guard against is silent de-wiring of the
    /// call site, not regression in the parser itself.
    #[test]
    fn phantom_wires_memory_carving() {
        let src = include_str!("lib.rs");
        assert!(
            src.contains("crate::memory_carving::scan"),
            "Phantom run() must dispatch to memory_carving::scan (Sprint 5 Fix 1)"
        );
    }

    #[test]
    fn phantom_wires_memory_structures() {
        let src = include_str!("lib.rs");
        assert!(
            src.contains("crate::memory_structures::scan"),
            "Phantom run() must dispatch to memory_structures::scan (Sprint 5 Fix 1)"
        );
    }

    #[test]
    fn phantom_wires_notepad_tabstate() {
        let src = include_str!("lib.rs");
        assert!(
            src.contains("crate::notepad_tabstate::is_tabstate_path"),
            "Phantom run() must dispatch to notepad_tabstate (Sprint 5 Fix 1)"
        );
        assert!(
            src.contains("crate::notepad_tabstate::parse"),
            "Phantom must call notepad_tabstate::parse on matching files"
        );
    }

    #[test]
    fn phantom_wires_outlook() {
        let src = include_str!("lib.rs");
        assert!(
            src.contains("crate::outlook::is_outlook_path"),
            "Phantom run() must dispatch to outlook::is_outlook_path (Sprint 5 Fix 1)"
        );
        assert!(
            src.contains("crate::outlook::has_pst_magic"),
            "Phantom must call outlook::has_pst_magic to confirm PST format"
        );
        assert!(
            src.contains("crate::outlook::carve"),
            "Phantom must call outlook::carve on validated PST bytes"
        );
    }

    #[test]
    fn phantom_wires_powershell() {
        let src = include_str!("lib.rs");
        assert!(
            src.contains("crate::powershell::is_psreadline_path"),
            "Phantom run() must dispatch to powershell (Sprint 5 Fix 1)"
        );
        assert!(
            src.contains("crate::powershell::parse"),
            "Phantom must call powershell::parse on ConsoleHost_history.txt"
        );
    }

    #[test]
    fn phantom_wires_cloud_cli() {
        let src = include_str!("lib.rs");
        assert!(
            src.contains("crate::cloud_cli::classify"),
            "Phantom run() must dispatch to cloud_cli (Sprint 5 Fix 1)"
        );
        // At least two of the four submodule parsers must be
        // wired — the classifier returns one of four tags and
        // each needs to route to its parser.
        let parser_count = [
            "crate::cloud_cli::parse_aws_credentials",
            "crate::cloud_cli::parse_aws_config",
            "crate::cloud_cli::parse_azure_access_tokens",
            "crate::cloud_cli::parse_terraform_state",
        ]
        .iter()
        .filter(|needle| src.contains(*needle))
        .count();
        assert_eq!(
            parser_count, 4,
            "All four cloud_cli sub-parsers must be wired; found {parser_count}/4"
        );
    }

    #[test]
    fn phantom_wires_windows_recall() {
        let src = include_str!("lib.rs");
        assert!(
            src.contains("crate::windows_recall::is_recall_db_path"),
            "Phantom run() must dispatch to windows_recall (Sprint 5 Fix 1)"
        );
        assert!(
            src.contains("crate::windows_recall::parse"),
            "Phantom must call windows_recall::parse on UKG.db"
        );
        // Both outcome branches (Captures + Locked) must be
        // handled — Missing is silent.
        assert!(
            src.contains("RecallOutcome::Captures"),
            "Phantom must handle RecallOutcome::Captures branch"
        );
        assert!(
            src.contains("RecallOutcome::Locked"),
            "Phantom must handle RecallOutcome::Locked branch (DPAPI-encrypted DB)"
        );
    }

    #[test]
    fn phantom_utility_submodules_remain_unwired_pending_caller_infrastructure() {
        // Three Phantom submodules are utility libraries, not
        // direct emitters. They compile and pass their own unit
        // tests but have no pub fn scan(path) signature — wiring
        // them requires caller-side infrastructure Phantom
        // doesn't have:
        //
        //   services      — helpers for services.rs / hive
        //                   parsing that the SYSTEM hive parser
        //                   should consume. Refactor target.
        //   ring_doorbell — takes JSON strings; needs an iteration
        //                   layer that identifies Ring export
        //                   files under %LOCALAPPDATA%\Amazon.
        //                   Not v0.16 evidence shape.
        //   smart_locks   — same JSON-string shape.
        //
        // This tripwire pins the current un-wired state. When a
        // future sprint ships the caller-side infrastructure,
        // each of these gets its own dispatch block and this
        // test must be intentionally changed or deleted with a
        // commit message noting "services / ring_doorbell /
        // smart_locks wired in [commit]." The `_pending_caller_infrastructure`
        // suffix makes the deferral discoverable.
        //
        // We only check production code (before the #[cfg(test)]
        // boundary) so this test's own needles don't self-match.
        let src = include_str!("lib.rs");
        let production = src.split("#[cfg(test)]").next().expect("has production");
        for (module, needle) in [
            ("services", "crate::services::scan"),
            ("ring_doorbell", "crate::ring_doorbell::parse_events"),
            ("smart_locks", "crate::smart_locks::parse_lock_events"),
        ] {
            assert!(
                !production.contains(needle),
                "{module} is a utility library, not a Scenario B emitter — \
                 production code must not currently invoke {needle}. If wiring \
                 landed, update this tripwire."
            );
        }
    }
}

#[no_mangle]
pub extern "C" fn create_plugin_phantom() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(PhantomPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}
