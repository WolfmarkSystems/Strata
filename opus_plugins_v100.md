# OPUS TASK — Supercharge Strata Plugins to v1.0
# Date: 2026-04-03
# Priority: CRITICAL — Plugins are Strata's competitive edge

---

## ARCHITECTURAL DECISION — READ THIS FIRST

```
Strata is the host. Plugins are the intelligence.

Strata MUST run without any plugins.
  Core examination (file listing, hex, timeline,
  hashing, bookmarks, reports) — all work standalone.
  Zero plugin dependency in core.

Plugins are MODULAR and INDEPENDENT.
  Each plugin is a separate crate.
  Each plugin can be updated independently.
  When the DFIR field discovers a new artifact,
  a new plugin ships — Strata binary unchanged.
  
Why this matters:
  Law enforcement agencies can approve Strata once.
  New plugins update without re-approval of core binary.
  CJIS compliance: known, audited binary + separate plugins.
  Examiners can enable/disable plugins per case type.
  Future: third-party plugin marketplace.

Plugin update model (future):
  Strata checks wolfmark.systems/plugins for updates
  Downloads signed plugin update
  Verifies Ed25519 signature
  Hot-swaps plugin without restart
  This is the revenue model — plugin subscriptions
```

---

## CURRENT STATE (from v0.3.0 build)

```
Build: CLEAN — 23MB binary
SDK:   strata-plugin-sdk upgraded to v0.3.0
       All 12 ArtifactCategory types
       All 5 ForensicValue levels
       Full PluginOutput/ArtifactRecord types

Plugins built:
  Remnant   v0.3.0 — walks directory, 12 signatures
  Chronicle v0.3.0 — identifies artifact file types
  Cipher    v0.3.0 — finds credential DBs + SSH keys
  Trace     v0.3.0 — 17 LOLBIN detections

Current limitation:
  Plugins identify FILE TYPES but don't parse content
  Chronicle finds .pf files but doesn't read them
  Cipher finds Login Data but doesn't query SQLite
  Trace finds certutil.exe but doesn't check arguments
  
This session: make them actually parse and extract data
```

---

## TARGET: v1.0 FOR ALL 4 PLUGINS

v1.0 definition:
```
  Parses artifact CONTENT — not just identifies files
  Returns structured, human-readable extracted data
  Each result has: timestamp, title, detail, source, value
  Results feed directly into Artifacts panel as real records
  Plugin can run standalone on any evidence path
  Plugin has its own tests
  Plugin has its own Cargo.toml with version = "1.0.0"
  Strata binary unchanged — plugins are separate compilation
```

---

## CRITICAL: PLUGIN SEPARATION ARCHITECTURE

Ensure this separation is correct before implementing:

```
apps/strata/                    ← Core binary (never touches plugin internals)
  src/
    plugin_host.rs              ← Loads plugins, calls execute(), displays results
    ui/artifacts_panel.rs       ← Displays ArtifactRecord from any plugin
    
crates/strata-plugin-sdk/       ← Shared types ONLY
  src/lib.rs                    ← ArtifactRecord, PluginOutput, StrataPlugin trait
                                   NO implementation, NO parsing logic here
                                   
plugins/                        ← Independent plugin crates
  strata-plugin-remnant/        ← Separate binary/lib
  strata-plugin-chronicle/      ← Separate binary/lib
  strata-plugin-cipher/         ← Separate binary/lib
  strata-plugin-trace/          ← Separate binary/lib
```

The plugin_host in Strata:
```rust
// apps/strata/src/plugin_host.rs

pub struct PluginHost {
    plugins: Vec<Box<dyn StrataPlugin>>,
}

impl PluginHost {
    pub fn load_all() -> Self {
        // Statically linked — plugins compiled into binary
        // But each plugin is an INDEPENDENT CRATE
        let plugins: Vec<Box<dyn StrataPlugin>> = vec![
            Box::new(strata_plugin_remnant::RemnantPlugin::new()),
            Box::new(strata_plugin_chronicle::ChroniclePlugin::new()),
            Box::new(strata_plugin_cipher::CipherPlugin::new()),
            Box::new(strata_plugin_trace::TracePlugin::new()),
        ];
        Self { plugins }
    }
    
    pub fn run_plugin(
        &self,
        plugin_name: &str,
        context: PluginContext,
        progress: impl ProgressReporter,
    ) -> Result<PluginOutput, PluginError> {
        self.plugins
            .iter()
            .find(|p| p.name() == plugin_name)
            .ok_or_else(|| PluginError { 
                message: format!("Plugin not found: {}", plugin_name),
                is_fatal: false 
            })?
            .execute(&context, &progress)
    }
}
```

Strata core ONLY knows about StrataPlugin trait.
It NEVER imports from specific plugin crates directly.
Plugin results are ArtifactRecord — Strata renders any ArtifactRecord.

---

## PLUGIN 1: REMNANT v1.0
### Deep File Carving — REAL Implementation

**What v1.0 adds:**
  Actually reads binary data and carves files
  60+ signatures (up from 12)
  Returns ArtifactRecord with real metadata
  Validates carved files (magic byte confirmation)
  Handles E01 images via the VFS layer

```rust
// plugins/strata-plugin-remnant/src/lib.rs

use strata_plugin_sdk::*;
use std::io::{Read, Seek, SeekFrom};

pub struct RemnantPlugin;

impl StrataPlugin for RemnantPlugin {
    fn name(&self) -> &str { "strata-plugin-remnant" }
    fn version(&self) -> &str { "1.0.0" }
    fn description(&self) -> &str { 
        "Deep file carving and deleted artifact recovery. \
         Recovers files from unallocated space using 60+ \
         file signatures." 
    }
    fn author(&self) -> &str { "Wolfmark Systems" }
    fn plugin_type(&self) -> PluginType { PluginType::Carver }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::FileCarving,
            PluginCapability::DeletedFileRecovery,
        ]
    }
    
    fn execute(
        &self,
        context: &PluginContext,
        progress: &dyn ProgressReporter,
    ) -> Result<PluginOutput, PluginError> {
        let mut artifacts = Vec::new();
        let mut carved_count = 0u64;
        
        // Get all raw bytes from evidence
        // Use existing VFS if available, fall back to direct file read
        let evidence_bytes = self.read_evidence_bytes(
            &context.evidence_path
        )?;
        
        let total = evidence_bytes.len() as u64;
        
        // Slide through evidence looking for signatures
        // Step by 512 bytes (one sector) for thoroughness
        let step = 512usize;
        let mut i = 0usize;
        
        while i + 8 <= evidence_bytes.len() {
            if progress.is_cancelled() { break; }
            
            if i % (1024 * 1024) == 0 { // Report every 1MB
                progress.report(
                    i as u64, total,
                    &format!("Carving: {:.1}% — {} files found",
                        (i as f64 / total as f64) * 100.0,
                        carved_count
                    )
                );
            }
            
            // Check each signature
            for sig in CARVE_SIGNATURES {
                if evidence_bytes[i..].starts_with(sig.header) {
                    // Extract file
                    let end = self.find_file_end(
                        &evidence_bytes, i, sig
                    );
                    let file_data = &evidence_bytes[i..end];
                    
                    // Validate it's actually this file type
                    if self.validate_carved_file(file_data, sig) {
                        carved_count += 1;
                        let filename = format!(
                            "CARVED_{:06}.{}",
                            carved_count, sig.extension
                        );
                        
                        // Write to output path
                        let out_dir = context.output_path
                            .join("remnant_carved");
                        std::fs::create_dir_all(&out_dir)
                            .map_err(|e| PluginError {
                                message: e.to_string(),
                                is_fatal: false,
                            })?;
                        let out_path = out_dir.join(&filename);
                        std::fs::write(&out_path, file_data)
                            .map_err(|e| PluginError {
                                message: e.to_string(),
                                is_fatal: false,
                            })?;
                        
                        artifacts.push(ArtifactRecord {
                            category: sig.category.clone(),
                            subcategory: format!(
                                "Carved {}", sig.name
                            ),
                            timestamp: None,
                            title: filename,
                            detail: format!(
                                "Offset: 0x{:X} | Size: {} bytes | \
                                 Type: {}",
                                i, file_data.len(), sig.name
                            ),
                            source_path: format!(
                                "{}@0x{:X}",
                                context.evidence_path.display(), i
                            ),
                            forensic_value: sig.forensic_value
                                .clone(),
                            mitre_technique: sig.mitre
                                .map(|s| s.to_string()),
                            is_suspicious: matches!(
                                sig.forensic_value,
                                ForensicValue::Critical
                            ),
                            raw_data: None,
                        });
                    }
                }
            }
            i += step;
        }
        
        let suspicious = artifacts.iter()
            .filter(|a| a.is_suspicious)
            .count();
            
        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            artifacts,
            timeline_events: vec![],
            summary: PluginSummary {
                total_artifacts: carved_count as usize,
                suspicious_count: suspicious,
                categories_populated: vec![
                    "Deleted & Recovered".to_string(),
                    "Execution History".to_string(),
                    "Media".to_string(),
                ],
                headline: format!(
                    "Carved {} files — {} critical",
                    carved_count, suspicious
                ),
            },
            warnings: vec![],
        })
    }
}

struct CarveSignature {
    name: &'static str,
    header: &'static [u8],
    footer: Option<&'static [u8]>,
    extension: &'static str,
    max_size: usize,
    category: ArtifactCategory,
    forensic_value: ForensicValue,
    mitre: Option<&'static str>,
}

static CARVE_SIGNATURES: &[CarveSignature] = &[
    // CRITICAL forensic value
    CarveSignature {
        name: "PE Executable",
        header: b"MZ",
        footer: None,
        extension: "exe",
        max_size: 100 * 1024 * 1024,
        category: ArtifactCategory::ExecutionHistory,
        forensic_value: ForensicValue::Critical,
        mitre: Some("T1564"),
    },
    CarveSignature {
        name: "Windows Event Log",
        header: b"ElfFile\x00",
        footer: None,
        extension: "evtx",
        max_size: 500 * 1024 * 1024,
        category: ArtifactCategory::SystemActivity,
        forensic_value: ForensicValue::Critical,
        mitre: Some("T1070.001"),
    },
    CarveSignature {
        name: "Registry Hive",
        header: b"regf",
        footer: None,
        extension: "hve",
        max_size: 500 * 1024 * 1024,
        category: ArtifactCategory::SystemActivity,
        forensic_value: ForensicValue::Critical,
        mitre: None,
    },
    CarveSignature {
        name: "SQLite Database",
        header: b"SQLite format 3\x00",
        footer: None,
        extension: "db",
        max_size: 1024 * 1024 * 1024,
        category: ArtifactCategory::Communications,
        forensic_value: ForensicValue::Critical,
        mitre: None,
    },
    CarveSignature {
        name: "PST Email Archive",
        header: &[0x21, 0x42, 0x44, 0x4E],
        footer: None,
        extension: "pst",
        max_size: 50 * 1024 * 1024 * 1024,
        category: ArtifactCategory::Communications,
        forensic_value: ForensicValue::Critical,
        mitre: None,
    },
    CarveSignature {
        name: "PEM Private Key",
        header: b"-----BEGIN",
        footer: None,
        extension: "pem",
        max_size: 64 * 1024,
        category: ArtifactCategory::EncryptionKeyMaterial,
        forensic_value: ForensicValue::Critical,
        mitre: Some("T1552.004"),
    },
    CarveSignature {
        name: "Prefetch File",
        header: b"MAM\x04",
        footer: None,
        extension: "pf",
        max_size: 10 * 1024 * 1024,
        category: ArtifactCategory::ExecutionHistory,
        forensic_value: ForensicValue::Critical,
        mitre: None,
    },
    // HIGH forensic value
    CarveSignature {
        name: "PDF Document",
        header: b"%PDF",
        footer: Some(b"%%EOF"),
        extension: "pdf",
        max_size: 500 * 1024 * 1024,
        category: ArtifactCategory::UserActivity,
        forensic_value: ForensicValue::High,
        mitre: None,
    },
    CarveSignature {
        name: "ZIP Archive",
        header: b"PK\x03\x04",
        footer: Some(b"PK\x05\x06"),
        extension: "zip",
        max_size: 2 * 1024 * 1024 * 1024,
        category: ArtifactCategory::UserActivity,
        forensic_value: ForensicValue::High,
        mitre: None,
    },
    CarveSignature {
        name: "LNK Shortcut",
        header: &[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00],
        footer: None,
        extension: "lnk",
        max_size: 1 * 1024 * 1024,
        category: ArtifactCategory::UserActivity,
        forensic_value: ForensicValue::High,
        mitre: Some("T1547.009"),
    },
    CarveSignature {
        name: "EML Email",
        header: b"From ",
        footer: None,
        extension: "eml",
        max_size: 100 * 1024 * 1024,
        category: ArtifactCategory::Communications,
        forensic_value: ForensicValue::High,
        mitre: None,
    },
    // MEDIUM
    CarveSignature {
        name: "JPEG Image",
        header: &[0xFF, 0xD8, 0xFF],
        footer: Some(&[0xFF, 0xD9]),
        extension: "jpg",
        max_size: 50 * 1024 * 1024,
        category: ArtifactCategory::Media,
        forensic_value: ForensicValue::Medium,
        mitre: None,
    },
    CarveSignature {
        name: "PNG Image",
        header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
        extension: "png",
        max_size: 50 * 1024 * 1024,
        category: ArtifactCategory::Media,
        forensic_value: ForensicValue::Medium,
        mitre: None,
    },
    // Add remaining 47 signatures following same pattern...
    // Include: MP4, AVI, RAR, 7Z, DOCX, XLSX, PPTX, DOC, XLS,
    //          GIF, BMP, TIFF, WEBP, MP3, WAV, OGG, DLL,
    //          Android backup, iOS plist, Bitcoin wallet,
    //          PFX cert, SSH private key formats,
    //          PowerShell scripts, VBScript, macOS DMG/PKG,
    //          Tor hidden service descriptor, VeraCrypt header,
    //          BitLocker header, EncFS config, AxCrypt
];
```

---

## PLUGIN 2: CHRONICLE v1.0
### Real Artifact Content Parsing

**What v1.0 adds:**
  Actually reads and parses Prefetch binary format
  Actually parses LNK file structure
  Actually queries SQLite for browser history
  Actually parses EVTX for high-value event IDs
  Returns parsed human-readable data per artifact

```rust
// plugins/strata-plugin-chronicle/src/lib.rs

pub struct ChroniclePlugin;

impl ChroniclePlugin {
    /// Parse Windows Prefetch files — REAL parser
    fn parse_prefetch_file(
        &self, 
        path: &std::path::Path,
        data: &[u8],
    ) -> Vec<ArtifactRecord> {
        let mut records = Vec::new();
        
        // Check for MAM compressed (Win10)
        let decompressed;
        let parse_data = if data.starts_with(b"MAM\x04") {
            // Decompress using lz4
            match lz4_flex::decompress_size_prepended(&data[8..]) {
                Ok(d) => { decompressed = d; &decompressed[..] }
                Err(_) => return records,
            }
        } else {
            data
        };
        
        // Parse based on version byte at offset 0
        let version = u32::from_le_bytes(
            parse_data[0..4].try_into().unwrap_or([0;4])
        );
        
        let exe_name = match std::str::from_utf8(&parse_data[16..76]) {
            Ok(s) => s.trim_end_matches('\0').to_string(),
            Err(_) => return records,
        };
        
        // Get run times based on version
        let (run_count, last_run_times) = match version {
            17 => { // XP
                let count = u32::from_le_bytes(
                    parse_data[16..20].try_into().unwrap_or([0;4])
                );
                let time = i64::from_le_bytes(
                    parse_data[0x78..0x80].try_into().unwrap_or([0;8])
                );
                (count, vec![filetime_to_datetime(time)])
            },
            23 => { // Vista/7
                let count = u32::from_le_bytes(
                    parse_data[152..156].try_into().unwrap_or([0;4])
                );
                let time = i64::from_le_bytes(
                    parse_data[128..136].try_into().unwrap_or([0;8])
                );
                (count, vec![filetime_to_datetime(time)])
            },
            26 => { // Win8
                let count = u32::from_le_bytes(
                    parse_data[208..212].try_into().unwrap_or([0;4])
                );
                // Up to 8 run times at offset 0x80
                let times: Vec<_> = (0..8).map(|i| {
                    let off = 0x80 + i * 8;
                    let t = i64::from_le_bytes(
                        parse_data[off..off+8].try_into().unwrap_or([0;8])
                    );
                    filetime_to_datetime(t)
                }).filter_map(|t| t).collect();
                (count, times)
            },
            30 => { // Win10
                let count = u32::from_le_bytes(
                    parse_data[208..212].try_into().unwrap_or([0;4])
                );
                let times: Vec<_> = (0..8).map(|i| {
                    let off = 0x80 + i * 8;
                    let t = i64::from_le_bytes(
                        parse_data[off..off+8].try_into().unwrap_or([0;8])
                    );
                    filetime_to_datetime(t)
                }).filter_map(|t| t).collect();
                (count, times)
            },
            _ => return records,
        };
        
        // Suspicious indicators
        let lower = exe_name.to_lowercase();
        let is_suspicious = SUSPICIOUS_EXE_NAMES.iter()
            .any(|s| lower.contains(s))
            || SUSPICIOUS_PATHS.iter()
                .any(|p| path.to_string_lossy()
                    .to_lowercase().contains(p));
        
        for run_time in &last_run_times {
            records.push(ArtifactRecord {
                category: ArtifactCategory::ExecutionHistory,
                subcategory: "Prefetch Execution".to_string(),
                timestamp: Some(*run_time),
                title: exe_name.clone(),
                detail: format!(
                    "Executed {} time(s). Last run: {}. \
                     Prefetch version: {}",
                    run_count,
                    run_time.format("%Y-%m-%d %H:%M:%S UTC"),
                    version
                ),
                source_path: path.to_string_lossy().to_string(),
                forensic_value: if is_suspicious {
                    ForensicValue::Critical
                } else {
                    ForensicValue::High
                },
                mitre_technique: Some("T1059".to_string()),
                is_suspicious,
                raw_data: Some(serde_json::json!({
                    "executable": exe_name,
                    "run_count": run_count,
                    "version": version,
                    "all_run_times": last_run_times.iter()
                        .map(|t| t.to_rfc3339())
                        .collect::<Vec<_>>()
                })),
            });
        }
        records
    }
    
    /// Parse browser history SQLite databases
    fn parse_browser_history(
        &self,
        context: &PluginContext,
    ) -> Vec<ArtifactRecord> {
        let mut records = Vec::new();
        
        // Find Chrome/Edge History DBs
        for file in &context.file_index {
            let path_lower = file.path.to_lowercase();
            
            // Chrome/Edge/Brave History
            if (path_lower.contains("chrome") 
                || path_lower.contains("edge")
                || path_lower.contains("brave"))
                && path_lower.ends_with("/history") {
                
                // Copy to temp (SQLite needs write access)
                // In real implementation: use in-memory or
                // read-only mode with rusqlite flags
                
                if let Ok(conn) = rusqlite::Connection::open_with_flags(
                    &file.path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                ) {
                    if let Ok(mut stmt) = conn.prepare(
                        "SELECT url, title, visit_count, 
                         last_visit_time 
                         FROM urls 
                         ORDER BY last_visit_time DESC 
                         LIMIT 10000"
                    ) {
                        let rows = stmt.query_map([], |row| {
                            Ok((
                                row.get::<_, String>(0)
                                    .unwrap_or_default(),
                                row.get::<_, String>(1)
                                    .unwrap_or_default(),
                                row.get::<_, i64>(2)
                                    .unwrap_or(0),
                                row.get::<_, i64>(3)
                                    .unwrap_or(0),
                            ))
                        });
                        
                        if let Ok(rows) = rows {
                            for row in rows.flatten() {
                                let (url, title, count, time) = row;
                                let is_suspicious = 
                                    self.is_suspicious_url(&url);
                                
                                records.push(ArtifactRecord {
                                    category: ArtifactCategory::WebActivity,
                                    subcategory: "Browser History".to_string(),
                                    timestamp: Some(
                                        chrome_time_to_utc(time)
                                    ),
                                    title: if title.is_empty() {
                                        url.clone()
                                    } else {
                                        title
                                    },
                                    detail: format!(
                                        "URL: {} | Visits: {}",
                                        url, count
                                    ),
                                    source_path: file.path.clone(),
                                    forensic_value: if is_suspicious {
                                        ForensicValue::Critical
                                    } else {
                                        ForensicValue::Low
                                    },
                                    mitre_technique: None,
                                    is_suspicious,
                                    raw_data: Some(serde_json::json!({
                                        "url": url,
                                        "visit_count": count,
                                    })),
                                });
                            }
                        }
                    }
                }
            }
            
            // Firefox places.sqlite
            if path_lower.ends_with("places.sqlite") 
                && path_lower.contains("firefox") {
                // SELECT url, title, visit_count, last_visit_date
                // FROM moz_places
                // ORDER BY last_visit_date DESC
                // Same structure as Chrome but different time format
                // Firefox time: microseconds since Unix epoch
            }
        }
        records
    }
    
    /// Parse EVTX for high-value event IDs
    fn parse_evtx_high_value(
        &self,
        context: &PluginContext,
    ) -> Vec<ArtifactRecord> {
        let mut records = Vec::new();
        
        // High-value event ID map
        const HIGH_VALUE: &[(u32, &str, ForensicValue, 
                              &str, bool)] = &[
            (4624, "Successful Logon", 
             ForensicValue::Medium, "T1078", false),
            (4625, "Failed Logon Attempt", 
             ForensicValue::High, "T1110", true),
            (4648, "Logon with Explicit Credentials", 
             ForensicValue::High, "T1078", true),
            (4688, "New Process Created", 
             ForensicValue::High, "T1059", false),
            (4698, "Scheduled Task Created", 
             ForensicValue::Critical, "T1053.005", true),
            (4720, "User Account Created", 
             ForensicValue::Critical, "T1136", true),
            (4726, "User Account Deleted", 
             ForensicValue::Critical, "T1531", true),
            (4732, "Member Added to Security Group", 
             ForensicValue::Critical, "T1098", true),
            (4740, "Account Locked Out", 
             ForensicValue::High, "T1110", true),
            (7045, "New Service Installed", 
             ForensicValue::Critical, "T1543.003", true),
            (4103, "PowerShell Pipeline Execution", 
             ForensicValue::High, "T1059.001", false),
            (4104, "PowerShell Script Block", 
             ForensicValue::Critical, "T1059.001", true),
            (1149, "RDP Authentication Success", 
             ForensicValue::High, "T1021.001", false),
        ];
        
        // Find all .evtx files
        for file in &context.file_index {
            if !file.path.to_lowercase().ends_with(".evtx") {
                continue;
            }
            
            // Parse with evtx crate
            if let Ok(data) = std::fs::read(&file.path) {
                if let Ok(mut parser) = evtx::EvtxParser::from_buffer(
                    data
                ) {
                    for record in parser.records_json() {
                        if let Ok(rec) = record {
                            // Extract EventID from JSON
                            if let Some(event_id) = 
                                extract_event_id(&rec.data) 
                            {
                                if let Some((_, desc, value, 
                                             mitre, suspicious)) =
                                    HIGH_VALUE.iter()
                                        .find(|(id, _, _, _, _)| 
                                            *id == event_id)
                                {
                                    records.push(ArtifactRecord {
                                        category: ArtifactCategory::SystemActivity,
                                        subcategory: format!(
                                            "Event ID {}", event_id
                                        ),
                                        timestamp: rec.timestamp.ok(),
                                        title: format!(
                                            "{} (Event {})", 
                                            desc, event_id
                                        ),
                                        detail: format!(
                                            "Source: {}",
                                            file.path
                                        ),
                                        source_path: file.path.clone(),
                                        forensic_value: value.clone(),
                                        mitre_technique: Some(
                                            mitre.to_string()
                                        ),
                                        is_suspicious: *suspicious,
                                        raw_data: Some(
                                            serde_json::from_str(
                                                &rec.data
                                            ).unwrap_or_default()
                                        ),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        records
    }
}

// Helper: Convert Windows FILETIME to DateTime<Utc>
fn filetime_to_datetime(ft: i64) -> Option<chrono::DateTime<chrono::Utc>> {
    if ft == 0 { return None; }
    let unix = (ft - 116_444_736_000_000_000) / 10_000_000;
    chrono::DateTime::from_timestamp(unix, 0)
}

// Helper: Convert Chrome time to DateTime<Utc>
fn chrome_time_to_utc(chrome_time: i64) -> chrono::DateTime<chrono::Utc> {
    // Chrome time: microseconds since Jan 1, 1601
    let unix_micros = chrome_time - 11_644_473_600_000_000;
    chrono::DateTime::from_timestamp(
        unix_micros / 1_000_000,
        ((unix_micros % 1_000_000) * 1000) as u32,
    ).unwrap_or_else(chrono::Utc::now)
}

const SUSPICIOUS_EXE_NAMES: &[&str] = &[
    "mimikatz", "meterpreter", "cobalt", "beacon",
    "empire", "powersploit", "invoke-", "bloodhound",
    "sharphound", "rubeus", "kerberoast", "asreproast",
    "psexec", "wce", "pwdump", "fgdump", "gsecdump",
    "secretsdump", "lazagne", "incognito", "getsystem",
    "bypassuac", "uacbypass", "exploit", "payload",
    "metasploit", "shellcode", "injector",
];

const SUSPICIOUS_PATHS: &[&str] = &[
    "\\temp\\", "/tmp/", "\\downloads\\", 
    "\\appdata\\roaming\\", "\\public\\",
    "\\recycle", "\\windows\\tasks\\",
    "/dev/shm/", "/var/tmp/",
];

const SUSPICIOUS_DOMAINS: &[&str] = &[
    "pastebin.com", "hastebin.com", "ghostbin.com",
    "transfer.sh", "mega.nz", "anonfiles.com",
    "file.io", "temp.sh", "0x0.st",
    "ngrok.io", "serveo.net", "pagekite.me",
];
```

---

## PLUGIN 3: CIPHER v1.0
### Real Credential Extraction

```rust
// plugins/strata-plugin-cipher/src/lib.rs

impl CipherPlugin {
    /// Actually query Chrome/Edge Login Data SQLite
    fn extract_browser_passwords(
        &self,
        context: &PluginContext,
    ) -> Vec<ArtifactRecord> {
        let mut records = Vec::new();
        
        let login_db_patterns = [
            "login data",      // Chrome/Edge
            "logins.json",     // Firefox
            "signons.sqlite",  // Old Firefox
        ];
        
        for file in &context.file_index {
            let name_lower = file.path
                .split(['/', '\\'])
                .last()
                .unwrap_or("")
                .to_lowercase();
            
            // Chrome/Edge Login Data
            if name_lower == "login data" {
                if let Ok(conn) = rusqlite::Connection::open_with_flags(
                    &file.path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                ) {
                    if let Ok(mut stmt) = conn.prepare(
                        "SELECT origin_url, username_value, 
                         date_created, times_used
                         FROM logins 
                         ORDER BY date_created DESC"
                    ) {
                        if let Ok(rows) = stmt.query_map([], |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        }) {
                            for row in rows.flatten() {
                                let (url, user, created, used) = row;
                                let is_sensitive = 
                                    self.is_sensitive_url(&url);
                                
                                records.push(ArtifactRecord {
                                    category: ArtifactCategory::AccountsCredentials,
                                    subcategory: "Saved Browser Password".to_string(),
                                    timestamp: Some(
                                        chrome_time_to_utc(created)
                                    ),
                                    title: format!("{} — {}", 
                                        self.domain_from_url(&url), 
                                        user
                                    ),
                                    detail: format!(
                                        "URL: {} | Username: {} | \
                                         Used {} times | \
                                         Password: [DPAPI encrypted]",
                                        url, user, used
                                    ),
                                    source_path: file.path.clone(),
                                    forensic_value: if is_sensitive {
                                        ForensicValue::Critical
                                    } else {
                                        ForensicValue::High
                                    },
                                    mitre_technique: Some(
                                        "T1555.003".to_string()
                                    ),
                                    is_suspicious: is_sensitive,
                                    raw_data: Some(serde_json::json!({
                                        "url": url,
                                        "username": user,
                                        "times_used": used,
                                        "password_note": 
                                            "Encrypted with DPAPI — \
                                             requires Windows key to decrypt"
                                    })),
                                });
                            }
                        }
                    }
                }
            }
            
            // Firefox logins.json
            if name_lower == "logins.json" {
                if let Ok(data) = std::fs::read_to_string(&file.path) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
                        if let Some(logins) = json["logins"].as_array() {
                            for login in logins {
                                let hostname = login["hostname"]
                                    .as_str()
                                    .unwrap_or("unknown");
                                let username = login["encryptedUsername"]
                                    .as_str()
                                    .unwrap_or("[encrypted]");
                                    
                                records.push(ArtifactRecord {
                                    category: ArtifactCategory::AccountsCredentials,
                                    subcategory: "Firefox Saved Password".to_string(),
                                    timestamp: login["timeCreated"]
                                        .as_i64()
                                        .and_then(|t| 
                                            chrono::DateTime::from_timestamp(
                                                t / 1000, 0
                                            )
                                        ),
                                    title: format!("Firefox: {}", hostname),
                                    detail: format!(
                                        "Host: {} | Username: [encrypted] | \
                                         Password: [NSS encrypted]",
                                        hostname
                                    ),
                                    source_path: file.path.clone(),
                                    forensic_value: ForensicValue::High,
                                    mitre_technique: Some(
                                        "T1555.003".to_string()
                                    ),
                                    is_suspicious: false,
                                    raw_data: Some(login.clone()),
                                });
                            }
                        }
                    }
                }
            }
        }
        records
    }
    
    /// Calculate Shannon entropy for encrypted container detection
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut freq = [0u64; 256];
        for &b in data { freq[b as usize] += 1; }
        let len = data.len() as f64;
        freq.iter()
            .filter(|&&f| f > 0)
            .map(|&f| { let p = f as f64 / len; -p * p.log2() })
            .sum()
    }
    
    /// Find files with high entropy (potential encrypted containers)
    fn detect_encrypted_containers(
        &self,
        context: &PluginContext,
    ) -> Vec<ArtifactRecord> {
        let mut records = Vec::new();
        
        for file in &context.file_index {
            // Only check large files > 1MB without known extension
            if file.size < 1_000_000 { continue; }
            
            let ext = std::path::Path::new(&file.path)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            
            // Skip known file types
            if ["jpg","png","mp4","zip","pdf","docx","exe","dll",
                "db","evtx","hve","pf"].contains(&ext.as_str()) {
                continue;
            }
            
            // Read first 1MB for entropy calculation
            if let Ok(mut f) = std::fs::File::open(&file.path) {
                let mut sample = vec![0u8; 1_048_576];
                if let Ok(n) = f.read(&mut sample) {
                    let entropy = Self::calculate_entropy(&sample[..n]);
                    
                    // High entropy (> 7.9) suggests encryption/compression
                    if entropy > 7.9 {
                        // Check for known encrypted container headers
                        let container_type = if sample.starts_with(
                            b"-FVE-FS-"
                        ) {
                            "BitLocker encrypted volume"
                        } else if sample[0..4] == [0x00; 4] 
                            && file.size % 512 == 0 
                        {
                            "Possible TrueCrypt/VeraCrypt container"
                        } else {
                            "High-entropy file (possible encrypted container)"
                        };
                        
                        records.push(ArtifactRecord {
                            category: ArtifactCategory::EncryptionKeyMaterial,
                            subcategory: "Encrypted Container".to_string(),
                            timestamp: file.modified,
                            title: format!("{}: {}",
                                container_type,
                                file.path.split(['/', '\\']).last()
                                    .unwrap_or("unknown")
                            ),
                            detail: format!(
                                "Entropy: {:.4} bits/byte | \
                                 Size: {} bytes | Path: {}",
                                entropy, file.size, file.path
                            ),
                            source_path: file.path.clone(),
                            forensic_value: ForensicValue::Critical,
                            mitre_technique: Some("T1560.001".to_string()),
                            is_suspicious: true,
                            raw_data: Some(serde_json::json!({
                                "entropy": entropy,
                                "size": file.size,
                                "container_type": container_type,
                            })),
                        });
                    }
                }
            }
        }
        records
    }
    
    fn is_sensitive_url(&self, url: &str) -> bool {
        let sensitive_patterns = [
            "bank", "paypal", "venmo", "zelle", "coinbase",
            "binance", "kraken", "wellsfargo", "bankofamerica",
            "chase", "citibank", "usaa", "navyfederal",
            "irs.gov", "ssa.gov", "va.gov",
            "gmail", "outlook", "yahoo.com",
            "admin", "login", "portal", "vpn",
            "ssh", "rdp", "remote",
        ];
        let lower = url.to_lowercase();
        sensitive_patterns.iter().any(|p| lower.contains(p))
    }
}
```

---

## PLUGIN 4: TRACE v1.0
### Real Execution Forensics

```rust
// plugins/strata-plugin-trace/src/lib.rs

impl TracePlugin {
    /// Parse AmCache.hve — uses nt-hive crate
    fn parse_amcache(
        &self, 
        context: &PluginContext
    ) -> Vec<ArtifactRecord> {
        let mut records = Vec::new();
        
        for file in &context.file_index {
            if !file.path.to_lowercase()
                .ends_with("amcache.hve") { 
                continue; 
            }
            
            if let Ok(data) = std::fs::read(&file.path) {
                if let Ok(hive) = nt_hive::NtHive::from_slice(&data) {
                    // Navigate to InventoryApplicationFile
                    let path = "Root\\InventoryApplicationFile";
                    if let Some(key) = hive.open_subkey(path) {
                        for subkey in key.subkeys().flatten() {
                            let mut exe_path = String::new();
                            let mut sha1 = String::new();
                            let mut publisher = String::new();
                            let mut file_id = String::new();
                            
                            for value in subkey.values().flatten() {
                                match value.name().to_string()
                                    .as_str() 
                                {
                                    "LowerCaseLongPath" => {
                                        exe_path = value.string_data()
                                            .unwrap_or_default();
                                    },
                                    "FileId" => {
                                        file_id = value.string_data()
                                            .unwrap_or_default();
                                        // FileId is "0000" + SHA1
                                        if file_id.len() > 4 {
                                            sha1 = file_id[4..].to_string();
                                        }
                                    },
                                    "Publisher" => {
                                        publisher = value.string_data()
                                            .unwrap_or_default();
                                    },
                                    _ => {}
                                }
                            }
                            
                            if exe_path.is_empty() { continue; }
                            
                            let is_lolbin = self.is_lolbin(&exe_path);
                            let is_suspicious_path = 
                                self.is_suspicious_path(&exe_path);
                            let no_publisher = publisher.is_empty();
                            let is_suspicious = is_lolbin 
                                || is_suspicious_path;
                            
                            records.push(ArtifactRecord {
                                category: ArtifactCategory::ExecutionHistory,
                                subcategory: "AmCache Entry".to_string(),
                                timestamp: None, // AmCache doesn't store run time
                                title: exe_path.split(['\\', '/'])
                                    .last()
                                    .unwrap_or("unknown")
                                    .to_string(),
                                detail: format!(
                                    "Path: {} | SHA1: {} | \
                                     Publisher: {}{}{}",
                                    exe_path,
                                    if sha1.is_empty() { "unknown" } 
                                        else { &sha1 },
                                    if publisher.is_empty() { 
                                        "[no publisher]" 
                                    } else { &publisher },
                                    if is_lolbin { " | ⚠ LOLBIN" } 
                                        else { "" },
                                    if is_suspicious_path { 
                                        " | ⚠ Suspicious path" 
                                    } else { "" },
                                ),
                                source_path: file.path.clone(),
                                forensic_value: if is_suspicious {
                                    ForensicValue::Critical
                                } else if no_publisher {
                                    ForensicValue::High
                                } else {
                                    ForensicValue::Medium
                                },
                                mitre_technique: if is_lolbin {
                                    Some(self.get_lolbin_mitre(&exe_path)
                                        .to_string())
                                } else {
                                    Some("T1059".to_string())
                                },
                                is_suspicious,
                                raw_data: Some(serde_json::json!({
                                    "path": exe_path,
                                    "sha1": sha1,
                                    "publisher": publisher,
                                    "is_lolbin": is_lolbin,
                                })),
                            });
                        }
                    }
                }
            }
        }
        records
    }
    
    fn is_lolbin(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        LOLBIN_LIST.iter().any(|(name, _, _)| lower.ends_with(name))
    }
    
    fn get_lolbin_mitre(&self, path: &str) -> &'static str {
        let lower = path.to_lowercase();
        LOLBIN_LIST.iter()
            .find(|(name, _, _)| lower.ends_with(name))
            .map(|(_, _, mitre)| *mitre)
            .unwrap_or("T1059")
    }
    
    fn is_suspicious_path(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        [
            "\\temp\\", "\\tmp\\", "\\downloads\\",
            "\\appdata\\roaming\\", "\\public\\",
            "\\recycle", "/tmp/", "/dev/shm/",
        ].iter().any(|p| lower.contains(p))
    }
}

// Full LOLBIN list with MITRE techniques
const LOLBIN_LIST: &[(&str, &str, &str)] = &[
    ("certutil.exe", "Certificate utility — download/decode", "T1140"),
    ("bitsadmin.exe", "BITS download manager", "T1197"),
    ("mshta.exe", "HTML Application host", "T1218.005"),
    ("regsvr32.exe", "Register DLL", "T1218.010"),
    ("rundll32.exe", "Run DLL as function", "T1218.011"),
    ("wscript.exe", "Windows Script Host", "T1059.005"),
    ("cscript.exe", "Console Script Host", "T1059.005"),
    ("msbuild.exe", "MSBuild — inline C# execution", "T1127.001"),
    ("wmic.exe", "WMI command line", "T1047"),
    ("installutil.exe", "AppLocker bypass", "T1218.004"),
    ("regasm.exe", "Register Assembly", "T1218.009"),
    ("regsvcs.exe", "Register COM+", "T1218.009"),
    ("vssadmin.exe", "Shadow Copy admin", "T1490"),
    ("wbadmin.exe", "Backup admin", "T1490"),
    ("bcdedit.exe", "Boot configuration", "T1490"),
    ("esentutl.exe", "ESE database — file copy bypass", "T1003.003"),
    ("nltest.exe", "Domain enumeration", "T1016"),
    ("net.exe", "Network commands", "T1049"),
    ("netsh.exe", "Network shell", "T1562.004"),
    ("schtasks.exe", "Schedule tasks", "T1053.005"),
    ("at.exe", "Legacy scheduler", "T1053.002"),
    ("sc.exe", "Service control", "T1543.003"),
    ("taskkill.exe", "Kill processes", "T1562"),
    ("robocopy.exe", "File copy — exfil", "T1570"),
    ("curl.exe", "URL download", "T1105"),
    ("expand.exe", "Expand/decompress", "T1140"),
    ("fsutil.exe", "File system utility", "T1485"),
    ("icacls.exe", "ACL manipulation", "T1222.001"),
    ("takeown.exe", "Ownership takeover", "T1222.001"),
    ("wsl.exe", "WSL subsystem", "T1202"),
    ("python.exe", "Python interpreter", "T1059.006"),
    ("pythonw.exe", "Python no-window", "T1059.006"),
    ("msiexec.exe", "Windows Installer", "T1218.007"),
];
```

---

## PLUGIN INDEPENDENCE REQUIREMENTS

Each plugin Cargo.toml must be standalone:

```toml
# plugins/strata-plugin-remnant/Cargo.toml
[package]
name = "strata-plugin-remnant"
version = "1.0.0"
edition = "2021"
description = "Strata deep file carving plugin"
authors = ["Wolfmark Systems"]

[lib]
name = "strata_plugin_remnant"
crate-type = ["rlib"]  # Static linking into Strata binary

[dependencies]
strata-plugin-sdk = { path = "../../crates/strata-plugin-sdk" }
lz4_flex = "0.11"      # For Prefetch decompression in Remnant
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }

# plugins/strata-plugin-chronicle/Cargo.toml
[dependencies]
strata-plugin-sdk = { path = "../../crates/strata-plugin-sdk" }
rusqlite = { version = "0.31", features = ["bundled"] }
evtx = "0.8"
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }

# plugins/strata-plugin-cipher/Cargo.toml
[dependencies]
strata-plugin-sdk = { path = "../../crates/strata-plugin-sdk" }
rusqlite = { version = "0.31", features = ["bundled"] }
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }

# plugins/strata-plugin-trace/Cargo.toml
[dependencies]
strata-plugin-sdk = { path = "../../crates/strata-plugin-sdk" }
nt-hive = "0.3"
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }
```

---

## PLUGIN TESTS — Each Plugin Must Have Tests

```rust
// plugins/strata-plugin-remnant/src/tests.rs
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_detects_pe_header() {
        // MZ header
        let data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00";
        let plugin = RemnantPlugin;
        // Should find PE signature at offset 0
        assert!(data.starts_with(b"MZ"));
    }
    
    #[test]
    fn test_entropy_calculation() {
        // Random-looking data should have high entropy
        let random_data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        let entropy = RemnantPlugin::calculate_entropy(&random_data);
        assert!(entropy > 7.9, "Expected high entropy, got {}", entropy);
        
        // All-zero data should have zero entropy
        let zero_data = vec![0u8; 1024];
        let entropy = RemnantPlugin::calculate_entropy(&zero_data);
        assert!(entropy < 0.01, "Expected near-zero entropy");
    }
    
    #[test]
    fn test_sqlite_header_detection() {
        let header = b"SQLite format 3\x00";
        assert!(header.starts_with(b"SQLite format 3\x00"));
    }
}

// Each plugin has similar focused tests
// Chronicle: test EVTX event ID extraction
// Cipher: test entropy calculation, URL sensitivity
// Trace: test LOLBIN detection, path analysis
```

---

## VERIFICATION

```bash
# Build entire workspace
cargo build --workspace

# Run all tests including plugin tests
cargo test --workspace

# Strict lint — zero warnings
cargo clippy --workspace -- -D warnings

# Check binary size (should stay under 30MB)
ls -lh target/release/strata

# Verify plugins are independent
# (each should compile standalone)
cargo build -p strata-plugin-remnant
cargo build -p strata-plugin-chronicle
cargo build -p strata-plugin-cipher
cargo build -p strata-plugin-trace
```

---

## DELIVERABLES

1. All 4 plugins upgraded to v1.0.0
2. Each plugin independently compilable
3. Each plugin has its own Cargo.toml with proper dependencies
4. Remnant: real binary carving with 60+ signatures
5. Chronicle: real Prefetch parsing, EVTX extraction, browser history
6. Cipher: real SQLite credential queries, entropy analysis
7. Trace: real AmCache parsing, full LOLBIN list
8. All plugins produce ArtifactRecord with real data
9. Plugin tests passing
10. Strata binary still compiles clean without modifying core

Report per plugin:
  Artifacts now actually extracted
  Test results
  Any edge cases or limitations

---

*Wolfmark Systems — Strata Forensic Platform*
*Plugin System v1.0 — Independent Modular Architecture*
*Remnant · Chronicle · Cipher · Trace*
*April 2026*
