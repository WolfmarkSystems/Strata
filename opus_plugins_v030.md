# OPUS TASK — Strata Plugin System v0.3.0
# Four Core Plugins: Remnant, Chronicle, Cipher, Trace
# Date: 2026-04-03
# Priority: HIGH — Plugins are what make Strata useful

---

## WHO YOU ARE

You are Opus, senior technical architect for Wolfmark Systems.
You are building Strata — a court-defensible digital forensic
examination platform. You built 159 parsers today.
Now you're wiring them into plugins that actually work.

---

## CURRENT STATE

```
Product:  Strata v0.3.0
Plugins:  4 built-in plugins exist as STUBS
          They show in the UI but do nothing useful
          
Plugin architecture decision (LOCKED):
  Trait-based, statically compiled
  NOT dynamic loading (.dll)
  Reason: CJIS compliance — no unknown code loading
  Reason: Full audit trail
  Plugins are Rust crates compiled into the binary
  
Plugin colors (from design system):
  Remnant:   #818cf8 (indigo)   — deep file carving
  Chronicle: #fbbf24 (amber)    — timeline enrichment
  Cipher:    #f43f5e (rose)     — encryption analysis
  Trace:     #4ade80 (green)    — execution tracking

Target version after this session: v0.3.0 for all 4 plugins
```

---

## WHAT v0.3.0 MEANS FOR EACH PLUGIN

```
v0.1.0 = stub (exists, does nothing)
v0.2.0 = parses one artifact type, outputs to UI
v0.3.0 = parses multiple artifact types, 
          populates Artifacts panel categories,
          produces audit log entries,
          shows results in human-readable tables,
          exports to CSV

This session brings all 4 from stub to v0.3.0
```

---

## SHARED PLUGIN INFRASTRUCTURE

Before implementing individual plugins, ensure this
infrastructure exists. Create if missing.

### Plugin Trait (in strata-sdk or strata-plugin-sdk)

```rust
// crates/strata-sdk/src/lib.rs
// OR crates/strata-plugin-sdk/src/lib.rs
// (use whichever exists — check first)

use std::path::Path;
use chrono::{DateTime, Utc};

/// Version of the plugin API this plugin targets
pub const PLUGIN_API_VERSION: &str = "0.3.0";

/// Base trait all plugins must implement
pub trait StrataPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn description(&self) -> &str;
    fn author(&self) -> &str;
    fn plugin_type(&self) -> PluginType;
    fn capabilities(&self) -> Vec<PluginCapability>;
    
    /// Called when plugin is loaded — return Ok or explain why it can't run
    fn initialize(&mut self) -> Result<(), PluginError>;
    
    /// Main execution — receives context, returns results
    fn execute(
        &self,
        context: &PluginContext,
        progress: &dyn ProgressReporter,
    ) -> Result<PluginResult, PluginError>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum PluginType {
    Carver,    // Remnant
    Analyzer,  // Chronicle, Trace
    Cipher,    // Cipher
}

#[derive(Debug, Clone)]
pub enum PluginCapability {
    FileCarving,
    TimelineEnrichment,
    ArtifactExtraction,
    EncryptionAnalysis,
    ExecutionTracking,
    CredentialExtraction,
    NetworkArtifacts,
    DeletedFileRecovery,
}

/// Context passed to plugin on execute
pub struct PluginContext {
    /// Path to the loaded evidence file or directory
    pub evidence_path: std::path::PathBuf,
    /// Path where plugin can write output (evidence drive)
    pub output_path: std::path::PathBuf,
    /// All files currently indexed (from VFS)
    pub file_index: Vec<IndexedFile>,
    /// Case information
    pub case_number: String,
    pub examiner_name: String,
    /// Execution timestamp
    pub started_at: DateTime<Utc>,
}

/// A file from the VFS index
pub struct IndexedFile {
    pub path: String,
    pub size: u64,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub sha256: Option<String>,
    pub category: Option<String>,
    pub is_deleted: bool,
}

/// Plugin execution result
pub struct PluginResult {
    pub plugin_name: String,
    pub plugin_version: String,
    pub executed_at: DateTime<Utc>,
    pub duration_ms: u64,
    /// Artifact records to populate the Artifacts panel
    pub artifacts: Vec<ArtifactRecord>,
    /// Timeline events to inject
    pub timeline_events: Vec<TimelineEvent>,
    /// Files discovered (carved or recovered)
    pub discovered_files: Vec<DiscoveredFile>,
    /// Summary for the UI
    pub summary: PluginSummary,
    /// Errors encountered (non-fatal)
    pub warnings: Vec<String>,
}

/// A single artifact record for the Artifacts panel
pub struct ArtifactRecord {
    pub category: ArtifactCategory,
    pub subcategory: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub title: String,
    pub detail: String,
    pub source_path: String,
    pub forensic_value: ForensicValue,
    pub mitre_technique: Option<String>,
    pub is_suspicious: bool,
    pub raw_data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ArtifactCategory {
    Communications,
    SocialMedia,
    WebActivity,
    UserActivity,
    SystemActivity,
    CloudSync,
    AccountsCredentials,
    Media,
    DeletedRecovered,
    ExecutionHistory,
    NetworkArtifacts,
    EncryptionKeyMaterial,
}

#[derive(Debug, Clone)]
pub enum ForensicValue {
    Critical,   // Must include in report
    High,       // Should include in report
    Medium,     // Worth noting
    Low,        // Background noise
    Informational,
}

pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub source: String,
    pub description: String,
    pub path: Option<String>,
    pub is_suspicious: bool,
    pub mitre_technique: Option<String>,
}

pub struct DiscoveredFile {
    pub output_path: std::path::PathBuf,
    pub original_offset: Option<u64>,
    pub file_type: String,
    pub size: u64,
    pub confidence: f32,
    pub is_deleted: bool,
}

pub struct PluginSummary {
    pub total_artifacts: usize,
    pub suspicious_count: usize,
    pub categories_populated: Vec<String>,
    pub headline: String, // "Found 47 saved passwords, 12 WiFi networks"
}

/// Progress reporting
pub trait ProgressReporter: Send + Sync {
    fn report(&self, current: u64, total: u64, message: &str);
    fn is_cancelled(&self) -> bool;
}

#[derive(Debug)]
pub struct PluginError {
    pub message: String,
    pub is_fatal: bool,
}
```

### Audit Integration

Every plugin execution MUST produce audit log entries:

```rust
// Before plugin runs:
audit_log.append(AuditEntry {
    action: "PLUGIN_START",
    detail: format!("{} v{} started on {}",
        plugin.name(), plugin.version(), evidence_path),
});

// After plugin runs:
audit_log.append(AuditEntry {
    action: "PLUGIN_COMPLETE",
    detail: format!("{}: {} artifacts found, {} suspicious",
        plugin.name(),
        result.artifacts.len(),
        result.artifacts.iter().filter(|a| a.is_suspicious).count()),
});
```

---

## PLUGIN 1 — REMNANT v0.3.0
### Deep File Carving + Deleted File Recovery
### Color: #818cf8 (Indigo)

**What Remnant does:**
Recovers deleted files and carves data from unallocated space.
Goes beyond the built-in 26-signature carver to include
communication artifacts, documents, and forensic-specific formats.

**v0.3.0 target capabilities:**

### 1.1 — Expanded Signature Database

Extend the existing 26 signatures to 60+ signatures:

```rust
// In remnant plugin — full signature list
pub struct FileSignature {
    pub name: &'static str,
    pub category: ArtifactCategory,
    pub header: &'static [u8],
    pub footer: Option<&'static [u8]>,
    pub extension: &'static str,
    pub max_size_mb: u32,
    pub forensic_value: ForensicValue,
}

pub const SIGNATURES: &[FileSignature] = &[
    // Documents
    FileSignature { name: "PDF", header: b"%PDF", footer: Some(b"%%EOF"), extension: "pdf", max_size_mb: 500, category: ArtifactCategory::UserActivity, forensic_value: ForensicValue::High },
    FileSignature { name: "Word DOCX", header: b"PK\x03\x04", footer: None, extension: "docx", max_size_mb: 100, category: ArtifactCategory::UserActivity, forensic_value: ForensicValue::High },
    FileSignature { name: "Excel XLSX", header: b"PK\x03\x04", footer: None, extension: "xlsx", max_size_mb: 100, category: ArtifactCategory::UserActivity, forensic_value: ForensicValue::High },
    FileSignature { name: "Legacy DOC", header: &[0xD0, 0xCF, 0x11, 0xE0], footer: None, extension: "doc", max_size_mb: 100, category: ArtifactCategory::UserActivity, forensic_value: ForensicValue::High },
    
    // Images
    FileSignature { name: "JPEG", header: &[0xFF, 0xD8, 0xFF], footer: Some(&[0xFF, 0xD9]), extension: "jpg", max_size_mb: 50, category: ArtifactCategory::Media, forensic_value: ForensicValue::Medium },
    FileSignature { name: "PNG", header: &[0x89, 0x50, 0x4E, 0x47], footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]), extension: "png", max_size_mb: 50, category: ArtifactCategory::Media, forensic_value: ForensicValue::Medium },
    FileSignature { name: "GIF", header: b"GIF87a", footer: Some(&[0x00, 0x3B]), extension: "gif", max_size_mb: 20, category: ArtifactCategory::Media, forensic_value: ForensicValue::Low },
    FileSignature { name: "BMP", header: b"BM", footer: None, extension: "bmp", max_size_mb: 50, category: ArtifactCategory::Media, forensic_value: ForensicValue::Low },
    FileSignature { name: "TIFF", header: &[0x49, 0x49, 0x2A, 0x00], footer: None, extension: "tif", max_size_mb: 100, category: ArtifactCategory::Media, forensic_value: ForensicValue::Medium },
    FileSignature { name: "WEBP", header: b"RIFF", footer: None, extension: "webp", max_size_mb: 50, category: ArtifactCategory::Media, forensic_value: ForensicValue::Low },
    
    // Video/Audio
    FileSignature { name: "MP4", header: &[0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70], footer: None, extension: "mp4", max_size_mb: 4000, category: ArtifactCategory::Media, forensic_value: ForensicValue::High },
    FileSignature { name: "AVI", header: b"RIFF", footer: None, extension: "avi", max_size_mb: 4000, category: ArtifactCategory::Media, forensic_value: ForensicValue::High },
    FileSignature { name: "MP3", header: &[0xFF, 0xFB], footer: None, extension: "mp3", max_size_mb: 500, category: ArtifactCategory::Media, forensic_value: ForensicValue::Medium },
    
    // Executables (HIGH forensic value)
    FileSignature { name: "PE Executable", header: b"MZ", footer: None, extension: "exe", max_size_mb: 500, category: ArtifactCategory::ExecutionHistory, forensic_value: ForensicValue::Critical },
    FileSignature { name: "PE DLL", header: b"MZ", footer: None, extension: "dll", max_size_mb: 500, category: ArtifactCategory::ExecutionHistory, forensic_value: ForensicValue::Critical },
    
    // Archives
    FileSignature { name: "ZIP", header: b"PK\x03\x04", footer: Some(b"PK\x05\x06"), extension: "zip", max_size_mb: 2000, category: ArtifactCategory::UserActivity, forensic_value: ForensicValue::Medium },
    FileSignature { name: "RAR", header: b"Rar!", footer: None, extension: "rar", max_size_mb: 2000, category: ArtifactCategory::UserActivity, forensic_value: ForensicValue::Medium },
    FileSignature { name: "7Z", header: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], footer: None, extension: "7z", max_size_mb: 2000, category: ArtifactCategory::UserActivity, forensic_value: ForensicValue::Medium },
    
    // Databases (HIGH forensic value)
    FileSignature { name: "SQLite Database", header: b"SQLite format 3\x00", footer: None, extension: "db", max_size_mb: 1000, category: ArtifactCategory::Communications, forensic_value: ForensicValue::Critical },
    
    // Email/Communication
    FileSignature { name: "PST (Outlook)", header: &[0x21, 0x42, 0x44, 0x4E], footer: None, extension: "pst", max_size_mb: 50000, category: ArtifactCategory::Communications, forensic_value: ForensicValue::Critical },
    FileSignature { name: "OST (Outlook)", header: &[0x21, 0x42, 0x44, 0x4E], footer: None, extension: "ost", max_size_mb: 50000, category: ArtifactCategory::Communications, forensic_value: ForensicValue::Critical },
    FileSignature { name: "EML Email", header: b"From ", footer: None, extension: "eml", max_size_mb: 100, category: ArtifactCategory::Communications, forensic_value: ForensicValue::High },
    
    // Forensic formats
    FileSignature { name: "Windows Event Log (EVTX)", header: b"ElfFile\x00", footer: None, extension: "evtx", max_size_mb: 1000, category: ArtifactCategory::SystemActivity, forensic_value: ForensicValue::Critical },
    FileSignature { name: "Registry Hive", header: b"regf", footer: None, extension: "hve", max_size_mb: 500, category: ArtifactCategory::SystemActivity, forensic_value: ForensicValue::Critical },
    FileSignature { name: "LNK Shortcut", header: &[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00], footer: None, extension: "lnk", max_size_mb: 1, category: ArtifactCategory::UserActivity, forensic_value: ForensicValue::High },
    FileSignature { name: "Prefetch", header: b"MAM\x04", footer: None, extension: "pf", max_size_mb: 10, category: ArtifactCategory::ExecutionHistory, forensic_value: ForensicValue::Critical },
    
    // Certificates/Keys
    FileSignature { name: "PEM Certificate", header: b"-----BEGIN", footer: None, extension: "pem", max_size_mb: 1, category: ArtifactCategory::EncryptionKeyMaterial, forensic_value: ForensicValue::Critical },
    FileSignature { name: "Private Key", header: b"-----BEGIN RSA PRIVATE KEY", footer: None, extension: "key", max_size_mb: 1, category: ArtifactCategory::EncryptionKeyMaterial, forensic_value: ForensicValue::Critical },
    FileSignature { name: "PFX Certificate", header: &[0x30, 0x82], footer: None, extension: "pfx", max_size_mb: 10, category: ArtifactCategory::EncryptionKeyMaterial, forensic_value: ForensicValue::Critical },
    
    // Cryptocurrency
    FileSignature { name: "Bitcoin Wallet", header: b"\x00\x00\x00\x01\x00\x00\x00\x00", footer: None, extension: "wallet", max_size_mb: 100, category: ArtifactCategory::AccountsCredentials, forensic_value: ForensicValue::Critical },
    
    // Scripts
    FileSignature { name: "PowerShell Script", header: b"#!", footer: None, extension: "ps1", max_size_mb: 10, category: ArtifactCategory::ExecutionHistory, forensic_value: ForensicValue::High },
    FileSignature { name: "VBScript", header: b"'VBS", footer: None, extension: "vbs", max_size_mb: 10, category: ArtifactCategory::ExecutionHistory, forensic_value: ForensicValue::High },
    
    // macOS artifacts
    FileSignature { name: "macOS PLIST (binary)", header: b"bplist00", footer: None, extension: "plist", max_size_mb: 100, category: ArtifactCategory::SystemActivity, forensic_value: ForensicValue::High },
    FileSignature { name: "macOS DMG", header: &[0x78, 0x01, 0x73, 0x0D], footer: None, extension: "dmg", max_size_mb: 50000, category: ArtifactCategory::UserActivity, forensic_value: ForensicValue::Medium },
    
    // Mobile artifacts
    FileSignature { name: "Android ADB Backup", header: b"ANDROID BACKUP\n", footer: None, extension: "ab", max_size_mb: 50000, category: ArtifactCategory::Communications, forensic_value: ForensicValue::Critical },
    FileSignature { name: "iOS iTunes Backup (Manifest)", header: b"bplist00", footer: None, extension: "plist", max_size_mb: 100, category: ArtifactCategory::Communications, forensic_value: ForensicValue::Critical },
];
```

### 1.2 — Carving Engine

```rust
impl RemnantPlugin {
    pub fn carve_evidence(
        &self,
        context: &PluginContext,
        progress: &dyn ProgressReporter,
    ) -> Result<PluginResult, PluginError> {
        let mut artifacts = Vec::new();
        let mut discovered_files = Vec::new();
        let mut timeline_events = Vec::new();
        
        // Read evidence in chunks
        let evidence_data = self.read_evidence(&context.evidence_path)?;
        let total_bytes = evidence_data.len() as u64;
        
        let chunk_size = 512 * 1024; // 512KB chunks
        let mut offset = 0usize;
        let mut carved_count = 0u32;
        
        while offset < evidence_data.len() {
            if progress.is_cancelled() { break; }
            
            progress.report(
                offset as u64,
                total_bytes,
                &format!("Carving... {:.1}%", (offset as f64 / total_bytes as f64) * 100.0)
            );
            
            let chunk = &evidence_data[offset..
                (offset + chunk_size).min(evidence_data.len())];
            
            // Check each signature against this position
            for sig in SIGNATURES {
                if chunk.starts_with(sig.header) {
                    // Found a match — extract the file
                    let extracted = self.extract_file(
                        &evidence_data,
                        offset,
                        sig,
                    );
                    
                    if let Some(file_data) = extracted {
                        carved_count += 1;
                        let output_filename = format!(
                            "CARVED_{:06}_{}.{}",
                            carved_count,
                            sig.name.replace(" ", "_"),
                            sig.extension
                        );
                        let output_path = context.output_path
                            .join("carved")
                            .join(&output_filename);
                        
                        // Write carved file
                        std::fs::write(&output_path, &file_data)?;
                        
                        discovered_files.push(DiscoveredFile {
                            output_path: output_path.clone(),
                            original_offset: Some(offset as u64),
                            file_type: sig.name.to_string(),
                            size: file_data.len() as u64,
                            confidence: 0.9,
                            is_deleted: true,
                        });
                        
                        // Create artifact record
                        artifacts.push(ArtifactRecord {
                            category: sig.category.clone(),
                            subcategory: format!("Carved {}", sig.name),
                            timestamp: None,
                            title: output_filename.clone(),
                            detail: format!(
                                "Carved from offset 0x{:X}, size: {} bytes",
                                offset,
                                file_data.len()
                            ),
                            source_path: format!("offset:0x{:X}", offset),
                            forensic_value: sig.forensic_value.clone(),
                            mitre_technique: self.get_mitre_for_type(sig.name),
                            is_suspicious: sig.forensic_value == ForensicValue::Critical,
                            raw_data: None,
                        });
                        
                        // Timeline event for executable carving
                        if sig.extension == "exe" || sig.extension == "dll" {
                            timeline_events.push(TimelineEvent {
                                timestamp: Utc::now(), // use file timestamps if available
                                event_type: "CarvedExecutable".to_string(),
                                source: "Remnant".to_string(),
                                description: format!(
                                    "Carved {} from offset 0x{:X}",
                                    output_filename, offset
                                ),
                                path: Some(output_path.to_string_lossy().to_string()),
                                is_suspicious: true,
                                mitre_technique: Some("T1564".to_string()),
                            });
                        }
                    }
                }
            }
            
            offset += 512; // Step 1 sector at a time for thoroughness
        }
        
        let suspicious_count = artifacts.iter()
            .filter(|a| a.is_suspicious)
            .count();
            
        Ok(PluginResult {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: Utc::now(),
            duration_ms: 0, // set after execution
            artifacts,
            timeline_events,
            discovered_files,
            summary: PluginSummary {
                total_artifacts: carved_count as usize,
                suspicious_count,
                categories_populated: vec![
                    "Deleted & Recovered".to_string(),
                    "Execution History".to_string(),
                    "Media".to_string(),
                ],
                headline: format!(
                    "Carved {} files ({} executables, {} databases, {} documents)",
                    carved_count,
                    self.count_by_ext(&discovered_files, "exe"),
                    self.count_by_ext(&discovered_files, "db"),
                    self.count_by_ext(&discovered_files, "pdf"),
                ),
            },
            warnings: vec![],
        })
    }
}
```

### 1.3 — Remnant UI in Plugins Panel

Show results as:
```
Remnant v0.3.0  [RUN ON EVIDENCE] [RUN ON SELECTION]
Status: ✓ Completed — 234 files carved
  → 12 executables  (CRITICAL)
  → 8 databases     (CRITICAL)  
  → 45 documents    (HIGH)
  → 169 media files (MEDIUM)
Last run: 2026-04-03 18:33:22 UTC
[View Results →]  [Export CSV]
```

---

## PLUGIN 2 — CHRONICLE v0.3.0
### Timeline Enrichment from All Artifact Sources
### Color: #fbbf24 (Amber)

**What Chronicle does:**
Chronicle aggregates timeline data from ALL parsed artifacts
and builds a unified, correlated activity timeline.
It pulls from every parser that was run and creates
a coherent narrative of what happened on the system.

**v0.3.0 target capabilities:**

### 2.1 — Artifact Source Integration

Chronicle reads from ALL these sources and creates timeline events:

```rust
impl ChroniclePlugin {
    pub fn build_timeline(
        &self,
        context: &PluginContext,
        progress: &dyn ProgressReporter,
    ) -> Result<PluginResult, PluginError> {
        let mut all_events: Vec<TimelineEvent> = Vec::new();
        let mut artifacts: Vec<ArtifactRecord> = Vec::new();
        
        let sources = [
            ("Prefetch", self.parse_prefetch_files(context)),
            ("LNK Files", self.parse_lnk_files(context)),
            ("Jump Lists", self.parse_jump_lists(context)),
            ("EVTX High Value", self.parse_evtx_high_value(context)),
            ("UserAssist", self.parse_userassist(context)),
            ("SRUM", self.parse_srum(context)),
            ("Shellbags", self.parse_shellbags(context)),
            ("Scheduled Tasks", self.parse_scheduled_tasks(context)),
            ("Browser History", self.parse_browser_history(context)),
            ("BITS Jobs", self.parse_bits_jobs(context)),
            ("MFT Timestamps", self.parse_mft_timestamps(context)),
            ("AmCache", self.parse_amcache(context)),
            ("Windows Notifications", self.parse_notifications(context)),
            ("RDP Artifacts", self.parse_rdp_artifacts(context)),
        ];
        
        let total = sources.len() as u64;
        for (i, (name, result)) in sources.iter().enumerate() {
            progress.report(i as u64, total, 
                &format!("Processing {}", name));
            
            match result {
                Ok(events) => all_events.extend(events),
                Err(e) => { /* log warning, continue */ }
            }
        }
        
        // Sort all events chronologically
        all_events.sort_by_key(|e| e.timestamp);
        
        // Detect activity bursts (> 50 events in 60 seconds)
        let bursts = self.detect_activity_bursts(&all_events);
        
        // Correlate events — find related events within 5 minutes
        let correlated = self.correlate_events(&all_events);
        
        // Create artifact records for high-value sequences
        for burst in &bursts {
            artifacts.push(ArtifactRecord {
                category: ArtifactCategory::SystemActivity,
                subcategory: "Activity Burst".to_string(),
                timestamp: Some(burst.start_time),
                title: format!("Activity burst: {} events in {}s",
                    burst.event_count, burst.duration_secs),
                detail: format!(
                    "Avg {:.1} events/sec — potential mass operation",
                    burst.events_per_second
                ),
                source_path: "chronicle:burst_detection".to_string(),
                forensic_value: ForensicValue::High,
                mitre_technique: None,
                is_suspicious: burst.events_per_second > 100.0,
                raw_data: None,
            });
        }
        
        // Execution sequence artifacts
        let execution_sequences = self.find_execution_sequences(&all_events);
        for seq in &execution_sequences {
            if seq.is_suspicious {
                artifacts.push(ArtifactRecord {
                    category: ArtifactCategory::ExecutionHistory,
                    subcategory: "Suspicious Execution Sequence".to_string(),
                    timestamp: Some(seq.first_event),
                    title: seq.description.clone(),
                    detail: seq.detail.clone(),
                    source_path: "chronicle:execution_analysis".to_string(),
                    forensic_value: ForensicValue::Critical,
                    mitre_technique: seq.mitre_technique.clone(),
                    is_suspicious: true,
                    raw_data: None,
                });
            }
        }
        
        Ok(PluginResult {
            plugin_name: self.name().to_string(),
            plugin_version: "0.3.0".to_string(),
            executed_at: Utc::now(),
            duration_ms: 0,
            artifacts,
            timeline_events: all_events.clone(),
            discovered_files: vec![],
            summary: PluginSummary {
                total_artifacts: all_events.len(),
                suspicious_count: all_events.iter()
                    .filter(|e| e.is_suspicious).count(),
                categories_populated: vec![
                    "User Activity".to_string(),
                    "System Activity".to_string(),
                    "Execution History".to_string(),
                    "Web Activity".to_string(),
                ],
                headline: format!(
                    "Built timeline: {} events from {} sources, {} suspicious",
                    all_events.len(),
                    sources.len(),
                    all_events.iter().filter(|e| e.is_suspicious).count(),
                ),
            },
            warnings: vec![],
        })
    }
}
```

### 2.2 — Key Event Parsers Chronicle Must Implement

#### Prefetch Events
```rust
fn parse_prefetch_files(&self, context: &PluginContext) 
    -> Result<Vec<TimelineEvent>, PluginError> 
{
    // Find all .pf files in evidence
    // For each: parse execution times
    // For each run_time create TimelineEvent:
    //   event_type: "PrefetchExecution"
    //   description: "MIMIKATZ.EXE executed (run 3 of 3)"
    //   is_suspicious: check known bad names + suspicious paths
    //   mitre: T1059 for scripts, T1003 for credential tools
}
```

#### EVTX High-Value Events
```rust
fn parse_evtx_high_value(&self, context: &PluginContext)
    -> Result<Vec<TimelineEvent>, PluginError>
{
    // Parse all .evtx files found in evidence
    // Extract ONLY high-value event IDs:
    
    const HIGH_VALUE_EVENTS: &[(u32, &str, &str)] = &[
        // Security events
        (4624, "Successful Logon", "T1078"),
        (4625, "Failed Logon", "T1110"),
        (4634, "Logoff", ""),
        (4648, "Logon with Explicit Credentials", "T1078"),
        (4672, "Special Privileges Assigned", "T1078.003"),
        (4688, "Process Creation", "T1059"),
        (4698, "Scheduled Task Created", "T1053.005"),
        (4702, "Scheduled Task Updated", "T1053.005"),
        (4720, "User Account Created", "T1136"),
        (4722, "User Account Enabled", ""),
        (4726, "User Account Deleted", "T1531"),
        (4732, "Member Added to Security Group", "T1098"),
        (4740, "Account Locked Out", "T1110"),
        (4776, "Credential Validation", "T1110"),
        // System events
        (7045, "New Service Installed", "T1543.003"),
        (7040, "Service Start Type Changed", "T1543.003"),
        // PowerShell
        (4103, "PowerShell Pipeline Execution", "T1059.001"),
        (4104, "PowerShell Script Block Logging", "T1059.001"),
        // RDP
        (1149, "RDP Authentication Success", "T1021.001"),
        (21, "Remote Desktop Logon", "T1021.001"),
        (24, "Remote Desktop Disconnect", ""),
        (25, "Remote Desktop Reconnect", ""),
        // USB
        (2003, "Driver Install (USB)", "T1052.001"),
        (2100, "PnP Device Connected", "T1052.001"),
    ];
    
    // Return TimelineEvent for each matching event ID
    // Mark as suspicious based on event type and content
}
```

#### UserAssist Execution History
```rust
fn parse_userassist(&self, context: &PluginContext)
    -> Result<Vec<TimelineEvent>, PluginError>
{
    // Find NTUSER.DAT in evidence
    // Parse UserAssist registry keys (ROT13 decoded)
    // For each entry create execution timeline event
    // Include: run count, focus time, last execution time
    // Flag suspicious: execution from Temp, Downloads, unusual paths
}
```

#### Browser History
```rust
fn parse_browser_history(&self, context: &PluginContext)
    -> Result<Vec<TimelineEvent>, PluginError>
{
    // Parse Chrome: History SQLite DB
    //   urls table: url, title, visit_count, last_visit_time
    //   visits table: visit_time, from_visit, transition
    // Parse Firefox: places.sqlite
    //   moz_places + moz_historyvisits
    // Parse Edge: same as Chrome (Chromium-based)
    
    // Flag suspicious URLs:
    //   - Pastebin, hastebin (code sharing)
    //   - Mega, WeTransfer (file sharing)  
    //   - .onion domains
    //   - IP addresses instead of domains
    //   - Known C2 domains (from MITRE)
    //   - Cryptocurrency exchanges
    //   - Job sites (potential insider threat indicator)
    
    // Returns: Vec<TimelineEvent> with visit timestamp,
    //          URL, title, browser source, is_suspicious
}
```

### 2.3 — Chronicle UI Results

```
Chronicle v0.3.0  [BUILD TIMELINE] [REBUILD]
Status: ✓ Completed — 137,202 events from 14 sources
  → 35,258 suspicious events flagged
  → 10 activity bursts detected
  → 3 suspicious execution sequences
  → 89 programs executed (Prefetch)
  → 4,231 registry accesses (UserAssist)

[Open in Timeline View →]  [Export CSV]  [Export JSON]
```

---

## PLUGIN 3 — CIPHER v0.3.0
### Encryption Analysis + Credential Extraction
### Color: #f43f5e (Rose)

**What Cipher does:**
Finds encrypted containers, extracts saved credentials,
identifies key material, detects crypto artifacts,
and flags potential data exfiltration via encryption.

**v0.3.0 target capabilities:**

### 3.1 — Saved Credential Extraction

```rust
impl CipherPlugin {
    fn extract_browser_credentials(
        &self, context: &PluginContext
    ) -> Result<Vec<ArtifactRecord>, PluginError> {
        let mut records = Vec::new();
        
        // Chrome/Edge/Brave Login Data
        // Path: AppData/Local/Google/Chrome/User Data/Default/Login Data
        // SQLite: logins table
        // Fields: origin_url, username_value, password_value (encrypted)
        // Note: password_value is DPAPI encrypted — can decrypt on Windows
        //       on non-Windows: report as "encrypted credential found"
        
        for db_path in self.find_chrome_login_dbs(context) {
            let conn = rusqlite::Connection::open(&db_path)?;
            let mut stmt = conn.prepare(
                "SELECT origin_url, username_value, 
                 password_value, date_created
                 FROM logins ORDER BY date_created DESC"
            )?;
            
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?, // url
                    row.get::<_, String>(1)?, // username
                    row.get::<_, Vec<u8>>(2)?, // encrypted password
                    row.get::<_, i64>(3)?,    // date
                ))
            })?;
            
            for row in rows {
                let (url, username, _pwd_enc, date) = row?;
                
                let is_sensitive = self.is_sensitive_domain(&url);
                
                records.push(ArtifactRecord {
                    category: ArtifactCategory::AccountsCredentials,
                    subcategory: "Saved Browser Password".to_string(),
                    timestamp: Some(chrome_time_to_utc(date)),
                    title: format!("{} — {}", url, username),
                    detail: format!(
                        "Saved credential for {} (password encrypted with DPAPI)",
                        url
                    ),
                    source_path: db_path.to_string_lossy().to_string(),
                    forensic_value: if is_sensitive {
                        ForensicValue::Critical
                    } else {
                        ForensicValue::High
                    },
                    mitre_technique: Some("T1555.003".to_string()),
                    is_suspicious: is_sensitive,
                    raw_data: Some(serde_json::json!({
                        "url": url,
                        "username": username,
                        "browser": "Chrome/Edge",
                        "note": "Password encrypted — requires DPAPI decryption"
                    })),
                });
            }
        }
        
        // Firefox logins.json
        for logins_path in self.find_firefox_logins(context) {
            // Parse logins.json
            // Fields: hostname, encryptedUsername, encryptedPassword
            // Note: encrypted with Firefox master password / NSS
        }
        
        Ok(records)
    }
    
    fn extract_wifi_credentials(
        &self, context: &PluginContext
    ) -> Result<Vec<ArtifactRecord>, PluginError> {
        let mut records = Vec::new();
        
        // Windows: SYSTEM\CurrentControlSet\Services\Wlansvc\Parameters\Interfaces
        // Profiles in: C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\
        // XML files contain SSIDs and encrypted PSK (DPAPI)
        
        // macOS: ~/Library/Preferences/SystemConfiguration/
        //        com.apple.wifi.known-networks.plist
        
        // Each network:
        records.push(ArtifactRecord {
            category: ArtifactCategory::AccountsCredentials,
            subcategory: "WiFi Network Profile".to_string(),
            timestamp: None,
            title: "Saved WiFi: [SSID]".to_string(),
            detail: "Known network — PSK encrypted with DPAPI".to_string(),
            source_path: "registry:wlansvc".to_string(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1552.001".to_string()),
            is_suspicious: false,
            raw_data: None,
        });
        
        Ok(records)
    }
    
    fn detect_encrypted_containers(
        &self, context: &PluginContext
    ) -> Result<Vec<ArtifactRecord>, PluginError> {
        let mut records = Vec::new();
        
        // Look for TrueCrypt/VeraCrypt containers:
        //   Files > 1MB with high entropy (> 7.9 bits/byte)
        //   No recognizable file header
        //   Sizes that are multiples of 512 bytes
        
        // Look for BitLocker:
        //   FVEFSM header: -FVE-FS-
        //   Registry: SYSTEM\CurrentControlSet\Control\BitLockerStatus
        
        // Look for EncFS directories (Linux):
        //   .encfs6.xml configuration file
        
        // Look for AxCrypt files:
        //   Header: .AXCRYPT (16 bytes)
        
        // Entropy analysis on large unknown files
        for file in self.find_high_entropy_files(context) {
            records.push(ArtifactRecord {
                category: ArtifactCategory::EncryptionKeyMaterial,
                subcategory: "Potential Encrypted Container".to_string(),
                timestamp: file.modified,
                title: format!("High-entropy file: {}", file.name),
                detail: format!(
                    "Entropy: {:.2} bits/byte — possible encrypted container. Size: {}",
                    file.entropy, file.size_human
                ),
                source_path: file.path.clone(),
                forensic_value: ForensicValue::Critical,
                mitre_technique: Some("T1560.001".to_string()),
                is_suspicious: true,
                raw_data: None,
            });
        }
        
        Ok(records)
    }
    
    fn extract_ssh_artifacts(
        &self, context: &PluginContext
    ) -> Result<Vec<ArtifactRecord>, PluginError> {
        // Find: ~/.ssh/id_rsa, id_ed25519, id_ecdsa (private keys)
        // Find: ~/.ssh/known_hosts (remote systems accessed)
        // Find: ~/.ssh/authorized_keys (who can access this system)
        // Find: ~/.ssh/config (SSH aliases and tunnels)
        
        // Flag: private keys without passphrase
        // Flag: unusual tunnel/proxy configurations
        // Flag: ForwardAgent yes (credential forwarding)
        // MITRE: T1021.004 (Remote Services: SSH)
        
        todo!()
    }
    
    fn calculate_entropy(data: &[u8]) -> f64 {
        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }
        let len = data.len() as f64;
        freq.iter()
            .filter(|&&f| f > 0)
            .map(|&f| {
                let p = f as f64 / len;
                -p * p.log2()
            })
            .sum()
    }
}
```

### 3.2 — Cipher UI Results

```
Cipher v0.3.0  [ANALYZE EVIDENCE] [ANALYZE SELECTION]
Status: ✓ Completed
  → 47 saved browser passwords found (Chrome: 31, Firefox: 16)
  → 12 WiFi network profiles
  → 3 high-entropy files (potential encrypted containers)
  → 2 SSH private keys detected
  → 1 certificate with private key (.pfx)

⚠ CRITICAL: 3 encrypted containers + 2 SSH private keys

[View Results →]  [Export CSV]
```

---

## PLUGIN 4 — TRACE v0.3.0
### Execution Tracking + Process Forensics
### Color: #4ade80 (Green)

**What Trace does:**
Deep execution artifact analysis.
Goes beyond Prefetch to build a comprehensive picture
of WHAT ran on this system, WHEN, and FROM WHERE.
Correlates execution evidence across multiple artifact sources.

**v0.3.0 target capabilities:**

### 4.1 — AmCache Analysis

```rust
fn parse_amcache(&self, context: &PluginContext)
    -> Result<Vec<ArtifactRecord>, PluginError>
{
    // File: C:\Windows\AppCompat\Programs\Amcache.hve
    // Registry hive format — use nt-hive crate
    
    // Key paths:
    // Root\InventoryApplicationFile — installed application files
    // Root\InventoryApplication — installed applications
    // Root\InventoryDriverBinary — drivers
    
    // For each entry extract:
    //   - FileId (SHA1 hash of first 31MB of file)
    //   - LowerCaseLongPath (full path)
    //   - Name (filename)
    //   - Publisher
    //   - Version
    //   - BinaryType (PE characteristics)
    //   - ProgramId
    //   - InstallDate
    
    // Flag:
    //   - Files from Temp, Downloads, AppData\Roaming
    //   - Files matching known malware names
    //   - Executables with no publisher
    //   - Very recent install dates
    //   - Files no longer present (deleted after execution)
    
    // MITRE: T1059 (Command and Scripting Interpreter)
    //        T1218 (System Binary Proxy Execution)
}
```

### 4.2 — ShimCache (AppCompatCache) Analysis

```rust
fn parse_shimcache(&self, context: &PluginContext)
    -> Result<Vec<ArtifactRecord>, PluginError>
{
    // Registry: SYSTEM\CurrentControlSet\Control\Session Manager\
    //           AppCompatCache\AppCompatCache
    
    // Binary format varies by Windows version:
    //   XP:      DWORD magic + entries (96 bytes each)
    //   Vista/7: DWORD magic + entry count + entries (128 bytes each)
    //   Win8+:   "APPCOMPAT" signature + entries
    //   Win10+:  Different offset layout
    
    // Each entry:
    //   Path: full executable path
    //   LastModified: timestamp of file modification
    //   ExecutedFlag: NOT always present (Win7 has it, Win10 removed it)
    //   DataSize: size of path
    
    // IMPORTANT: ShimCache records presence on system,
    //            not necessarily execution.
    //            Document this distinction in output.
    
    // Up to 1024 entries (oldest evicted)
    // Ordered: most recent first (after reboot order reversal)
    
    // Flag:
    //   - Entries from suspicious paths
    //   - Entries no longer present on disk
    //   - Known malware filenames
    //   - LOLBins used as proxies
}
```

### 4.3 — LOLBIN (Living Off The Land) Detection

```rust
const LOLBINS: &[(&str, &str, &str)] = &[
    // (binary_name, description, mitre_technique)
    ("certutil.exe", "Certificate utility — used for download/decode", "T1140"),
    ("bitsadmin.exe", "BITS admin — used for download", "T1197"),
    ("mshta.exe", "HTML Application host — executes HTA files", "T1218.005"),
    ("regsvr32.exe", "Register DLL — AppLocker bypass", "T1218.010"),
    ("rundll32.exe", "Run DLL — proxy execution", "T1218.011"),
    ("wscript.exe", "Windows Script Host", "T1059.005"),
    ("cscript.exe", "Console Script Host", "T1059.005"),
    ("powershell.exe", "PowerShell", "T1059.001"),
    ("cmd.exe", "Command Prompt — often with suspicious args", "T1059.003"),
    ("msiexec.exe", "Windows Installer — proxy execution", "T1218.007"),
    ("installutil.exe", "Install utility — AppLocker bypass", "T1218.004"),
    ("regasm.exe", "Register Assembly — AppLocker bypass", "T1218.009"),
    ("regsvcs.exe", "Register COM+ app", "T1218.009"),
    ("msbuild.exe", "MSBuild — executes inline C#", "T1127.001"),
    ("wmic.exe", "WMI command line", "T1047"),
    ("schtasks.exe", "Schedule Tasks", "T1053.005"),
    ("at.exe", "Legacy scheduler", "T1053.002"),
    ("sc.exe", "Service control", "T1543.003"),
    ("net.exe", "Network commands", "T1049"),
    ("netsh.exe", "Network shell — firewall rules/tunneling", "T1562.004"),
    ("nltest.exe", "Domain enumeration", "T1016"),
    ("whoami.exe", "Current user discovery", "T1033"),
    ("tasklist.exe", "Process enumeration", "T1057"),
    ("taskkill.exe", "Kill processes", "T1562"),
    ("ipconfig.exe", "IP configuration", "T1016"),
    ("systeminfo.exe", "System info", "T1082"),
    ("quser.exe", "Query users", "T1033"),
    ("qwinsta.exe", "Query RDP sessions", "T1049"),
    ("expand.exe", "Expand files", "T1140"),
    ("esentutl.exe", "ESE database tool — file copy bypass", "T1003.003"),
    ("vssadmin.exe", "Volume Shadow Copy admin", "T1490"),
    ("wbadmin.exe", "Backup admin — backup deletion", "T1490"),
    ("bcdedit.exe", "Boot config — disable safe mode", "T1490"),
    ("fsutil.exe", "File system utility", "T1485"),
    ("icacls.exe", "ACL management", "T1222.001"),
    ("takeown.exe", "Take file ownership", "T1222.001"),
    ("xcopy.exe", "File copy", "T1570"),
    ("robocopy.exe", "Robust file copy — data exfil", "T1570"),
    ("curl.exe", "URL transfer — download", "T1105"),
    ("python.exe", "Python interpreter", "T1059.006"),
    ("pythonw.exe", "Python no window", "T1059.006"),
    ("wsl.exe", "Windows Subsystem for Linux", "T1202"),
];

fn detect_lolbin_execution(
    &self,
    execution_records: &[ExecutionRecord]
) -> Vec<ArtifactRecord> {
    execution_records.iter()
        .filter(|r| {
            let name = r.executable_name.to_lowercase();
            LOLBINS.iter().any(|(lol, _, _)| 
                name.ends_with(lol))
        })
        .map(|r| {
            let (_, desc, mitre) = LOLBINS.iter()
                .find(|(lol, _, _)| 
                    r.executable_name.to_lowercase().ends_with(lol))
                .unwrap();
                
            ArtifactRecord {
                category: ArtifactCategory::ExecutionHistory,
                subcategory: "LOLBIN Execution".to_string(),
                timestamp: r.last_executed,
                title: format!("LOLBIN: {}", r.executable_name),
                detail: format!(
                    "{} — run {} time(s), last: {:?}. {}",
                    r.executable_name,
                    r.run_count,
                    r.last_executed,
                    desc
                ),
                source_path: r.path.clone(),
                forensic_value: ForensicValue::Critical,
                mitre_technique: Some(mitre.to_string()),
                is_suspicious: true,
                raw_data: None,
            }
        })
        .collect()
}
```

### 4.4 — Execution Correlation Engine

```rust
fn correlate_executions(
    &self,
    prefetch: &[PrefetchRecord],
    amcache: &[AmCacheRecord],
    shimcache: &[ShimCacheRecord],
    userassist: &[UserAssistRecord],
    srum: &[SrumRecord],
) -> Vec<ArtifactRecord> {
    // For each executable found in 2+ sources:
    //   Cross-reference timestamps
    //   Higher confidence when multiple sources agree
    //   Flag if only in AmCache (ran once, file deleted)
    //   Flag if in Prefetch but not AmCache (may be portable)
    
    // Confidence scoring:
    //   Prefetch only:            0.7 (likely executed)
    //   AmCache only:             0.5 (present, maybe executed)
    //   Prefetch + AmCache:       0.9 (definitely executed)
    //   Prefetch + SRUM:          0.95 (executed + network activity)
    //   All 4 sources:            0.99 (definitely executed)
    
    // Return one ArtifactRecord per unique executable
    // with sources array and confidence score
}
```

### 4.5 — Trace UI Results

```
Trace v0.3.0  [ANALYZE EXECUTIONS] [DEEP SCAN]
Status: ✓ Completed
  → 89 programs in Prefetch
  → 1,247 entries in AmCache
  → 847 entries in ShimCache  
  → 4,231 UserAssist executions
  → 23 LOLBIN executions detected ⚠
  → 8 executables ran and were deleted ⚠
  → 3 suspicious execution chains ⚠

⚠ CRITICAL: certutil.exe, mshta.exe, bitsadmin.exe detected

[View Results →]  [Export CSV]
```

---

## ARTIFACTS PANEL POPULATION

When each plugin runs it populates specific categories.
Here's the complete mapping:

```
REMNANT populates:
  Deleted & Recovered → carved files by type
  Execution History   → carved executables
  Media               → carved images/video/audio
  Encryption Key Material → carved certs/keys

CHRONICLE populates:
  User Activity       → Prefetch, LNK, Jump Lists, UserAssist
  System Activity     → EVTX high-value events, Services
  Web Activity        → Browser history
  Execution History   → Correlated execution timeline
  Communications      → Email artifacts if found

CIPHER populates:
  Accounts & Credentials → Browser passwords, WiFi, SSH
  Encryption Key Material → Containers, keys, certs
  Communications      → Encrypted messaging artifacts

TRACE populates:
  Execution History   → AmCache, ShimCache, LOLBIN detection
  System Activity     → Scheduled tasks, services, drivers
  User Activity       → UserAssist execution counts
```

---

## PLUGIN MANIFEST FILES

Create for each plugin:

```toml
# strata-plugin-remnant.toml
[plugin]
name = "strata-plugin-remnant"
version = "0.3.0"
description = "Deep file carving and deleted artifact recovery"
author = "Wolfmark Systems"
color = "#818cf8"
icon = "remnant"
capabilities = ["carve", "recover", "enrich"]
min_strata_version = "0.3.0"

# strata-plugin-chronicle.toml  
[plugin]
name = "strata-plugin-chronicle"
version = "0.3.0"
description = "Timeline enrichment from all artifact sources"
author = "Wolfmark Systems"
color = "#fbbf24"
icon = "chronicle"
capabilities = ["timeline", "correlate", "enrich"]
min_strata_version = "0.3.0"

# strata-plugin-cipher.toml
[plugin]
name = "strata-plugin-cipher"
version = "0.3.0"
description = "Encryption analysis and credential extraction"
author = "Wolfmark Systems"
color = "#f43f5e"
icon = "cipher"
capabilities = ["decrypt_meta", "credentials", "entropy"]
min_strata_version = "0.3.0"

# strata-plugin-trace.toml
[plugin]
name = "strata-plugin-trace"
version = "0.3.0"
description = "Execution tracking and process forensics"
author = "Wolfmark Systems"
color = "#4ade80"
icon = "trace"
capabilities = ["execution", "lolbin", "correlate"]
min_strata_version = "0.3.0"
```

---

## PLUGIN UI IMPROVEMENTS

### Plugin Panel Layout

Each plugin card should show:

```
┌─────────────────────────────────────────────────────────┐
│  ⬡ REMNANT  v0.3.0           [RUN ON EVIDENCE] [RUN ON SELECTION] │
│  Deep file carving and deleted artifact recovery        │
│  Author: Wolfmark Systems  Type: Carver  Status: INTEGRATED │
│  ─────────────────────────────────────────────────────  │
│  Capabilities: File Carving · Deleted Recovery          │
│  ─────────────────────────────────────────────────────  │
│  Last run: Never                                        │
│  ─────────────────────────────────────────────────────  │
│  Results: Not yet run                                   │
└─────────────────────────────────────────────────────────┘
```

After running:

```
┌─────────────────────────────────────────────────────────┐
│  ⬡ REMNANT  v0.3.0        ✓ COMPLETE    [RE-RUN] [EXPORT CSV] │
│  ─────────────────────────────────────────────────────  │
│  Last run: 2026-04-03 18:33:22 UTC  Duration: 4m 12s    │
│  ─────────────────────────────────────────────────────  │
│  Results:                                               │
│    234 files carved total                               │
│    ⚠ 12 executables (CRITICAL)                          │
│    ⚠  8 databases (CRITICAL)                            │
│       45 documents (HIGH)                               │
│      169 media files (MEDIUM)                           │
│  ─────────────────────────────────────────────────────  │
│  [View in Artifacts Panel →]                            │
└─────────────────────────────────────────────────────────┘
```

---

## CONSTRAINTS

```
All plugins:
  NEVER modify evidence — read only
  NEVER write to system drive
  NEVER write outside context.output_path
  All output to evidence drive only
  All operations logged to audit trail
  All errors non-fatal — log warning, continue
  Progress reporting required — no silent hangs
  Timeout: 30 minutes max per plugin
  
Court-defensibility:
  Every artifact record has source_path
  Every artifact record has timestamp where available
  MITRE technique where applicable
  Confidence indicators where relevant
  Encrypted values noted as encrypted (not guessed)

Build:
  cargo check --workspace
  cargo test --workspace  
  cargo clippy --workspace -- -D warnings
  All must pass clean
```

---

## DELIVERABLES

1. Plugin trait infrastructure (if not already present)
2. Remnant v0.3.0 — 60+ signatures, carving engine
3. Chronicle v0.3.0 — 14 artifact sources, timeline building
4. Cipher v0.3.0 — credentials, encryption, SSH analysis
5. Trace v0.3.0 — AmCache, ShimCache, LOLBIN detection
6. All 4 plugins populate Artifacts panel categories
7. Plugin manifest files updated to v0.3.0
8. Plugin UI shows results after execution
9. All plugin output goes to evidence drive only
10. All plugin actions logged to audit trail

Report for each plugin:
  Files created/modified
  Artifact types now detected
  Categories populated in Artifacts panel
  Test results

---

*Wolfmark Systems — Strata Forensic Platform*
*Plugin System v0.3.0*
*Remnant · Chronicle · Cipher · Trace*
*April 2026*
