# SPRINTS.md — STRATA AUTONOMOUS BUILD QUEUE
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md and SPRINTS.md. Execute all incomplete sprints in order.
#         For each sprint: implement, test, commit, then move to the next."
# Last updated: 2026-04-14
# Completed: W-1 through W-9, Pulse fix, Sentinel, M-1 through M-6

# LEGAL NOTICE — READ BEFORE IMPLEMENTING ANY SPRINT:
# Several open-source tools were studied as research references for these specs.
# Their architectures and approaches informed our designs.
# WE DO NOT COPY OR INCORPORATE ANY EXTERNAL CODE.
# Every implementation in this file is written independently from scratch.
#
# Reference tools and their licenses:
#   MIT (free to study, must not copy verbatim):
#     evtx (omerbenamram), dfir-toolkit (dfir-dd), zff-rs, searchlight,
#     masstin, chromium_ripper, par-hash, malwaredb-rs, yoink, chat4n6
#   GPL-3.0 (study architecture only — NEVER incorporate into Strata):
#     chainsaw, tau-engine, Aralez, 4n6mount, ext4fs-forensic, memory-forensic
#
# Strata is proprietary commercial software. GPL code cannot be linked,
# incorporated, or derived from under any circumstances.

---

## HOW TO EXECUTE

Read CLAUDE.md first. Then execute each sprint below in order.
For each sprint:
1. Implement exactly as specified
2. Run `cargo test` — all tests must pass
3. Run `cargo clippy -- -D warnings` — must be clean
4. Verify zero `.unwrap()`, zero `unsafe{}`, zero `println!`
5. Commit with message: "feat: [sprint-id] [artifact name]"
6. Move to next sprint immediately

If a sprint is marked COMPLETE — skip it.
If blocked on a crate — implement manually, document why in a comment.

---

## RESUME INSTRUCTIONS

If this session was interrupted by a rate limit:
1. Run: git log --oneline -5
2. Find the last completed sprint commit
3. Mark that sprint COMPLETE in this file
4. Continue from the next incomplete sprint
5. Do not re-implement anything already committed

## COMPLETED SPRINTS (skip these)

- W-1 ShimCache/AppCompatCache — commit 956d1b4
- W-2 Prefetch Deep Parser — commit 73bb8e4
- W-3 EVTX Structured Output — commit ad20832
- Pulse borrow fix + Sentinel scaffold — commit 6bec0b3
- W-4 AmCache Manual — commit 31e3cd1
- W-5 USB Device Chain — commit 4cc940c
- W-6 MRU Keys — commit 39a2665
- W-7 Zone.Identifier ADS — commit 08fcfcc
- W-8 Thumbcache — commit 0c44268
- W-9 Registry Transaction Logs — commit fd0bb17
- M-1 Biome Parser — commit 32cd3a1
- M-2 FSEvents — commit 62ff603
- M-3 TCC Database — commit 7a2cbba
- M-4 KnowledgeC Database — commit 76110be
- M-5 Unified Logs Parser — commit 76110be
- M-6 plist Artifacts — commit 76110be
- M-7 Modern macOS Artifacts (13-26) — commit b4d46cb
- X-1 FOR572 DNS/IDS Improvements — commit 51e3a84
- X-2 Windows Search Index (ESE) — commit c06ad76
- A-1 Timeline SQLite Layer — commit 53669c9
- A-2 Global IOC Search — commit e0bdc63
- MOB-1 iOS Biome Parser — this commit

---

## SPRINT M-4 — KnowledgeC Database

Create `plugins/strata-plugin-mactrace/src/knowledgec.rs`.

Parse the macOS KnowledgeC database — primary user activity store for macOS 10.x
through macOS 12. Superseded by Biome on macOS 13+.

Location: `/private/var/db/CoreDuet/Knowledge/knowledgeC.db`
Format: SQLite. Use `rusqlite` (already in Cargo.toml).

Table: `ZOBJECT`
Key columns:
- ZSTREAMNAME (TEXT) — stream type identifier
- ZSTARTDATE (REAL) — CoreData epoch (seconds since 2001-01-01 UTC)
- ZENDDATE (REAL) — CoreData epoch
- ZVALUEINTEGER (INTEGER nullable)
- ZVALUESTRING (TEXT nullable)
- ZVALUEDOUBLE (REAL nullable)
- ZDEVICEID (TEXT nullable)

CoreData epoch conversion: Unix timestamp = CoreData + 978_307_200

Parse these stream names:
- `/app/inFocus` — bundle_id from ZVALUESTRING
- `/app/webUsage` — url from ZVALUESTRING
- `/device/isLocked` — locked bool from ZVALUEINTEGER (1=locked)
- `/safari/history` — url from ZVALUESTRING
- `/user/appSession` — bundle_id from ZVALUESTRING, duration = ZENDDATE-ZSTARTDATE
- `/display/isBacklit` — backlit bool from ZVALUEINTEGER

Typed struct `KnowledgeCRecord`:
```rust
/// A single record from the KnowledgeC CoreDuet database.
/// NOTE: KnowledgeC is the primary user activity store on macOS 10.x-12.x.
/// On macOS 13+ (Ventura and later), Apple replaced most KnowledgeC streams
/// with Biome — parse Biome for modern systems.
pub struct KnowledgeCRecord {
    /// Stream identifier e.g. /app/inFocus, /safari/history
    pub stream_name: String,
    /// Activity start time (CoreData epoch converted to UTC)
    pub start_time: DateTime<Utc>,
    /// Activity end time — None when event has no duration
    pub end_time: Option<DateTime<Utc>>,
    /// App bundle identifier e.g. com.apple.Safari
    pub bundle_id: Option<String>,
    /// URL for web-related streams
    pub url: Option<String>,
    /// Integer value — meaning depends on stream type
    pub value_integer: Option<i64>,
    /// Device identifier for cross-device sync records
    pub device_id: Option<String>,
}
```

Emit `Artifact::new("KnowledgeC Record", path_str)` per row.
MITRE: T1217 for web/safari streams, T1059 for app focus, T1083 for others.
forensic_value: High.

Wire into MacTrace `run()` when filename is `knowledgeC.db`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT M-5 — Unified Logs Parser

Create `plugins/strata-plugin-mactrace/src/unified_logs.rs`.

Parse Apple Unified Logging System files.
Location: `/private/var/db/diagnostics/` — `.tracev3` binary files.

Evaluate the `macos-unifiedlogs` crate (github.com/mandiant/macos-unifiedlogs).
If it is in Cargo.toml already — use it.
If not — add it as a dependency with `macos-unifiedlogs = "0.1"` and implement.
If the crate is unavailable — implement a minimal reader that extracts:
  timestamp, process name, pid, subsystem, category, message string.

Key forensic queries to surface as high-value artifacts:
- process == "sudo" — privilege escalation
- process == "SecurityAgent" — authentication events
- subsystem == "com.apple.securityd" — security daemon
- eventMessage contains "authentication" — auth events
- process == "sshd" — remote access
- process == "screensharingd" — screen sharing
- subsystem == "com.apple.ManagedClient" — MDM activity

Typed struct `UnifiedLogEntry`:
```rust
pub struct UnifiedLogEntry {
    /// Event timestamp in UTC
    pub timestamp: DateTime<Utc>,
    /// Process name that generated the log
    pub process: String,
    /// Process ID
    pub pid: u32,
    /// Apple subsystem identifier e.g. com.apple.securityd
    pub subsystem: Option<String>,
    /// Log category within the subsystem
    pub category: Option<String>,
    /// Human-readable log message
    pub message: String,
    /// Log level: Default/Info/Debug/Error/Fault
    pub log_level: String,
}
```

Emit `Artifact::new("Unified Log Entry", path_str)` only for forensically
significant entries (sudo, SecurityAgent, sshd, screensharingd, authentication).
Do not emit every log line — too noisy.

MITRE: T1548.003 for sudo, T1078 for auth events, T1021.004 for sshd,
T1021.005 for screensharingd.
forensic_value: High for privilege/auth events, Medium for others.

Wire into MacTrace `run()` when filename ends with `.tracev3`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT M-6 — plist Artifact Parser

Create `plugins/strata-plugin-mactrace/src/plist_artifacts.rs`.

Parse high-value macOS property list artifacts.
Use `plist` crate (already in Cargo.toml).

Parse these specific plist files by filename/path match:

### Recent Items
Path match: `com.apple.recentitems.plist`
Fields: recent_documents (Vec<String> — file paths), recent_applications
(Vec<String> — bundle IDs), recent_servers (Vec<String> — server URLs)
MITRE: T1074.001

### Login Items
Path match: `com.apple.loginitems.plist` or `LoginItems.plist`
Fields: item_name (String), item_path (String), item_kind (String),
hidden (bool)
MITRE: T1547.011

### Quarantine Events
Path match: `com.apple.LaunchServices.QuarantineEventsV2`
Format: SQLite (use rusqlite)
Table: LSQuarantineEvent
Fields: quarantine_timestamp (REAL CoreData epoch), quarantine_agent_name
(TEXT), quarantine_data_url (TEXT), quarantine_origin_url (TEXT),
quarantine_origin_title (TEXT)
MITRE: T1566, T1105
forensic_value: High — shows download origin

### Sidebar Lists (mounted volumes history)
Path match: `sidebarlists.plist`
Fields: volume_name (String), volume_path (String)
MITRE: T1052.001
forensic_value: High — historical USB/network volume connections

### Dock Items
Path match: `com.apple.dock.plist`
Fields: app_name (String), app_path (String), tile_type (String)
MITRE: T1547.011

Typed struct `PlistArtifact`:
```rust
pub struct PlistArtifact {
    /// Type of plist artifact
    pub artifact_type: PlistArtifactType,
    /// Human readable name of the item
    pub name: String,
    /// Path, URL, or identifier value
    pub value: String,
    /// Additional metadata (hidden, kind, etc.)
    pub metadata: Option<String>,
    /// Timestamp when available
    pub timestamp: Option<DateTime<Utc>>,
}
```

Emit `Artifact::new("Plist Artifact", path_str)` per item.
Wire into MacTrace `run()` by filename match.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT M-7 — Modern macOS Artifacts (13-26)

Create `plugins/strata-plugin-mactrace/src/modern_macos.rs`.

Parse artifacts specific to macOS Ventura (13) through Tahoe (26).

### Background Task Management (macOS 13+)
Location: `/Library/Application Support/com.apple.backgroundtaskmanagementd/`
Format: SQLite — `BackgroundItems-v8.db`
Table: `BTMEntry`
Fields: app_identifier (TEXT), app_path (TEXT), developer_name (TEXT),
is_legacy (INTEGER bool), user_approved (INTEGER bool),
created_at (INTEGER Unix timestamp)
MITRE: T1547.011 — persistence via background task
forensic_value: High for non-Apple unapproved entries

### Screen Time Database (macOS 12+)
Location: `~/Library/Application Support/com.apple.ScreenTime/RMAdminStore-Local.sqlite`
Table: `ZUSAGETIMEDITEM`
Fields: ZBUNDLEID (TEXT), ZTOTALTIME (REAL seconds), ZDATE (REAL CoreData epoch)
MITRE: T1059 — app usage evidence
forensic_value: Medium

### Install History
Location: `/Library/Receipts/InstallHistory.plist`
Format: plist array
Fields: displayName (String), displayVersion (String),
date (DateTime from plist Date type), packageIdentifier (String),
processName (String)
MITRE: T1072 — software deployment
forensic_value: Medium — shows what was installed and when

### Network Usage (netusage.sqlite)
Location: `/private/var/networkd/db/netusage.sqlite`
Table: `PLProcessNetStats`
Fields: pBaseName (TEXT — process name), wifiIn (INTEGER bytes),
wifiOut (INTEGER bytes), wiredIn (INTEGER bytes), wiredOut (INTEGER bytes),
ztimestamp (INTEGER Unix)
MITRE: T1071 — application layer protocol
forensic_value: High for unexpected high-bandwidth processes

Typed structs for each artifact type, every field doc-commented.
Emit appropriate `Artifact::new()` per record.
Wire into MacTrace `run()` by filename/path match.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT X-1 — FOR572 DNS/IDS Improvements

Improve `plugins/strata-plugin-netflow/src/` DNS and IDS parsing.

### DNS Log Parser improvements
Support these DNS log formats:
- BIND named query log: `client @0x... 1.2.3.4#port (domain): query: domain IN A +`
- Windows DNS debug log: `1/1/2026 12:00:00 PM 0A00 PACKET ... RCVD UDP...`
- macOS mDNSResponder: from Unified Logs (integrate with M-5 output)

Fields: timestamp, client_ip, query_name, query_type, response_code,
response_ip (Vec<String>), log_format (enum: BIND/WindowsDNS/MDNSResponder)
MITRE: T1071.004

### Snort/Suricata IDS Alert Parser
Parse Snort alert files (fast alert format):
`[**] [1:2001:1] ET SCAN ... [**] [Classification: ...] [Priority: 1] {TCP} 1.2.3.4:port -> 5.6.7.8:port`

Parse Suricata eve.json format (JSON per line):
Fields: timestamp, event_type, src_ip, src_port, dst_ip, dst_port,
proto, alert.signature, alert.category, alert.severity, alert.rule_id

Typed structs for each format.
Emit `Artifact::new("DNS Query", path_str)` and `Artifact::new("IDS Alert", path_str)`.
MITRE: T1071.004 for DNS, per-rule for IDS.
Wire into Netflow `run()` by filename pattern.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT X-2 — Windows Search Index (ESE Database)

Create `plugins/strata-plugin-phantom/src/windows_search.rs`.

Parse Windows Search Index database.
Location: `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`
Format: Extensible Storage Engine (ESE/JET Blue) database.

NOTE: `frnsc-esedb` is unpublished on crates.io. Do NOT attempt to use it.
Evaluate `libesedb` Rust bindings — if unavailable, implement a minimal
ESE reader that can:
1. Open the ESE file and validate the header magic (`\xef\xcd\xab\x89` at offset 4)
2. Read the catalog table to enumerate data tables
3. Extract records from `SystemIndex_0A` table (primary search index)

Key fields from SystemIndex_0A:
- System_ItemName (text) — filename
- System_ItemPathDisplay (text) — full path
- System_DateModified (integer — Windows FILETIME)
- System_Size (integer — bytes)
- System_Author (text nullable)
- System_Keywords (text nullable)
- System_ItemUrl (text nullable)

If full ESE parsing is not feasible without the crate, implement a
string-carving fallback that extracts UTF-16LE path strings from the
raw database bytes with a minimum length of 10 characters and path-like
structure (contains `\` or `/`).

Document clearly in comments which approach was used and why.

Emit `Artifact::new("Search Index Entry", path_str)` per record.
MITRE: T1083 — file and directory discovery.
forensic_value: Medium — indexed file confirms user awareness of file.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT A-1 — Timeline SQLite Layer

Create `crates/strata-core/src/timeline/mod.rs` and
`crates/strata-core/src/timeline/database.rs`.

Implement a unified timeline database that aggregates artifacts across
all plugins into a single queryable SQLite store.

Schema:
```sql
CREATE TABLE IF NOT EXISTS timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_us INTEGER NOT NULL,  -- Unix microseconds
    artifact_type TEXT NOT NULL,
    plugin TEXT NOT NULL,
    description TEXT NOT NULL,
    raw_data TEXT,                  -- JSON serialized artifact fields
    mitre_technique TEXT,
    confidence REAL DEFAULT 1.0,
    source_file TEXT,
    suspicious INTEGER DEFAULT 0    -- bool
);

CREATE INDEX IF NOT EXISTS idx_timeline_timestamp
    ON timeline(timestamp_us);

CREATE INDEX IF NOT EXISTS idx_timeline_artifact_type
    ON timeline(artifact_type);

CREATE INDEX IF NOT EXISTS idx_timeline_mitre
    ON timeline(mitre_technique);

CREATE VIRTUAL TABLE IF NOT EXISTS timeline_fts
    USING fts5(description, raw_data, content=timeline, content_rowid=id);
```

Public API:
```rust
pub struct TimelineDatabase {
    conn: rusqlite::Connection,
}

impl TimelineDatabase {
    /// Open or create a timeline database at the given path.
    pub fn open(path: &Path) -> Result<Self, TimelineError>;

    /// Insert an artifact into the timeline.
    pub fn insert(&mut self, artifact: &Artifact, plugin: &str)
        -> Result<i64, TimelineError>;

    /// Insert all artifacts from a plugin run.
    pub fn insert_all(&mut self, artifacts: &[Artifact], plugin: &str)
        -> Result<usize, TimelineError>;

    /// Query timeline by time range (Unix microseconds).
    pub fn query_range(&self, start_us: i64, end_us: i64)
        -> Result<Vec<TimelineEntry>, TimelineError>;

    /// Full-text search across description and raw_data.
    pub fn search(&self, query: &str)
        -> Result<Vec<TimelineEntry>, TimelineError>;

    /// Query by MITRE technique.
    pub fn query_mitre(&self, technique: &str)
        -> Result<Vec<TimelineEntry>, TimelineError>;
}
```

Register in `crates/strata-core/src/lib.rs`.
Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT A-2 — Global IOC Search

Create `crates/strata-core/src/ioc/search.rs`.

Implement global Indicator of Compromise search across all artifact results.

IOC types to detect:
```rust
pub enum IocType {
    IpAddress,
    Domain,
    FileHash(HashType),  // MD5, SHA1, SHA256
    FilePath,
    RegistryKey,
    Url,
    EmailAddress,
    Username,
}
```

Search functionality:
```rust
pub struct IocSearcher {
    indicators: Vec<Ioc>,
}

pub struct Ioc {
    pub ioc_type: IocType,
    pub value: String,
    pub source: String,        // where this IOC came from
    pub confidence: f32,
    pub mitre_technique: Option<String>,
}

impl IocSearcher {
    /// Load IOCs from a flat text file (one per line).
    pub fn load_from_file(path: &Path) -> Result<Self, IocError>;

    /// Search all artifact fields for IOC matches.
    pub fn search(&self, artifacts: &[Artifact]) -> Vec<IocMatch>;

    /// Extract IOCs from artifact fields (reverse — find IOCs in evidence).
    pub fn extract_from_artifacts(artifacts: &[Artifact]) -> Vec<Ioc>;
}
```

Pattern detection using regex (use `regex` crate — check if in Cargo.toml):
- IPv4: `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
- Domain: `\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+\b`
- SHA256: `\b[0-9a-fA-F]{64}\b`
- SHA1: `\b[0-9a-fA-F]{40}\b`
- MD5: `\b[0-9a-fA-F]{32}\b`
- Email: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`
- URL: `https?://[^\s<>"{}|\\^[\]]+`

Register in `crates/strata-core/src/ioc/mod.rs`.
Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT MOB-1 — iOS Biome Parser

Create `plugins/strata-plugin-mactrace/src/ios_biome.rs`.

iOS Biome uses the same SEGB/protobuf format as macOS Biome (M-1).
Reuse the SEGB container parser and protobuf decoder from `biome.rs`.

iOS-specific locations:
- `/private/var/mobile/Library/Biome/` — user biome
- `/private/var/db/biome/` — system biome

iOS-specific stream types:
- `streams/app/inFocus` — foreground app
- `streams/device/locked` — screen lock
- `streams/safariHistory` — Safari
- `streams/photos/assetAdded` — photo captured: asset_id (string field 1), timestamp (fixed64 field 3)
- `streams/messaging/sent` — iMessage sent: recipient (string field 1), timestamp (fixed64 field 3)
- `streams/location/significant` — location: latitude (double field 1), longitude (double field 2), timestamp (fixed64 field 3)

Location stream is HIGH forensic value — MITRE T1430.

Typed struct `IosBiomeRecord` extending/mirroring `BiomeRecord` with:
- `latitude: Option<f64>`
- `longitude: Option<f64>`
- `photo_asset_id: Option<String>`
- `message_recipient: Option<String>`

Emit `Artifact::new("iOS Biome Record", path_str)`.
MITRE: T1430 for location, T1636.002 for messages, T1217 for Safari.
forensic_value: High for location and messaging.

Wire into MacTrace `run()` when path contains `mobile/Library/Biome` or
`var/db/biome` and platform is detected as iOS (check for
`/private/var/mobile/` path prefix).

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT MOB-2 — iOS KnowledgeC

Create `plugins/strata-plugin-mactrace/src/ios_knowledgec.rs`.

iOS KnowledgeC shares schema with macOS KnowledgeC (M-4) but with
iOS-specific stream names.

Location: `/private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db`
Format: SQLite.

iOS-specific stream names to parse:
- `/app/inFocus` — foreground app
- `/device/isPluggedIn` — charging state (bool from ZVALUEINTEGER)
- `/device/batteryPercentage` — battery level (ZVALUEDOUBLE 0.0-1.0)
- `/media/nowPlaying` — media playing (title from ZVALUESTRING)
- `/safariHistory` — Safari browsing (url from ZVALUESTRING)
- `/com.apple.messages.count` — message activity (count from ZVALUEINTEGER)
- `/location/significant` — significant location changes

Reuse CoreData epoch conversion from M-4.

Typed struct `IosKnowledgeCRecord` — doc-comment noting deprecated on iOS 16+
where Biome supersedes this database.

Emit `Artifact::new("iOS KnowledgeC Record", path_str)`.
Wire into MacTrace `run()` when path contains `mobile/Library/CoreDuet`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT MOB-3 — iMessage Parser Enhancement

Enhance the existing iMessage parser in the appropriate plugin.
Location: `~/Library/Messages/chat.db` (macOS)
          `/private/var/mobile/Library/SMS/sms.db` (iOS)

Current coverage: verify what exists. If already parsing — extend with:

Additional fields to extract from `message` table:
- `attributedBody` (BLOB) — decode NSAttributedString to get actual
  message text when `text` column is NULL (common in iOS 16+)
- `thread_originator_guid` — conversation thread tracking
- `associated_message_guid` — tapback/reaction tracking
- `expressive_send_style_id` — message effect (slam, loud, etc.)
- `was_downgraded` (INTEGER bool) — iMessage→SMS fallback indicator

From `attachment` table:
- `transfer_name` — original filename
- `mime_type` — attachment type
- `total_bytes` — size
- `is_sticker` — sticker vs real attachment

MITRE: T1636.002 (contact list access via messages),
T1530 for cloud-synced attachments.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT AGENT-1 — code-reviewer.md

Create `.claude/code-reviewer.md`.

This is a skill file for Claude Code — loaded when reviewing Strata code.

Content must cover:
- Forensic parser review checklist:
  * All timestamp fields use correct epoch (FILETIME, CoreData, Unix)
  * FILETIME conversion uses checked arithmetic (no overflow)
  * All binary reads are bounds-checked
  * Artifact category is set correctly per plugin domain
  * MITRE technique is present on every emitted artifact
  * forensic_value field is set (High/Medium/Low)
  * source field traces back to the original evidence file
  * doc comments explain forensic significance, not just field type
- Strata-specific anti-patterns to flag:
  * `.unwrap()` on any Result or Option
  * `unsafe {}` blocks
  * `println!` instead of `log::debug!`/`log::warn!`
  * Adding dependencies not already in Cargo.toml
  * Touching files outside the sprint scope
  * Removing or modifying existing tests
  * Plugin routing a file type already owned by another plugin
- Load-bearing tests — never remove:
  * build_lines_includes_no_image_payload
  * hash_recipe_byte_compat_with_strata_tree
  * rule_28_does_not_fire_with_no_csam_hits
  * advisory_notice_present_in_all_findings
  * is_advisory_always_true (strata-ml-anomaly)
  * advisory_notice_always_present_in_output
  * examiner_approved_defaults_to_false
  * summary_status_defaults_to_draft
  * is_advisory_always_true (strata-ml-charges)

---

## SPRINT AGENT-2 — security-reviewer.md

Create `.claude/security-reviewer.md`.

Skill file for security-sensitive code review in Strata.

Content must cover:
- CSAM module rules (always in effect):
  * Never log hash values that match CSAM hashes
  * Advisory notice must always be present in findings output
  * examiner_approved must default to false
  * CSAM results must never auto-submit anywhere
- Evidence integrity rules:
  * Parsers must never modify input bytes
  * All reads must be read-only (no write operations on evidence)
  * Hash verification must use constant-time comparison
- Chain of custody rules:
  * Source file path must always be recorded in artifact.source
  * Timestamps must preserve original timezone info where available
  * Never truncate or normalize paths that would change meaning
- NemoClaw sandbox awareness:
  * Sandbox: wolfmarksystems
  * Security: Landlock + seccomp + netns
  * Agents run in isolated containers
  * Cannot access evidence data or keys outside sandbox

---

## SPRINT AGENT-3 — tdd-guide.md

Create `.claude/tdd-guide.md`.

Skill file for test-driven development in Strata forensic parsers.

Content must cover:
- Minimum test requirements per parser:
  * Test 1: Valid known-good fixture — verify field values exactly
  * Test 2: Empty/zero-byte input — must return None or empty Vec, not panic
  * Test 3: Corrupt/truncated input — must return None or partial, not panic
  * Additional: One test per Windows version variant (for Windows artifacts)
  * Additional: One test per format version (for versioned formats)
- Fixture guidelines:
  * Fixtures must be minimal — smallest valid input that exercises the parser
  * Binary fixtures embedded as `&[u8]` constants in test modules
  * No `.unwrap()` in test code — use `assert!(result.is_some())`
  * Timestamp fixtures must use known values with verified UTC output
- Test naming convention:
  * `test_parse_[artifact]_valid` — happy path
  * `test_parse_[artifact]_empty` — empty input
  * `test_parse_[artifact]_corrupt` — corrupt input
  * `test_parse_[artifact]_[variant]` — version/format variants
- Performance: parsers processing >10MB fixtures should complete in <5s

---

*STRATA AUTONOMOUS BUILD QUEUE*
*Wolfmark Systems — 2026-04-14*
*Execute all incomplete sprints in order. Ship everything.*

---

## SPRINT R-1 — LNK File Parser (informed by dfir-toolkit lnk2bodyfile)
# Reference: dfir-toolkit/lnk2bodyfile (MIT) — study approach, implement independently

Create `plugins/strata-plugin-phantom/src/lnk.rs`.

Parse Windows LNK (Shell Link) shortcut files.
Location: `%AppData%\Microsoft\Windows\Recent\*.lnk`
          `%AppData%\Microsoft\Office\Recent\*.lnk`
Format: Binary — MS-SHLLINK specification

Key fields to extract:
- target_path: String (the file/folder the LNK points to)
- working_directory: Option<String>
- arguments: Option<String>
- target_created: Option<DateTime<Utc>> (FILETIME)
- target_modified: Option<DateTime<Utc>> (FILETIME)
- target_accessed: Option<DateTime<Utc>> (FILETIME)
- target_size: u64
- drive_type: String (Fixed, Removable, Network, etc.)
- drive_serial: Option<String>
- volume_label: Option<String>
- machine_id: Option<String> (NetBIOS name of origin machine)
- droid_volume_id: Option<String> (GUID)
- droid_file_id: Option<String> (GUID — tracks file across renames)

LNK header magic: `4C 00 00 00` at offset 0
GUID at offset 4: `01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46`

Typed struct `LnkFile` every field doc-commented with forensic meaning.
Note in doc: machine_id reveals origin machine even when file is moved.
Note in doc: droid_file_id can track files across volume changes.

Emit `Artifact::new("LNK File", path_str)` per file.
MITRE: T1547.009 (shortcut modification), T1070.006 (indicator removal).
forensic_value: High — reveals target file existence even after deletion.
suspicious=true when target_path points to temp/appdata/downloads.

Wire into Phantom `run()` when filename ends `.lnk` case-insensitive.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT R-2 — Chromium Browser Artifacts (informed by chromium_ripper)
# Reference: chromium_ripper (MIT) — study approach, implement independently

Enhance `plugins/strata-plugin-carbon/src/` with deep Chromium artifact parsing.
Applies to: Chrome, Edge, Brave, Opera, Vivaldi (all Chromium-based).

Profile location pattern: `*/Google/Chrome/User Data/*/`
                          `*/Microsoft/Edge/User Data/*/`
                          `*/BraveSoftware/Brave-Browser/User Data/*/`

Parse these SQLite databases:

### History (History file — no extension)
Tables: urls, visits, downloads, keyword_search_terms
Fields from urls: url, title, visit_count, last_visit_time (WebKit epoch)
Fields from downloads: target_path, start_time, end_time, total_bytes,
                       danger_type, tab_url, tab_referrer_url
Fields from keyword_search_terms: term (search query), url_id

### Login Data (Login Data file)
Table: logins
Fields: origin_url, username_value, date_created, date_last_used,
        times_used
NOTE: password_value is encrypted — do NOT attempt decryption.
      Record presence and metadata only.

### Web Data (Web Data file)
Table: autofill
Fields: name, value, date_created, date_last_used, count

### Favicons (Favicons file)
Table: icon_mapping
Fields: page_url — confirms URLs visited even if history cleared

### Network Action Predictor
Table: network_action_predictor
Fields: user_text (typed URL prefix), url

WebKit epoch: microseconds since 1601-01-01.
Convert: Unix_us = WebKit_us - 11644473600000000

Typed structs for each artifact type, every field doc-commented.
Emit appropriate `Artifact::new()` per record.
MITRE: T1217 for history/favicons, T1555.003 for login data presence,
T1056.003 for search terms.
forensic_value: High for downloads and login data, Medium for history.

Wire into Carbon `run()` by filename match.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT R-3 — Lateral Movement Timeline (informed by masstin)
# Reference: masstin (MIT) — study approach, implement independently

Enhance `plugins/strata-plugin-sentinel/src/` with lateral movement detection.

Correlate these event IDs to build a lateral movement timeline:
- 4624 logon_type=3 (network logon) — inbound lateral movement
- 4624 logon_type=10 (RemoteInteractive/RDP) — RDP inbound
- 4648 (explicit credential logon) — pass-the-hash/pass-the-ticket indicator
- 4768/4769 (Kerberos TGT/service ticket) — Kerberos activity
- 4776 (NTLM authentication) — NTLM lateral movement
- 5140/5145 (network share access) — SMB lateral movement
- 7045 service install from remote (cross-reference with 4624 type=3 timing)

Create `plugins/strata-plugin-sentinel/src/lateral_movement.rs`.

For each detected lateral movement indicator emit:
`Artifact::new("Lateral Movement", path_str)` with fields:
- movement_type: String (RDP/SMB/Kerberos/NTLM/Service)
- source_ip: Option<String>
- target_account: String
- timestamp: DateTime<Utc>
- correlated_events: String (pipe-separated event IDs involved)
- confidence: String (High/Medium/Low)

High confidence: two or more correlated events within 60 seconds.
Medium confidence: single event of type 4648 or type=10 logon.

MITRE: T1021.001 (RDP), T1021.002 (SMB), T1550.002 (pass-the-hash),
T1558 (Kerberos).
forensic_value: High.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT R-4 — File Carving Enhancement (informed by searchlight)
# Reference: searchlight (MIT) — study approach, implement independently

Enhance `plugins/strata-plugin-recon/src/` with pattern-based file carving.

Implement header/footer signature carving for these file types:

```rust
pub struct CarveSignature {
    /// File type name
    pub file_type: &'static str,
    /// Magic bytes at file start
    pub header: &'static [u8],
    /// Magic bytes at file end (if known)
    pub footer: Option<&'static [u8]>,
    /// Maximum reasonable file size for this type
    pub max_size: usize,
    /// MIME type
    pub mime_type: &'static str,
}
```

Signatures to implement:
- JPEG: header `FF D8 FF`, footer `FF D9`
- PNG: header `89 50 4E 47 0D 0A 1A 0A`, footer `49 45 4E 44 AE 42 60 82`
- PDF: header `25 50 44 46`, footer `25 25 45 4F 46`
- ZIP/DOCX/XLSX: header `50 4B 03 04`
- RAR: header `52 61 72 21 1A 07`
- 7-ZIP: header `37 7A BC AF 27 1C`
- SQLite: header `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00`
- ELF: header `7F 45 4C 46`
- PE/EXE/DLL: header `4D 5A`
- GIF: header `47 49 46 38`
- MP4: header at offset 4: `66 74 79 70`

Sliding window approach: scan raw bytes with 4KB read buffer.
Cap carved file count at 10,000 per input file.
Cap individual carved file size at max_size.

Emit `Artifact::new("Carved File", path_str)` per carved item with:
file_type, offset (hex string), size, header_hex (first 16 bytes as hex),
mime_type, entropy (f64 — high entropy suggests encryption/compression).

MITRE: T1027 (obfuscated files), T1083 (file discovery).
forensic_value: High for PE files and SQLite, Medium for documents.
suspicious=true when PE found in non-executable location or high entropy.

Wire into Recon `run()` on raw disk image input.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT R-5 — Chat/Messaging Forensics (informed by chat4n6)
# Reference: chat4n6 (MIT) — study approach, implement independently

Create `plugins/strata-plugin-pulse/src/chat_forensics.rs`.

Parse chat artifacts from desktop messaging applications.

### Slack Desktop
Location: `%AppData%\Slack\storage\` (Windows)
          `~/Library/Application Support/Slack/` (macOS)
Files: `root-state.db` (SQLite), `C[workspace_id]-[channel_id].db`
Tables: messages — timestamp, user_id, text, attachments JSON
Emit: `Artifact::new("Slack Message", path_str)`
MITRE: T1552.003

### Microsoft Teams (Classic)
Location: `%AppData%\Microsoft\Teams\storage.db`
Table: conversations — id, creator, create_time, display_name
Table: messages — originalarrivaltime, content, messagetype
Emit: `Artifact::new("Teams Message", path_str)`
MITRE: T1552.003

### Discord Desktop
Location: `%AppData%\discord\Local Storage\leveldb\`
Format: LevelDB — parse .ldb and .log files for JSON message fragments
Extract: channel_id, message_id, content, timestamp, author_id
Emit: `Artifact::new("Discord Message", path_str)`
NOTE: Discord is already in Pulse — check existing coverage first,
      extend if needed rather than duplicate.
MITRE: T1552.003

Typed structs per platform, every field doc-commented.
forensic_value: High for all messaging artifacts.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT R-6 — Malware Hash Database Integration (informed by malwaredb-rs)
# Reference: malwaredb-rs (MIT) — study approach, implement independently

Enhance `crates/strata-core/src/hashset/` with malware hash matching.

Create `crates/strata-core/src/hashset/malware_hashset.rs`.

Support loading known-malware hash sets from:
- Plain text files: one SHA256 per line (LOKI/THOR IOC format)
- CSV files: hash,name,category columns
- MISP format: JSON array of {value, type, comment} objects

```rust
pub struct MalwareHashSet {
    /// SHA256 hashes mapped to malware name
    sha256: HashMap<[u8; 32], String>,
    /// MD5 hashes mapped to malware name  
    md5: HashMap<[u8; 16], String>,
    /// SHA1 hashes mapped to malware name
    sha1: HashMap<[u8; 20], String>,
    /// Source file for attribution
    source: String,
    /// Entry count
    count: usize,
}

impl MalwareHashSet {
    pub fn load_from_file(path: &Path) -> Result<Self, HashSetError>;
    pub fn check_sha256(&self, hash: &[u8; 32]) -> Option<&str>;
    pub fn check_md5(&self, hash: &[u8; 16]) -> Option<&str>;
    pub fn check_sha1(&self, hash: &[u8; 20]) -> Option<&str>;
}
```

When a hash match is found during any artifact parse, add to the artifact:
- `malware_match=true`
- `malware_name=<name from hashset>`
- `malware_source=<hashset source file>`
- `forensic_value=High`
- `suspicious=true`

MITRE: T1588.001 (malware acquisition).
Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT R-7 — ZFF Container Support (informed by zff-rs)
# Reference: zff-rs (MIT) — study approach, implement independently

Add ZFF forensic container format support to image acquisition/reading.
ZFF is a modern alternative to E01 — pure Rust, better compression,
designed for modern forensics workflows.

Location: `crates/strata-core/src/disk/`

ZFF file magic: `ZFF` at offset 0 (check zff-rs spec for exact bytes)

Implement minimal ZFF reader:
```rust
pub struct ZffReader {
    path: PathBuf,
    segment_count: u32,
    chunk_size: u64,
    compression: ZffCompression,
    hash_value: Option<Vec<u8>>,
    acquisition_date: Option<DateTime<Utc>>,
    examiner_name: Option<String>,
    case_number: Option<String>,
}

impl ZffReader {
    pub fn open(path: &Path) -> Result<Self, ZffError>;
    pub fn read_sector(&self, lba: u64) -> Result<Vec<u8>, ZffError>;
    pub fn metadata(&self) -> &ZffMetadata;
}
```

Expose metadata as `Artifact::new("ZFF Image Metadata", path_str)` with:
examiner_name, case_number, acquisition_date, hash_value,
compression_type, segment_count, total_size.

MITRE: N/A — acquisition format, not artifact.
forensic_value: Medium — confirms image integrity.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

*STRATA AUTONOMOUS BUILD QUEUE — Updated 2026-04-14*
*Research references: MIT-licensed tools studied for architectural inspiration.*
*All implementations are original Wolfmark Systems code.*
*GPL-referenced tools: architecture studied only, zero code incorporated.*
*Every examiner. Every artifact. Every platform. Ship it all.*
