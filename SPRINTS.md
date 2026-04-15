# SPRINTS.md — STRATA AUTONOMOUS BUILD QUEUE
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md and SPRINTS.md. Execute all incomplete sprints in order.
#         For each sprint: implement, test, commit, then move to the next."
# Last updated: 2026-04-14
# Completed: W-1 through W-9, Pulse fix, Sentinel, M-1 through M-3

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
- M-2 FSEvents — in progress
- M-3 TCC Database — commit 7a2cbba

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
