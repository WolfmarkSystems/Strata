# SPRINTS_v2.md — STRATA AUTONOMOUS BUILD QUEUE
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md and SPRINTS_v2.md. Execute all incomplete sprints in order.
#         For each sprint: implement, test, commit, then move to the next."
# Last updated: 2026-04-16
# Prerequisite: All SPRINTS.md sprints complete (W-1 through R-7, AGENT-1 through AGENT-3)

# LEGAL NOTICE — READ BEFORE IMPLEMENTING ANY SPRINT:
# Several open-source tools were studied as research references for these specs.
# Their architectures and approaches informed our designs.
# WE DO NOT COPY OR INCORPORATE ANY EXTERNAL CODE.
# Every implementation in this file is written independently from scratch.
#
# All implementations are original Wolfmark Systems code.
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

---

## COMPLETED SPRINTS (skip these)

None yet — this is v2.

---

## SPRINT VAULT-1 — New Plugin: strata-plugin-vault

Create `plugins/strata-plugin-vault/`.

This is a new Strata plugin. Vault detects hidden storage, encryption tools,
anti-forensic applications, and data concealment artifacts across Windows,
macOS, and mobile platforms. Every examiner needs this — it is the difference
between finding what a suspect tried to hide and missing it entirely.

Scaffold the plugin following the exact same structure as existing plugins:
- `plugins/strata-plugin-vault/Cargo.toml`
- `plugins/strata-plugin-vault/src/lib.rs`
- Register in workspace `Cargo.toml`
- Wire into the plugin registry

Plugin metadata:
```rust
pub fn name() -> &'static str { "Vault" }
pub fn version() -> &'static str { "1.0.0" }
pub fn description() -> &'static str {
    "Detects hidden storage, encryption tools, anti-forensic applications, \
     and data concealment artifacts. Find what they tried to hide."
}
pub fn color() -> &'static str { "#a855f7" }  // Purple
```

Scaffold only in this sprint — implementation in VAULT-2 through VAULT-6.
Zero unwrap, zero unsafe, Clippy clean, one smoke test minimum.

---

## SPRINT VAULT-2 — VeraCrypt / TrueCrypt Artifacts

Create `plugins/strata-plugin-vault/src/veracrypt.rs`.

Detect VeraCrypt and TrueCrypt volume files and usage artifacts.

### VeraCrypt Volume Detection
VeraCrypt volumes have NO magic header by design — this is intentional deniability.
Detection approach:
- File size is an exact multiple of 512 bytes (sector aligned)
- File has no recognized file header magic in first 512 bytes
- File size >= 2MB (minimum VeraCrypt volume)
- Entropy of first 512 bytes > 7.9 (near-random = encrypted)
- Extensions to flag: `.vc`, `.hc`, `.tc`, no extension on large files

Entropy calculation: Shannon entropy over the first 512 bytes.
`entropy = -sum(p * log2(p)) for each byte value p > 0`

### VeraCrypt Preferences Artifact
Windows path: `%APPDATA%\VeraCrypt\VeraCrypt.xml`
macOS path: `~/Library/Application Support/VeraCrypt/VeraCrypt.xml`
Parse XML fields:
- `last_used_keyfiles` (Vec<String> — paths to keyfiles used)
- `last_used_volume_path` (Option<String> — last mounted volume path)
- `history` (Vec<String> — recently mounted volumes)

### VeraCrypt Registry Artifacts (Windows)
Key: `HKCU\Software\VeraCrypt\`
Key: `HKCU\Software\TrueCrypt\`
Fields: last_volume_path, favorites (mounted volume list)

### Mount History
Windows: Recently mounted drive letters — cross-reference with
`HKLM\SYSTEM\MountedDevices` for unrecognized volumes.
macOS: `/var/log/system.log` entries containing "disk image" mounts
with no corresponding known application.

Typed struct `VeraCryptArtifact`:
```rust
pub struct VeraCryptArtifact {
    /// Detection method used
    pub detection_method: String,
    /// Path to the suspected volume or artifact file
    pub path: String,
    /// Calculated Shannon entropy (None if not applicable)
    pub entropy: Option<f64>,
    /// File size in bytes
    pub file_size: Option<u64>,
    /// Last known mount path or drive letter
    pub last_mount: Option<String>,
    /// Keyfile paths referenced
    pub keyfiles: Vec<String>,
    /// Volume history entries
    pub history: Vec<String>,
}
```

Emit `Artifact::new("VeraCrypt Volume", path_str)` for suspected volumes.
Emit `Artifact::new("VeraCrypt Preferences", path_str)` for config files.
suspicious=true for all VeraCrypt artifacts.
MITRE: T1027.013 (encrypted/encoded file), T1553 (subvert trust controls).
forensic_value: High.

Wire into Vault `run()` by path pattern and entropy analysis.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT VAULT-3 — Mobile Photo Vault Applications

Create `plugins/strata-plugin-vault/src/photo_vault.rs`.

Detect calculator-disguised vault apps and photo hiding applications on
iOS and Android. These are among the most common concealment tools found
on devices in CSAM, SAPR, and trafficking investigations.

### iOS Photo Vault Apps
Detect by bundle ID presence in app list or artifact paths:

Known vault app bundle IDs:
- `com.destek.recovery` — Secret Photo Vault
- `com.privateapp.vault` — Private Photo Vault  
- `com.keepsafe.keepsafe` — Keepsafe
- `com.mobilityware.calculator` — Calculator+ (vault disguised as calculator)
- `com.nqmobile.vault` — NQ Vault
- `com.hideitmedia.hideitpro` — Hide It Pro
- `com.secret.folder` — Secret Folder
- `com.photo.safe` — Photo Safe

Artifact locations (within app container):
- `Documents/vault.db` — SQLite database of hidden items
- `Documents/media/` — hidden media directory
- `Library/Preferences/<bundle_id>.plist` — app preferences

Parse vault SQLite databases where present:
Table: `vault_items` or `media` (schema varies by app)
Fields: original_filename, date_added, file_size, thumbnail_path

### Android Photo Vault Apps
Known package names:
- `com.keepsafe.vault` — Keepsafe
- `com.nqmobile.vault20` — NQ Vault
- `com.calculator.vault` — Calculator Vault
- `com.hide.secret.photo.video` — Hide Photos
- `com.photo.vault.locker` — Photo Vault Locker
- `org.privacyprotector` — Privacy Protector

Artifact locations:
- `/data/data/<package>/databases/` — app databases
- `/data/data/<package>/files/` — hidden media
- `.nomedia` files in non-standard locations (signals intentional hiding)

`.nomedia` detection: flag any directory containing `.nomedia` that is
NOT a known system or media player directory. A `.nomedia` file prevents
Android Gallery from indexing a folder — forensic red flag.

Typed struct `PhotoVaultArtifact`:
```rust
pub struct PhotoVaultArtifact {
    /// App name (human readable)
    pub app_name: String,
    /// Package/bundle identifier
    pub bundle_id: String,
    /// Platform: iOS or Android
    pub platform: String,
    /// Path where artifact was found
    pub artifact_path: String,
    /// Number of hidden items detected (if parseable)
    pub item_count: Option<u64>,
    /// Whether a vault database was found and parsed
    pub database_found: bool,
    /// .nomedia flag present
    pub nomedia_present: bool,
}
```

Emit `Artifact::new("Photo Vault App", path_str)` per detected app.
suspicious=true for all photo vault artifacts.
MITRE: T1027 (obfuscated files), T1083 (file and directory discovery).
forensic_value: High — presence alone is significant in CSAM/SAPR cases.

Wire into Vault `run()` by path and bundle ID pattern matching.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT VAULT-4 — Secure Delete / Anti-Forensic Tool Artifacts

Create `plugins/strata-plugin-vault/src/antiforensic.rs`.

Detect artifacts left by secure deletion and anti-forensic tools.
Paradoxically, these tools always leave evidence of their own use.

### Windows Anti-Forensic Tools

**CCleaner**
Registry: `HKCU\Software\Piriform\CCleaner\`
Fields: last_run (FILETIME), options (what was cleaned), scheduled_tasks
Log: `%AppData%\Roaming\CCleaner\CCleaner64.ini`
Parse: last_run timestamp, which modules were enabled (browser, registry, etc.)

**BleachBit**
Path: `%AppData%\BleachBit\bleachbit.ini`
Fields: last_run, cleaners_enabled (Vec<String>)
Log entries in Windows Event Log: process creation for `bleachbit.exe`

**Eraser**
Path: `%AppData%\Eraser 6\Task List.ersx` (XML)
Fields: scheduled_tasks (Vec), last_execution, target_paths, erasure_method
Registry: `HKCU\Software\Eraser\Eraser 6\`

**sdelete / Cipher.exe**
Event Log: process creation (4688) for `sdelete.exe`, `sdelete64.exe`
Prefetch: `SDELETE.EXE-{hash}.pf`, `SDELETE64.EXE-{hash}.pf`
Cipher.exe: `cipher /w:` wipes free space — detect via prefetch + shimcache

**Windows built-in wiping**
`format /p:N` — detect via event logs
VSS deletion: `vssadmin delete shadows` — Event ID 8224 in VSS provider log

### macOS Anti-Forensic Tools

**Permanent Eraser / Secure Empty Trash**
Log: `~/Library/Logs/` entries
History: `.Trash/` metadata anomalies (items deleted faster than normal)

**Terminal `srm` command** (deprecated macOS 10.12+ but still used)
Unified Logs: process = "srm" or arguments containing `-rf`

### Cross-Platform

**Metadata stripping tools**
ExifTool run artifacts — detect `exiftool` in shell history, prefetch
MAT2 artifacts

Typed struct `AntiForensicArtifact`:
```rust
pub struct AntiForensicArtifact {
    /// Tool name (CCleaner, BleachBit, Eraser, sdelete, etc.)
    pub tool_name: String,
    /// Last known execution time
    pub last_run: Option<DateTime<Utc>>,
    /// Artifact path where evidence was found
    pub artifact_path: String,
    /// What was targeted for deletion (if determinable)
    pub targets: Vec<String>,
    /// Cleaning modules enabled
    pub modules_enabled: Vec<String>,
    /// Detection source (registry/prefetch/log/config)
    pub detection_source: String,
}
```

Emit `Artifact::new("Anti-Forensic Tool", path_str)` per detection.
suspicious=true for all anti-forensic artifacts.
MITRE: T1070 (indicator removal), T1027 (obfuscated files),
T1485 (data destruction), T1561 (disk wipe).
forensic_value: High — anti-forensic tool use is itself evidence of intent.

Wire into Vault `run()` by path pattern, registry key, and prefetch name.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT VAULT-5 — Hidden Partition and Container Detection

Create `plugins/strata-plugin-vault/src/hidden_partition.rs`.

Detect hidden partitions, anomalous disk geometry, and steganography indicators.

### Partition Table Analysis
Parse MBR and GPT partition tables from raw disk images.

MBR: offset 446 — four 16-byte partition entries
GPT: offset 512 — GPT header, offset 1024 — partition entries

Flag anomalies:
- Unaccounted sectors between partitions (gap > 2048 sectors without explanation)
- Partition entries with type `0x00` (empty) but non-zero LBA values
- Total partition sizes do not account for full disk size
- GPT/MBR hybrid with mismatched partition counts

Host Protected Area (HPA):
- Compare `READ NATIVE MAX ADDRESS` vs `IDENTIFY DEVICE` reported capacity
- If native max > identify capacity → HPA present
- Document as `HpaDetected { hidden_sectors: u64 }`
- NOTE: HPA detection requires raw ATA commands — flag as "requires live acquisition"
  if working from forensic image only

Device Configuration Overlay (DCO):
- Similar to HPA — document same way

### Steganography Indicators
Statistical analysis on image files (JPEG, PNG, BMP):

Chi-square test on LSB plane:
- Extract LSBs of all pixel values
- Chi-square statistic > 0.05 threshold suggests random LSB distribution
  (natural images have non-random LSBs — randomness indicates embedding)
- Flag as `SteganographyIndicator { method: "LSB", confidence: f64 }`

File size anomalies:
- JPEG file significantly larger than expected for its dimensions and quality
  (expected_bytes ≈ width * height * 0.1 for typical JPEG quality)
- If actual_size > expected_size * 3.0 → flag for review

Known steganography tool output patterns:
- OpenStego output files: typically PNG with specific metadata markers
- SilentEye: AVI/MP3/BMP with appended data after EOF marker

Typed struct `HiddenStorageArtifact`:
```rust
pub struct HiddenStorageArtifact {
    /// Detection type
    pub detection_type: HiddenStorageType,
    /// Path or disk region where detected
    pub location: String,
    /// Size of hidden region in bytes (if determinable)
    pub hidden_size: Option<u64>,
    /// Confidence level
    pub confidence: String,
    /// Statistical score where applicable
    pub stat_score: Option<f64>,
    /// Additional notes for examiner
    pub notes: String,
}

pub enum HiddenStorageType {
    UnaccountedPartitionGap,
    HostProtectedArea,
    DeviceConfigurationOverlay,
    SteganographyIndicator,
    AnomalousFileSize,
}
```

Emit `Artifact::new("Hidden Storage Indicator", path_str)` per detection.
suspicious=true for all.
MITRE: T1027.003 (steganography), T1564.005 (hidden file system).
forensic_value: High.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT VAULT-6 — Encrypted Archive and Secure Messaging Artifacts

Create `plugins/strata-plugin-vault/src/encrypted_artifacts.rs`.

Detect encrypted archives, secure communication artifacts, and
operational security tool usage.

### Encrypted Archive Detection
Detect encrypted archives by header and flag for examiner review.

7-Zip encrypted: header `37 7A BC AF 27 1C` + AES-256 flag in header
ZIP with encryption: `50 4B 03 04` + general purpose bit flag 0x0001 set
RAR encrypted: `52 61 72 21 1A 07` + encryption flag in file header
AxCrypt files: extension `.axx`, header `C2 26 15 71 07 9F 4F 15`

Typed struct `EncryptedArchive`:
```rust
pub struct EncryptedArchive {
    /// Archive format (7Zip, ZIP, RAR, AxCrypt)
    pub format: String,
    /// Full path to archive
    pub path: String,
    /// File size in bytes
    pub file_size: u64,
    /// Encryption method if determinable from header
    pub encryption_method: Option<String>,
    /// Number of encrypted entries (if readable without decryption)
    pub entry_count: Option<u64>,
}
```

### Secure Communication App Artifacts

**Signal Desktop**
Windows: `%AppData%\Signal\`
macOS: `~/Library/Application Support/Signal/`
Database: `sql\db.sqlite` (encrypted with SQLCipher — do NOT attempt decryption)
Detect presence only — flag that Signal was installed and used.
Emit artifact with: install_path, last_modified timestamp on db file,
profile_name from `config.json` if present.

**Wickr**
Windows: `%AppData%\Wickr\`
macOS: `~/Library/Application Support/Wickr Me\`
Same approach — detect presence, parse config, note encrypted DB.

**Briar** (decentralized messaging)
Android: `/data/data/org.briarproject.briar.android/`
Detect package presence.

**Session** (Signal fork, no phone number required)
Windows: `%AppData%\Session\`
Detect presence and config.

### Tor Browser Artifacts

Windows: `%AppData%\Tor Browser\Browser\TorBrowser\Data\`
macOS: `~/Library/Application Support/TorBrowser-Data/`

Parse:
- `Browser\profile.default\places.sqlite` — SQLite, `moz_places` table
  Fields: url (filter for .onion), title, visit_count, last_visit_date
- `Browser\profile.default\extensions.json` — installed extensions
- `state` file — last known Tor circuit information
- `torrc` — custom Tor configuration (bridges, entry guards)

Flag all `.onion` URLs as `forensic_value: High, suspicious: true`.

Typed struct `TorBrowserArtifact`:
```rust
pub struct TorBrowserArtifact {
    /// Type of Tor artifact
    pub artifact_type: String,
    /// .onion URLs visited (empty if none found)
    pub onion_urls: Vec<String>,
    /// Total visit count across all URLs
    pub visit_count: u64,
    /// Custom bridges configured (suggests advanced user)
    pub custom_bridges: bool,
    /// Extensions installed (beyond defaults)
    pub extra_extensions: Vec<String>,
    /// Last activity timestamp
    pub last_activity: Option<DateTime<Utc>>,
}
```

Emit `Artifact::new("Tor Browser History", path_str)` per URL batch.
Emit `Artifact::new("Secure Messaging App", path_str)` per detected app.
suspicious=true for Tor artifacts.
MITRE: T1090.003 (multi-hop proxy/Tor), T1552.003 (credentials in files).
forensic_value: High for Tor + .onion URLs, Medium for app detection only.

Wire into Vault `run()` by path pattern.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT W-10 — PowerShell Execution Artifacts

Enhance `plugins/strata-plugin-phantom/src/` with PowerShell artifact parsing.

### PSReadLine History
Path: `%AppData%\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
Format: Plain text — one command per line (up to 4096 entries, PS v5+)

Parse all lines. Flag suspicious patterns:
- Base64 encoded strings: `-EncodedCommand`, `[Convert]::FromBase64String`
- Download cradles: `IEX`, `Invoke-Expression`, `DownloadString`, `WebClient`
- AMSI bypass patterns: `AmsiContext`, `amsiInitFailed`
- Credential harvesting: `Get-Credential`, `ConvertTo-SecureString`
- Lateral movement: `Enter-PSSession`, `Invoke-Command`, `New-PSSession`
- Living off the land: `certutil`, `bitsadmin`, `regsvr32`, `mshta`, `wscript`

Typed struct `PowerShellHistoryEntry`:
```rust
pub struct PowerShellHistoryEntry {
    /// The raw command line
    pub command: String,
    /// Line number in history file
    pub line_number: usize,
    /// Suspicious pattern detected (if any)
    pub suspicious_pattern: Option<String>,
    /// Contains base64 encoded content
    pub has_encoded_content: bool,
    /// Contains download cradle
    pub has_download_cradle: bool,
}
```

Emit `Artifact::new("PowerShell History", path_str)` per suspicious entry.
Emit one summary artifact with total_commands count for clean entries.
suspicious=true when suspicious_pattern is Some.
MITRE: T1059.001 (PowerShell), T1027.010 (command obfuscation),
T1105 (ingress tool transfer).
forensic_value: High for suspicious entries, Medium for clean history.

Wire into Phantom `run()` when filename is `ConsoleHost_history.txt`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT W-11 — Windows Services Deep Parse

Enhance `plugins/strata-plugin-phantom/src/` with Windows Services artifact parsing.

### Registry Path
`HKLM\SYSTEM\CurrentControlSet\Services\`

Each subkey is a service. Parse:
- `ImagePath` (REG_EXPAND_SZ) — executable path
- `DisplayName` (REG_SZ) — human readable name
- `Description` (REG_SZ nullable) — service description
- `Start` (REG_DWORD) — startup type:
  0=Boot, 1=System, 2=Automatic, 3=Manual, 4=Disabled
- `Type` (REG_DWORD) — service type:
  1=KernelDriver, 2=FilesystemDriver, 16=OwnProcess, 32=ShareProcess
- `ObjectName` (REG_SZ) — account the service runs as
- `FailureActions` (REG_BINARY nullable) — recovery behavior

Flag suspicious services:
- `ImagePath` points to temp directory, AppData, or Downloads
- `ImagePath` contains encoded strings or unusual extensions
- `ObjectName` is not LocalSystem/LocalService/NetworkService and not a standard account
- Service name is random characters (entropy > 3.5 on service key name)
- No `Description` on an `Automatic` start service

Typed struct `WindowsService`:
```rust
pub struct WindowsService {
    /// Registry key name (service name)
    pub service_name: String,
    /// Human readable display name
    pub display_name: Option<String>,
    /// Executable path
    pub image_path: String,
    /// Startup type
    pub start_type: String,
    /// Service type
    pub service_type: String,
    /// Account the service runs as
    pub object_name: Option<String>,
    /// Why this service was flagged as suspicious (if applicable)
    pub suspicious_reason: Option<String>,
}
```

Emit `Artifact::new("Windows Service", path_str)` per service entry.
suspicious=true when suspicious_reason is Some.
MITRE: T1543.003 (Windows Service persistence).
forensic_value: High for suspicious services, Low for standard services.

Wire into Phantom `run()` when path matches `CurrentControlSet\Services`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT W-12 — Outlook PST/OST Email Artifacts

Create `plugins/strata-plugin-phantom/src/outlook.rs`.

Parse Microsoft Outlook PST and OST email database files.
This is critical for FBI, SEC, IRS-CI, and corporate insider threat cases.

### PST/OST Format
Magic: `21 42 44 4E` (`!BDN`) at offset 0
Format versions: ANSI (32-bit, legacy) and Unicode (64-bit, current)
Unicode header: `0x17` at offset 10 (version field)

PST files are complex — use a layered approach:
1. Validate magic bytes
2. Read root node table (NDB layer)
3. Walk message store to enumerate folders
4. Extract message metadata (not full body — metadata only for performance)

Fields to extract per message:
- `subject` (PT_STRING8 or PT_UNICODE — property tag 0x0037)
- `sender_name` (property tag 0x0C1A)
- `sender_email` (property tag 0x0C1F)
- `recipients` (Vec<String> — TO/CC/BCC)
- `sent_time` (PT_SYSTIME — Windows FILETIME, property tag 0x0039)
- `received_time` (property tag 0x0E06)
- `has_attachments` (bool — property tag 0x0E1B)
- `attachment_names` (Vec<String> — from attachment table)
- `message_size` (u64 — property tag 0x0E08)
- `folder_path` (String — reconstructed from folder hierarchy)

If full PST parsing is not feasible without an external crate:
1. Check if `pst` or `libpff` Rust bindings are in Cargo.toml
2. If not — implement string-carving fallback:
   Scan for email address patterns and subject strings in UTF-16LE
   Emit as `Artifact::new("PST String Carve", path_str)` with caveat note
3. Document clearly which approach was used

Typed struct `OutlookMessage`:
```rust
pub struct OutlookMessage {
    /// Email subject line
    pub subject: String,
    /// Sender display name
    pub sender_name: Option<String>,
    /// Sender email address
    pub sender_email: Option<String>,
    /// Recipient addresses
    pub recipients: Vec<String>,
    /// When the message was sent
    pub sent_time: Option<DateTime<Utc>>,
    /// When the message was received
    pub received_time: Option<DateTime<Utc>>,
    /// Whether the message has attachments
    pub has_attachments: bool,
    /// Names of attached files
    pub attachment_names: Vec<String>,
    /// Folder path within PST (e.g. "Inbox/Subfolder")
    pub folder_path: String,
    /// Message size in bytes
    pub message_size: u64,
}
```

Emit `Artifact::new("Outlook Email", path_str)` per message.
MITRE: T1114 (email collection), T1530 (cloud storage object access).
forensic_value: High for messages with attachments or unusual recipients.

Wire into Phantom `run()` when extension is `.pst` or `.ost` case-insensitive.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT W-13 — BITS Jobs Deep Parse

Enhance `plugins/strata-plugin-trace/src/` with BITS job structured output.

Background Intelligent Transfer Service (BITS) is heavily abused for
malware persistence and C2 download. Trace v2.0 detects presence —
this sprint adds full structured field extraction.

### BITS Database Files
Windows 7-10: `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr0.dat`
              `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr1.dat`
Windows 10+:  `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr.db` (ESE)

For qmgr0.dat / qmgr1.dat (binary format):
These are proprietary binary — implement pattern-based extraction:
- Scan for URL patterns (`https?://`) — extract surrounding context (256 bytes)
- Scan for file path patterns (`[A-Za-z]:\\`) — extract as destination
- Scan for GUID patterns (`\{[0-9A-F-]{36}\}`) — extract as job ID

For qmgr.db (ESE — same caveat as X-2):
If ESE parsing available — extract from `Jobs` table:
Fields: JobId (GUID), DisplayName, Description, NotifyUrl,
        FileCount, BytesTotal, BytesTransferred,
        CreationTime, ModificationTime, CompletionTime,
        State (Queued/Connecting/Transferring/Suspended/Error/Cancelled/Transferred)

Typed struct `BitsJob`:
```rust
pub struct BitsJob {
    /// GUID job identifier
    pub job_id: String,
    /// Human readable job name
    pub display_name: Option<String>,
    /// Source URL (download source)
    pub source_url: Option<String>,
    /// Destination file path
    pub destination_path: Option<String>,
    /// Job state
    pub state: Option<String>,
    /// Creation timestamp
    pub created: Option<DateTime<Utc>>,
    /// Completion timestamp
    pub completed: Option<DateTime<Utc>>,
    /// Total bytes transferred
    pub bytes_transferred: Option<u64>,
    /// Notify/callback URL (C2 indicator)
    pub notify_url: Option<String>,
}
```

Flag suspicious BITS jobs:
- `source_url` is not a Microsoft/Windows Update domain
- `notify_url` is present (legitimate BITS jobs rarely use this)
- `destination_path` is in temp or AppData
- Job was created outside business hours

Emit `Artifact::new("BITS Job", path_str)` per job.
suspicious=true when any flag condition is met.
MITRE: T1197 (BITS Jobs).
forensic_value: High for suspicious jobs, Medium for clean jobs.

Wire into Trace `run()` when filename is `qmgr0.dat`, `qmgr1.dat`, or `qmgr.db`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT EXIF-1 — EXIF Deep Parser

Create `plugins/strata-plugin-apex/src/exif.rs`.

Parse EXIF metadata from images. Critical for DEA (drug trafficking),
ATF (weapons photos), insurance fraud, and trafficking investigations.

Use the `kamadak-exif` crate or `rexiv2` bindings — check Cargo.toml.
If neither present — add `kamadak-exif = "0.5"` as dependency.

File types: JPEG (`.jpg`, `.jpeg`), TIFF (`.tif`, `.tiff`),
            PNG (`.png` — EXIF in iTXt chunk), HEIC/HEIF (`.heic`, `.heif`)

Fields to extract:
```rust
pub struct ExifRecord {
    /// Image file path
    pub path: String,
    /// GPS latitude in decimal degrees (positive = North)
    pub gps_latitude: Option<f64>,
    /// GPS longitude in decimal degrees (positive = East)
    pub gps_longitude: Option<f64>,
    /// GPS altitude in meters
    pub gps_altitude: Option<f64>,
    /// Camera/device make (e.g. Apple, Samsung, Canon)
    pub device_make: Option<String>,
    /// Camera/device model (e.g. iPhone 15 Pro, SM-G998B)
    pub device_model: Option<String>,
    /// When the photo was taken (camera clock)
    pub date_taken: Option<DateTime<Utc>>,
    /// When the file was last modified (filesystem)
    pub date_modified: Option<DateTime<Utc>>,
    /// Image dimensions
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// Software used (e.g. Photoshop — indicates possible editing)
    pub software: Option<String>,
    /// Whether GPS coordinates are present
    pub has_gps: bool,
    /// Whether timestamps differ between EXIF and filesystem (tampering indicator)
    pub timestamp_mismatch: bool,
}
```

Flag for examiner:
- `has_gps = true` — always high forensic value
- `software` contains "Photoshop", "GIMP", "Lightroom" — possible manipulation
- `timestamp_mismatch = true` — EXIF date vs filesystem date differ by > 60s
- `device_model` identifies a specific device (cross-reference with known devices)

Emit `Artifact::new("EXIF Metadata", path_str)` per image.
MITRE: T1592.001 (gather victim identity info), T1430 (location tracking).
forensic_value: High when GPS present, Medium otherwise.

Wire into Apex `run()` when extension is jpg/jpeg/tiff/tif/heic/heif/png.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT CRYPTO-1 — Cryptocurrency Wallet Artifacts

Create `plugins/strata-plugin-vault/src/crypto_wallets.rs`.

Detect cryptocurrency wallet files and exchange artifacts.
Critical for IRS-CI, USSS, DEA, and financial crimes investigations.

### Bitcoin Core
File: `wallet.dat` — Berkeley DB format
Magic: `00 31 BB 30 DB BB C4 02` (BDB magic)
Detection: filename `wallet.dat` + BDB magic validation
Parse: Extract version field and key count from BDB header if possible.
Note: Full wallet parsing requires private key access — detect and flag only.

### Electrum Wallet
File: `default_wallet` or `*.wallet` (no extension or `.wallet`)
Format: JSON
Path Windows: `%APPDATA%\Electrum\wallets\`
Path macOS: `~/Library/Application Support/Electrum/wallets/`
Parse JSON fields:
- `wallet_type` (standard/multisig/imported)
- `seed_type` (standard/segwit/old)
- `use_encryption` (bool — if true, wallet is encrypted)
- `addresses` — count only, do not log actual addresses

### MetaMask Browser Extension
Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\`
Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\*.default\storage\default\moz-extension+++*\`
File: LevelDB format — parse `.ldb` / `.log` files for JSON fragments
Extract: `selectedAddress` (current wallet address), `networkVersion`,
`vault` presence (encrypted keystore blob)

### Exchange CSV Detection
Detect exported transaction files from major exchanges by header pattern:
Coinbase: CSV with header `Timestamp,Transaction Type,Asset,Quantity Transacted,...`
Binance: CSV with header `Date(UTC),Pair,Side,Price,Executed,Amount,Fee`
Kraken: CSV with header `txid,ordertxid,pair,time,type,ordertype,price,...`
Gemini: CSV with header `Date,Time (UTC),Type,Symbol,Specification,...`

Emit `Artifact::new("Crypto Wallet", path_str)` per wallet detected.
Emit `Artifact::new("Exchange Export", path_str)` per CSV detected.
suspicious=true for all crypto artifacts in law enforcement context.
MITRE: T1531 (account access removal), T1657 (financial theft).
forensic_value: High.

Wire into Vault `run()` by filename pattern and magic bytes.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT GAMING-1 — Gaming Platform Artifacts

Create `plugins/strata-plugin-pulse/src/gaming.rs`.

Parse gaming platform artifacts. Critical for ICAC investigations —
predators use gaming platforms to contact and groom children.

### Steam
Windows: `%LOCALAPPDATA%\Steam\`
macOS: `~/Library/Application Support/Steam/`

Files to parse:
- `config\loginusers.vdf` (Valve Data Format — key-value text)
  Fields: AccountName, PersonaName, Timestamp (last login), RememberPassword
- `logs\chat_log_*.txt` — plain text chat logs with timestamps
  Format: `[YYYY-MM-DD HH:MM:SS] <PersonaName>: message`
- `userdata\<steamid>\config\localconfig.vdf`
  Fields: friends list, game playtime history

Parse VDF format: `"key" "value"` pairs, nested with `{` `}` blocks.

### Discord (Desktop — extend existing coverage)
Verify current Pulse coverage. If not already parsed:
Windows: `%APPDATA%\Discord\Local Storage\leveldb\`
Parse LevelDB `.ldb` files for JSON message fragments containing:
`channel_id`, `id` (message ID), `content`, `timestamp`, `author.id`, `author.username`

### Xbox Live (local artifacts)
Windows: `%LOCALAPPDATA%\Packages\Microsoft.XboxApp_*\LocalState\`
Files: `*.json` — gamertag, friend list, message history fragments

### Roblox (ICAC Priority)
Windows: `%LOCALAPPDATA%\Roblox\logs\`
macOS: `~/Library/Logs/Roblox/`
Log files: plain text with chat fragments, player IDs, game session data
Parse: timestamps, player_id, username, chat_message, game_id

Typed struct `GamingArtifact`:
```rust
pub struct GamingArtifact {
    /// Platform name (Steam, Discord, Xbox, Roblox)
    pub platform: String,
    /// Username or account identifier
    pub username: Option<String>,
    /// Platform-specific user ID
    pub user_id: Option<String>,
    /// Chat message content (if applicable)
    pub message: Option<String>,
    /// Message timestamp
    pub timestamp: Option<DateTime<Utc>>,
    /// Contact/friend username (for friend list entries)
    pub contact: Option<String>,
    /// Source artifact type (chat_log/friend_list/login_record)
    pub artifact_subtype: String,
}
```

Emit `Artifact::new("Gaming Platform", path_str)` per artifact.
MITRE: T1566 (phishing via gaming), T1534 (internal spearphishing).
forensic_value: High for chat messages, Medium for account/friend records.

Wire into Pulse `run()` by path pattern per platform.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

---

## SPRINT W-14 — Windows Recall Artifacts

Create `plugins/strata-plugin-phantom/src/windows_recall.rs`.

Parse Microsoft Windows Recall artifacts — available on Copilot+ PCs with NPU
(ARM64, Intel/AMD Copilot+ hardware). Disabled by default in corporate builds
but enabled on consumer Copilot+ PCs since May 2025. When present, this is
among the highest-value artifacts on the system — it is a near-complete
activity log with screenshots and OCR'd text.

### Detection
Check for presence of Recall feature directory first.
If not present — emit no artifacts, log debug message, return Ok(()).

Path: `%AppData%\Local\CoreAIPlatform.00\UKP{GUID}\`
The GUID directory name varies per installation — glob for `UKP*` subdirectory.

### Screenshot Store
Location: `{recall_root}\ImageStore\`
Files: JPEG screenshots named by timestamp

Parse filenames for timestamp (format: `{unix_ms}.jpg` or similar).
Do NOT read image bytes into memory — record path, size, and timestamp only.
Emit `Artifact::new("Recall Screenshot", path_str)` per image file found.
Record: timestamp, file_size, image_path.

### Recall SQLite Database
Location: `{recall_root}\ukg.db`

Tables of forensic interest:

`WindowCapture` table:
- `Id` (INTEGER) — unique capture ID
- `WindowTitle` (TEXT) — title of active window
- `TimeStamp` (INTEGER — Unix milliseconds)
- `ImageToken` (TEXT — links to screenshot file)
- `AppName` (TEXT) — executable name
- `AppPath` (TEXT) — full path to executable

`TextContent` table (OCR extracted text):
- `CaptureId` (INTEGER — foreign key to WindowCapture.Id)
- `Text` (TEXT — OCR'd content from screenshot)
- `TimeStamp` (INTEGER)

`AppActivity` table (if present):
- `AppName`, `AppPath`, `FocusedTime`, `LastFocusedTime`

Query strategy:
1. Join WindowCapture with TextContent on CaptureId
2. Emit one artifact per WindowCapture row
3. Include OCR text as a field (truncate at 2048 chars for artifact output)

Typed struct `RecallCapture`:
```rust
pub struct RecallCapture {
    /// Capture ID from database
    pub capture_id: i64,
    /// Window title at time of capture
    pub window_title: Option<String>,
    /// Application name
    pub app_name: Option<String>,
    /// Full path to application executable
    pub app_path: Option<String>,
    /// Capture timestamp
    pub timestamp: DateTime<Utc>,
    /// OCR'd text from screenshot (truncated at 2048 chars)
    pub ocr_text: Option<String>,
    /// Path to associated screenshot JPEG
    pub screenshot_path: Option<String>,
}
```

NOTE: Recall database may be encrypted with DPAPI or Windows Hello.
If database opens without decryption — parse it. If SQLite returns
"file is not a database" error — emit one `Artifact::new("Recall Database Locked", path_str)`
noting that Recall was present but database is encrypted, requires live acquisition.

suspicious=false (this is an OS feature, not inherently suspicious).
MITRE: T1113 (screen capture), T1005 (data from local system).
forensic_value: High — complete activity reconstruction when accessible.

Wire into Phantom `run()` when path matches `CoreAIPlatform.00\UKP*\ukg.db`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT W-15 — Windows 11 Notepad TabState

Create `plugins/strata-plugin-phantom/src/notepad_tabstate.rs`.

Parse Windows 11 Notepad tab state files. This artifact can recover
text content that was typed in Notepad and NEVER saved to disk — including
malicious scripts, notes, credentials, and commands written by threat actors.

### Location
`%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState\`

Files: `{GUID}.bin` — one per open Notepad tab
Also present: `{GUID}.0.bin`, `{GUID}.1.bin` — temporary write files, less content

Parse only `{GUID}.bin` files (not `.0.bin` or `.1.bin`).

### Binary Format
The TabState format is a custom binary format. Parse these fields:

Offset 0: Magic/version bytes (document in comment — verify against known samples)
Content block: UTF-16LE encoded text of tab content
Metadata block: file path (if tab was associated with a saved file), hash, timestamps

Field extraction approach:
1. Scan for UTF-16LE BOM (`FF FE`) or UTF-16LE encoded text patterns
2. Extract contiguous UTF-16LE text blocks > 4 characters
3. Scan for Windows path patterns in UTF-16LE (`[A-Z]:\\`)
4. If a file path is found — this tab was associated with a saved file

For saved file tabs:
- Extract: file_path, last_modified (FILETIME if present), file_hash (if present)
- Note: recent versions no longer record hash — document in comment

For unsaved file tabs:
- Extract: content (full text — this is the forensic gold)
- Flag as unsaved_content=true

Typed struct `NotepadTab`:
```rust
pub struct NotepadTab {
    /// GUID identifier for this tab
    pub tab_guid: String,
    /// Whether this tab has unsaved content (typed but never saved)
    pub unsaved_content: bool,
    /// Text content of the tab (may be partial if encoding detection fails)
    pub content: Option<String>,
    /// Associated file path if tab was linked to a saved file
    pub file_path: Option<String>,
    /// Content length in characters
    pub content_length: usize,
    /// Whether content contains suspicious patterns
    pub suspicious_pattern: Option<String>,
}
```

Flag suspicious patterns in content:
- Base64 strings > 32 chars
- PowerShell commands (`Invoke-`, `IEX`, `-EncodedCommand`)
- URL patterns (`http://`, `https://`)
- IP addresses
- Credential patterns (`password`, `passwd`, `secret`, `api_key`)

Emit `Artifact::new("Notepad TabState", path_str)` per tab file.
suspicious=true when suspicious_pattern is Some.
MITRE: T1059 (command and scripting), T1552 (unsecured credentials).
forensic_value: High for unsaved content with suspicious patterns, Medium otherwise.

Wire into Phantom `run()` when path contains
`Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState` and
filename matches `*.bin` but NOT `*.0.bin` or `*.1.bin`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT TRACE-2 — Program Compatibility Assistant (PCA)

Enhance `plugins/strata-plugin-trace/src/` with PCA artifact parsing.

The Program Compatibility Assistant logs execution of programs that triggered
compatibility shims. New in Windows 11 22H2 — distinct from ShimCache and
AmCache. Provides an additional execution evidence source.

### Location
`C:\Windows\appcompat\pca\`

Files:
- `PcaAppLaunchDic.txt` — plain text, one entry per line
  Format: `{full_exe_path}|{YYYY-MM-DD HH:MM:SS.mmm}`
  Records: last execution time per executable
- `PcaGeneralDb2.txt` — additional compatibility entries
  Format: tab-delimited or pipe-delimited — document actual format in comment

### Parsing PcaAppLaunchDic.txt
Split each line on `|`.
Left side: full executable path.
Right side: timestamp string — parse as local time, convert to UTC.
Note: PCA uses local system time — flag in artifact metadata.

Typed struct `PcaEntry`:
```rust
pub struct PcaEntry {
    /// Full path to the executable
    pub exe_path: String,
    /// Executable filename extracted from path
    pub exe_name: String,
    /// Last execution timestamp (local time converted to UTC)
    pub last_executed: DateTime<Utc>,
    /// Whether timestamp was local time (true = conversion applied)
    pub local_time_converted: bool,
    /// Source file (PcaAppLaunchDic or PcaGeneralDb2)
    pub source_file: String,
}
```

Flag suspicious entries:
- `exe_path` in temp, AppData, Downloads, or user-writable locations
- `exe_name` matches known LOLBins (certutil, mshta, wscript, regsvr32, rundll32)
- Execution time outside normal hours (flag for examiner — not auto-suspicious)

Emit `Artifact::new("PCA Execution", path_str)` per entry.
suspicious=true when suspicious path or LOLBin match.
MITRE: T1059 (command execution), T1218 (signed binary proxy execution).
forensic_value: High for suspicious entries — corroborates ShimCache/AmCache.

Wire into Trace `run()` when filename is `PcaAppLaunchDic.txt` or `PcaGeneralDb2.txt`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT CHRON-2 — Capability Access Manager Windows 11 Expansion

Enhance `plugins/strata-plugin-chronicle/src/` with Windows 11-specific
Capability Access Manager (CAM) parsing.

Chronicle v2.0 has basic CapabilityAccessManager coverage. Windows 11 23H2
and 24H2 introduced expanded CAM artifacts with a dedicated SQLite database
in addition to the registry keys. This sprint adds the database parsing.

### Existing Coverage (do not duplicate)
Registry path: `HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\`
This is already in Chronicle v2.0 — verify and extend if needed.

### New: CAM Database (Windows 11 23H2+)
Location: `%ProgramData%\Microsoft\Windows\CapabilityAccessManager\`
File: `CapabilityAccessManager.db` (SQLite)

Tables of forensic interest:

`Capabilities` table:
- `CapabilityName` (TEXT) — e.g. "microphone", "camera", "location", "screencapture"
- `PackageName` (TEXT) — app package or exe name requesting access
- `LastUsed` (INTEGER — Windows FILETIME or Unix — verify format)
- `AccessGranted` (INTEGER bool)
- `UserDecision` (INTEGER — 0=not decided, 1=allowed, 2=denied)

`AccessHistory` table (if present):
- `CapabilityName`, `PackageName`, `AccessTime`, `Duration`

This is critical for privacy investigations — proves which app accessed
microphone/camera/location and when. High value in SAPR, stalkerware,
and corporate espionage cases.

Typed struct `CamRecord`:
```rust
pub struct CamRecord {
    /// Resource type accessed (microphone/camera/location/contacts/screencapture)
    pub capability: String,
    /// Application or package that accessed the resource
    pub app_name: String,
    /// When access last occurred
    pub last_used: Option<DateTime<Utc>>,
    /// Whether access was granted
    pub access_granted: bool,
    /// User decision (Allowed/Denied/NotDecided)
    pub user_decision: String,
    /// Source: Registry or Database
    pub source: String,
}
```

Emit `Artifact::new("Capability Access", path_str)` per record.
Flag microphone/camera/location access by non-system applications.
suspicious=true when screencapture capability accessed by unknown app.
MITRE: T1123 (audio capture), T1125 (video capture), T1430 (location tracking).
forensic_value: High for mic/camera/location access by unexpected apps.

Wire into Chronicle `run()` when filename is `CapabilityAccessManager.db`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT PULSE-10 — Electron/WebView2 Generic Scanner

Create `plugins/strata-plugin-pulse/src/electron_scanner.rs`.

Many modern desktop applications are built on Electron or WebView2 and store
data in Chromium-style LevelDB and IndexedDB databases. These go largely
unexamined by mainstream forensic tools. This sprint implements a generic
scanner that extracts readable content from these stores.

Applications that use this architecture include:
- WhatsApp Desktop (WebView2 as of Dec 2025)
- Microsoft Teams
- Slack Desktop
- Discord Desktop
- Signal Desktop
- VS Code (development artifacts)
- Notion Desktop

### LevelDB Scanner
LevelDB stores: `Local Storage\leveldb\` under app profile directories

Scan `.ldb` and `.log` files for JSON fragments:
- Read file as bytes
- Find sequences starting with `{` or `[` followed by valid JSON characters
- Extract JSON objects containing forensically relevant keys:
  * `message`, `content`, `text`, `body` — message content
  * `timestamp`, `time`, `date`, `ts` — timestamps
  * `from`, `author`, `sender`, `userId` — sender identity
  * `to`, `recipient`, `channel` — destination
  * `filename`, `url`, `uri` — file/URL references

### IndexedDB Scanner
IndexedDB stores: `IndexedDB\` under app profile directories
Files: `*.leveldb` directories containing LevelDB format

Apply same scanning approach as LevelDB.

### App Detection
Identify the parent application by scanning the path:
- `\WhatsApp\` → WhatsApp
- `\Slack\` → Slack
- `\discord\` → Discord
- `\Signal\` → Signal
- `\Microsoft\Teams\` → Teams
- Unknown path → "Electron App (unknown)"

Typed struct `ElectronArtifact`:
```rust
pub struct ElectronArtifact {
    /// Detected application name
    pub app_name: String,
    /// Store type (LevelDB/IndexedDB)
    pub store_type: String,
    /// Extracted JSON fragment (truncated at 1024 chars)
    pub content: String,
    /// Keys found in the JSON fragment
    pub keys_found: Vec<String>,
    /// Source file path
    pub source_path: String,
    /// Byte offset in source file
    pub offset: u64,
}
```

Emit `Artifact::new("Electron App Data", path_str)` per extracted fragment.
MITRE: T1552.003 (credentials in files), T1005 (data from local system).
forensic_value: Medium — content varies widely by app and state.

Wire into Pulse `run()` by scanning for LevelDB directories under known
Electron app profile paths on Windows and macOS.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT PULSE-11 — WhatsApp Desktop WebView2 Architecture

Enhance `plugins/strata-plugin-pulse/src/whatsapp.rs`.

WhatsApp Desktop migrated from UWP to WebView2 architecture on December 9, 2025.
This sprint updates Strata's WhatsApp Desktop parser for the new artifact locations.
Existing WhatsApp mobile coverage (Android/iOS) is unaffected.

### New Artifact Locations (WebView2, Dec 2025+)
Base: `%LocalAppData%\Packages\5319275A.WhatsAppDesktop_*\LocalState\`

Key directories:
- `sessions\` — contains SHA1-named subdirectories per session
  Each subdir: `nativeSettings.db` (SQLite — contains encryption key metadata)
- `session.db` — SQLite WAL-mode database, session data
- `session.db-wal` — WAL file — may contain recoverable message fragments
  even if main database is locked/encrypted

### session.db-wal Recovery
The WAL file persists recent writes. Even if `session.db` is encrypted,
the WAL may contain plaintext fragments in UTF-16LE or UTF-8.

Scan WAL file for:
- Phone number patterns (`+[0-9]{7,15}`)
- Message text fragments (UTF-8 or UTF-16LE text blocks > 10 chars)
- Timestamp patterns (Unix milliseconds in 13-digit range)

### nativeSettings.db
Open with rusqlite. If it opens (unencrypted) — extract:
- Key type metadata (do NOT log key values)
- Account identifiers
- Session configuration

If encrypted — emit `Artifact::new("WhatsApp WebView2 Locked", path_str)`
noting architecture version and that live acquisition is required.

### Legacy UWP Detection
Check for old UWP path: `%LocalAppData%\Packages\5319275A.WhatsAppDesktop_*\LocalState\`
with UWP-era `shared.db` or `messages.db` — if present, use existing parser logic.

Emit `Artifact::new("WhatsApp Desktop", path_str)` per finding.
Note architecture version (UWP vs WebView2) in artifact metadata.
MITRE: T1552.003, T1636.002.
forensic_value: High.

Wire into Pulse `run()` by path pattern matching WhatsApp package directory.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT PULSE-12 — Telegram Desktop Artifacts

Create `plugins/strata-plugin-pulse/src/telegram.rs`.

Parse Telegram Desktop artifacts on Windows and macOS.

### Artifact Locations
Windows: `%AppData%\Telegram Desktop\tdata\`
macOS: `~/Library/Application Support/Telegram Desktop/tdata/`

### tdata Structure
Telegram uses a custom binary format (TDF) for most data.
Full decryption requires the local passcode — do NOT attempt decryption.

However, these artifacts are accessible without decryption:

**D877F783D5D3EF8C directory** (settings store):
- Contains `s` file — partial plaintext settings
- Scan for phone number patterns, username strings

**`dumps\` directory** (crash dumps — often plaintext):
- Plain text fragments from recent sessions
- Extract: timestamps, message fragments, contact names visible in dumps

**`media_cache\` directory** (downloaded media metadata):
- File listing reveals media was received/sent
- Filenames may contain user IDs or timestamps

**`user_data\` or account-specific directories**:
- Scan for SQLite files (newer Telegram versions may use SQLite)
- If SQLite found: parse `messages`, `dialogs`, `contacts` tables

**Keystore detection**:
- `key_datas` file — presence indicates local passcode is set
- `key_data` file — presence indicates no local passcode (data accessible)
If `key_data` present without local passcode: note higher likelihood of data recovery.

Typed struct `TelegramArtifact`:
```rust
pub struct TelegramArtifact {
    /// Type of artifact found
    pub artifact_type: String,
    /// Account phone number if recoverable
    pub phone_number: Option<String>,
    /// Username if recoverable
    pub username: Option<String>,
    /// Whether local passcode is set (affects data accessibility)
    pub local_passcode_set: bool,
    /// Message fragments recovered from dumps
    pub message_fragments: Vec<String>,
    /// Media file count in cache
    pub media_cache_count: Option<u64>,
    /// Path to tdata directory
    pub tdata_path: String,
}
```

Emit `Artifact::new("Telegram Desktop", path_str)`.
MITRE: T1552.003, T1636.002.
forensic_value: High — even partial recovery is significant.

Wire into Pulse `run()` by path matching `Telegram Desktop\tdata`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT PULSE-13 — Viber, WeChat, and Line Desktop Artifacts

Create `plugins/strata-plugin-pulse/src/messaging_extended.rs`.

Parse desktop messaging app artifacts for Viber, WeChat, and Line.
These appear frequently in international investigations, financial fraud
(WeChat Pay), and trafficking cases.

### Viber Desktop
Windows: `%AppData%\ViberPC\{phone_number}\viber.db`
macOS: `~/Library/Application Support/Viber/`

Format: SQLite (unencrypted on desktop)

Tables:
- `Messages`: msg_id, address (phone), body, date (Unix ms), type (sent/received),
  m_type (media type), read_status
- `Participants`: canonical_id, display_name, phone_number
- `Calls`: call_id, address, date, duration, type (incoming/outgoing/missed)

Emit `Artifact::new("Viber Message", path_str)` per message.
Emit `Artifact::new("Viber Call", path_str)` per call record.
MITRE: T1636.002, T1636.003.
forensic_value: High.

### WeChat Desktop
Windows: `%AppData%\Tencent\WeChat\`
Key file: `{user_id}\Msg\Multi\MSG{N}.db` (SQLite, may be encrypted with user key)

If unencrypted — parse:
- `Chat_` prefixed tables: content, createTime, talker, isSender
- `Friend` table: userName, nickName, remark

WeChat Pay artifacts (financial forensics):
- `%AppData%\Tencent\WeChat\` payment logs
- Scan for payment confirmation strings in any accessible SQLite
- Flag: payment_amount, recipient_id, timestamp if found

If encrypted — emit `Artifact::new("WeChat Database Locked", path_str)`
with note that user key derivation requires live acquisition.

Emit `Artifact::new("WeChat Message", path_str)` per message.
Emit `Artifact::new("WeChat Payment", path_str)` per payment artifact.
MITRE: T1552.003, T1657 (financial theft) for payment artifacts.
forensic_value: High for messages and payments.

### Line Desktop
Windows: `%AppData%\LINE\Data\`
Key file: `LineQcChat.db` or `naver_line.db` (SQLite)

Tables:
- `chat_history`: id, chat_id, content, created_time (Unix ms),
  sender (user ID), type
- `contacts`: mid, display_name, status_message

Emit `Artifact::new("Line Message", path_str)` per message.
MITRE: T1636.002.
forensic_value: High in Asia-Pacific investigations.

Typed struct `ExtendedMessagingArtifact`:
```rust
pub struct ExtendedMessagingArtifact {
    /// Platform name (Viber/WeChat/Line)
    pub platform: String,
    /// Artifact subtype (Message/Call/Payment)
    pub artifact_subtype: String,
    /// Sender identifier (phone/username/ID)
    pub sender: Option<String>,
    /// Recipient identifier
    pub recipient: Option<String>,
    /// Message or event content
    pub content: Option<String>,
    /// Timestamp
    pub timestamp: Option<DateTime<Utc>>,
    /// Call duration in seconds (for call records)
    pub call_duration_secs: Option<u64>,
    /// Payment amount as string (for payment artifacts)
    pub payment_amount: Option<String>,
}
```

Wire into Pulse `run()` by filename pattern per platform.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum (one per platform).

---

## SPRINT PULSE-14 — AI App Local Artifacts

Create `plugins/strata-plugin-pulse/src/ai_apps.rs`.

Parse locally-stored artifacts from AI assistant applications.
These applications are increasingly present on devices in investigations
and store conversation data, browser artifacts, and usage history locally.

### ChatGPT Desktop / Mobile (iOS & Android)
Desktop (Windows): `%AppData%\ChatGPT\` (Electron app)
  - LevelDB at `Local Storage\leveldb\` — covered by PULSE-10
  - Additional: `config.json` — account email, subscription tier
iOS: `~/Documents/` in app container — SQLite `chatgpt.db`
  Tables: `conversations` (id, title, created_at), `messages` (role, content, timestamp)
Android: `/data/data/com.openai.chatgpt/databases/`
  Similar SQLite structure

### Microsoft Copilot
Windows (Edge integration): artifacts in Edge profile
  `%LocalAppData%\Microsoft\Edge\User Data\Default\` — Chromium-style storage
  LevelDB at `Local Storage\leveldb\` — covered by PULSE-10
Dedicated Copilot app (Windows):
  `%LocalAppData%\Microsoft\WindowsApps\` package directory

### Detection Only for Encrypted Apps
For apps where local data is encrypted (Gemini, Claude mobile):
  Detect app installation and last-used timestamp only.
  Emit `Artifact::new("AI App Installed", path_str)` with:
  - app_name, install_path, last_modified timestamp on database file

### Conversation Fragment Recovery
For any AI app SQLite that opens unencrypted:
Parse `conversations` or equivalent table.
Emit `Artifact::new("AI Conversation", path_str)` per conversation with:
- title, created_at, message_count
- Flag if conversation title contains sensitive keywords:
  * "password", "hack", "exploit", "bomb", "weapon", "drug", "csam"
  (flag for examiner review — not auto-suspicious)

Typed struct `AiAppArtifact`:
```rust
pub struct AiAppArtifact {
    /// AI application name (ChatGPT/Copilot/Gemini/Claude/Other)
    pub app_name: String,
    /// Platform (Windows/iOS/Android)
    pub platform: String,
    /// Artifact type (Conversation/InstallRecord/Config)
    pub artifact_type: String,
    /// Conversation title if available
    pub conversation_title: Option<String>,
    /// Number of messages in conversation
    pub message_count: Option<u64>,
    /// Conversation creation timestamp
    pub created_at: Option<DateTime<Utc>>,
    /// Whether conversation content was accessible (unencrypted)
    pub content_accessible: bool,
    /// Sensitive keyword flag
    pub keyword_flagged: bool,
}
```

MITRE: T1005 (data from local system), T1552 (unsecured credentials if
credentials visible in conversation content).
forensic_value: Medium for install records, High for accessible conversation content.

Wire into Pulse `run()` by path pattern per platform.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT PULSE-15 — Ephemeral Messaging Indicators

Enhance `plugins/strata-plugin-pulse/src/` with ephemeral messaging
detection across all supported messaging platforms.

Disappearing messages leave metadata footprints even after content is gone.
This sprint detects and reports those indicators across WhatsApp, Telegram,
Signal, and Snapchat.

### WhatsApp Disappearing Message Indicators
Database: `msgstore.db` (Android) / `ChatStorage.sqlite` (iOS)

In `message` table:
- `ephemeral_duration` column — non-zero value means disappearing messages enabled
  Values: 86400 (24h), 604800 (7d), 7776000 (90d)
- `message_expiry_timestamp` — when message was/will be deleted
- Rows where `message_expiry_timestamp` < current time but row exists = expired message

In `chat` table:
- `ephemeral_setting` — global disappearing message setting for conversation
- `ephemeral_setting_timestamp` — when setting was changed

WAL file scanning: scan `msgstore.db-wal` for expired message content fragments.

### Telegram Secret Chats
In `cache4.db` or equivalent:
- `secret_chats` table presence indicates secret chat usage
- `ttl` field on messages — Time To Live before auto-delete
- Scan for deleted message slots (rows with NULL content but non-NULL id)

### Signal Disappearing Messages
Signal database is encrypted — detect only:
- `signal.db` WAL file scanning for plaintext fragments
- `~/.config/Signal/` profile directory last-modified timestamps
- Disappearing message timer files in Signal profile directory

### Snapchat
iOS: app container SQLite databases
Android: `/data/data/com.snapchat.android/databases/`
- `arroyo.db` — message metadata including expiry timestamps
- Even after snap deletion: `snap_id`, `sender_id`, `timestamp`, `viewed_timestamp`
  persist in some versions

### SQLite WAL Fragment Recovery
For all messaging databases with WAL files:
Scan the WAL file for UTF-8 text blocks > 20 chars that appear to be
message content (contain common words, punctuation patterns suggesting
natural language). These are messages written to WAL but deleted from
main database.

Typed struct `EphemeralIndicator`:
```rust
pub struct EphemeralIndicator {
    /// Platform (WhatsApp/Telegram/Signal/Snapchat)
    pub platform: String,
    /// Type of indicator found
    pub indicator_type: String,
    /// Disappearing message duration setting if found (seconds)
    pub timer_seconds: Option<u64>,
    /// Number of expired/deleted message slots detected
    pub deleted_message_count: Option<u64>,
    /// WAL fragment content (partial, truncated at 512 chars)
    pub wal_fragment: Option<String>,
    /// Timestamp of when disappearing messages were enabled
    pub setting_timestamp: Option<DateTime<Utc>>,
}
```

Emit `Artifact::new("Ephemeral Messaging", path_str)` per platform per finding.
suspicious=true when disappearing messages enabled in combination with
other suspicious indicators in the case.
MITRE: T1070.003 (clear command history — analog for message deletion),
T1485 (data destruction).
forensic_value: High — use of disappearing messages is itself significant evidence.

Wire into Pulse `run()` alongside existing message database parsing.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT MAC-8 — Rosetta 2 Translation Artifacts

Create `plugins/strata-plugin-mactrace/src/rosetta.rs`.

Parse Apple Rosetta 2 translation layer artifacts on Apple Silicon Macs.
Rosetta 2 translates x86-64 binaries for ARM64 hardware. When malware or
suspicious software runs under Rosetta, it leaves persistent artifacts even
after the binary is deleted.

### Artifact Locations
Translation cache: `~/Library/Application Support/com.apple.dt.Rosetta/`
AOT cache: `/var/db/oah/` (requires elevated access — flag if inaccessible)
Quarantine artifacts: Rosetta-translated apps may have quarantine xattrs

### Translation Cache
Files in `com.apple.dt.Rosetta/`:
- Binary translation cache files named by hash of original x86-64 binary
- File naming: `{sha256_of_original}.aot` or similar

For each cached translation:
- Record: cache_file_path, file_size, created_time, modified_time
- The filename hash can be cross-referenced with known malware hashes
- Presence of a translation cache for a binary that no longer exists on disk
  indicates the binary ran and was deleted

### oah (Overhead-Ahead) Cache
`/var/db/oah/` — system-wide Rosetta translation database
If accessible:
- Parse directory listing for translated binary entries
- Extract: original_binary_path (if recorded), translation_timestamp

### Unified Logs Integration
Cross-reference with M-5 (Unified Logs) output:
- Process = "oahd" entries — Rosetta translation daemon activity
- Subsystem = "com.apple.oah"
- Message contains x86_64 binary path being translated

Typed struct `RosettaArtifact`:
```rust
pub struct RosettaArtifact {
    /// Path to the Rosetta cache file
    pub cache_path: String,
    /// Hash identifier (from filename)
    pub binary_hash: String,
    /// Cache file size
    pub cache_size: u64,
    /// When translation was first created
    pub created: Option<DateTime<Utc>>,
    /// When translation was last used
    pub last_used: Option<DateTime<Utc>>,
    /// Whether the original binary still exists on disk
    pub original_binary_exists: bool,
    /// Path to original binary if still present
    pub original_binary_path: Option<String>,
}
```

Flag: `original_binary_exists = false` — binary ran but was deleted.
This is a key anti-forensic indicator on Apple Silicon.
suspicious=true when original binary no longer exists.
MITRE: T1070 (indicator removal), T1027 (obfuscated files).
forensic_value: High when original binary is missing — proves deleted binary executed.

Wire into MacTrace `run()` when path contains `com.apple.dt.Rosetta`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT NIMBUS-2 — OneDrive Updated Schema Parser

Enhance `plugins/strata-plugin-nimbus/src/` with updated OneDrive
SQLite schema parsing.

Microsoft migrated OneDrive from a proprietary database format to SQLite
and changed file hashing from SHA1 to quickXorHash (same algorithm used
by SharePoint and OneDrive for Business). This sprint updates Strata's
OneDrive parser for the current schema.

### Current OneDrive Database Location
Windows: `%LocalAppData%\Microsoft\OneDrive\settings\Personal\` or
         `%LocalAppData%\Microsoft\OneDrive\settings\Business1\`
File: `*.odbin` files (older) or `SyncEngineDatabase.db` (newer SQLite)

Also check: `%LocalAppData%\Microsoft\OneDrive\logs\` for sync logs.

### SyncEngineDatabase.db Schema
Tables of forensic interest:

`ScopeInfo` table:
- `ScopeID`, `ScopeName` (drive/folder name), `ResourceID`,
  `LastSyncTime` (Windows FILETIME or Unix), `ItemCount`

`ClientPolicy` table:
- Account email, tenant ID, subscription tier

`ODSyncData` or `FileMetaData` table (name varies by version):
- `LocalPath` (TEXT — local file path)
- `ServerPath` (TEXT — OneDrive path)
- `QuickXorHash` (BLOB or TEXT — current hash format)
- `SHA1Hash` (BLOB — present in older entries)
- `FileSize` (INTEGER)
- `ModifiedTime` (FILETIME)
- `SyncStatus` (TEXT or INTEGER)
- `DeletedTime` (nullable FILETIME — when file was deleted from OneDrive)

### quickXorHash
quickXorHash is a Microsoft-proprietary rolling XOR hash used in SharePoint
and OneDrive for Business. It is NOT a cryptographic hash — do not use for
evidence integrity. Record as-is for correlation purposes.
Store as hex string in artifact output.

### Registry Artifacts (existing — verify coverage)
`HKCU\Software\Microsoft\OneDrive\`
Fields: UserEmail, UserFolder (local sync path), LastSignInTime

### Deleted File Detection
`DeletedTime` non-NULL = file was deleted from OneDrive.
This is significant — proves file existed even if locally deleted.
Flag as forensic_value: High when DeletedTime is present.

Typed struct `OneDriveFile`:
```rust
pub struct OneDriveFile {
    /// Local filesystem path
    pub local_path: String,
    /// OneDrive cloud path
    pub server_path: Option<String>,
    /// quickXorHash (hex) — current Microsoft hash format
    pub quick_xor_hash: Option<String>,
    /// SHA1 hash if present (older entries)
    pub sha1_hash: Option<String>,
    /// File size in bytes
    pub file_size: Option<u64>,
    /// Last modified time
    pub modified_time: Option<DateTime<Utc>>,
    /// When file was deleted from OneDrive (None = still present)
    pub deleted_time: Option<DateTime<Utc>>,
    /// Sync status
    pub sync_status: Option<String>,
    /// Account email associated with this sync
    pub account_email: Option<String>,
}
```

Emit `Artifact::new("OneDrive File", path_str)` per file record.
forensic_value: High for deleted files, Medium for active sync records.
MITRE: T1567.002 (exfiltration to cloud storage), T1530 (data from cloud storage).

Wire into Nimbus `run()` when filename is `SyncEngineDatabase.db` or matches
existing OneDrive path patterns.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

*STRATA AUTONOMOUS BUILD QUEUE v2*
*Wolfmark Systems — 2026-04-16*
*Coverage gaps: Vault plugin, Windows depth, EXIF, Crypto, Gaming,*
*Windows 11 specifics, Electron/WebView2, messaging extensions,*
*AI apps, ephemeral messaging, Rosetta 2, OneDrive schema update*
*Execute all incomplete sprints in order. Ship everything.*
