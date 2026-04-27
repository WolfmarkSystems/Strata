# Sprint 18 — Windows Artifact Depth: MRU + ADS + Thumbcache + LNK Deep Parse
# FOR CODEX — Read AGENTS.md before starting

_Date: 2026-04-26_
_Agent: Codex (OpenAI)_
_Approved by: KR_
_Working directory: ~/Wolfmark/strata/_

---

## Before you start

1. Read AGENTS.md completely
2. Run `git pull`
3. Run `cargo test -p strata-shield-engine --test quality_gate`
4. Run `cargo test --workspace 2>&1 | tail -5`
5. Both must pass. Baseline: 3,988 tests.

---

## Hard rules

- Zero new `.unwrap()` in production code
- Zero new `unsafe{}` without justification  
- Zero new `println!` in library code
- Quality gate must pass after every priority
- All 9 load-bearing tests must always pass
- `cargo clippy --workspace -- -D warnings` clean
- `npm run build --prefix apps/strata-ui` clean
- Do NOT use `git add -A` — stage only files you modified

---

## PRIORITY 1 — MRU Registry Keys

### Context

Most Recently Used (MRU) lists are among the highest-value Windows
forensic artifacts. They prove user interaction with specific files
and applications — critical for establishing what a user did and when.

MITRE: T1005 (Data from Local System), T1083 (File and Directory Discovery)

### Keys to parse

**OpenSavePidlMRU** — files opened/saved via Windows dialogs:
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\
```
Subkeys organized by extension (doc, pdf, exe, *):
- Each value is a Shell Item List (PIDL binary blob)
- `MRUListEx` value gives the order (DWORD array)
- Each entry resolves to a file path

**LastVisitedPidlMRU** — applications that opened files:
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU\
```
- Maps which application opened which directory
- Binary PIDL format — resolve to path + executable name

**RunMRU** — commands typed in the Run dialog:
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\
```
- Values are plain strings (REG_SZ)
- `MRUList` value gives order (letter sequence like "dcba")
- Direct command strings — often contains malicious commands

**RecentDocs** — recently accessed documents:
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\
```
- Subkeys by extension
- Binary Shell Item Lists

**TypedPaths** — URLs/paths typed in Explorer address bar:
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths\
```
- Values url1, url2... are plain REG_SZ strings
- Shows exactly what a user typed in Explorer

### Implementation

Add `mru.rs` to Phantom plugin:

```rust
pub struct MruEntry {
    pub key_type: MruKeyType,
    pub position: u32,          // order in MRU list (0 = most recent)
    pub value: String,          // resolved path or command
    pub extension: Option<String>, // for OpenSavePidlMRU
    pub application: Option<String>, // for LastVisitedPidlMRU
    pub timestamp: Option<i64>, // key LastWrite time
}

pub enum MruKeyType {
    OpenSave,
    LastVisited,
    RunMru,
    RecentDocs,
    TypedPaths,
}
```

**PIDL parsing:**
Shell Item Lists are complex binary structures. For forensic
purposes, extract the display name from each Shell Item:

```rust
fn parse_pidl_display_name(data: &[u8]) -> Option<String> {
    // Each Shell Item starts with a 2-byte size
    // Followed by type byte and data
    // For file items: look for the display name string
    // (Unicode at known offsets depending on item type)
    // Graceful failure → return None, not panic
}
```

If PIDL parsing is complex, fall back to extracting printable
Unicode strings from the blob — imperfect but better than nothing.
Document the limitation clearly in the artifact advisory.

**RunMRU is simple** — plain strings, parse directly.
**TypedPaths is simple** — plain strings, parse directly.

### Tests

```rust
#[test]
fn runmru_parses_plain_string_values() {
    // REG_SZ values → string entries in MRU order
}

#[test]
fn typedpaths_parses_url_values() {
    // url1, url2 values → path strings
}

#[test]
fn mru_order_respected_from_mrulist() {
    // MRUList "dcba" → entries ordered d, c, b, a
}

#[test]
fn pidl_parse_failure_returns_none_not_panic() {
    // Malformed PIDL data → None, no panic
}
```

### Acceptance criteria — P1

- [ ] RunMRU parsed (plain strings, ordered)
- [ ] TypedPaths parsed (url1, url2...)
- [ ] OpenSavePidlMRU parsed (at minimum display name extracted)
- [ ] RecentDocs parsed (at minimum display name extracted)
- [ ] MRU order preserved in artifact position field
- [ ] MITRE T1005 mapping
- [ ] User Activity category populated with MRU entries
- [ ] 4 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 2 — Zone.Identifier ADS Parser

### Context

Every file downloaded from the internet on Windows receives an
Alternate Data Stream called Zone.Identifier. This stream contains
the URL the file was downloaded from and the security zone.
This is critical evidence for proving a file's internet origin.

Even if a file is copied elsewhere, the ADS may persist.
Zone.Identifier proves "this file came from the internet" which
is foundational for malware investigations.

MITRE: T1105 (Ingress Tool Transfer)

### What Zone.Identifier contains

```ini
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://evil.com/malware/
HostUrl=https://evil.com/malware/payload.exe
LastWriterPackageFamilyName=Microsoft.MicrosoftEdge_...
```

ZoneId values:
- 0 = My Computer
- 1 = Local Intranet
- 2 = Trusted Sites
- 3 = Internet ← most forensically significant
- 4 = Restricted Sites

### Implementation

**Where to look:**

When walking evidence files, for each file, check if a
`:Zone.Identifier` ADS exists. On NTFS this requires reading
the MFT's attribute list for the file and finding DATA attributes
named "Zone.Identifier".

In the existing VFS/walker infrastructure, check if
`VfsEntry::list_streams()` or equivalent exists:

```bash
grep -rn "alternate_data\|zone.identifier\|stream\|ADS\|:Zone" \
    crates/ --include="*.rs" | grep -v target | head -20
```

If ADS enumeration isn't implemented, add a targeted lookup:
for each `.exe`, `.dll`, `.zip`, `.pdf`, `.doc`, `.docx`, `.ps1`
file found on evidence, attempt to read `<filename>:Zone.Identifier`
as a separate data stream.

**Parser:**

```rust
pub struct ZoneIdentifier {
    pub file_path: String,
    pub zone_id: u32,
    pub zone_name: String,      // "Internet", "Intranet", etc
    pub referrer_url: Option<String>,
    pub host_url: Option<String>,
    pub is_internet_origin: bool,  // zone_id == 3
}

pub fn parse_zone_identifier(content: &str) -> Option<ZoneIdentifier>
```

Parse the INI-format content. Handle missing fields gracefully.

**Where to wire this:**

Add to the MacTrace plugin for macOS (quarantine xattr is the
macOS equivalent) or Vector plugin for Windows evidence.

For Windows evidence: Vector plugin or a new dedicated ADS parser
in Phantom. Check what makes most architectural sense given
existing plugin ownership.

**macOS quarantine xattr (bonus):**
macOS equivalent is `com.apple.quarantine` extended attribute:
```
0083;5f8a3c2d;Safari;
```
Parse: flags;timestamp;application that downloaded

### Tests

```rust
#[test]
fn zone_identifier_zone3_detected_as_internet() {
    let content = "[ZoneTransfer]\nZoneId=3\n";
    let z = parse_zone_identifier(content).unwrap();
    assert!(z.is_internet_origin);
}

#[test]
fn zone_identifier_referrer_url_extracted() {
    let content = "[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://evil.com/\n";
    let z = parse_zone_identifier(content).unwrap();
    assert_eq!(z.referrer_url.unwrap(), "https://evil.com/");
}

#[test]
fn zone_identifier_missing_fields_handled_gracefully() {
    let content = "[ZoneTransfer]\nZoneId=3\n";
    // No ReferrerUrl → referrer_url == None, no panic
    let z = parse_zone_identifier(content);
    assert!(z.is_some());
}

#[test]
fn zone_identifier_non_internet_zone_not_flagged() {
    let content = "[ZoneTransfer]\nZoneId=1\n";
    let z = parse_zone_identifier(content).unwrap();
    assert!(!z.is_internet_origin);
}
```

### Acceptance criteria — P2

- [ ] Zone.Identifier INI parser implemented
- [ ] ZoneId → zone name mapping (0-4)
- [ ] ReferrerUrl and HostUrl extracted when present
- [ ] Internet-origin files flagged (ZoneId=3)
- [ ] MITRE T1105 mapping on internet-origin files
- [ ] Forensic value High for ZoneId=3 with URL
- [ ] macOS quarantine xattr parsed (bonus if time allows)
- [ ] 4 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 3 — Thumbcache Parser

### Context

Windows thumbnail cache stores image previews. Even after an image
file is deleted, its thumbnail may remain in the thumbcache database.
This is critical for CSAM investigations and for proving a user
viewed specific images.

Location:
```
C:\Users\<user>\AppData\Local\Microsoft\Windows\Explorer\
  thumbcache_32.db
  thumbcache_96.db
  thumbcache_256.db
  thumbcache_1024.db
  thumbcache_idx.db   ← index file linking entries to file paths
```

MITRE: T1005 (Data from Local System)

### Thumbcache database format

**Header (thumbcache_*.db):**
```
Magic: "CMMM" (4 bytes)
Format version: DWORD
Cache type: DWORD (32, 96, 256, 1024)
First entry offset: DWORD
First available offset: DWORD
Entries removed: DWORD
```

**Entry:**
```
Magic: "CMMM" (4 bytes)  
Entry size: DWORD
Entry hash: QWORD         ← links to thumbcache_idx.db
Filename hash: QWORD
Padding size: DWORD
Data size: DWORD
Width: DWORD
Height: DWORD
Checksum: QWORD
Data: [u8; data_size]    ← JPEG thumbnail bytes
```

**thumbcache_idx.db:**
Links entry hashes to original file paths (Shell Item lists).

### Implementation

```rust
pub struct ThumbcacheEntry {
    pub entry_hash: u64,
    pub cache_type: u32,      // 32, 96, 256, 1024
    pub width: u32,
    pub height: u32,
    pub data_size: u32,
    pub file_path: Option<String>,  // from idx.db if available
    pub thumbnail_data: Vec<u8>,    // JPEG bytes
}

pub fn parse_thumbcache(data: &[u8]) -> Vec<ThumbcacheEntry>
```

**What to emit as artifacts:**

For each thumbcache entry:
- Name: "Thumbnail: <filename or hash>"
- Category: User Activity
- Value: `thumbcache_<size>.db entry — <width>x<height> JPEG, <size> bytes`
- Forensic value: High (proves user viewed the image)
- Advisory: "Thumbnail exists for file that may have been deleted.
  Original file may no longer be present on the system."

**Don't embed thumbnail bytes in the artifact** — link to the
source path so the examiner can use the hex viewer to see the
raw JPEG bytes.

### Tests

```rust
#[test]
fn thumbcache_header_magic_validated() {
    // Data without "CMMM" magic → empty result, no panic
}

#[test]
fn thumbcache_entry_dimensions_parsed() {
    // Synthetic entry bytes → width/height correct
}

#[test]
fn thumbcache_advisory_present_on_all_entries() {
    // Every ThumbcacheEntry artifact → advisory_notice non-empty
}
```

### Acceptance criteria — P3

- [ ] thumbcache_*.db header magic validated
- [ ] Entry parsing: hash, dimensions, data size
- [ ] thumbcache_idx.db correlation attempted
- [ ] Artifact emitted per entry with advisory
- [ ] MITRE T1005 mapping
- [ ] Forensic value High
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 4 — LNK File Deep Parsing

### Context

LNK (Windows Shortcut) files are created automatically when a user
opens a file. They contain rich forensic data including MAC timestamps
of the target, volume serial number, and network share paths. Even
if the original file is gone, the LNK proves it existed.

Strata currently parses basic LNK target paths. This sprint adds
depth to the existing parser.

### What LNK contains (deep)

```
Shell Link Header (76 bytes):
  HeaderSize: DWORD (always 0x4C)
  LinkCLSID: GUID
  LinkFlags: DWORD
  FileAttributes: DWORD
  CreationTime: FILETIME    ← target file creation time
  AccessTime: FILETIME      ← target file last access time
  WriteTime: FILETIME       ← target file last write time
  FileSize: DWORD           ← target file size
  
LinkInfo structure:
  VolumeID:
    DriveType: DWORD (removable, fixed, network, etc)
    DriveSerialNumber: DWORD  ← CRITICAL for device tracking
    VolumeLabelOffset: DWORD
    VolumeLabel: string
  LocalBasePath: string     ← full local path to target
  CommonNetworkRelativeLinkOffset:
    NetworkShareName: string  ← UNC path if network share
    
StringData:
  NameString: string        ← description
  RelativePath: string
  WorkingDir: string
  CommandLineArguments: string  ← arguments passed to target
  IconLocation: string
```

### Investigation first

```bash
grep -rn "lnk\|LNK\|\.lnk\|shortcut" \
    plugins/ --include="*.rs" | grep -v target | head -20
```

Find the existing LNK parser. Extend it with the missing fields.

### What to add

From the existing parser, add:
1. **Target MAC timestamps** (CreationTime, AccessTime, WriteTime)
   from the Shell Link Header — proves when the target file existed
2. **Drive serial number** — cross-correlate with USBSTOR to prove
   which USB device a file came from
3. **Drive type** — was it a removable drive? Network share?
4. **Network share path** — UNC path if file was on a network share
5. **Command line arguments** — what args were passed to the target
6. **Target file size** — useful even after deletion

### Tests

```rust
#[test]
fn lnk_creation_time_extracted_from_header() {
    // Known LNK bytes → CreationTime FILETIME → Unix timestamp
}

#[test]
fn lnk_drive_serial_extracted() {
    // Known LNK bytes → drive serial number string
}

#[test]
fn lnk_removable_drive_flagged() {
    // DriveType == DRIVE_REMOVABLE → flagged in artifact
}

#[test]
fn lnk_network_share_path_extracted() {
    // LNK with network target → network_share_path populated
}
```

### Acceptance criteria — P4

- [ ] Target MAC timestamps (create/access/write) in artifacts
- [ ] Drive serial number extracted
- [ ] Drive type (removable/fixed/network) labeled
- [ ] Network share path extracted when present
- [ ] Command line arguments captured
- [ ] Target file size captured
- [ ] Cross-reference note when serial matches known USB device
- [ ] 4 new tests pass
- [ ] Quality gate passes

---

## After all priorities complete

```bash
cargo test --workspace 2>&1 | grep "test result" | grep "passed" | \
    awk -F' ' '{sum += $4} END {print sum " total passing"}'
cargo test -p strata-shield-engine --test quality_gate 2>&1 | tail -3
cargo clippy --workspace -- -D warnings 2>&1 | grep "^error" | head -5
npm run build --prefix apps/strata-ui 2>&1 | tail -3
```

Stage only Sprint 18 files:
```bash
git add <only files you modified>
git commit -m "feat: sprint-18 MRU registry + Zone.Identifier ADS + Thumbcache + LNK depth"
```

Report:
- Which priorities passed
- Test count before (3,988) and after
- If limit reached, document stopping point in commit message
- Any deviations from spec

---

_Sprint 18 for Codex — read AGENTS.md first_
_KR approval: granted_
_4 priorities — P1 and P2 are highest value._
_P3 and P4 if time/limit allows._
_Document stopping point clearly if limit reached._
