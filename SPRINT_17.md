# Sprint 17 — AmCache + USB Chain + EVTX Analytics + Timeline Export
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
5. Both must pass. Baseline: 3,978 tests.

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

## PRIORITY 1 — AmCache.hve Parser

### Context

AmCache.hve is one of the highest-value Windows execution artifacts.
It records every program that ran on the system with SHA-1 hash,
file path, compile time, and first execution time. Unlike ShimCache,
AmCache contains the actual file hash — enabling malware identification
even after deletion.

MITRE: T1059 (execution), T1070.004 (file deletion indicator)

### Investigation first

```bash
grep -rn "amcache\|AmCache\|am_cache" \
    plugins/ --include="*.rs" | grep -v target | head -10
```

If AmCache is already partially implemented, extend it.
If not, add to the Phantom plugin (Windows registry specialist).

### What AmCache contains

AmCache.hve is a registry hive at:
`C:\Windows\AppCompat\Programs\Amcache.hve`

Key paths:
```
Root\InventoryApplicationFile\  — file execution entries
  Each subkey name = SHA-1 hash of file
  Values:
    FileId       — SHA-1 hash (with leading zeros trimmed)
    LowerCaseLongPath — full file path
    ProductName  — product name string
    CompanyName  — publisher
    FileVersion  — version string
    LinkDate     — PE compile timestamp (hex FILETIME)
    LastModified — last write time of hive key (FILETIME)
    ProgramId    — links to InventoryApplication

Root\InventoryApplication\  — installed program entries
  Each subkey = program GUID
  Values:
    Name, Publisher, Version, InstallDate, RootDirPath
```

### Implementation

Add `amcache.rs` to the Phantom plugin:

```rust
pub struct AmCacheEntry {
    pub sha1_hash: String,
    pub file_path: String,
    pub product_name: String,
    pub company_name: String,
    pub file_version: String,
    pub compile_time: Option<i64>,    // from LinkDate FILETIME
    pub first_run: Option<i64>,       // from key LastModified
    pub is_deleted: bool,             // path no longer exists on disk
}
```

For each `InventoryApplicationFile` subkey:
1. Extract SHA-1 from subkey name
2. Parse all value fields
3. Convert LinkDate (hex FILETIME string) to Unix timestamp
4. Emit artifact with MITRE T1059

**Deleted file detection:**
If the file path no longer exists on the evidence image, set
`is_deleted: true` and add MITRE T1070.004 — this is evidence
of execution AND deletion, which is highly suspicious.

### Tests

```rust
#[test]
fn amcache_sha1_extracted_from_subkey_name() {
    // Subkey "0000abcdef..." → sha1_hash == "abcdef..."
    // (leading zeros stripped per AmCache format)
}

#[test]
fn amcache_linkdate_converts_from_filetime_hex() {
    // "01D9A3B2C4E5F678" → correct Unix timestamp
}

#[test]
fn amcache_deleted_file_gets_mitre_t1070() {
    // Entry with path that doesn't exist on evidence
    // → is_deleted = true, mitre includes T1070.004
}

#[test]
fn amcache_produces_high_forensic_value() {
    // All AmCache entries → forensic_value = High
}
```

### Acceptance criteria — P1

- [ ] AmCache.hve parsed via nt-hive (already used by Phantom)
- [ ] SHA-1 hash extracted per entry
- [ ] File path, product name, company parsed
- [ ] LinkDate FILETIME → Unix timestamp
- [ ] Deleted file detection with T1070.004
- [ ] Execution History category populated with AmCache entries
- [ ] 4 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 2 — Full USB Device Artifact Chain

### Context

USB device insertion is one of the most common evidence types
in insider threat and data exfiltration cases. Strata partially
handles USB artifacts but misses several key registry keys that
together tell the complete USB story.

The complete USB chain requires data from FIVE registry locations:

```
1. USBSTOR — device identity
   HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\
   → Vendor, Product, Serial, ClassGUID

2. USB — driver info  
   HKLM\SYSTEM\CurrentControlSet\Enum\USB\
   → VID/PID, hardware IDs

3. MountedDevices — drive letter assignment
   HKLM\SYSTEM\MountedDevices
   → Which drive letter the USB got

4. MountPoints2 — user-specific mount history
   HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\
   → Volume GUIDs user connected to

5. SetupAPI logs — first connection timestamp
   C:\Windows\INF\setupapi.dev.log
   → Exact first insertion date/time (text log, not registry)
```

### Investigation first

```bash
grep -rn "USBSTOR\|usb\|USB\|MountedDevices\|MountPoints" \
    plugins/strata-plugin-phantom/src/ \
    --include="*.rs" | grep -v target | head -20
```

Find what USB parsing already exists in Phantom. Build on it.

### Implementation

**Cross-correlate all 5 sources:**

```rust
pub struct UsbDeviceRecord {
    pub vendor: String,
    pub product: String,
    pub serial: String,
    pub vid_pid: String,            // "VID_0781&PID_5583"
    pub drive_letter: Option<String>, // "E:"
    pub volume_guid: Option<String>,
    pub first_insert: Option<i64>,  // from setupapi.dev.log
    pub last_insert: Option<i64>,   // from USBSTOR key LastWrite
    pub user_connected: Vec<String>, // from MountPoints2 user hives
}
```

Emit one artifact per unique USB device (by serial number),
correlating all available data sources.

**SetupAPI log parsing:**
The setupapi.dev.log is a text file. Parse lines matching:
```
>>>  [Device Install (Hardware initiated) - USBSTOR\...]
>>>  Section start 2025/11/04 17:19:08.123
```
Extract the timestamp from the "Section start" line following
a USBSTOR device install entry.

### Tests

```rust
#[test]
fn usb_serial_extracted_from_usbstor_key() {
    // USBSTOR key name → serial number parsed
}

#[test]
fn setupapi_timestamp_parsed_correctly() {
    // Known log line → correct Unix timestamp
}

#[test]
fn usb_records_deduplicated_by_serial() {
    // Same serial in USBSTOR + MountPoints2 → one UsbDeviceRecord
}
```

### Acceptance criteria — P2

- [ ] USBSTOR key parsed (vendor, product, serial)
- [ ] MountedDevices correlated (drive letter)
- [ ] MountPoints2 parsed (user-specific history)
- [ ] SetupAPI log parsed (first insertion timestamp)
- [ ] Records deduplicated by serial number
- [ ] Single comprehensive USB artifact per device
- [ ] MITRE T1091 (replication through removable media)
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 3 — EVTX Structured Analytics

### Context

The Sentinel plugin currently processes Windows Event Logs (EVTX)
but extracts raw events. What examiners need is structured analytics
— not "here are 50,000 events" but "here are the 12 events that
actually matter for this investigation."

### High-value EVTX event IDs to surface

**Authentication events (Security.evtx):**
- 4624 — Successful logon (Type 2=interactive, Type 3=network, Type 10=remote)
- 4625 — Failed logon attempt
- 4634/4647 — Logoff
- 4648 — Logon with explicit credentials (pass-the-hash indicator)
- 4672 — Special privileges assigned (admin logon)
- 4720 — User account created
- 4726 — User account deleted
- 4732 — Member added to security group

**System events (System.evtx):**
- 6005 — Event log service started (system boot)
- 6006 — Event log service stopped (system shutdown)
- 7045 — New service installed (persistence indicator)
- 7040 — Service start type changed

**Application events:**
- 1102 — Audit log cleared (anti-forensics indicator — CRITICAL)
- 104  — System log cleared

**PowerShell (Microsoft-Windows-PowerShell/Operational.evtx):**
- 4103 — Pipeline execution
- 4104 — Script block logging
- 4688 — New process created (with command line if audited)

### Implementation

Extend Sentinel plugin to emit structured artifacts for these
specific event IDs rather than raw event dumps:

```rust
pub struct EvtxAnalytic {
    pub event_id: u32,
    pub channel: String,         // "Security", "System", etc
    pub timestamp: i64,
    pub computer: String,
    pub subject_username: Option<String>,
    pub subject_domain: Option<String>,
    pub logon_type: Option<u32>,  // for 4624/4625
    pub target_username: Option<String>,
    pub source_ip: Option<String>,
    pub process_name: Option<String>,
    pub command_line: Option<String>,
    pub significance: String,    // human-readable explanation
    pub mitre_technique: String,
}
```

**Special handling for log cleared (1102/104):**
These are CRITICAL — mark with `forensic_value: Critical`,
emit a prominent advisory: "Event log was cleared. Prior events
may be unrecoverable. This is a common anti-forensics technique."

### Tests

```rust
#[test]
fn evtx_4624_logon_type_extracted() {
    // Event 4624 XML → logon_type parsed correctly
}

#[test]
fn evtx_1102_audit_cleared_is_critical() {
    // Event 1102 → forensic_value == Critical
    // advisory_notice contains "anti-forensics"
}

#[test]
fn evtx_analytics_filter_to_high_value_ids_only() {
    // Feed 100 events with mixed IDs
    // Only the high-value IDs produce EvtxAnalytic artifacts
}
```

### Acceptance criteria — P3

- [ ] 15+ high-value event IDs parsed structurally
- [ ] 4624 logon type extracted and labeled
- [ ] 4625 failed logon with source IP
- [ ] 1102/104 log cleared marked Critical with anti-forensics advisory
- [ ] 7045 new service marked as persistence indicator
- [ ] 4104 PowerShell script block content captured
- [ ] MITRE techniques mapped per event type
- [ ] 3 new tests pass
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

Stage only Sprint 17 files:
```bash
git add <only files you modified>
git commit -m "feat: sprint-17 AmCache + USB device chain + EVTX analytics"
```

Report:
- Which priorities passed
- Test count before (3,978) and after
- Any deviations from spec
- If Codex limit reached, document exactly where it stopped

---

_Sprint 17 for Codex — read AGENTS.md first_
_KR approval: granted_
_If you hit your limit mid-sprint, commit what passed and document_
_the stopping point clearly in the commit message._
