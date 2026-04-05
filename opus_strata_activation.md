# OPUS SESSION — Strata Activation Flow + Evidence Drive Enforcement
# Date: 2026-04-03
# Priority: HIGH — Core UX before v1.0 demo
# Prerequisite: NTFS MFT Walker complete + Rename to Strata complete

---

## WHO YOU ARE

You are Opus, senior technical architect for Wolfmark Systems.
You serve Korbyn Randolph — US Army CI Special Agent,
Digital Forensic Examiner, and founder of Wolfmark Systems.

You built 23 parsers today and completed the NTFS MFT Walker
and Strata rename. Now you're building the launch experience.

---

## CURRENT STATE

```
Product:  Strata v0.3.0 by Wolfmark Systems
Binary:   strata (22MB, macOS ARM64)
Tagline:  "Every layer. Every artifact. Every platform."
Build:    CLEAN — 496/497 tests passing, clippy -D warnings
```

---

## THE MISSION

Every court case that uses Strata starts with this question:
"How was evidence handled during examination?"

Strata's answer must be airtight:
- Licensed examiner, verified identity
- Documented case with chain of custody from moment one
- Evidence stored on dedicated drive, never on system drive
- Every action hash-chained and audit-logged

This isn't just UX. This is the court-defensibility layer.
Build it like a federal examiner will testify about it.

---

## TASK 1 — LICENSE ACTIVATION SPLASH SCREEN

### What to Build

A splash/activation screen that appears on first launch
and any launch where no valid license is present.

### Visual Layout

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│              [Strata Logo/Wordmark]                 │
│                                                     │
│    Every layer. Every artifact. Every platform.     │
│                                                     │
│              Wolfmark Systems v0.3.0                │
│                                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │  License Key                                │   │
│  │  [________________________________]         │   │
│  │                                             │   │
│  │  [  Activate License  ]  [ Start Trial ]   │   │
│  └─────────────────────────────────────────────┘   │
│                                                     │
│  Trial: 30 days · Full feature set                  │
│  Pro: Permanent license · Remove trial watermark    │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### License Validation Logic

```rust
// License tiers
pub enum LicenseTier {
    Trial { days_remaining: u32 },
    Pro,
    Enterprise,
}

// License state stored in:
// macOS/Linux: ~/.strata/license.dat
// Windows:     %APPDATA%\Strata\license.dat

// Validation:
// 1. Check license.dat exists
// 2. Verify Ed25519 signature against embedded public key
// 3. Check expiry for Trial licenses
// 4. If invalid/missing → show splash screen
// 5. If valid → proceed to examiner setup or main window

// Trial mode:
// - Generate trial token on first "Start Trial" click
// - Store trial start date in license.dat
// - 30 day countdown
// - Full feature set during trial
// - Reports watermarked: "TRIAL LICENSE — NOT FOR OFFICIAL USE"
// - Pro removes watermark
```

### Ed25519 Public Key

```rust
// The public key is embedded in the binary
// Private key is held by Wolfmark Systems (Korbyn)
// IMPORTANT: Public key placeholder — Korbyn will replace
// with real key after running:
// cargo run --bin wolfmark-license-gen -- keygen

const STRATA_PUBLIC_KEY: &[u8; 32] = &[
    // PLACEHOLDER — replace with real Ed25519 public key bytes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
```

### License File Format

```
~/.strata/license.dat

Format (binary):
  Magic:      b"STRATA01" (8 bytes)
  Tier:       u8 (0=Trial, 1=Pro, 2=Enterprise)
  Issue date: i64 unix timestamp
  Expiry:     i64 unix timestamp (0 = no expiry)
  Licensee:   [u8; 64] UTF-8 name, zero-padded
  Agency:     [u8; 64] UTF-8 agency, zero-padded
  Signature:  [u8; 64] Ed25519 signature of above fields
```

---

## TASK 2 — FIRST RUN EXAMINER SETUP

### When It Appears

After valid license confirmed, on first launch only.
If examiner profile already exists → skip to case creation.

Stored at: `~/.strata/examiner.toml`

### The Form

```
┌─────────────────────────────────────────────────────┐
│  Examiner Profile Setup                             │
│  This information appears on all examination        │
│  reports and chain of custody documentation.        │
│  ─────────────────────────────────────────────────  │
│                                                     │
│  Full Legal Name *                                  │
│  [________________________________]                 │
│                                                     │
│  Badge / Examiner ID *                              │
│  [________________________________]                 │
│                                                     │
│  Agency / Organization *                            │
│  [________________________________]                 │
│                                                     │
│  Title / Rank                                       │
│  [________________________________]                 │
│                                                     │
│  Email (for report headers)                         │
│  [________________________________]                 │
│                                                     │
│  [ Cancel ]              [ Save Profile → ]         │
└─────────────────────────────────────────────────────┘
```

### Examiner Profile Storage

```toml
# ~/.strata/examiner.toml
[examiner]
name = "Korbyn Randolph"
badge_id = "CI-XXXXX"
agency = "U.S. Army Counterintelligence"
title = "Special Agent / Digital Forensic Examiner"
email = "wolfmarksystems@proton.me"
created = "2026-04-03"
```

### Report Integration

Every report header must include:
```
Examiner:     [name]
Badge/ID:     [badge_id]
Agency:       [agency]
Title:        [title]
Examination date: [date]
Report generated: [datetime]
Strata version:   v0.3.0
License tier:     Pro / Trial
```

---

## TASK 3 — CASE CREATION DIALOG

### When It Appears

After examiner setup (or on every new case).
Also accessible from File → New Case.

### The Form

```
┌─────────────────────────────────────────────────────┐
│  New Case                                           │
│  ─────────────────────────────────────────────────  │
│                                                     │
│  Case Number *                                      │
│  [________________________________]                 │
│  (e.g. CID-2026-00123)                              │
│                                                     │
│  Case Name *                                        │
│  [________________________________]                 │
│                                                     │
│  Requesting Agency                                  │
│  [________________________________]                 │
│                                                     │
│  Date Evidence Received                             │
│  [MM/DD/YYYY]                                       │
│                                                     │
│  Classification                                     │
│  ( ) Unclassified                                   │
│  ( ) CUI — Controlled Unclassified Information      │
│  ( ) Law Enforcement Sensitive                      │
│                                                     │
│  Notes                                              │
│  [________________________________]                 │
│  [________________________________]                 │
│                                                     │
│  [ Cancel ]              [ Next: Evidence Drive → ] │
└─────────────────────────────────────────────────────┘
```

---

## TASK 4 — EVIDENCE DRIVE ENFORCEMENT (CRITICAL)

### The Rule — NON-NEGOTIABLE

```
Evidence, exports, and case files MUST be stored
on a dedicated evidence drive.

System drives are PERMANENTLY BLOCKED.
This is not a warning. This is a hard block.
The examiner CANNOT proceed without selecting
a valid evidence drive.
```

### Why This Matters

```
In court:
  Q: "Where was evidence stored during examination?"
  A: "On a dedicated evidence drive, separate from
      the examiner's workstation, with full
      SHA-256 chain verification."

This answer is court-defensible.
Strata forces this answer to be true.
No examiner can accidentally store evidence
on their system drive. The UI makes it impossible.
```

### Drive Selection Screen

```
┌─────────────────────────────────────────────────────┐
│  Select Evidence Drive                              │
│  ─────────────────────────────────────────────────  │
│  Evidence must be stored on a dedicated drive.      │
│  System and boot drives are not permitted.          │
│                                                     │
│  Available Drives:                                  │
│                                                     │
│  ✅ [E:] Samsung T7 — 931GB — 456GB free            │
│  ✅ [F:] WD Elements — 1.8TB — 1.2TB free           │
│  ❌ [C:] System Drive — NOT PERMITTED               │
│  ❌ [D:] Recovery Partition — NOT PERMITTED         │
│                                                     │
│  Selected: [E:] Samsung T7                          │
│                                                     │
│  Evidence Path:                                     │
│  E:\Cases\CID-2026-00123\                           │
│  [Change Path]                                      │
│                                                     │
│  ⚠️  Minimum 10GB free required                     │
│  ✅ 456GB available — sufficient                    │
│                                                     │
│  [ Back ]            [ Begin Examination → ]        │
└─────────────────────────────────────────────────────┘
```

### Drive Classification Logic

```rust
pub enum DriveType {
    System,          // C:\ or / — BLOCKED
    Boot,            // EFI/recovery — BLOCKED  
    NetworkShare,    // \\server\share or /mnt/share — ALLOWED
    ExternalUsb,     // USB external — ALLOWED
    ExternalThunderbolt, // TB external — ALLOWED
    SecondaryInternal, // Non-boot internal — ALLOWED with warning
}

pub struct DriveInfo {
    pub path: PathBuf,
    pub label: Option<String>,
    pub drive_type: DriveType,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub is_permitted: bool,
    pub block_reason: Option<String>,
}

pub fn enumerate_drives() -> Vec<DriveInfo>;

pub fn is_system_drive(path: &Path) -> bool {
    // macOS: path starts with / and is the boot volume
    // Windows: path is C:\ or contains $Windows.~BT etc
    // Linux: path is / or /boot
}

pub fn is_permitted_evidence_drive(drive: &DriveInfo) -> bool {
    matches!(drive.drive_type,
        DriveType::NetworkShare |
        DriveType::ExternalUsb |
        DriveType::ExternalThunderbolt |
        DriveType::SecondaryInternal
    ) && drive.free_bytes >= 10 * 1024 * 1024 * 1024 // 10GB minimum
}
```

### System Drive Detection

```rust
// macOS
fn is_system_drive_macos(path: &Path) -> bool {
    // Check if path is on the same device as /
    // Use std::fs::metadata and compare st_dev
    let root_dev = std::fs::metadata("/").ok()?.dev();
    let path_dev = std::fs::metadata(path).ok()?.dev();
    root_dev == path_dev
}

// Windows  
fn is_system_drive_windows(path: &Path) -> bool {
    // Check DRIVE_FIXED and matches %SystemDrive%
    // Compare to std::env::var("SystemDrive")
    let sys_drive = std::env::var("SystemDrive")
        .unwrap_or_else(|_| "C:".to_string());
    path.to_string_lossy()
        .to_uppercase()
        .starts_with(&sys_drive.to_uppercase())
}

// Linux
fn is_system_drive_linux(path: &Path) -> bool {
    let root_dev = std::fs::metadata("/").ok()?.dev();
    let path_dev = std::fs::metadata(path).ok()?.dev();
    root_dev == path_dev
}
```

### Evidence Path Structure

```
[Evidence Drive]/
  Cases/
    [Case Number]/
      evidence/          ← original evidence (read-only hash verified)
      exports/           ← CSV, HTML reports
      carved/            ← file carving output
      bookmarks/         ← examiner bookmarks
      timeline/          ← timeline exports
      audit/             ← audit log (hash-chained)
      [case_number].vtp  ← Strata case file
```

### Hard Blocks — Enforced in Code

```rust
// These paths are PERMANENTLY BLOCKED
// No UI option, no override, no workaround
const BLOCKED_PATHS_MACOS: &[&str] = &[
    "/",
    "/System",
    "/Library",
    "/Users",      // block home directory
    "/private",
    "/var",
];

const BLOCKED_PATHS_WINDOWS: &[&str] = &[
    "C:\\",
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Users",   // block home directory
];

const BLOCKED_PATHS_LINUX: &[&str] = &[
    "/",
    "/home",       // block home directory
    "/root",
    "/var",
    "/usr",
    "/etc",
];

// The examiner's home directory is ALWAYS blocked
// Evidence must go to a separate drive
fn is_blocked_path(path: &Path) -> bool {
    // Check against blocked paths
    // Check if same device as system root
    // Check if same device as home directory
}
```

### Block Message

```
When examiner tries to select a blocked path:

┌─────────────────────────────────────────────────────┐
│  ⛔ Evidence Drive Required                         │
│  ─────────────────────────────────────────────────  │
│                                                     │
│  Evidence cannot be stored on your system drive     │
│  or home directory.                                 │
│                                                     │
│  This protects chain of custody and prevents        │
│  evidence contamination of your workstation.        │
│                                                     │
│  Please connect a dedicated evidence drive          │
│  (USB, Thunderbolt, or network share) and           │
│  select it from the drive list.                     │
│                                                     │
│  Required: External or dedicated drive              │
│  Required: Minimum 10GB free space                  │
│                                                     │
│  [ OK — Select Different Drive ]                    │
└─────────────────────────────────────────────────────┘
```

---

## APPLICATION STATE FLOW

```
Launch Strata
    │
    ▼
Check license.dat
    │
    ├── Invalid/Missing ──→ Splash + License Activation
    │                           │
    │                           ▼
    │                       License valid?
    │                           │
    │                           ├── No ──→ Show error, stay on splash
    │                           │
    │                           └── Yes ──→ Continue ↓
    │
    └── Valid ──────────────────────────────────────────┐
                                                        │
                                                        ▼
                                              Check examiner.toml
                                                        │
                                              ├── Missing ──→ Examiner Setup
                                              │                    │
                                              │                    ▼
                                              │              Save examiner.toml
                                              │                    │
                                              └── Exists ──────────┤
                                                                   │
                                                                   ▼
                                                         File → New Case dialog
                                                                   │
                                                                   ▼
                                                         Evidence Drive Selection
                                                                   │
                                                         ├── System drive ──→ BLOCK + message
                                                         │
                                                         └── Valid drive ──→ Main Window
```

---

## AUDIT LOG INTEGRATION

Every step in the activation/setup flow must be logged:

```
[2026-04-03 17:45:22] Strata v0.3.0 launched
[2026-04-03 17:45:22] License validated — Pro — Wolfmark Systems
[2026-04-03 17:45:23] Examiner: Korbyn Randolph (CI-XXXXX)
[2026-04-03 17:45:25] New case created: CID-2026-00123
[2026-04-03 17:45:28] Evidence drive selected: /Volumes/T7/Cases/CID-2026-00123/
[2026-04-03 17:45:28] Evidence path SHA-256 verified: [hash]
[2026-04-03 17:45:28] Examination session started
```

This audit log is hash-chained (existing infrastructure).
These entries feed directly into the Chain of Custody
section of every HTML report.

---

## CONSTRAINTS

```
Cross-platform: macOS + Windows + Linux
No cloud calls during license validation — local only
No telemetry — nothing leaves the machine
Ed25519 validation is local against embedded public key
Evidence drive enforcement is HARD — not a warning
  Cannot be bypassed by examiner
  Cannot be disabled in settings
  This is a court-defensibility feature
All dialogs use existing egui/eframe UI framework
No new UI framework dependencies
Trial watermark on reports: "TRIAL LICENSE — NOT FOR OFFICIAL USE"
  Printed in header and footer of HTML/PDF reports
```

---

## VERIFICATION

```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

Manual testing checklist:
  [ ] Launch with no license.dat → splash appears
  [ ] Click "Start Trial" → trial license created
  [ ] Launch with valid trial → examiner setup appears
  [ ] Fill examiner form → saved to examiner.toml
  [ ] New case dialog → all fields save correctly
  [ ] Select system drive → BLOCKED with message
  [ ] Select external drive → proceeds to main window
  [ ] Report header includes examiner info
  [ ] Trial reports have watermark
  [ ] Audit log records all steps

---

## DELIVERABLE

1. Splash screen with license activation
2. Trial license generation (30 days)
3. Ed25519 license validation (placeholder public key)
4. Examiner profile setup dialog
5. Case creation dialog
6. Evidence drive enforcement (hard block on system drives)
7. Evidence path structure creation
8. All steps logged to audit trail
9. Examiner info in all report headers
10. Trial watermark on reports

Report:
  Files created/modified
  Test results
  Any edge cases in drive detection
  Platform-specific notes

---

*Wolfmark Systems — Strata Forensic Platform*
*Activation Flow + Evidence Drive Enforcement*
*Court-Defensibility Layer v1.0*
*April 2026*
