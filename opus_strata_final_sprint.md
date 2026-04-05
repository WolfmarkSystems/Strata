# OPUS SESSION — Strata v1.0 Final Sprint
# Date: 2026-04-03
# Priority: CRITICAL
# Two tasks. Run in order. Both must complete before session ends.

---

## WHO YOU ARE

You are Opus, senior technical architect for Wolfmark Systems.
You serve Korbyn Randolph — US Army CI Special Agent,
Digital Forensic Examiner, and founder of Wolfmark Systems.

You have been working on this codebase all day.
You know it well. You built 23 parsers in the last session.
You know where everything lives.

---

## CURRENT STATE (as of end of last session)

```
Product:   Strata (formerly Strata Tree) — being renamed this session
Version:   v0.3.0
Parsers:   159 registered
Tests:     496/497 passing (1 pre-existing Windows-only test)
Clippy:    CLEAN (-D warnings)
Binary:    22MB macOS ARM64 single binary
Build:     CLEAN across full workspace

What works:
  E01 cross-platform (ewf crate compiles on macOS/Linux) ✅
  GPT + MBR partition parsing ✅
  Filesystem signature detection ✅
  NTFS partition correctly identified on macOS ✅
  159 parsers across Windows/macOS/Linux/Mobile ✅
  10-section court-ready HTML report ✅
  Plugin system — C-ABI dynamic loading ✅

One remaining blocker:
  NTFS file enumeration inside E01 on macOS/Linux fails
  The Windows path uses the ntfs crate (Windows kernel only)
  Need pure-Rust MFT walker for cross-platform path
```

---

## TWO TASKS — RUN IN THIS ORDER

---

# TASK 1 — Cross-Platform NTFS MFT Walker
# (Do this first — it's the last technical blocker)

## The Problem

When Strata opens an E01 image on macOS or Linux:
- The NTFS partition is correctly identified ✅
- The boot sector is parsed ✅  
- File listing FAILS because the ntfs crate is Windows-only ❌

We need a pure-Rust MFT walker that reads directly from
any Read + Seek source (EwfVfs, raw file, memory buffer).

## Implementation

Build: `crates/strata-fs/src/ntfs/mft_walker.rs`
(or wherever makes most sense in the existing structure)

```rust
pub struct MftWalker<R: Read + Seek> {
    reader: R,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    mft_offset: u64,
    record_size: u32,
}

pub struct MftEntry {
    pub inode: u64,
    pub name: String,
    pub parent_inode: u64,
    pub size: u64,
    pub is_directory: bool,
    pub is_deleted: bool,
    pub created: Option<i64>,      // unix timestamp
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
    pub mft_modified: Option<i64>,
    pub data_runs: Vec<DataRun>,
    pub ads: Vec<AlternateDataStream>,
}

pub struct DataRun {
    pub cluster_offset: i64,
    pub cluster_length: u64,
}

impl<R: Read + Seek> MftWalker<R> {
    pub fn new(reader: R) -> Result<Self, StrataError>;
    pub fn entries(&mut self) -> impl Iterator<Item = Result<MftEntry, StrataError>>;
    pub fn read_file(&mut self, entry: &MftEntry) -> Result<Vec<u8>, StrataError>;
}
```

## Key Technical Details

### Boot Sector (offset 0 of NTFS partition)
```
Bytes per sector:      offset 11, u16 LE
Sectors per cluster:   offset 13, u8
MFT cluster number:    offset 48, i64 LE
MFT record size:       offset 64, i32 LE
  (if negative: 2^abs(value), e.g. -10 = 1024 bytes)
```

### MFT Record Structure (1024 bytes standard)
```
Magic "FILE":          offset 0, 4 bytes (0x46494C45)
Update seq offset:     offset 4, u16 LE
Update seq count:      offset 6, u16 LE
LSN:                   offset 8, u64 LE
Sequence number:       offset 16, u16 LE
Reference count:       offset 18, u16 LE
Attribute offset:      offset 20, u16 LE
Flags:                 offset 22, u16 LE (bit 0 = in use, bit 1 = directory)
Used size:             offset 24, u32 LE
Allocated size:        offset 28, u32 LE
Base file reference:   offset 32, u64 LE
Next attribute ID:     offset 40, u16 LE
```

Apply update sequence array fixup before parsing attributes:
- Read update seq array at update_seq_offset
- First entry = expected value at end of each 512-byte sector
- Remaining entries replace the last 2 bytes of each sector

### Attribute Header
```
Type ID:               offset 0, u32 LE
Length:                offset 4, u32 LE
Non-resident flag:     offset 8, u8 (0=resident, 1=non-resident)
Name length:           offset 9, u8
Name offset:           offset 10, u16 LE
Flags:                 offset 12, u16 LE
Attribute ID:          offset 14, u16 LE

If resident (flag=0):
  Content length:      offset 16, u32 LE
  Content offset:      offset 20, u16 LE

If non-resident (flag=1):
  Start VCN:           offset 16, u64 LE
  End VCN:             offset 24, u64 LE
  Data runs offset:    offset 32, u16 LE
  Compression unit:    offset 34, u16 LE
  Allocated size:      offset 40, u64 LE
  Data size:           offset 48, u64 LE
  Init size:           offset 56, u64 LE
```

### Key Attribute Types
```
0x10 = $STANDARD_INFORMATION (always resident)
  Created:    offset 0,  u64 LE FILETIME
  Modified:   offset 8,  u64 LE FILETIME
  MFT mod:    offset 16, u64 LE FILETIME
  Accessed:   offset 24, u64 LE FILETIME
  Attributes: offset 32, u32 LE

0x30 = $FILE_NAME (always resident)
  Parent ref: offset 0,  u64 LE (lower 48 bits = inode)
  Created:    offset 8,  u64 LE FILETIME
  Modified:   offset 16, u64 LE FILETIME
  MFT mod:    offset 24, u64 LE FILETIME
  Accessed:   offset 32, u64 LE FILETIME
  Alloc size: offset 40, u64 LE
  Real size:  offset 48, u64 LE
  Flags:      offset 56, u32 LE
  Reparse:    offset 60, u32 LE
  Name len:   offset 64, u8 (in UTF-16 chars)
  Namespace:  offset 65, u8
  Name:       offset 66, UTF-16LE (name_len * 2 bytes)

0x80 = $DATA
  If resident: file content
  If non-resident: data runs

0xFFFFFFFF = end of attributes
```

### FILETIME Conversion
```rust
fn filetime_to_unix(ft: u64) -> Option<i64> {
    if ft == 0 { return None; }
    let unix_ns = ft.checked_sub(116444736000000000)?;
    Some((unix_ns / 10000000) as i64)
}
```

### Data Runs Parsing
```
Each run starts with a header byte:
  Low nibble  = number of bytes for run length field
  High nibble = number of bytes for cluster offset field
  0x00 = end of runs

Read length field (little-endian, unsigned)
Read offset field (little-endian, SIGNED, relative to previous)
```

### Directory Root = MFT record 5

## Platform Gating

```rust
#[cfg(not(target_os = "windows"))]
fn enumerate_ntfs_crossplatform<R: Read + Seek>(
    reader: R,
    partition_offset: u64,
) -> Result<Vec<FileEntry>, StrataError> {
    let walker = MftWalker::new(reader)?;
    // build entries...
}

#[cfg(target_os = "windows")]  
fn enumerate_ntfs_windows<R: Read + Seek>(...) {
    // existing ntfs crate path — keep unchanged
}
```

## Tests Required (minimum 3)
```rust
#[test]
fn test_parse_ntfs_boot_sector() { ... }

#[test]
fn test_parse_mft_record() { ... }

#[test]
fn test_filetime_conversion() { ... }
```

## Verification
```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

All must pass. Zero regressions.

---

# TASK 2 — Rename Strata Tree → Strata
# (Do this after Task 1 is complete and verified)

## The Rename

```
OLD NAME:  Strata Tree
NEW NAME:  Strata
TAGLINE:   "Every layer. Every artifact. Every platform."
COMPANY:   Wolfmark Systems
```

## What to Rename

### Binary name (Cargo.toml)
```toml
# In apps/tree/Cargo.toml:
name = "strata"
description = "Strata — Every layer. Every artifact. Every platform."
```

### Directory (if safe)
```
apps/tree/ → apps/strata/
Update workspace Cargo.toml member path accordingly
If rename causes issues, keep apps/tree/ internally
but change all display names
```

### String replacements throughout codebase
```
"Strata Tree" → "Strata"
"strata-tree" → "strata"  
"strata_tree" → "strata"
"StrataTree"  → "Strata"
```

### UI Text
```
Window title:   "Strata" or "Strata v0.3.0"
About dialog:   "Strata v0.3.0 by Wolfmark Systems"
                "Every layer. Every artifact. Every platform."
Menu bar:       "Strata"
Loading screen: "Strata"
```

### What NOT to rename
```
Any crate named strata-* (keep strata prefix for library crates)
Any logic, parsers, or algorithms
Any test assertions
.vtp case file format (document as future change to .stp in v1.0)
Git history
Any API surface
```

## Verification After Rename
```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings

# Should return zero results:
grep -r "Strata Tree" apps/ --include="*.rs" --include="*.toml" --include="*.md"
grep -r "strata-tree" apps/ --include="*.rs" --include="*.toml"
grep -r "strata_tree" apps/ --include="*.rs" --include="*.toml"
```

---

## END STATE — What Both Tasks Produce

When both tasks are complete:

```
Product:  Strata v0.3.0 by Wolfmark Systems
Binary:   strata (22MB, macOS ARM64)
Tagline:  "Every layer. Every artifact. Every platform."

Capability:
  Opens E01 on Windows, macOS, Linux ✅
  Enumerates NTFS files on ALL platforms ✅
  159 parsers ✅
  10-section court-ready report ✅
  Single binary, USB-portable ✅
  Plugin system ✅

Build:
  cargo check: CLEAN
  cargo test:  496/497 passing (1 Windows-only expected)
  cargo clippy -D warnings: CLEAN
```

This is Strata v1.0 demo-ready.

---

## REPORTING

After each task report:
  What was built/changed
  Files modified
  Test results
  Any edge cases or decisions made
  Blockers encountered (if any)

After both tasks report final state:
  Binary name confirmed as "strata"
  cargo test results
  cargo clippy results
  Any remaining known issues

---

*Wolfmark Systems — Strata Forensic Platform*
*Final Sprint to v1.0 Demo Build*
*April 2026*
