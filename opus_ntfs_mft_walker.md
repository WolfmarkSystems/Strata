# OPUS TASK — Cross-Platform NTFS MFT Walker
# Priority: CRITICAL — Last major blocker before Strata v1.0 demo
# Date: 2026-04-03

---

## CONTEXT

Strata (formerly Strata Tree) is a court-defensible digital forensic
examination platform. Single binary, 22MB, USB-portable, cross-platform.

Current state:
  Build:   CLEAN — 496/497 tests passing, clippy -D warnings
  Binary:  22MB macOS ARM64
  E01:     Cross-platform — ewf crate compiles on macOS/Linux ✅

The one remaining critical blocker:

```
NTFS file enumeration inside E01 images on macOS/Linux returns
the NTFS partition correctly identified but file listing fails.

The Windows path uses the native `ntfs` crate which is
Windows-only (requires Windows kernel APIs).

We need a pure-Rust MFT enumeration path for EwfVfs
on macOS/Linux that does NOT use the ntfs crate.
```

When this is fixed:
  Strata opens any E01 image on Mac or Linux
  Walks the NTFS filesystem natively
  Full examination capability on any platform
  No Windows dependency for core examination
  Strata becomes the first cross-platform
  NTFS-capable forensic tool as a single binary

---

## THE TASK

Build a pure-Rust cross-platform NTFS MFT walker that:

1. Works on macOS and Linux (and Windows)
2. Does NOT depend on the Windows-only `ntfs` crate
3. Reads directly from the EwfVfs byte stream
4. Parses the MFT ($MFT) to enumerate files
5. Extracts the same data as the Windows path:
   - File name
   - File size
   - Created/Modified/Accessed/MFT timestamps (all 4)
   - Is directory flag
   - Is deleted flag (record in use bit)
   - Parent reference (for tree building)
   - Data runs (for file extraction)
   - Alternate Data Streams
   - File attributes ($SI and $FN)

---

## TECHNICAL APPROACH

### Step 1 — Locate $MFT

NTFS boot sector is at offset 0 of the partition.
Boot sector contains:
  - Bytes per sector (usually 512)
  - Sectors per cluster
  - MFT cluster offset (bytes_per_sector * sectors_per_cluster * mft_lcn)

Parse the boot sector to find $MFT location.

### Step 2 — Parse MFT Records

Each MFT record is 1024 bytes (standard) or as specified in boot sector.
Record structure:
  - Magic: "FILE" (0x46494C45)
  - Update sequence array offset + size
  - Log file sequence number
  - Sequence number
  - Reference count
  - Attribute offset
  - Flags (in use, directory)
  - Used size, allocated size
  - Base file reference
  - Next attribute ID

Apply fixup (update sequence array) before parsing attributes.

### Step 3 — Parse Attributes

Walk attributes from attribute offset until type 0xFFFFFFFF.
Each attribute:
  - Type ID (u32)
  - Length (u32)
  - Non-resident flag (u8)
  - Name length (u8)
  - Name offset (u16)
  - Flags (u16)
  - Attribute ID (u16)

Resident attribute: data immediately follows header
Non-resident attribute: has data runs describing disk location

Key attribute types:
  0x10 ($STANDARD_INFORMATION) — timestamps, flags
  0x30 ($FILE_NAME)            — filename, parent ref, timestamps
  0x80 ($DATA)                 — file data / data runs
  0x90 ($INDEX_ROOT)           — directory index
  0xA0 ($INDEX_ALLOCATION)     — directory index allocation

### Step 4 — Parse $STANDARD_INFORMATION (0x10)

At resident data offset:
  - Created time (FILETIME u64) — offset 0
  - Modified time (FILETIME u64) — offset 8
  - MFT modified time (FILETIME u64) — offset 16
  - Accessed time (FILETIME u64) — offset 24
  - File attributes (u32) — offset 32

FILETIME conversion:
  unix_seconds = (filetime - 116444736000000000) / 10000000

### Step 5 — Parse $FILE_NAME (0x30)

At resident data offset:
  - Parent directory reference (u64, lower 48 bits = inode)
  - Created time (FILETIME u64)
  - Modified time (FILETIME u64)
  - MFT modified time (FILETIME u64)
  - Accessed time (FILETIME u64)
  - Allocated size (u64)
  - Real size (u64)
  - Flags (u32)
  - Reparse tag (u32)
  - Filename length (u8, in UTF-16 chars)
  - Filename namespace (u8)
  - Filename (UTF-16LE, length * 2 bytes)

### Step 6 — Parse Data Runs (for non-resident $DATA)

Data runs encode the disk location of file data.
Each run:
  - Header byte: low nibble = length field size, high nibble = offset field size
  - Length: run length in clusters (little-endian, length field size bytes)
  - Offset: cluster offset (signed, relative to previous run)
  - Header byte 0x00 = end of runs

### Step 7 — Build File Tree

Use parent references from $FILE_NAME to build directory tree.
Root directory is always MFT record 5.
Walk from record 5 outward to build full path for each file.

---

## IMPLEMENTATION REQUIREMENTS

```rust
// Target: crates/strata-fs/src/parsers/ntfs_mft.rs
// OR: crates/strata-fs/src/ntfs/mft_walker.rs

// Must compile on:
//   #[cfg(target_os = "windows")]
//   #[cfg(target_os = "macos")]  
//   #[cfg(target_os = "linux")]

// Input: anything that implements Read + Seek
// (works with EwfVfs, raw files, memory buffers)

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

---

## INTEGRATION POINTS

Once the MftWalker is built, integrate it into:

```
1. crates/strata-fs/src/lib.rs
   Add MftWalker to public API

2. apps/strata/src/vfs/ewf_vfs.rs (or equivalent)
   When platform is NOT Windows AND filesystem is NTFS:
   Use MftWalker instead of ntfs crate

3. The platform gate should look like:
   #[cfg(not(target_os = "windows"))]
   fn enumerate_ntfs(reader: impl Read + Seek) -> ... {
       MftWalker::new(reader)?.entries()...
   }
   
   #[cfg(target_os = "windows")]
   fn enumerate_ntfs(...) -> ... {
       // existing ntfs crate path
   }
```

---

## CONSTRAINTS

- Pure Rust — no C FFI, no unsafe unless absolutely necessary
  (fixup application may need a small unsafe block — document it)
- No new crates beyond what's already in Cargo.toml
  If a new crate is needed, prefer:
    byteorder (already likely present)
    encoding_rs (for UTF-16)
  Do NOT add ntfs, windows-sys, or any Windows-specific crate
- Must return StrataError on failure — no panic!, no unwrap()
- All timestamps must handle edge cases:
    FILETIME of 0 → return None
    FILETIME before 1970 → return None or negative unix ts
    FILETIME far future (> year 2100) → flag as suspicious
- Deleted files: record the in-use bit, surface deleted entries
  This is critical for forensic value

---

## VERIFICATION

After implementation run:

```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

All must pass clean.

Then test manually:
  Create a small test NTFS image (or use a fixture)
  Enumerate files and verify names/timestamps match
  expected values

---

## DELIVERABLE

1. MftWalker implementation — pure Rust, cross-platform
2. Integration into EwfVfs path for non-Windows platforms
3. At least 3 unit tests:
   - Parse boot sector and locate $MFT
   - Parse a single MFT record with $FILE_NAME
   - Build a simple directory tree from multiple records
4. cargo check + cargo test + cargo clippy all passing
5. Report: what was built, what was tested, any edge cases noted

This is the last major blocker before Strata v1.0 demo build.
Make it count.

---

*Wolfmark Systems — Strata Forensic Platform*
*NTFS Cross-Platform Implementation*
*April 2026*
