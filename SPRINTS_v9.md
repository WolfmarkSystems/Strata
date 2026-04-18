# SPRINTS_v9.md — STRATA EVIDENCE INGESTION SUPER SPRINT
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md and SPRINTS_v9.md. Execute all incomplete sprints in order.
#         For each sprint: implement, test, commit, then move to the next."
# Last updated: 2026-04-18
# Prerequisite: SPRINTS_v1.md through SPRINTS_v8.md complete (3,574 tests passing)
#
# THIS IS THE CRITICAL SPRINT QUEUE. Without this, Strata is not a forensic tool.
#
# ═══════════════════════════════════════════════════════════════════════
# THE PROBLEM
# ═══════════════════════════════════════════════════════════════════════
#
# Real-world testing on 2026-04-18 revealed that while Strata has 26
# functional plugin parsers (3,574 unit tests passing), it cannot actually
# ingest forensic evidence images. Specifically:
#
# 1. E01/EWF files: plugins receive the path as a binary blob. They walk
#    the "directory" looking for files like SYSTEM hive, find nothing
#    (because E01 is one opaque binary), return 0 artifacts cleanly.
#    Full pipeline runs in 41ms with 4 total artifacts across 22 plugins.
#
# 2. RAW/DD images: same issue. No partition walker, no filesystem mount.
#
# 3. VMDK/VHD/VHDX: same issue.
#
# 4. Only pre-extracted directory trees work (Takeout, unpacked tarballs).
#    These represent <10% of real casework.
#
# 5. The "506/506 plugin runs green" validation metric has been measuring
#    "plugin executed without error" rather than "plugin extracted real
#    artifacts from real evidence." This must change.
#
# ROOT CAUSE: The `run_all_on_path` dispatcher passes the raw evidence
# path directly to each plugin. Plugins walk whatever is at that path
# with std::fs. There is no evidence image layer that opens the E01,
# parses partitions, mounts filesystems, and presents a walkable root.
#
# CONSEQUENCE: 90% of forensic casework (which arrives as E01/RAW/DD)
# cannot be processed by Strata today. This must be fixed before any
# further parser work is meaningful.
#
# ═══════════════════════════════════════════════════════════════════════
# THE MISSION
# ═══════════════════════════════════════════════════════════════════════
#
# Build the evidence ingestion layer that makes all 26 plugins actually
# work against real forensic images. When this queue completes:
#
# - Examiner runs: strata ingest run --source case.E01 --case-dir ./case
# - Strata opens the E01 via libewf
# - Strata identifies partitions via MBR/GPT walker
# - Strata opens each partition via pure-Rust filesystem walkers (NTFS,
#   APFS, ext4, exFAT, FAT32)
# - Strata presents a unified VirtualFilesystem (VFS) to plugins
# - Plugins walk the VFS, find real SYSTEM hives, real sms.db, real
#   Photos.sqlite, and produce real artifacts
# - Artifacts persist to case SQLite database
# - Examiner opens the case and sees thousands of real findings
#
# This is pure-Rust architecturally. NO libfuse, NO macFUSE, NO kernel
# extensions, NO sudo, NO platform-specific mounting. Pure userspace
# read-only virtualfilesystem on top of raw bytes.
#
# ═══════════════════════════════════════════════════════════════════════
# THE SCOPE
# ═══════════════════════════════════════════════════════════════════════
#
# 22 sprints across 7 parts:
#
# Part 1 — Evidence image readers (E01, RAW, VMDK, VHD) ............ 5 sprints
# Part 2 — Partition table walkers (MBR + GPT) ..................... 2 sprints
# Part 3 — Pure-Rust filesystem walkers (NTFS, APFS, ext4, FAT) .... 5 sprints
# Part 4 — VirtualFilesystem abstraction + plugin rewiring ......... 4 sprints
# Part 5 — Artifact persistence (actually write to SQLite) ......... 2 sprints
# Part 6 — Ground truth validation against known datasets .......... 2 sprints
# Part 7 — Regression validation of all previous v6/v7/v8 work ..... 2 sprints
#
# When this queue is complete, Strata can actually be used in casework.

---

## HOW TO EXECUTE

Read CLAUDE.md first. Then execute each sprint below in order.
For each sprint:
1. Implement exactly as specified
2. Run `cargo test --workspace` — all tests must pass (starting from 3,574)
3. Run `cargo clippy --workspace -- -D warnings` — must be clean
4. Verify zero `.unwrap()`, zero `unsafe{}`, zero `println!` added
5. Commit with message: "feat: [sprint-id] [description]" or "fix: [sprint-id] [description]"
6. Move to next sprint immediately

This queue has HIGHER priority than any previous queue because without
evidence ingestion working, Strata is not a forensic tool regardless of
how many plugins it has.

---

## COMPLETED SPRINTS (skip these)

None yet — this is v9.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 1 — EVIDENCE IMAGE READERS
# ═══════════════════════════════════════════════════════════════════════

## SPRINT EVIDENCE-1 — Raw/DD Image Reader

Create `crates/strata-evidence/` as a new workspace crate.
Sub-module: `crates/strata-evidence/src/raw.rs`.

**Problem statement:**
Raw/DD images (`.raw`, `.dd`, `.img`, `.001`) are the simplest forensic
image format — just a byte-for-byte copy of a disk. Start here because
if the raw reader works, E01/VMDK/VHD are "open it then expose bytes the
same way."

**Implementation:**

```rust
pub trait EvidenceImage {
    /// Total logical size of the disk in bytes
    fn size(&self) -> u64;
    
    /// Read a range of bytes from the image
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;
    
    /// Sector size (typically 512 or 4096)
    fn sector_size(&self) -> u32;
    
    /// Format name for display/reporting
    fn format_name(&self) -> &'static str;
    
    /// Metadata (acquisition info if available)
    fn metadata(&self) -> ImageMetadata;
}

pub struct ImageMetadata {
    pub format: String,
    pub size_bytes: u64,
    pub sector_size: u32,
    pub examiner: Option<String>,
    pub case_number: Option<String>,
    pub acquisition_date: Option<DateTime<Utc>>,
    pub acquisition_tool: Option<String>,
    pub acquisition_hash_md5: Option<String>,
    pub acquisition_hash_sha256: Option<String>,
    pub notes: Option<String>,
}

pub struct RawImage {
    path: PathBuf,
    size: u64,
    sector_size: u32,
    // Memory-mapped for efficient random access
    mmap: memmap2::Mmap,
}

impl RawImage {
    pub fn open(path: &Path) -> std::io::Result<Self>;
}

impl EvidenceImage for RawImage {
    // Implementation reads from mmap at offset
}
```

**Multi-segment support:**
Some raw images come as `.001`, `.002`, `.003`, etc. (like split dd).
Detect and concatenate logically:
- Input: `image.001` → also checks for `.002`, `.003`, etc.
- Logical size = sum of all segments
- `read_at(offset)` routes to correct segment

**Sector size detection:**
Default 512. If image size is not divisible by 512 but divisible by 4096,
use 4096. If neither, log warning, use 512.

**Tests required:**
- Open small raw image (built-in test fixture: 1MB file with known pattern)
- Read bytes at various offsets — match ground truth
- Multi-segment: create .001/.002/.003 fixture, read across boundary
- Edge cases: read past EOF (return 0 bytes, not error)

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

**Cargo dependencies added:**
- `memmap2 = "0.9"` (safe memory mapping)

---

## SPRINT EVIDENCE-2 — E01/EWF Image Reader

Enhance `crates/strata-evidence/` with E01 support via pure-Rust EWF reader.

**Problem statement:**
E01 (Expert Witness Format) is the dominant forensic image format.
Developed by Guidance Software (now OpenText EnCase). Supported by
nearly every forensic tool. Strata MUST support this or it's dead on
arrival commercially.

libewf is the reference implementation (C library, GPL). There is NOT
a mature pure-Rust libewf binding yet, so we have options:

**Option A (preferred): Implement minimal pure-Rust EWF reader**
EWF format is well-documented. We implement the read path directly.
Pros: no FFI, no C dependency, cross-platform, no licensing concerns.
Cons: 400-800 lines of format parsing code.

**Option B: FFI to system libewf**
Via `libewf-sys` or similar crate.
Pros: less code.
Cons: requires libewf installed, FFI is `unsafe{}` (violates our rules),
may not even compile on all platforms without work.

**Option C: Integrate existing `ewf-rs` crate if mature enough**
Check `ewf-rs`, `libewf-rs` on crates.io for maturity.

**Implementation direction: Option A for forensic soundness + zero FFI.**

**EWF format reference (summary):**
- Magic: `EVF\x09\x0D\x0A\xFF\x00`
- Header section contains acquisition metadata
- Table sections map logical offsets to chunk locations
- Chunks are typically 32KB (compressed with zlib or uncompressed)
- Multi-segment: `.E01`, `.E02`, `.E03`, etc.
- Hash section at end contains MD5/SHA1

```rust
pub struct E01Image {
    segments: Vec<PathBuf>,
    total_size: u64,
    sector_size: u32,
    chunk_size: u32,              // Usually 32768
    chunk_table: Vec<ChunkLocation>,
    header: EwfHeader,
    hashes: EwfHashSection,
    // Decompression cache for recently-accessed chunks
    chunk_cache: LruCache<u64, Vec<u8>>,
}

struct ChunkLocation {
    segment_index: usize,
    file_offset: u64,
    compressed: bool,
    size: u32,
}

struct EwfHeader {
    examiner: String,
    case_number: String,
    evidence_number: String,
    acquisition_date: DateTime<Utc>,
    acquisition_tool: String,
    notes: String,
    total_sectors: u64,
    bytes_per_sector: u32,
}

impl E01Image {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        // 1. Find all segments (.E01, .E02, ...)
        // 2. Parse first segment header for metadata
        // 3. Parse tables across all segments into chunk_table
        // 4. Find hash section, extract MD5/SHA1
        // 5. Return opened image
    }
}

impl EvidenceImage for E01Image {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        // 1. Calculate chunk_index and offset_in_chunk
        // 2. If chunk cached, copy from cache
        // 3. Else: read chunk from segment file, decompress if needed,
        //    cache, copy to buf
    }
}
```

**Compression handling:**
- zlib: use `flate2` crate
- bzip2: use `bzip2` crate  
- Uncompressed: copy directly

**Hash verification:**
On open, provide `verify_acquisition_hash()` method that reads entire
image streaming, computes hash, compares to stored value. Report result.

**Tests required:**
- Open single-segment E01 (will need a small test fixture — can generate
  one from dd + ewfacquire, or use a tiny public EWF file)
- Multi-segment E01 (.E01 + .E02)
- Compressed chunk reading
- Uncompressed chunk reading
- Hash verification success
- Hash verification failure (tampered image detection)

**Cargo dependencies added:**
- `flate2 = "1.0"` (zlib)
- `bzip2 = "0.4"` (bz2)
- `md-5 = "0.10"`, `sha1 = "0.10"` (already present)

Zero unwrap, zero unsafe, Clippy clean, six tests minimum.

---

## SPRINT EVIDENCE-3 — VMDK Image Reader

Enhance `crates/strata-evidence/` with VMDK support.

**Problem statement:**
VMware VMDK files are common in:
- Virtual machine acquisitions
- VM escape artifacts
- Converted forensic images (some tools use VMDK as intermediate format)

**Implementation:**

VMDK formats:
- Monolithic sparse (`createType=monolithicSparse`)
- Monolithic flat (`createType=monolithicFlat`)  
- Stream-optimized (`createType=streamOptimized`)
- Split sparse (multiple `-s00N.vmdk` files)

Use existing Rust crate if mature, or implement minimal reader:

```rust
pub struct VmdkImage {
    descriptor: VmdkDescriptor,
    extent_files: Vec<VmdkExtent>,
    total_size: u64,
    // Grain directory for sparse lookup
    grain_directory: Vec<GrainEntry>,
}

struct VmdkDescriptor {
    create_type: String,
    parent_cid: u32,
    cid: u32,
    extents: Vec<ExtentDescription>,
}
```

For sparse VMDKs:
- Parse grain directory (maps virtual address → physical sector)
- Read grain (typically 64KB) on demand
- Handle unallocated grains (read as zeros)

For flat VMDKs:
- Descriptor points to a `-flat.vmdk` file
- That file is a raw dd equivalent

**Candidate crate to evaluate:** `vmdk` on crates.io if available/mature.

**Tests required:**
- Open flat VMDK
- Open sparse VMDK
- Read across grain boundaries
- Handle unallocated grain (returns zeros)

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT EVIDENCE-4 — VHD / VHDX Image Reader

Enhance `crates/strata-evidence/` with Microsoft virtual disk support.

**Problem statement:**
Hyper-V environments produce VHD (legacy) and VHDX (modern) images.
Windows Server forensics often requires these.

**VHD format:**
- Fixed: raw data + 512-byte footer
- Dynamic: header + BAT (block allocation table) + data blocks

**VHDX format:**
- Modern 64-bit disks
- Log-structured updates
- 4KB sector awareness
- Different header layout

```rust
pub struct VhdImage {
    kind: VhdKind,  // Fixed | Dynamic | Differencing
    size: u64,
    // Dynamic: BAT for block lookup
    bat: Option<Vec<u32>>,
}

pub struct VhdxImage {
    headers: VhdxHeaders,
    size: u64,
    block_size: u32,
    // Region table for block lookup
    region_table: VhdxRegionTable,
}
```

**Candidate crate:** Check `vhd` and `vhdx` on crates.io.

**Tests required:**
- Open VHD fixed
- Open VHD dynamic
- Open VHDX
- Read from allocated block
- Handle unallocated block

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT EVIDENCE-5 — Unified Image Dispatcher + Format Detection

Create `crates/strata-evidence/src/dispatch.rs`.

**Problem statement:**
Plugins should never care what format the image is. Given any path,
the dispatcher returns a `Box<dyn EvidenceImage>` trait object.

**Implementation:**

```rust
pub fn open_evidence(path: &Path) -> EvidenceResult<Box<dyn EvidenceImage>> {
    // 1. Read first 512 bytes for magic bytes
    let mut header = [0u8; 512];
    File::open(path)?.read_exact(&mut header)?;
    
    // 2. Detect format by magic bytes + extension hints
    match detect_format(&header, path) {
        ImageFormat::Raw => Ok(Box::new(RawImage::open(path)?)),
        ImageFormat::E01 => Ok(Box::new(E01Image::open(path)?)),
        ImageFormat::Vmdk => Ok(Box::new(VmdkImage::open(path)?)),
        ImageFormat::Vhd => Ok(Box::new(VhdImage::open(path)?)),
        ImageFormat::Vhdx => Ok(Box::new(VhdxImage::open(path)?)),
        ImageFormat::AppleDmg => Ok(Box::new(DmgImage::open(path)?)),
        ImageFormat::Unknown => Err(EvidenceError::UnknownFormat(path.to_path_buf())),
    }
}

pub enum ImageFormat {
    Raw,
    E01,
    Vmdk,
    Vhd,
    Vhdx,
    AppleDmg,
    Unknown,
}

fn detect_format(header: &[u8], path: &Path) -> ImageFormat {
    // E01: magic "EVF\x09\x0D\x0A\xFF\x00" at offset 0
    if header.starts_with(b"EVF\x09\x0D\x0A\xFF\x00") {
        return ImageFormat::E01;
    }
    
    // VHDX: magic "vhdxfile" at offset 0
    if header.starts_with(b"vhdxfile") {
        return ImageFormat::Vhdx;
    }
    
    // VMDK: descriptor starts with "# Disk DescriptorFile"
    if header.starts_with(b"# Disk DescriptorFile") {
        return ImageFormat::Vmdk;
    }
    
    // VHD: footer detection (need to seek to end-512)
    // ... complex, check extension as hint
    
    // Fall back to extension-based detection
    match path.extension().and_then(|e| e.to_str()) {
        Some("raw") | Some("dd") | Some("img") | Some("001") => ImageFormat::Raw,
        Some("vhd") => ImageFormat::Vhd,
        Some("vhdx") => ImageFormat::Vhdx,
        Some("vmdk") => ImageFormat::Vmdk,
        Some("dmg") => ImageFormat::AppleDmg,
        _ => ImageFormat::Unknown,
    }
}
```

**Apple DMG bonus:**
While we're here, add basic DMG support. DMG files may be:
- UDRO (read-only raw) — trivially a raw image
- UDIF (with checksum/hash) — needs header parsing
- Encrypted DMG — declined in forensic context (require decrypted)

**Tests required:**
- Detect each format from magic bytes
- Detect each format from extension fallback
- Reject unknown format cleanly
- Dispatcher returns correct concrete type for each

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 2 — PARTITION TABLE WALKERS
# ═══════════════════════════════════════════════════════════════════════

## SPRINT PARTITION-1 — MBR Partition Table Walker

Create `crates/strata-evidence/src/partition/mbr.rs`.

**Problem statement:**
A disk image has partitions. We need to identify them before we can
walk their filesystems. MBR (Master Boot Record) is the legacy format
used for disks under 2TB and for most Windows XP / Windows 7 systems.

**Implementation:**

```rust
pub struct MbrPartition {
    pub index: u8,                   // 0-3 (primary) or 4+ (logical)
    pub active: bool,                // Boot flag
    pub partition_type: u8,          // 0x07 NTFS, 0x0B FAT32, etc.
    pub partition_type_name: String, // "NTFS" | "FAT32" | "Linux" | etc.
    pub start_lba: u64,              // Starting sector
    pub sector_count: u64,           // Length in sectors
    pub offset_bytes: u64,           // Start byte offset on disk
    pub size_bytes: u64,             // Size in bytes
}

pub fn read_mbr(image: &dyn EvidenceImage) -> EvidenceResult<Vec<MbrPartition>> {
    // MBR is at offset 0, 512 bytes
    let mut mbr = [0u8; 512];
    image.read_at(0, &mut mbr)?;
    
    // Verify signature 0x55AA at offset 510
    if &mbr[510..512] != &[0x55, 0xAA] {
        return Err(EvidenceError::NoValidMbr);
    }
    
    // Parse 4 partition entries at offset 446, each 16 bytes
    let mut partitions = Vec::new();
    for i in 0..4 {
        let entry_offset = 446 + (i * 16);
        let entry = &mbr[entry_offset..entry_offset + 16];
        // Parse: active flag, partition type, start LBA, sector count
        if entry[4] != 0 {  // Non-empty
            partitions.push(parse_mbr_entry(entry, i as u8, image.sector_size())?);
        }
    }
    
    // Extended partitions (type 0x05 or 0x0F): follow the chain
    let mut extended_partitions = Vec::new();
    for p in &partitions {
        if p.partition_type == 0x05 || p.partition_type == 0x0F {
            extended_partitions.extend(walk_extended_partition_chain(image, p.offset_bytes)?);
        }
    }
    partitions.extend(extended_partitions);
    
    Ok(partitions)
}
```

**Partition type mapping:**
- 0x00: Empty
- 0x01: FAT12
- 0x04, 0x06, 0x0E: FAT16
- 0x07: NTFS / exFAT (disambiguate by filesystem boot sector)
- 0x0B, 0x0C: FAT32
- 0x0F, 0x05: Extended
- 0x82: Linux swap
- 0x83: Linux filesystem (ext2/3/4)
- 0xEE: GPT protective (means this is actually a GPT disk)
- 0xEF: EFI System Partition
- 0xAF: HFS/HFS+
- 0xA8: Apple UFS

**Extended partition chain walking:**
EBR (Extended Boot Record) chain — each EBR points to next and describes
one logical partition.

**Tests required:**
- Parse MBR with 1 primary partition
- Parse MBR with 4 primary partitions
- Parse MBR with extended partition and 2 logical partitions
- Detect GPT-protective MBR (type 0xEE) and return empty (caller should
  use GPT walker)
- Reject invalid MBR (bad signature)

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT PARTITION-2 — GPT Partition Table Walker

Create `crates/strata-evidence/src/partition/gpt.rs`.

**Problem statement:**
Modern disks (>2TB, most Windows 10/11, most macOS, most Linux) use GPT
(GUID Partition Table).

**Implementation:**

```rust
pub struct GptPartition {
    pub index: u32,
    pub partition_type_guid: Uuid,       // Identifies filesystem type
    pub partition_type_name: String,     // "Microsoft Basic Data" | "Apple APFS" | etc.
    pub unique_guid: Uuid,               // Per-partition UUID
    pub start_lba: u64,
    pub end_lba: u64,
    pub attributes: u64,
    pub name: String,                    // UTF-16 name
    pub offset_bytes: u64,
    pub size_bytes: u64,
}

pub fn read_gpt(image: &dyn EvidenceImage) -> EvidenceResult<Vec<GptPartition>> {
    // GPT header at LBA 1 (after protective MBR)
    let sector_size = image.sector_size() as u64;
    let mut header = vec![0u8; sector_size as usize];
    image.read_at(sector_size, &mut header)?;
    
    // Verify "EFI PART" signature
    if &header[0..8] != b"EFI PART" {
        return Err(EvidenceError::NoValidGpt);
    }
    
    // Parse GPT header
    let partition_entry_lba = u64::from_le_bytes(...);
    let partition_count = u32::from_le_bytes(...);
    let partition_entry_size = u32::from_le_bytes(...);
    
    // Read partition entries
    let mut partitions = Vec::new();
    for i in 0..partition_count {
        let offset = partition_entry_lba * sector_size + (i as u64 * partition_entry_size as u64);
        let mut entry = vec![0u8; partition_entry_size as usize];
        image.read_at(offset, &mut entry)?;
        
        // Skip empty entries (partition type GUID = 0)
        if entry[0..16].iter().all(|&b| b == 0) {
            continue;
        }
        
        partitions.push(parse_gpt_entry(&entry, i, sector_size)?);
    }
    
    Ok(partitions)
}
```

**Common partition type GUIDs:**
- `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` = EFI System Partition
- `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7` = Microsoft Basic Data (NTFS/FAT/exFAT)
- `E3C9E316-0B5C-4DB8-817D-F92DF00215AE` = Microsoft Reserved
- `DE94BBA4-06D1-4D40-A16A-BFD50179D6AC` = Windows Recovery Environment
- `0FC63DAF-8483-4772-8E79-3D69D8477DE4` = Linux Filesystem
- `7C3457EF-0000-11AA-AA11-00306543ECAC` = Apple APFS
- `48465300-0000-11AA-AA11-00306543ECAC` = Apple HFS+

**Backup GPT validation:**
GPT has a backup header at the last sector of the disk. Optionally
validate it matches the primary. Flag mismatches as potential corruption.

**Tests required:**
- Parse GPT with multiple partitions (Windows Boot + ESP + Recovery + Main)
- Parse GPT with macOS APFS container partition
- Parse GPT with Linux root + home partitions
- Reject invalid GPT (bad signature)
- Detect backup GPT mismatch (corruption indicator)

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 3 — PURE-RUST FILESYSTEM WALKERS
# ═══════════════════════════════════════════════════════════════════════

## SPRINT FS-1 — NTFS Filesystem Walker

Create `crates/strata-fs/src/ntfs/` subsystem.

**Problem statement:**
NTFS is the dominant Windows filesystem. Every Windows forensics case
involves NTFS. Pure-Rust NTFS reader is mandatory.

**Implementation approach:**
Evaluate existing Rust crates:
- `ntfs` crate by Colin Finck — most mature pure-Rust NTFS reader,
  read-only, active development
- `ntfs-reader` — alternative, less mature

**Use `ntfs` crate if API fits. Wrap in `NtfsWalker` that implements
our `VirtualFilesystem` trait (see Part 4).**

```rust
pub struct NtfsWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    // ntfs crate handles
}

impl NtfsWalker {
    pub fn open(image: Arc<dyn EvidenceImage>, partition: &GptPartition) -> Result<Self>;
    
    /// Walk all files in the filesystem, calling callback for each
    pub fn walk<F>(&self, callback: F) -> Result<()>
    where F: FnMut(&NtfsFileEntry);
    
    /// Read file content by path
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>>;
    
    /// List directory
    pub fn list_dir(&self, path: &str) -> Result<Vec<NtfsFileEntry>>;
    
    /// Get alternate data streams for a file (ADS detection)
    pub fn list_ads(&self, path: &str) -> Result<Vec<String>>;
}

pub struct NtfsFileEntry {
    pub path: String,
    pub size: u64,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub mft_entry: DateTime<Utc>,  // MFT record change time
    pub is_directory: bool,
    pub attributes: u32,
    pub mft_record_number: u64,
    pub has_ads: bool,
    pub deleted: bool,              // From $MFT unallocated entries
    pub resident: bool,             // Data stored in MFT vs. external clusters
}
```

**Must support:**
- Walking live files (allocated MFT entries)
- Walking deleted files (unallocated MFT entries in $MFT)
- Reading file content for both allocated and deleted files
- Alternate Data Streams (ADS) enumeration
- MFT timestamps (all 4: created, modified, accessed, MFT entry change)
- Resident vs. non-resident data
- Compressed files (NTFS compression)
- Sparse files

**Special files to expose for plugins:**
- `$MFT` — Master File Table (first file)
- `$LogFile` — transaction log
- `$UsnJrnl:$J` — USN change journal ADS
- `$Bitmap` — cluster allocation bitmap
- `$Secure:$SDS` — security descriptors

**Tests required:**
- Open NTFS partition, list root directory
- Read a regular file's content
- Walk entire filesystem, count files
- Find and read a deleted file from unallocated MFT
- List ADS on a file
- Parse $MFT directly

**Cargo dependencies added:**
- `ntfs = "0.5"` or equivalent

Zero unwrap, zero unsafe, Clippy clean, six tests minimum.

---

## SPRINT FS-2 — APFS Filesystem Walker

Create `crates/strata-fs/src/apfs/`.

**Problem statement:**
APFS is the macOS/iOS filesystem since 2017. Every Mac and iPhone case
involves APFS. There is no mature pure-Rust APFS reader.

**Implementation approach:**
Strata already has an APFS walker (referenced in earlier sessions — 850
lines, 6 tests passing). Verify it works and wire to the new evidence
layer.

If the existing walker works: wrap in `ApfsWalker` implementing
`VirtualFilesystem` trait.

If not yet complete:
- Parse APFS container (NXSB magic at offset 32 of partition)
- Walk volume list (multiple volumes can coexist in one APFS container)
- Parse B-tree structure
- Walk OMAP (object map) for object ID resolution
- Extract 4-timestamp nanosecond-precision records

```rust
pub struct ApfsWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    volumes: Vec<ApfsVolume>,
}

pub struct ApfsVolume {
    pub name: String,           // "Macintosh HD", "Macintosh HD - Data", etc.
    pub role: String,           // System / Data / Preboot / Recovery / VM
    pub uuid: Uuid,
    pub snapshot_count: u32,
    pub case_sensitive: bool,
    pub encrypted: bool,
    // Root tree for walking
}

impl ApfsWalker {
    pub fn open(image: Arc<dyn EvidenceImage>, partition: &GptPartition) -> Result<Self>;
    pub fn volumes(&self) -> &[ApfsVolume];
    pub fn walk_volume<F>(&self, volume_name: &str, callback: F) -> Result<()>;
    pub fn read_file(&self, volume: &str, path: &str) -> Result<Vec<u8>>;
    pub fn list_snapshots(&self, volume: &str) -> Result<Vec<ApfsSnapshot>>;
}
```

**Snapshot handling:**
APFS snapshots are critical forensic evidence — they preserve point-in-time
filesystem state. Expose snapshots as read-only subtrees for plugins to
walk independently.

**Read-only sealed system volume:**
macOS Sonoma+ has sealed system volume. Accept sealed state, walk it
read-only anyway (forensic examination is always read-only).

**Tests required:**
- Open APFS container, list volumes
- Walk a volume, read file content
- Read from Data volume (user files)
- List snapshots
- Walk a snapshot

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT FS-3 — ext4 Filesystem Walker (Linux)

Create `crates/strata-fs/src/ext4/`.

**Problem statement:**
Linux servers, Chromebook Crostini, Android userdata partitions often
use ext4. Need pure-Rust read-only walker.

**Implementation approach:**
Evaluate existing crate: `ext4` on crates.io (by Chris West / FauxFaux —
read-only, mature enough to evaluate).

Wrap in `Ext4Walker` implementing `VirtualFilesystem`.

```rust
pub struct Ext4Walker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    block_size: u32,
    inode_size: u32,
    // ext4 crate handles
}

impl Ext4Walker {
    pub fn open(image: Arc<dyn EvidenceImage>, partition: &MbrPartition) -> Result<Self>;
    pub fn walk<F>(&self, callback: F) -> Result<()>;
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>>;
    pub fn read_inode(&self, inode: u64) -> Result<Ext4Inode>;
}

pub struct Ext4Inode {
    pub inode_number: u64,
    pub file_type: FileType,
    pub size: u64,
    pub blocks: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub atime: DateTime<Utc>,
    pub ctime: DateTime<Utc>,
    pub mtime: DateTime<Utc>,
    pub crtime: Option<DateTime<Utc>>,  // Birth time (ext4-specific)
    pub dtime: Option<DateTime<Utc>>,    // Deletion time
    pub link_count: u16,
    pub extended_attributes: HashMap<String, Vec<u8>>,
}
```

**Special handling:**
- Extents vs block-mapping (ext4 vs ext2/3)
- Journal file ($Journal equivalent)
- Deleted files (dtime != 0)
- Extended attributes (security.*, user.*, trusted.*)

**Tests required:**
- Open ext4 partition
- List root directory
- Read regular file
- Find deleted inode
- Read extended attributes

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT FS-4 — FAT32 / exFAT Filesystem Walker

Create `crates/strata-fs/src/fat/`.

**Problem statement:**
FAT32 and exFAT are common on:
- USB drives (evidence of removable media)
- SD cards (camera artifacts)
- Older Windows recovery partitions
- Android external storage
- macOS external drives

**Implementation approach:**
Use existing `fatfs` crate (mature, pure-Rust, read-only support available).

```rust
pub struct FatWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    variant: FatVariant,  // Fat12 | Fat16 | Fat32 | ExFat
}

impl FatWalker {
    pub fn open(image: Arc<dyn EvidenceImage>, partition: &MbrPartition) -> Result<Self>;
    // Walks files including 8.3 short names and long filenames
    pub fn walk<F>(&self, callback: F) -> Result<()>;
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>>;
    // FAT chain recovery for deleted files
    pub fn recover_deleted(&self) -> Result<Vec<FatDeletedEntry>>;
}
```

**exFAT specific:**
- Separate bitmap allocation
- Different directory entry structures
- Up to 128-byte filenames in UTF-16

**Tests required:**
- Open FAT32 partition
- Open exFAT partition
- Walk files, handle long filenames
- Recover deleted files from FAT chains

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT FS-5 — HFS+ Filesystem Walker (Legacy macOS)

Create `crates/strata-fs/src/hfsplus/`.

**Problem statement:**
Pre-2017 Macs use HFS+. Still in active casework because:
- Older seized devices
- Time Machine backups (which use HFS+ even on newer Macs)
- Industrial/fleet older Macs in enterprise

**Implementation:**

HFS+ structure:
- Volume Header at sector 2
- Catalog B-tree for files/folders
- Extents Overflow B-tree for fragmented files
- Attributes B-tree for extended attributes

```rust
pub struct HfsPlusWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    volume_header: HfsPlusVolumeHeader,
    catalog_tree: CatalogBtree,
}

impl HfsPlusWalker {
    pub fn open(image: Arc<dyn EvidenceImage>, partition: &MbrPartition) -> Result<Self>;
    pub fn walk<F>(&self, callback: F) -> Result<()>;
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>>;
}
```

**HFS+ specific:**
- Case-insensitive by default
- Fork-based files (data fork + resource fork)
- Journal support
- Hard links via indirect nodes

**Tests required:**
- Open HFS+ partition from Time Machine backup
- Walk files
- Read data fork
- Read resource fork

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 4 — VIRTUALFILESYSTEM ABSTRACTION + PLUGIN REWIRING
# ═══════════════════════════════════════════════════════════════════════

## SPRINT VFS-1 — Unified VirtualFilesystem Trait

Create `crates/strata-fs/src/vfs.rs` — the abstraction plugins query.

**Problem statement:**
Plugins currently call `std::fs::read_dir` directly on `ctx.root_path`.
For a real forensic image, they need to query a virtual filesystem that
might represent NTFS, APFS, ext4, FAT, or HFS+ transparently.

**Implementation:**

```rust
pub trait VirtualFilesystem: Send + Sync {
    /// Filesystem type name for reporting
    fn fs_type(&self) -> &'static str;
    
    /// List entries in a directory
    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>>;
    
    /// Read file content
    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>>;
    
    /// Read file content range (for large files)
    fn read_file_range(&self, path: &str, offset: u64, len: usize) -> VfsResult<Vec<u8>>;
    
    /// Get file metadata without reading content
    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata>;
    
    /// Walk all files in the filesystem recursively
    /// Filter callback decides whether to descend into each directory
    fn walk<F>(&self, filter: F) -> VfsResult<Vec<VfsEntry>>
    where F: FnMut(&VfsEntry) -> WalkDecision;
    
    /// Check if file exists
    fn exists(&self, path: &str) -> bool;
    
    /// Get alternate data streams (NTFS) or extended attributes (ext4/APFS)
    fn alternate_streams(&self, path: &str) -> VfsResult<Vec<String>>;
    
    /// Read an alternate stream
    fn read_alternate_stream(&self, path: &str, stream: &str) -> VfsResult<Vec<u8>>;
    
    /// List deleted files if filesystem supports recovery
    fn list_deleted(&self) -> VfsResult<Vec<VfsDeletedEntry>>;
    
    /// Read a deleted file's content if recoverable
    fn read_deleted(&self, entry: &VfsDeletedEntry) -> VfsResult<Vec<u8>>;
}

pub struct VfsEntry {
    pub path: String,                       // Logical path within filesystem
    pub name: String,                       // Just the filename
    pub is_directory: bool,
    pub size: u64,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub metadata_changed: Option<DateTime<Utc>>, // $MFT change / ctime
    pub attributes: VfsAttributes,
    pub inode_number: Option<u64>,
    pub has_alternate_streams: bool,
    pub fs_specific: VfsSpecific,
}

pub struct VfsAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    pub archive: bool,
    pub compressed: bool,
    pub encrypted: bool,
    pub sparse: bool,
    pub unix_mode: Option<u32>,
    pub unix_uid: Option<u32>,
    pub unix_gid: Option<u32>,
}

pub enum VfsSpecific {
    Ntfs { mft_record: u64, resident: bool },
    Apfs { object_id: u64, snapshot: Option<String> },
    Ext4 { inode: u64, extents_based: bool },
    Fat { cluster: u32 },
    HfsPlus { catalog_id: u32 },
}

pub enum WalkDecision {
    Descend,       // Continue into this directory
    Skip,          // Skip this directory entirely
    Stop,          // Stop walking completely
}
```

**Implementation strategy:**
Each filesystem walker (NtfsWalker, ApfsWalker, Ext4Walker, FatWalker,
HfsPlusWalker) implements the VirtualFilesystem trait.

**Composite VFS:**
When an image has multiple partitions (Windows boot + data, macOS system
+ data), create a `CompositeVfs` that presents them under named roots:
- `/[C:]` → NTFS boot partition
- `/[D:]` → NTFS data partition
- `/[Macintosh HD]` → APFS system volume
- `/[Macintosh HD - Data]` → APFS data volume

Plugins can walk the whole composite or filter by partition.

**Tests required:**
- NtfsWalker implements VirtualFilesystem correctly
- ApfsWalker implements VirtualFilesystem correctly
- Walk produces correct file list
- List deleted files works where supported
- Composite VFS with multiple partitions

Zero unwrap, zero unsafe, Clippy clean, six tests minimum.

---

## SPRINT VFS-2 — File Index Built from VFS

Enhance `crates/strata-core/src/file_index/`.

**Problem statement:**
The existing file_index was built to index host filesystem files. Now
it needs to index a VirtualFilesystem (disk image) transparently.

**Implementation:**

```rust
impl FileIndex {
    /// Build index by walking a VirtualFilesystem
    pub fn build_from_vfs(vfs: &dyn VirtualFilesystem) -> Result<Self, FileIndexError> {
        let mut index = FileIndex::new();
        vfs.walk(|entry| {
            if entry.is_directory {
                WalkDecision::Descend
            } else {
                // Index this file
                index.insert(IndexEntry {
                    path: entry.path.clone(),
                    size: entry.size,
                    modified: entry.modified,
                    created: entry.created,
                    // ...
                });
                WalkDecision::Descend
            }
        })?;
        Ok(index)
    }
}
```

**Performance:**
For large images (1TB+), index building must be streaming. Write index
records to SQLite as they're discovered, don't buffer in memory.

**Deleted file handling:**
Include deleted files in the index with a `deleted=true` flag. Plugins
can opt in to seeing deleted files.

**Alternate streams:**
Index alternate streams as separate entries with a suffix (`file.txt:Zone.Identifier`).

**Tests required:**
- Build index from NtfsWalker
- Index includes deleted files
- Index includes ADS
- Streaming build for large filesystems
- Query by path pattern

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT VFS-3 — Plugin Context Redesign

Enhance `crates/strata-plugin-sdk/src/lib.rs` — extend PluginContext.

**Problem statement:**
Plugins currently receive `ctx.root_path: String`. They need VFS access
instead so they can query real evidence filesystems.

**Implementation:**

```rust
pub struct PluginContext {
    /// Legacy: path to root (for host filesystem plugins)
    pub root_path: String,
    
    /// New: VirtualFilesystem for this evidence (if mounted)
    pub vfs: Option<Arc<dyn VirtualFilesystem>>,
    
    /// New: File index built from the VFS
    pub file_index: Option<Arc<FileIndex>>,
    
    /// Case directory for artifact output
    pub case_dir: PathBuf,
    
    /// Plugin configuration
    pub config: HashMap<String, String>,
    
    /// Prior plugin results for correlation
    pub prior_results: Vec<PluginOutput>,
    
    /// Audit logger for chain of custody events
    pub audit: Arc<AuditLogger>,
}

impl PluginContext {
    /// Helper: find files matching a pattern via file_index
    pub fn find_files(&self, pattern: &str) -> Vec<String>;
    
    /// Helper: find files by name (case-insensitive)
    pub fn find_by_name(&self, name: &str) -> Vec<String>;
    
    /// Helper: read a file via VFS if available, else host fs
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>>;
    
    /// Helper: check file exists via VFS if available, else host fs
    pub fn file_exists(&self, path: &str) -> bool;
    
    /// Helper: list directory via VFS if available, else host fs
    pub fn list_dir(&self, path: &str) -> Result<Vec<String>>;
}
```

**Backward compatibility:**
Keep `root_path` field. When VFS is present, `root_path` is a sentinel
like `"vfs://"`. Plugins that call `ctx.file_exists()` etc. work
transparently whether VFS is present or not.

**Tests required:**
- PluginContext with VFS present: file_exists, read_file work via VFS
- PluginContext without VFS: file_exists, read_file fall back to host fs
- find_files uses index correctly
- find_by_name handles case-insensitivity

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT VFS-4 — Plugin Migration to VFS-aware APIs

Migrate all 26 plugins to use the new context helpers.

**Problem statement:**
Every plugin currently calls `std::fs::read_dir(ctx.root_path)` or
`std::fs::read(path)` directly. These must be replaced with
`ctx.list_dir()` and `ctx.read_file()` to work transparently with
both VFS and host filesystem.

**Implementation:**

For each plugin in `plugins/`:

1. Replace `std::fs::read_dir` → `ctx.list_dir`
2. Replace `std::fs::read(path)` → `ctx.read_file(path_str)`
3. Replace `Path::new(&ctx.root_path).exists()` → `ctx.file_exists`
4. Use `ctx.find_by_name("SYSTEM")` instead of manual recursive search
   in plugins like Phantom
5. Use `ctx.find_files("**/*.sqlite")` glob patterns where applicable

**Plugins to migrate:**
- Phantom (registry hives)
- Chronicle (user activity)
- Trace (execution artifacts)
- Remnant (deleted files)
- Sentinel (event logs)
- Guardian (AV artifacts)
- Cipher (credentials)
- Nimbus (cloud apps)
- Conduit (network)
- Vector (malware)
- Wraith (memory artifacts)
- Recon (identity)
- NetFlow (network forensics)
- MacTrace (macOS)
- Apex (Apple built-in apps)
- Carbon (Google)
- Pulse (iOS/third-party mobile)
- Specter (mobile/gaming)
- Vault (steganography/antiforensic)
- ARBOR (Linux)
- Sigma (correlation — already uses prior_results, minimal changes)
- CSAM scanner
- All others

**Tests required:**
After migration, ALL existing 3,574 tests must still pass. Additionally:
- Each plugin's run() works correctly when VFS is provided
- Each plugin's run() works correctly when VFS is None (host fs fallback)

**Verification:**
Re-run the `strata ingest run` against Takeout folder → should produce
similar or better artifact count (not worse).

Zero unwrap, zero unsafe, Clippy clean, all existing tests + 10 new minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 5 — ARTIFACT PERSISTENCE
# ═══════════════════════════════════════════════════════════════════════

## SPRINT PERSIST-1 — Artifacts SQLite Database

Create `crates/strata-core/src/artifacts/database.rs`.

**Problem statement:**
Today when plugins emit artifacts, they flow through `run_all_on_path`
and are returned in memory. Nothing is written to disk. When the CLI
exits, all artifacts are lost.

We need an artifacts.sqlite database in every case directory that
persists every artifact with full fidelity.

**Implementation:**

```sql
CREATE TABLE artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    plugin_name TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    source_path TEXT,
    timestamp INTEGER,              -- Unix epoch microseconds
    forensic_value TEXT NOT NULL,   -- Critical/High/Medium/Low
    mitre_technique TEXT,
    mitre_name TEXT,
    confidence REAL,                -- 0.0 to 1.0
    suspicious INTEGER DEFAULT 0,   -- Boolean
    raw_data BLOB,                  -- JSON-encoded plugin-specific data
    created_at INTEGER NOT NULL,    -- When artifact was inserted
    examiner_approved INTEGER DEFAULT 0,  -- Examiner marked as reviewed
    examiner_notes TEXT,
    examiner_tags TEXT              -- Comma-separated
);

CREATE INDEX idx_artifacts_case ON artifacts(case_id);
CREATE INDEX idx_artifacts_plugin ON artifacts(plugin_name);
CREATE INDEX idx_artifacts_category ON artifacts(category);
CREATE INDEX idx_artifacts_timestamp ON artifacts(timestamp);
CREATE INDEX idx_artifacts_forensic_value ON artifacts(forensic_value);
CREATE INDEX idx_artifacts_suspicious ON artifacts(suspicious);
CREATE INDEX idx_artifacts_approved ON artifacts(examiner_approved);

CREATE TABLE artifact_relationships (
    source_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    relationship_type TEXT NOT NULL,
    confidence REAL,
    PRIMARY KEY (source_id, target_id, relationship_type),
    FOREIGN KEY (source_id) REFERENCES artifacts(id),
    FOREIGN KEY (target_id) REFERENCES artifacts(id)
);
```

**API:**

```rust
pub struct ArtifactDatabase {
    conn: Connection,
    case_id: String,
}

impl ArtifactDatabase {
    pub fn open_or_create(case_dir: &Path, case_id: &str) -> Result<Self>;
    pub fn insert(&mut self, plugin: &str, artifact: &ArtifactRecord) -> Result<i64>;
    pub fn insert_batch(&mut self, plugin: &str, artifacts: &[ArtifactRecord]) -> Result<Vec<i64>>;
    pub fn query_by_plugin(&self, plugin: &str) -> Result<Vec<StoredArtifact>>;
    pub fn query_by_category(&self, category: &str) -> Result<Vec<StoredArtifact>>;
    pub fn query_by_time_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<StoredArtifact>>;
    pub fn search(&self, query: &str) -> Result<Vec<StoredArtifact>>;
    pub fn count(&self) -> Result<u64>;
    pub fn count_by_plugin(&self) -> Result<HashMap<String, u64>>;
}
```

**Performance:**
Use transactions for batch inserts. Plugins emitting 10,000+ artifacts
must not be 10,000 individual INSERTs.

**Tests required:**
- Open/create database
- Insert single artifact, retrieve
- Batch insert 10,000 artifacts < 1 second
- Query by category
- Query by time range
- Full-text search across title + detail

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT PERSIST-2 — Integrate Database with Ingest Pipeline

Wire the artifact database into `run_all_on_path` and `ingest run`.

**Problem statement:**
`run_all_on_path` must receive a reference to an ArtifactDatabase and
write every artifact each plugin produces immediately. The CLI's
`ingest run` command must create the database in the case directory
before plugins run.

**Implementation:**

Modify `run_all_on_path`:

```rust
pub fn run_all_on_path(
    root_path: &Path,
    vfs: Option<Arc<dyn VirtualFilesystem>>,
    file_index: Option<Arc<FileIndex>>,
    case_dir: &Path,
    case_id: &str,
    examiner: &str,
    plugin_filter: Option<&[String]>,
    audit: &Arc<AuditLogger>,
) -> Vec<(String, Result<PluginOutput, String>)> {
    // Create or open artifact database
    let mut db = ArtifactDatabase::open_or_create(case_dir, case_id)?;
    
    let plugins = build_plugins();
    let mut prior = Vec::new();
    let mut results = Vec::new();
    
    for plugin in plugins.iter() {
        let name = plugin.name().to_string();
        if let Some(filter) = plugin_filter {
            if !filter.iter().any(|n| n == &name) {
                continue;
            }
        }
        
        let context = PluginContext {
            root_path: root_path.to_string_lossy().into_owned(),
            vfs: vfs.clone(),
            file_index: file_index.clone(),
            case_dir: case_dir.to_path_buf(),
            config: HashMap::new(),
            prior_results: prior.clone(),
            audit: audit.clone(),
        };
        
        match plugin.execute(context) {
            Ok(output) => {
                // Persist artifacts to database
                let ids = db.insert_batch(&name, &output.artifacts)?;
                audit.log_plugin_run(&name, output.artifacts.len(), &ids);
                
                prior.push(output.clone());
                results.push((name, Ok(output)));
            }
            Err(e) => {
                audit.log_plugin_error(&name, &format!("{e}"));
                results.push((name, Err(format!("{e}"))));
            }
        }
    }
    
    results
}
```

**`ingest run` command:**
Modify the CLI to:
1. Open the evidence image
2. Parse partitions
3. Open filesystems → build VFS
4. Build file_index from VFS (stream to disk)
5. Call run_all_on_path with VFS + file_index + case_dir
6. Report final artifact count to examiner
7. Write run_summary.json with stats

**Verify with smoke test:**
After this sprint, re-run Takeout test:
```
strata ingest run --source /path/to/Takeout --case-dir /tmp/takeout-test --auto-unpack --auto
```
Check: `/tmp/takeout-test/artifacts.sqlite` must exist with >0 rows.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 6 — GROUND TRUTH VALIDATION
# ═══════════════════════════════════════════════════════════════════════

## SPRINT TRUTH-1 — NPS Jean Hobbes Ground Truth Test

Create `tests/ground_truth/nps_jean.rs`.

**Problem statement:**
NPS Jean Hobbes (`nps-2008-jean.E01`) is a standard DFIR teaching
dataset with well-documented contents. If Strata's plugins extract
artifacts correctly, we know specific things should appear.

**Implementation:**

Documented Jean Hobbes contents (from published DFIR coursework):
- Windows XP system
- Jean is the primary user
- Specific browser history (Internet Explorer)
- Specific documents in My Documents
- Specific email artifacts (Outlook Express)
- Specific USB device history entries
- Specific installed programs

**Test specification:**

```rust
#[test]
fn nps_jean_ground_truth() {
    // Skip if image not present
    let image_path = "/Users/randolph/Wolfmark/Test Material/nps-2008-jean.E01";
    if !Path::new(image_path).exists() {
        eprintln!("SKIP: NPS Jean image not present");
        return;
    }
    
    let case_dir = tempdir().unwrap();
    
    // Run full ingestion pipeline
    let result = run_full_ingestion(
        image_path,
        case_dir.path(),
        "nps-jean-test",
        "Test Examiner",
    );
    assert!(result.is_ok());
    
    // Open artifact database
    let db = ArtifactDatabase::open_or_create(case_dir.path(), "nps-jean-test").unwrap();
    
    // MUST find: hostname
    let hostname_artifacts = db.query_by_title("Hostname").unwrap();
    assert!(!hostname_artifacts.is_empty(), "Phantom must extract hostname");
    
    // MUST find: Jean user account
    let user_artifacts = db.query_by_title_contains("Jean").unwrap();
    assert!(!user_artifacts.is_empty(), "Must find Jean user account");
    
    // MUST find: IE browsing history
    let browser = db.query_by_category("Web Activity").unwrap();
    assert!(browser.len() > 10, "Must find multiple IE history entries");
    
    // MUST find: installed programs
    let programs = db.query_by_title_contains("Installed Program").unwrap();
    assert!(programs.len() > 5, "Must find installed programs");
    
    // Total artifact count sanity check
    let total = db.count().unwrap();
    assert!(total > 100, "Jean image should produce at least 100 artifacts, got {}", total);
    
    println!("NPS Jean ground truth test: {} total artifacts", total);
}
```

**Similar tests for:**
- `charlie-2009-11-12.E01` (known DFIR dataset)
- `terry-2009-12-03.E01` (known DFIR dataset)
- `windows-ftkimager-first.E01` (digitalcorpora)

**Run as integration tests:**
These tests run with `cargo test --test ground_truth --release`.
Skip cleanly if images not present.

**Purpose:**
From now on, "plugin runs green" is not enough. Regression tests enforce
"plugin extracts expected artifacts from known evidence."

Zero unwrap, zero unsafe, Clippy clean, four tests minimum (one per image).

---

## SPRINT TRUTH-2 — Artifact Count Ground Truth

Create `tests/ground_truth/artifact_counts.rs`.

**Problem statement:**
For each test image, document expected minimum artifact counts per
plugin. If Strata regresses (plugin stops extracting), tests catch it.

**Implementation:**

```rust
struct ExpectedCounts {
    image_path: &'static str,
    image_type: &'static str,
    min_artifacts_total: u64,
    min_per_plugin: &'static [(&'static str, u64)],
}

const GROUND_TRUTH: &[ExpectedCounts] = &[
    ExpectedCounts {
        image_path: "nps-2008-jean.E01",
        image_type: "WindowsXp",
        min_artifacts_total: 100,
        min_per_plugin: &[
            ("Strata Phantom", 20),    // Registry: hostname, user, timezone, etc.
            ("Strata Chronicle", 15),  // UserAssist, Recent Docs, Jump Lists
            ("Strata Trace", 10),      // Prefetch entries
            ("Strata Remnant", 5),     // Deleted files in Recycle Bin
            // ...
        ],
    },
    ExpectedCounts {
        image_path: "Android_14_Public_Image.tar",
        image_type: "Android",
        min_artifacts_total: 500,
        min_per_plugin: &[
            ("Strata Carbon", 100),    // Google apps
            ("Strata Pulse", 50),      // Third-party apps
            // ...
        ],
    },
    // ...
];

#[test]
fn artifact_counts_meet_ground_truth() {
    for expected in GROUND_TRUTH {
        if !Path::new(expected.image_path).exists() {
            continue; // Skip missing
        }
        
        let (total, per_plugin) = run_and_count(expected.image_path);
        
        assert!(
            total >= expected.min_artifacts_total,
            "Image {} produced {} artifacts, expected >= {}",
            expected.image_path, total, expected.min_artifacts_total
        );
        
        for (plugin, min_count) in expected.min_per_plugin {
            let actual = per_plugin.get(*plugin).copied().unwrap_or(0);
            assert!(
                actual >= *min_count,
                "Plugin {} on {} produced {} artifacts, expected >= {}",
                plugin, expected.image_path, actual, min_count
            );
        }
    }
}
```

**Calibration:**
First run reports actual counts. Second run sets the minimums. Future
regressions cause test failures.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 7 — REGRESSION VALIDATION
# ═══════════════════════════════════════════════════════════════════════

## SPRINT REGRESS-1 — Re-run All v6/v7/v8 Validation with Real Ingestion

Re-execute FIELD_VALIDATION for v6, v7, v8 but with actual evidence
ingestion now working.

**Problem statement:**
The earlier validation reports measured "plugins didn't crash." Now
they must measure "plugins extracted real artifacts from mounted
evidence."

**Implementation:**

For each image in `~/Wolfmark/Test Material/`:

1. Run `strata ingest run` with real VFS mounting
2. Open resulting artifacts.sqlite
3. Count artifacts per plugin
4. Compare against ground truth expectations from TRUTH-2
5. Identify any plugins that previously reported 0 and still report 0

**Per-image report:**

```
=== 2019 CTF - Windows-Desktop-001.E01 ===
Image type: WindowsWorkstation (detected correctly ✓)
Mount: NTFS partition mounted successfully
File index: 487,213 files indexed (1m 22s)
Plugins executed: 13 (Windows-appropriate subset)

Artifact counts:
  Strata Phantom:    247 artifacts
  Strata Chronicle:  182 artifacts
  Strata Trace:      156 artifacts
  Strata Sentinel:    89 artifacts
  Strata Remnant:     34 artifacts
  Strata Guardian:    12 artifacts
  Strata Cipher:       8 artifacts
  Strata Nimbus:       6 artifacts
  Strata Conduit:     23 artifacts
  Strata Vector:       0 artifacts  (no malware on this system)
  Strata Wraith:       0 artifacts  (no memory dump)
  Strata Recon:       78 artifacts
  Strata Sigma:        5 correlations

Total: 835 artifacts
Previous v6 report: 4 artifacts
Improvement: 209x

Total runtime: 4m 17s
```

**Deliverable:**
`FIELD_VALIDATION_v9_REPORT.md` — the first honest field validation
report. Compare against v6/v7/v8 reports. Document the dramatic
improvement and any regressions.

**Expected outcome:**
- E01 images (which previously produced 0 artifacts) now produce
  hundreds to thousands each
- Windows images populate Phantom/Chronicle/Trace correctly
- macOS images populate MacTrace/Apex correctly
- iOS images populate Pulse correctly
- Android images populate Carbon correctly
- Previously "working" images (tarballs, Takeout) produce same or more
  (never less)

---

## SPRINT REGRESS-2 — Fix Any Parsing Gaps Revealed

Fix any plugins that still produce 0 artifacts when they shouldn't.

**Problem statement:**
Real evidence ingestion will likely reveal plugins whose parsers work
on test fixtures but fail on real-world data. Schema differences,
version variations, edge cases.

**Methodology:**

For each plugin that produced significantly fewer artifacts than
expected on its appropriate image type:

1. Open artifacts.sqlite for that case
2. Check what the plugin did emit (if anything)
3. Open the actual target file in the image (e.g., SYSTEM hive for
   Phantom) with a known-good tool (Registry Explorer, etc.) to
   confirm data exists
4. Debug the plugin against the real file
5. Write a test case using a fixture derived from the real file (with
   any sensitive data redacted)
6. Fix the parser to handle the real-world format
7. Verify fix preserves all existing tests

**Common failure modes to expect:**
- Version detection failures (plugin built for Win 10, image is Win 7)
- Schema differences (SQLite tables with different column names)
- Encoding issues (UTF-16 vs UTF-8, BOM handling)
- Path matching failures (plugin expects `/Users/` but image has
  `/Documents and Settings/`)
- Deleted file handling (plugin reads allocated files only)
- Null handling (plugin assumes field is always present)

**No time box on this sprint.** It runs until every plugin performs
as expected on its appropriate image types.

Zero unwrap, zero unsafe, Clippy clean, tests for every fix.

---

# ═══════════════════════════════════════════════════════════════════════
# COMPLETION CRITERIA
# ═══════════════════════════════════════════════════════════════════════

SPRINTS_v9.md is complete when:

**Evidence ingestion (Parts 1-2):**
- Raw/DD images open and read correctly
- E01 images open, read, and provide metadata
- VMDK, VHD, VHDX open correctly
- MBR and GPT partition tables parsed
- Format auto-detection works

**Filesystem walkers (Part 3):**
- NTFS walker reads live + deleted files + ADS
- APFS walker reads volumes + snapshots
- ext4 walker reads files + extended attributes
- FAT32/exFAT walker reads files + recovers deleted
- HFS+ walker reads files + resource forks

**VFS + plugins (Part 4):**
- VirtualFilesystem trait implemented by all walkers
- File index builds from VFS
- PluginContext extended with VFS access
- All 26 plugins migrated to VFS-aware APIs
- Existing 3,574 tests still pass

**Persistence (Part 5):**
- Artifact database created per case
- All plugin output persists to SQLite
- Batch inserts perform (10K in <1s)
- Queries work (by plugin, category, time)

**Ground truth (Part 6):**
- NPS Jean Hobbes test produces >100 artifacts
- Charlie/Terry/Windows-FTK tests produce expected counts
- Ground truth minimums documented

**Regression validation (Part 7):**
- Full Test Material matrix re-run with real ingestion
- Every E01 produces >50 artifacts (vs 0 before)
- FIELD_VALIDATION_v9_REPORT.md published
- Any revealed gaps fixed

**Quality gates:**
- Test count: 3,574+ plus new tests (likely 4,500+ total)
- All tests passing
- Clippy clean workspace-wide
- Zero .unwrap(), zero unsafe{}, zero println! introduced
- Load-bearing tests preserved
- Public API changes documented

**Strategic outcome:**
Strata is a real forensic platform. An examiner can:
1. Receive an E01 file
2. Run `strata ingest run --source case.E01 --case-dir ./case --auto`
3. Walk away for 30 minutes
4. Return to a case directory with thousands of real forensic artifacts
5. Query, filter, and report on actual evidence

This is the difference between "parser library" and "forensic tool."

---

*STRATA AUTONOMOUS BUILD QUEUE v9*
*Wolfmark Systems — 2026-04-18*
*Part 1: Evidence image readers (Raw/DD/E01/VMDK/VHD)*
*Part 2: Partition table walkers (MBR/GPT)*
*Part 3: Pure-Rust filesystem walkers (NTFS/APFS/ext4/FAT/HFS+)*
*Part 4: VirtualFilesystem + plugin rewiring*
*Part 5: Artifact persistence to SQLite*
*Part 6: Ground truth validation*
*Part 7: Regression + gap closure*
*Mission: Transform Strata from "parser library" to "forensic platform"*
*This is the critical sprint queue. Without this, Strata is not a forensic tool.*
*Execute all incomplete sprints in order. Ship everything.*
