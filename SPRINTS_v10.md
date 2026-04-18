# SPRINTS_v10.md — STRATA FILESYSTEM WALKERS + END-TO-END INGESTION
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md, SESSION_STATE_v9_BLOCKER.md, and SPRINTS_v10.md.
#         Execute all incomplete sprints in order. For each sprint:
#         implement, test, commit, then move to the next."
# Last updated: 2026-04-18
# Prerequisite: SPRINTS_v1.md through SPRINTS_v9.md complete (3,633 tests passing)
#
# ═══════════════════════════════════════════════════════════════════════
# THE MISSION
# ═══════════════════════════════════════════════════════════════════════
#
# v9 shipped the evidence reading foundation — E01/Raw/VMDK/VHD readers,
# MBR/GPT partition walkers, VirtualFilesystem trait, artifact persistence
# to SQLite. But it stopped at the filesystem walkers because each is
# substantial focused work that needed its own queue.
#
# v10 closes the loop. When v10 completes:
#
#   strata ingest run --source nps-2008-jean.E01 --case-dir ./jean --auto
#
# produces a case directory with artifacts.sqlite containing hundreds of
# real Windows artifacts extracted from the real E01 image by real
# plugins walking a real NTFS filesystem.
#
# That moment is when Strata becomes a forensic tool.
#
# ═══════════════════════════════════════════════════════════════════════
# SCOPE — NARROW AND FOCUSED
# ═══════════════════════════════════════════════════════════════════════
#
# 14 sprints across 5 parts:
#
# Part 1 — NTFS walker (unlocks 80% of casework) ................... 3 sprints
# Part 2 — APFS + HFS+ walkers (Apple coverage) .................... 3 sprints
# Part 3 — ext4 + FAT walkers (Linux + removable media) ............ 3 sprints
# Part 4 — Plugin migration to VFS-aware APIs ...................... 2 sprints
# Part 5 — End-to-end validation + gap closure ..................... 3 sprints
#
# No new plugins. No new artifact types. No new OS coverage. This queue
# does ONE thing: make existing plugins work on mounted evidence images.

---

## HOW TO EXECUTE

Read CLAUDE.md and SESSION_STATE_v9_BLOCKER.md first. Then execute each
sprint below in order. For each sprint:
1. Implement exactly as specified
2. Run `cargo test --workspace` — all tests must pass (starting from 3,633)
3. Run `cargo clippy --workspace -- -D warnings` — must be clean
4. Verify zero `.unwrap()`, zero `unsafe{}`, zero `println!`
5. Commit with message: "feat: [sprint-id] [description]" or "fix: [sprint-id] [description]"
6. Move to next sprint immediately

**Critical discipline carried from v9:**
- "Do not silently compromise the spec" — if a sprint reveals an architectural
  blocker, stop, document in `SESSION_STATE_v10_BLOCKER.md`, continue with
  subsequent unblocked sprints.
- NTFS walker ordering is strategic — shipping it first unlocks the
  highest-volume image type and enables incremental validation.
- Each filesystem walker must ship with ground truth validation against
  a real test image before being declared "shipped."

---

## COMPLETED SPRINTS (skip these)

None yet — this is v10.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 1 — NTFS WALKER (PRIORITY: UNLOCK WINDOWS EVIDENCE)
# ═══════════════════════════════════════════════════════════════════════

## SPRINT FS-NTFS-1 — NTFS Walker Core Implementation

Create `crates/strata-fs/src/ntfs/mod.rs`, `walker.rs`, `entry.rs`.

**Problem statement:**
NTFS is the dominant Windows filesystem. Every Windows forensics case
involves NTFS. Shipping NTFS walker first means that once this sprint
completes, every Windows E01 in Test Material becomes processable by
all 26 existing plugins.

**Implementation approach:**

Evaluate the `ntfs` crate (Colin Finck, pure-Rust, read-only, active).
Based on evaluation, wrap it in `NtfsWalker` that implements our
`VirtualFilesystem` trait.

**Why the `ntfs` crate:**
- Pure Rust, no FFI
- Read-only by design (matches forensic use case)
- Handles MFT parsing, attributes, runlists, compression
- Actively maintained
- Apache 2.0 license

**Core structure:**

```rust
pub struct NtfsWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    mft_start_lcn: u64,
    // ntfs crate handles wrapped in our types
    inner: NtfsInner,
}

impl NtfsWalker {
    /// Open NTFS from a partition on an evidence image
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> NtfsResult<Self> {
        // 1. Read NTFS boot sector at partition_offset
        // 2. Verify NTFS signature ("NTFS    " at offset 3)
        // 3. Extract bytes_per_sector, sectors_per_cluster, MFT location
        // 4. Initialize ntfs crate reader with a custom Read+Seek adapter
        //    that routes through image.read_at()
        // 5. Return opened walker
    }
    
    /// Walk all allocated files
    pub fn walk_allocated<F>(&self, mut callback: F) -> NtfsResult<()>
    where F: FnMut(&NtfsFileEntry) -> WalkDecision {
        // Traverse MFT, yield each allocated file record
    }
    
    /// Walk unallocated MFT entries (deleted files)
    pub fn walk_deleted<F>(&self, mut callback: F) -> NtfsResult<()>
    where F: FnMut(&NtfsFileEntry) -> WalkDecision {
        // Scan MFT for unallocated entries with recoverable data
    }
    
    /// Read file content by path
    pub fn read_file(&self, path: &str) -> NtfsResult<Vec<u8>>;
    
    /// Read file content range
    pub fn read_file_range(&self, path: &str, offset: u64, len: usize) -> NtfsResult<Vec<u8>>;
    
    /// List alternate data streams for a file
    pub fn list_ads(&self, path: &str) -> NtfsResult<Vec<String>>;
    
    /// Read an alternate data stream
    pub fn read_ads(&self, path: &str, stream_name: &str) -> NtfsResult<Vec<u8>>;
    
    /// Get full MFT record for a file (forensic detail)
    pub fn mft_record(&self, path: &str) -> NtfsResult<NtfsMftRecord>;
}

pub struct NtfsFileEntry {
    pub path: String,                    // Logical path within NTFS
    pub name: String,
    pub size: u64,
    pub allocated_size: u64,
    pub is_directory: bool,
    pub created: DateTime<Utc>,          // $STANDARD_INFORMATION created
    pub modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub mft_entry_changed: DateTime<Utc>, // $MFT record change time
    pub mft_record_number: u64,
    pub attributes: NtfsAttributes,
    pub has_alternate_streams: bool,
    pub deleted: bool,
    pub resident: bool,                  // Small files stored inline in MFT
}

pub struct NtfsAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    pub archive: bool,
    pub compressed: bool,
    pub encrypted: bool,
    pub sparse: bool,
    pub reparse_point: bool,
}

pub struct NtfsMftRecord {
    pub record_number: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub flags: u16,
    pub standard_information: StandardInformation,
    pub file_name_attributes: Vec<FileNameAttribute>,
    pub data_attributes: Vec<DataAttribute>,
    pub attribute_list: Option<AttributeList>,
}
```

**Read+Seek adapter:**
The `ntfs` crate expects `Read + Seek`. Our `EvidenceImage` trait uses
`read_at(offset, buf)`. Write an adapter:

```rust
pub struct EvidenceReadSeekAdapter {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    cursor: u64,
}

impl Read for EvidenceReadSeekAdapter { /* route to image.read_at */ }
impl Seek for EvidenceReadSeekAdapter { /* update cursor */ }
```

**Test fixtures:**
Create `crates/strata-fs/tests/fixtures/ntfs_small.img` — a minimal
NTFS filesystem with known content:
- A few regular files (hello.txt, notes.md, binary.dat)
- A subdirectory with nested files
- A file with an alternate data stream
- A deleted file (unallocated MFT entry but recoverable)
- A compressed file

Can be generated with `mkntfs` on Linux / `dd` + WSL, or obtained from
public DFIR test corpora.

**Tests required:**
- Open NTFS from partition on raw image
- List root directory
- Read content of a regular file
- Walk entire filesystem, count files
- Find an ADS, read its content
- Parse MFT record with all timestamps
- Recover a deleted file from unallocated MFT
- Handle compressed file reading

**Cargo dependencies added:**
- `ntfs = "0.5"` or latest

Zero unwrap, zero unsafe, Clippy clean, eight tests minimum.

---

## SPRINT FS-NTFS-2 — NtfsWalker Implements VirtualFilesystem

Wire `NtfsWalker` to implement the `VirtualFilesystem` trait from v9.

**Problem statement:**
Plugins query VFS through the trait. NtfsWalker must implement every
trait method correctly.

**Implementation:**

```rust
impl VirtualFilesystem for NtfsWalker {
    fn fs_type(&self) -> &'static str { "ntfs" }
    
    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        // Map NtfsFileEntry → VfsEntry
    }
    
    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        self.read_file(path).map_err(Into::into)
    }
    
    fn read_file_range(&self, path: &str, offset: u64, len: usize) -> VfsResult<Vec<u8>> {
        self.read_file_range(path, offset, len).map_err(Into::into)
    }
    
    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata> {
        // Map NtfsFileEntry metadata to VfsMetadata
    }
    
    fn walk<F>(&self, mut filter: F) -> VfsResult<Vec<VfsEntry>>
    where F: FnMut(&VfsEntry) -> WalkDecision {
        let mut results = Vec::new();
        self.walk_allocated(|entry| {
            let vfs_entry = ntfs_to_vfs(entry);
            let decision = filter(&vfs_entry);
            if matches!(decision, WalkDecision::Descend | WalkDecision::Skip) {
                results.push(vfs_entry);
            }
            decision
        })?;
        Ok(results)
    }
    
    fn exists(&self, path: &str) -> bool {
        self.mft_record(path).is_ok()
    }
    
    fn alternate_streams(&self, path: &str) -> VfsResult<Vec<String>> {
        self.list_ads(path).map_err(Into::into)
    }
    
    fn read_alternate_stream(&self, path: &str, stream: &str) -> VfsResult<Vec<u8>> {
        self.read_ads(path, stream).map_err(Into::into)
    }
    
    fn list_deleted(&self) -> VfsResult<Vec<VfsDeletedEntry>> {
        let mut deleted = Vec::new();
        self.walk_deleted(|entry| {
            deleted.push(ntfs_to_deleted_vfs(entry));
            WalkDecision::Descend
        })?;
        Ok(deleted)
    }
    
    fn read_deleted(&self, entry: &VfsDeletedEntry) -> VfsResult<Vec<u8>> {
        // Use MFT record number to retrieve deleted file content
    }
}
```

**Path semantics:**
NTFS paths use backslash on Windows but Strata normalizes to forward
slash. All paths passed to `list_dir`, `read_file`, etc. are
forward-slash-separated. Internal conversion handles NTFS's native
backslash format.

**NTFS-specific VfsSpecific:**
Populate the `VfsSpecific::Ntfs { mft_record, resident }` field with
the actual MFT record number and whether the data is resident.

**Tests required:**
- NtfsWalker as `dyn VirtualFilesystem`: walk returns expected files
- list_dir returns correct entries for root and subdirectories
- read_file via VFS produces same bytes as direct NtfsWalker
- list_deleted returns unallocated MFT entries
- alternate_streams returns ADS list
- exists returns correct boolean

Zero unwrap, zero unsafe, Clippy clean, six tests minimum.

---

## SPRINT FS-NTFS-3 — NTFS Ground Truth Against NPS Jean Hobbes

Create `crates/strata-fs/tests/ground_truth_ntfs.rs`.

**Problem statement:**
Must validate that NtfsWalker works on a real E01 image, not just our
synthetic test fixture. NPS Jean Hobbes is the canonical test case.

**Implementation:**

```rust
const JEAN_E01: &str = "/Users/randolph/Wolfmark/Test Material/nps-2008-jean.E01";

#[test]
fn ntfs_walker_opens_jean_image() {
    if !Path::new(JEAN_E01).exists() {
        eprintln!("SKIP: NPS Jean image not present");
        return;
    }
    
    let image = open_evidence(Path::new(JEAN_E01)).expect("open E01");
    let mbr = read_mbr(image.as_ref()).expect("read MBR");
    
    // Jean is XP — MBR with at least one NTFS partition
    let ntfs_partition = mbr.iter()
        .find(|p| p.partition_type == 0x07)
        .expect("find NTFS partition");
    
    let walker = NtfsWalker::open(
        Arc::clone(&image),
        ntfs_partition.offset_bytes,
        ntfs_partition.size_bytes,
    ).expect("open NTFS");
    
    // Must find root directory entries
    let root = walker.list_dir("/").expect("list root");
    assert!(!root.is_empty(), "Jean's root must contain directories");
    
    // Known directories on Jean's XP system
    let root_names: HashSet<String> = root.iter().map(|e| e.name.clone()).collect();
    assert!(root_names.contains("Documents and Settings"), "Jean has Documents and Settings");
    assert!(root_names.contains("Program Files"), "Jean has Program Files");
    assert!(root_names.contains("WINDOWS"), "Jean has WINDOWS");
    
    eprintln!("✓ NPS Jean: root contains {} entries", root.len());
}

#[test]
fn ntfs_walker_finds_jean_hives() {
    if !Path::new(JEAN_E01).exists() {
        eprintln!("SKIP");
        return;
    }
    
    let image = open_evidence(Path::new(JEAN_E01)).expect("open");
    let ntfs = first_ntfs(image).expect("ntfs");
    
    // Must find SYSTEM hive
    let system = ntfs.read_file("/WINDOWS/system32/config/SYSTEM")
        .expect("read SYSTEM hive");
    assert!(system.len() > 1024, "SYSTEM hive must be substantial");
    assert_eq!(&system[0..4], b"regf", "SYSTEM hive must have regf magic");
    
    // Must find Jean's NTUSER.DAT
    let ntuser = ntfs.read_file("/Documents and Settings/Jean/NTUSER.DAT")
        .expect("read NTUSER");
    assert!(ntuser.len() > 1024);
    assert_eq!(&ntuser[0..4], b"regf");
    
    eprintln!("✓ NPS Jean: SYSTEM hive {} bytes, NTUSER {} bytes",
              system.len(), ntuser.len());
}

#[test]
fn ntfs_walker_full_walk_counts_jean() {
    if !Path::new(JEAN_E01).exists() {
        eprintln!("SKIP");
        return;
    }
    
    let image = open_evidence(Path::new(JEAN_E01)).expect("open");
    let ntfs = first_ntfs(image).expect("ntfs");
    
    let mut count = 0;
    let mut dir_count = 0;
    ntfs.walk(|entry| {
        count += 1;
        if entry.is_directory { dir_count += 1; }
        WalkDecision::Descend
    }).expect("walk");
    
    // Jean's XP system should have thousands of files
    assert!(count > 5000, "Jean should have >5000 entries, got {}", count);
    eprintln!("✓ NPS Jean: {} total entries, {} directories", count, dir_count);
}
```

**Additional ground truth tests:**
Same pattern for `charlie-2009-11-12.E01`, `terry-2009-12-03.E01`,
`windows-ftkimager-first.E01`. Each skip-guarded if image not present.

**Once these pass:** NTFS walker is proven correct on real evidence.
All 26 plugins can now query it via the VFS trait — they just aren't
wired to yet (that's VFS-PLUGIN-1 in Part 4).

Zero unwrap, zero unsafe, Clippy clean, four tests minimum (one per image).

---

# ═══════════════════════════════════════════════════════════════════════
# PART 2 — APFS + HFS+ WALKERS (APPLE COVERAGE)
# ═══════════════════════════════════════════════════════════════════════

## SPRINT FS-APFS-1 — APFS Walker Implementation

Enhance `crates/strata-fs/src/apfs/` to implement VirtualFilesystem.

**Problem statement:**
APFS (Apple File System) is used on every modern Mac and iPhone.
v9 session state notes an existing in-tree APFS walker (~850 lines,
6 tests passing) — this sprint wires it to the new evidence layer.

**Implementation:**

Check the existing in-tree work:

```bash
find crates/strata-fs/src/apfs -name "*.rs"
```

Evaluate coverage vs. what's needed:
- Container Super Block (NXSB) parsing
- Volume Super Block (APSB) parsing
- B-tree walking (root tree, extent tree, snapshot tree)
- Object Map (OMAP) resolution for object ID lookups
- File/directory inode parsing
- Extended attributes (xattrs)
- Snapshots

If existing walker is incomplete, add missing pieces. If complete, wrap
in VirtualFilesystem trait.

```rust
pub struct ApfsWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    container: ApfsContainer,
    volumes: Vec<ApfsVolume>,
    active_volume: Option<usize>,  // Which volume the trait methods act on
}

pub struct ApfsVolume {
    pub name: String,
    pub role: ApfsVolumeRole,  // System/Data/Preboot/Recovery/VM/Update
    pub uuid: Uuid,
    pub case_sensitive: bool,
    pub encrypted: bool,
    pub snapshot_count: u32,
}

impl ApfsWalker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> ApfsResult<Self>;
    
    pub fn volumes(&self) -> &[ApfsVolume];
    pub fn set_active_volume(&mut self, name: &str) -> ApfsResult<()>;
    pub fn list_snapshots(&self, volume: &str) -> ApfsResult<Vec<ApfsSnapshot>>;
    pub fn walk_snapshot<F>(&self, volume: &str, snapshot_id: u64, callback: F) -> ApfsResult<()>;
}
```

**VirtualFilesystem implementation:**
Similar pattern to NtfsWalker. The trait methods operate on the active
volume. To walk a different volume, call `set_active_volume("Data")`.

**Composite VFS for multi-volume:**
When an APFS container has multiple volumes (System + Data + Preboot +
Recovery + VM — standard macOS layout), present via `CompositeVfs`:
- `/[Macintosh HD]` → System volume
- `/[Macintosh HD - Data]` → Data volume
- `/[Preboot]` → Preboot volume
- `/[Recovery]` → Recovery volume

Plugins walk the composite or specify a volume.

**Sonoma+ sealed system volume:**
macOS Sonoma+ has a read-only sealed system volume. Walker must:
- Accept sealed state (don't try to unseal)
- Walk read-only
- Note seal status in metadata

**Tests required:**
- Open APFS container from test image
- List volumes (System, Data, etc.)
- Walk active volume, count files
- Read a file via VFS trait
- List snapshots on a volume
- Walk a specific snapshot

Zero unwrap, zero unsafe, Clippy clean, six tests minimum.

---

## SPRINT FS-APFS-2 — APFS Ground Truth Against Real Mac Image

Create ground truth tests for APFS walker against real Mac images.

**Problem statement:**
Validate APFS walker works on a real Mac image. Test Material has
`2020 CTF - iOS` (iOS uses APFS internally), `Jess_CTF_iPhone8`,
potentially a Mac image from digitalcorpora.

**Implementation:**

```rust
#[test]
fn apfs_walker_opens_ios_ctf_image() {
    let ios_dir = "/Users/randolph/Wolfmark/Test Material/2020 CTF - iOS";
    if !Path::new(ios_dir).exists() {
        eprintln!("SKIP");
        return;
    }
    
    // iOS CTF may be a folder of extracted files, not an image
    // Locate actual APFS image within it
    let image_file = find_first_image_in_dir(ios_dir);
    if image_file.is_none() {
        eprintln!("SKIP: no image in iOS CTF dir");
        return;
    }
    
    let image = open_evidence(&image_file.unwrap()).expect("open");
    let partitions = read_gpt(image.as_ref()).expect("gpt");
    
    let apfs_partition = partitions.iter()
        .find(|p| is_apfs_partition_type(&p.partition_type_guid))
        .expect("find APFS");
    
    let walker = ApfsWalker::open(
        Arc::clone(&image),
        apfs_partition.offset_bytes,
        apfs_partition.size_bytes,
    ).expect("open APFS");
    
    assert!(!walker.volumes().is_empty(), "APFS must have volumes");
    eprintln!("✓ iOS CTF APFS: {} volumes", walker.volumes().len());
}
```

**Additional tests:**
- iOS APFS must contain `/private/var/mobile/` directory
- iOS APFS must contain Biome stream files somewhere
- macOS APFS must contain `/System/Library/CoreServices/SystemVersion.plist`

**Ground truth once proven:**
Document expected volume names, expected file counts, expected key
files. Encode as assertions.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT FS-HFSPLUS-1 — HFS+ Walker Implementation

Enhance `crates/strata-fs/src/hfsplus/` to implement VirtualFilesystem.

**Problem statement:**
Pre-2017 Macs use HFS+. Still in casework because:
- Older seized devices
- Time Machine backups use HFS+ even on modern Macs
- Industrial/fleet older Macs

v9 session state notes existing in-tree HFS+ module. This sprint wires
it to the VirtualFilesystem trait.

**Implementation:**

Evaluate the existing in-tree module. If incomplete, finish it.

```rust
pub struct HfsPlusWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    volume_header: HfsPlusVolumeHeader,
    catalog_tree: CatalogBtree,
    extents_tree: ExtentsBtree,
    attributes_tree: AttributesBtree,
}

impl HfsPlusWalker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> HfsPlusResult<Self>;
    
    pub fn walk<F>(&self, callback: F) -> HfsPlusResult<()>
    where F: FnMut(&HfsPlusFileEntry) -> WalkDecision;
    
    pub fn read_data_fork(&self, path: &str) -> HfsPlusResult<Vec<u8>>;
    pub fn read_resource_fork(&self, path: &str) -> HfsPlusResult<Vec<u8>>;
    pub fn list_extended_attrs(&self, path: &str) -> HfsPlusResult<HashMap<String, Vec<u8>>>;
}
```

**HFS+ specific concerns:**
- Case-insensitive by default (HFSX is case-sensitive — detect via volume header)
- Fork-based files: data fork AND resource fork
- Resource fork exposed as alternate stream `filename:rsrc`
- Hard links via indirect nodes (`iNode` catalog entries)
- Journal support (transactions in `.journal`)

**VirtualFilesystem trait implementation:**
- `alternate_streams(path)` returns resource fork if present (`["rsrc"]`)
- `read_alternate_stream(path, "rsrc")` reads resource fork
- `metadata(path)` includes both forks' sizes

**Tests required:**
- Open HFS+ partition
- List root
- Read data fork of a file
- Read resource fork where present
- Walk full filesystem
- Extended attributes

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 3 — EXT4 + FAT WALKERS
# ═══════════════════════════════════════════════════════════════════════

## SPRINT FS-EXT4-1 — ext4 Walker Implementation

Create `crates/strata-fs/src/ext4/mod.rs`.

**Problem statement:**
Linux servers, Chromebook Crostini containers, Android userdata
partitions use ext4. Need pure-Rust read-only walker.

**Implementation:**

Evaluate `ext4` crate (FauxFaux, pure-Rust, read-only).

```rust
pub struct Ext4Walker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    superblock: Ext4Superblock,
    block_size: u32,
    // ext4 crate wrapper
}

impl Ext4Walker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> Ext4Result<Self>;
    
    pub fn walk<F>(&self, callback: F) -> Ext4Result<()>;
    pub fn read_file(&self, path: &str) -> Ext4Result<Vec<u8>>;
    pub fn read_inode(&self, inode: u64) -> Ext4Result<Ext4Inode>;
    pub fn list_xattrs(&self, path: &str) -> Ext4Result<HashMap<String, Vec<u8>>>;
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
    pub dtime: Option<DateTime<Utc>>,    // Deletion time (0 = not deleted)
    pub link_count: u16,
    pub extended_attributes: HashMap<String, Vec<u8>>,
}
```

**VirtualFilesystem implementation:**
- `alternate_streams(path)` returns extended attribute names
- `read_alternate_stream(path, xattr)` returns xattr value
- `list_deleted()` scans for inodes with dtime != 0

**Special handling:**
- Extents (ext4) vs block-mapping (legacy ext2/3)
- Journal file ($Journal equivalent — exposed for forensic examination)
- Sparse files
- Symlinks (inline for short targets, block-stored for long)

**Tests required:**
- Open ext4 partition
- List root
- Read regular file
- Read extended attribute
- Find deleted inode
- Walk full filesystem

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT FS-FAT-1 — FAT32 / exFAT Walker Implementation

Create `crates/strata-fs/src/fat/mod.rs`.

**Problem statement:**
FAT32/exFAT used on USB drives, SD cards, older Windows recovery
partitions, Android external storage. v9 attempted this with `fatfs`
crate and hit the `ReadWriteSeek` trait constraint — fatfs requires
write support even for read-only use.

**Implementation approach:**

**Option A (preferred): Implement minimal read-only FAT parser.**
FAT format is simple and well-documented. Read-only walker is ~500 LOC.

**Option B: Use `fatfs` with a fake Write implementation that errors on
any write call.**
Less code but philosophically wrong — `fatfs` is write-capable, we're
misusing it.

**Option C: Fork `fatfs` to expose read-only API.**
Slow, not worth it.

**Recommend Option A.** Implement pure-Rust read-only FAT/exFAT parser
directly. Total LOC comparable to writing a good wrapper.

```rust
pub enum FatVariant {
    Fat12,
    Fat16,
    Fat32,
    ExFat,
}

pub struct FatWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    variant: FatVariant,
    boot_sector: FatBootSector,
    fat_offset: u64,
    data_offset: u64,
    root_dir_offset: u64,
}

impl FatWalker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> FatResult<Self>;
    
    pub fn walk<F>(&self, callback: F) -> FatResult<()>;
    pub fn read_file(&self, path: &str) -> FatResult<Vec<u8>>;
    pub fn recover_deleted(&self) -> FatResult<Vec<FatDeletedEntry>>;
}
```

**FAT format specifics to implement:**
- Boot sector parsing
- FAT table reading (12/16/32-bit cluster chains)
- Directory entry parsing (standard 8.3 format)
- Long filename (LFN) entries (VFAT extension)
- Cluster chain walking
- Deleted file detection (first byte of filename = 0xE5)
- exFAT's bitmap allocation
- exFAT's long filenames (UTF-16, up to 255 chars)

**Tests required:**
- Open FAT32 partition
- Open exFAT partition
- Walk files with LFN names
- Read regular file
- Recover deleted file from FAT chain
- Handle fragmented files (multi-cluster chains)

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT FS-DISPATCH-1 — Filesystem Auto-Detection and Dispatcher

Create `crates/strata-fs/src/dispatch.rs`.

**Problem statement:**
Given a partition on an evidence image, Strata must auto-detect what
filesystem is inside and return the appropriate walker.

**Implementation:**

```rust
pub fn open_filesystem(
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
) -> FsResult<Box<dyn VirtualFilesystem>> {
    // 1. Read first 512 bytes of partition
    let mut boot = [0u8; 512];
    image.read_at(partition_offset, &mut boot)?;
    
    // 2. Detect filesystem by magic/signature
    match detect_filesystem(&boot) {
        FsType::Ntfs => {
            let walker = NtfsWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Apfs => {
            let walker = ApfsWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::HfsPlus => {
            let walker = HfsPlusWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Ext4 => {
            let walker = Ext4Walker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Fat32 | FsType::ExFat => {
            let walker = FatWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Unknown => Err(FsError::UnknownFilesystem),
    }
}

fn detect_filesystem(boot_sector: &[u8]) -> FsType {
    // NTFS: "NTFS    " at offset 3
    if &boot_sector[3..11] == b"NTFS    " {
        return FsType::Ntfs;
    }
    
    // FAT32: "FAT32   " at offset 82
    if boot_sector.len() > 90 && &boot_sector[82..90] == b"FAT32   " {
        return FsType::Fat32;
    }
    
    // FAT16: "FAT16   " at offset 54
    if boot_sector.len() > 62 && &boot_sector[54..62] == b"FAT16   " {
        return FsType::Fat16;
    }
    
    // exFAT: "EXFAT   " at offset 3
    if &boot_sector[3..11] == b"EXFAT   " {
        return FsType::ExFat;
    }
    
    // APFS: Read superblock at offset 32 — "NXSB" magic
    // (must read at partition_offset + 0, checking offset 32)
    // NXSB is at offset 32 of partition start, 4 bytes
    if boot_sector.len() > 36 && &boot_sector[32..36] == b"NXSB" {
        return FsType::Apfs;
    }
    
    // HFS+: Volume header at sector 2, "H+" at offset 0x400 from partition start
    // (must read partition_offset + 0x400 separately)
    
    // ext4: Superblock at offset 0x400 from partition start, magic 0xEF53 at offset 0x38 of superblock
    // (must read partition_offset + 0x400 separately)
    
    FsType::Unknown
}
```

**Secondary detection passes:**
For APFS, HFS+, ext4 where magic is not in boot sector, do a second
read at the appropriate offset.

**Integration with partition walkers:**
MBR/GPT partition walkers already identify filesystem TYPES (e.g.,
MBR partition type 0x07 = "NTFS or exFAT"). Pass that as a hint to
the dispatcher to speed detection and disambiguate ambiguous types.

**Tests required:**
- Dispatch NTFS correctly
- Dispatch FAT32 correctly
- Dispatch exFAT correctly
- Dispatch APFS correctly
- Dispatch HFS+ correctly
- Dispatch ext4 correctly
- Reject unknown filesystem gracefully

Zero unwrap, zero unsafe, Clippy clean, seven tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 4 — PLUGIN MIGRATION TO VFS-AWARE APIs
# ═══════════════════════════════════════════════════════════════════════

## SPRINT VFS-PLUGIN-1 — PluginContext Gains VFS Reference

Extend `crates/strata-plugin-sdk/src/lib.rs` with VFS field.

**Problem statement:**
v9 deferred adding a VFS pointer to PluginContext to avoid circular
dependency issues. Now that strata-fs has concrete VFS implementations,
wire it through.

**Implementation:**

```rust
pub struct PluginContext {
    /// Path to evidence root (host filesystem or unpacked directory)
    pub root_path: String,
    
    /// Optional VFS for plugins to query (when evidence is a mounted image)
    pub vfs: Option<Arc<dyn VirtualFilesystem>>,
    
    /// File index built from the VFS or host filesystem
    pub file_index: Option<Arc<FileIndex>>,
    
    /// Case directory for artifact output
    pub case_dir: PathBuf,
    
    /// Plugin configuration
    pub config: HashMap<String, String>,
    
    /// Prior plugin results for correlation
    pub prior_results: Vec<PluginOutput>,
    
    /// Audit logger
    pub audit: Option<Arc<dyn AuditLogger>>,
}
```

**Circular dependency resolution:**
The PluginSDK cannot depend on strata-fs directly (that would create a
loop: sdk → fs → core → ... → sdk). Instead:
- Define `VirtualFilesystem` trait in `strata-plugin-sdk` (move or
  re-export from strata-fs via trait alias)
- Each filesystem walker in strata-fs implements the SDK trait
- Plugins only see the SDK's trait definition

**Helper methods on PluginContext:**

```rust
impl PluginContext {
    /// Find files by exact name (case-insensitive) across the VFS or host fs
    pub fn find_by_name(&self, name: &str) -> Vec<String> {
        if let Some(vfs) = &self.vfs {
            // Walk VFS, collect paths where filename matches
            let mut matches = Vec::new();
            vfs.walk(|entry| {
                if entry.name.to_lowercase() == name.to_lowercase() {
                    matches.push(entry.path.clone());
                }
                WalkDecision::Descend
            }).unwrap_or(matches.clone());
            matches
        } else {
            // Walk host fs at root_path
            walk_host_fs_for_name(&self.root_path, name)
        }
    }
    
    /// Find files by glob pattern
    pub fn find_files(&self, pattern: &str) -> Vec<String>;
    
    /// Read a file through VFS or host fs
    pub fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
        if let Some(vfs) = &self.vfs {
            vfs.read_file(path).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
        } else {
            std::fs::read(path)
        }
    }
    
    /// Check file existence through VFS or host fs
    pub fn file_exists(&self, path: &str) -> bool;
    
    /// List directory through VFS or host fs
    pub fn list_dir(&self, path: &str) -> io::Result<Vec<String>>;
    
    /// Read alternate data stream (NTFS ADS or ext4 xattr)
    pub fn read_alternate_stream(&self, path: &str, stream: &str) -> io::Result<Vec<u8>>;
}
```

**Backward compatibility:**
Plugins that still call `std::fs::read_dir(ctx.root_path)` continue to
work when VFS is None. When VFS is provided, those calls fail harmlessly
(reading from a non-existent host path) — the plugin gets no artifacts,
which is visible in regression testing.

**Tests required:**
- PluginContext with VFS present uses VFS for all operations
- PluginContext without VFS falls back to host filesystem
- find_by_name works across both modes
- read_file works across both modes

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT VFS-PLUGIN-2 — Migrate All 26 Plugins to Use Context Helpers

Update every plugin's run() function to use PluginContext helpers
instead of direct `std::fs` calls.

**Problem statement:**
Every plugin currently calls `std::fs::read_dir(ctx.root_path)` or
reads files via `Path::new(&ctx.root_path).join(...)`. These must be
migrated to `ctx.find_by_name()`, `ctx.read_file()`, etc.

**Implementation methodology:**

Pilot plugin (Phantom) first. Once Phantom works cleanly, apply the
same pattern to all others.

For each plugin:

1. Identify all `std::fs::read_dir`, `std::fs::read`, `Path::exists`
   calls
2. Replace with `ctx.list_dir()`, `ctx.read_file()`, `ctx.file_exists()`
3. Replace manual recursive file search with `ctx.find_by_name()`
4. Run the plugin's unit tests — must all pass
5. Run workspace tests — must all pass
6. Commit per-plugin

**Plugin migration order (strategic):**
1. **Phantom** — Windows registry, most complex, sets pattern
2. **Chronicle** — Windows user activity, similar pattern to Phantom
3. **Trace** — Windows execution
4. **Remnant** — Deleted files
5. **Sentinel** — Event logs
6. **Guardian** — Windows AV
7. **Cipher** — Windows credentials
8. **Nimbus** — Cloud apps
9. **Conduit** — Network
10. **Vector** — Malware
11. **Wraith** — Memory
12. **Recon** — Identity
13. **NetFlow** — Network forensics
14. **MacTrace** — macOS
15. **Apex** — Apple built-in
16. **Carbon** — Google
17. **Pulse** — iOS/third-party
18. **Specter** — Mobile/gaming
19. **Vault** — Steganography
20. **ARBOR** — Linux
21. **Sigma** — Correlation (minimal change — uses prior_results)
22. **CSAM scanner**
23-26. **Remaining**: index, tree-example, etc.

**Pattern example for Phantom:**

Before:
```rust
fn run(&self, ctx: PluginContext) -> PluginResult {
    let root = Path::new(&ctx.root_path);
    let mut results = Vec::new();
    
    let files = match walk_dir(root) {
        Ok(f) => f,
        Err(_) => return Ok(results),
    };
    
    for path in files {
        // ... match by filename
    }
}
```

After:
```rust
fn run(&self, ctx: PluginContext) -> PluginResult {
    let mut results = Vec::new();
    
    // Find SYSTEM hive via VFS or host fs
    for system_path in ctx.find_by_name("SYSTEM") {
        if let Ok(data) = ctx.read_file(&system_path) {
            results.extend(parsers::system::parse(Path::new(&system_path), &data));
        }
    }
    
    // Same for SOFTWARE, SAM, SECURITY, AmCache.hve, etc.
    for path in ctx.find_by_name("SOFTWARE") { /* ... */ }
    // ...
    
    Ok(results)
}
```

**Tests required:**
- All existing 3,633 tests must still pass
- Each migrated plugin's tests continue to pass
- Smoke test: Phantom on a real Windows VFS produces artifacts

Zero unwrap, zero unsafe, Clippy clean, all existing tests preserved.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 5 — END-TO-END VALIDATION
# ═══════════════════════════════════════════════════════════════════════

## SPRINT E2E-1 — CLI Integration: ingest run Wires Through Evidence + VFS

Update `strata-shield-cli/src/commands/ingest.rs` to use the new layers.

**Problem statement:**
`strata ingest run` currently passes the raw source path to
`run_all_on_path`. Now it must:
1. Open the evidence image
2. Parse partitions
3. Open each partition's filesystem
4. Build a CompositeVfs across all partitions
5. Build a file_index from the VFS
6. Pass the VFS + file_index through PluginContext to all plugins
7. Persist artifacts to case SQLite

**Implementation:**

```rust
pub fn run_ingest(args: IngestArgs) -> Result<IngestResult> {
    // 1. Initialize case directory
    let case_dir = &args.case_dir;
    fs::create_dir_all(case_dir)?;
    
    // 2. Open evidence
    let source = Path::new(&args.source);
    
    let (vfs, evidence_metadata) = if source.is_dir() {
        // Host filesystem directory (Takeout, extracted images, etc.)
        let vfs: Arc<dyn VirtualFilesystem> = Arc::new(HostVfs::new(source));
        (Some(vfs), None)
    } else {
        // Forensic image file
        let image = open_evidence(source)?;
        let evidence_metadata = Some(image.metadata());
        
        // Try GPT first, fall back to MBR
        let partitions = match read_gpt(image.as_ref()) {
            Ok(parts) => parts.into_iter().map(Partition::Gpt).collect::<Vec<_>>(),
            Err(_) => read_mbr(image.as_ref())?.into_iter().map(Partition::Mbr).collect(),
        };
        
        if partitions.is_empty() {
            // No partition table — might be a single filesystem
            let vfs = open_filesystem(Arc::clone(&image), 0, image.size())?;
            (Some(vfs.into()), evidence_metadata)
        } else {
            // Multi-partition — build CompositeVfs
            let mut composite = CompositeVfs::new();
            for (i, partition) in partitions.iter().enumerate() {
                let (offset, size) = partition.offset_size();
                match open_filesystem(Arc::clone(&image), offset, size) {
                    Ok(walker) => {
                        let name = format!("partition_{}", i);
                        composite.add(&name, walker);
                    }
                    Err(e) => {
                        log::warn!("Partition {} unreadable: {}", i, e);
                    }
                }
            }
            (Some(Arc::new(composite) as Arc<dyn VirtualFilesystem>), evidence_metadata)
        }
    };
    
    // 3. Build file index from VFS
    let file_index = if let Some(vfs) = &vfs {
        Some(Arc::new(FileIndex::build_from_vfs(vfs.as_ref())?))
    } else {
        None
    };
    
    // 4. Open artifact database
    let mut db = ArtifactDatabase::open_or_create(case_dir, &args.case_name)?;
    
    // 5. Log evidence metadata to audit
    let audit = Arc::new(AuditLogger::new(case_dir.join("audit_log.jsonl"))?);
    if let Some(meta) = &evidence_metadata {
        audit.log_evidence_opened(&args.source, meta);
    }
    
    // 6. Run plugins with full context
    let results = run_all_with_persistence(
        source,
        vfs,
        file_index,
        case_dir,
        &args.case_name,
        &args.examiner,
        args.plugins.as_deref(),
        Arc::clone(&audit),
        &mut db,
    );
    
    // 7. Report results
    let total_artifacts: u64 = results.iter()
        .filter_map(|(_, r)| r.as_ref().ok().map(|o| o.artifacts.len() as u64))
        .sum();
    
    println!("=== Strata Ingest Run ===");
    println!("Case: {}", args.case_name);
    println!("Examiner: {}", args.examiner);
    println!("Source: {}", args.source);
    println!("Elapsed: {} ms", elapsed);
    println!("Plugins: {} total", results.len());
    println!("Artifacts: {} (persisted to {})", total_artifacts, db.path().display());
    
    Ok(IngestResult { ... })
}
```

**Auto-unpack still applies:**
If source is a container (.zip, .tar, UFED), auto-unpack runs first
(v6 UNPACK-3), then the ingest pipeline runs on the unpacked directory.

**Output verification:**
After completion, `artifacts.sqlite` in case_dir must contain at least
1 row per plugin that ran (or 0 if plugin correctly found nothing).

**Tests required:**
- Integration test: E01 → full pipeline → artifacts.sqlite populated
- Integration test: directory source → full pipeline → artifacts.sqlite populated
- Integration test: Cellebrite tar → auto-unpack → filesystem → artifacts.sqlite populated

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT E2E-2 — Regression Validation: Full Test Material Matrix

Run `strata ingest run` against every image in Test Material and measure
real artifact output.

**Problem statement:**
Must now measure actual forensic extraction, not just "plugin didn't
crash." This is the first honest field validation.

**Implementation:**

Create `tests/regression/matrix_v10.rs`:

```rust
#[test]
#[ignore] // Run manually with cargo test --ignored
fn v10_matrix_validation() {
    let test_material = "/Users/randolph/Wolfmark/Test Material";
    let results_dir = tempdir().unwrap();
    
    let images = vec![
        ("nps-2008-jean.E01", 100, "WindowsXp"),
        ("charlie-2009-11-12.E01", 80, "WindowsXp"),
        ("terry-2009-12-03.E01", 80, "WindowsXp"),
        ("windows-ftkimager-first.E01", 150, "Windows7Plus"),
        ("2019 CTF - Windows-Desktop/2019 CTF - Windows-Desktop-001.E01", 500, "Windows10Plus"),
        // ... all images
    ];
    
    let mut report = Vec::new();
    
    for (image, min_artifacts, expected_type) in images {
        let full_path = format!("{}/{}", test_material, image);
        if !Path::new(&full_path).exists() {
            report.push(format!("SKIP: {} (not present)", image));
            continue;
        }
        
        let case_dir = results_dir.path().join(format!("case-{}", sanitize(image)));
        
        let result = run_full_ingestion(
            &full_path,
            &case_dir,
            &format!("test-{}", sanitize(image)),
            "Regression Test",
        );
        
        match result {
            Ok(r) => {
                let db = ArtifactDatabase::open(&case_dir, &r.case_id).unwrap();
                let total = db.count().unwrap();
                let per_plugin = db.count_by_plugin().unwrap();
                
                let status = if total >= min_artifacts {
                    "PASS"
                } else {
                    "FAIL"
                };
                
                report.push(format!(
                    "{} {}: {} artifacts (min {}), plugins: {:?}",
                    status, image, total, min_artifacts, per_plugin
                ));
            }
            Err(e) => {
                report.push(format!("ERROR: {} — {}", image, e));
            }
        }
    }
    
    // Write report
    fs::write(
        "FIELD_VALIDATION_v10_REPORT.md",
        format!("# Field Validation v10\n\n{}\n", report.join("\n")),
    ).unwrap();
    
    for line in &report {
        println!("{}", line);
    }
}
```

**Expected results after v10:**
- NPS Jean: hundreds of artifacts (previously 4)
- Charlie/Terry: hundreds (previously 0)
- Windows CTF images: thousands (previously 0 or 4)
- Android CTF: thousands (correctly)
- iOS CTF: hundreds
- Takeout: 4+ (baseline preserved)
- Cellebrite.tar: hundreds (auto-unpack + filesystem mount)

**If any image regresses or produces 0:**
Document in SESSION_STATE_v10_FINDINGS.md and address in E2E-3.

Zero unwrap, zero unsafe, Clippy clean, one large integration test.

---

## SPRINT E2E-3 — Gap Closure and Final Field Validation

Fix any plugins revealed as broken by E2E-2.

**Problem statement:**
Real evidence ingestion will likely reveal plugins whose parsers work
on unit test fixtures but fail on real-world data. Close the gaps.

**Methodology:**

For each plugin in E2E-2 that produced significantly fewer artifacts
than expected on its appropriate image type:

1. Open artifacts.sqlite for that case
2. Check what the plugin did emit (if anything)
3. Open the real target file with a known-good tool to confirm data exists
4. Debug plugin against real file
5. Write test case from real-file-derived fixture (redact sensitive data)
6. Fix parser
7. Verify fix preserves existing tests
8. Re-run E2E-2, confirm artifact count now meets minimum

**Common failure modes anticipated:**
- Path case sensitivity (plugin expects `/Users/` but NTFS path is `/Users/`)
- Path separator issues (backslash vs forward slash internally)
- Schema version mismatches (plugin built for Win 10, image is XP)
- Missing field handling (plugin assumes column exists)
- Encoding (UTF-16LE vs UTF-8, BOM handling)
- Deleted file handling (plugin reads allocated only)

**Output:**
Update `FIELD_VALIDATION_v10_REPORT.md` with final numbers after all
gaps closed. Minimum acceptable:
- Every Windows E01 produces ≥100 artifacts
- Every macOS/iOS image produces ≥50 artifacts
- Every Android image produces ≥200 artifacts
- Every Linux image produces ≥50 artifacts
- Ground truth tests from FS-NTFS-3 all pass

Zero unwrap, zero unsafe, Clippy clean, regression tests for every fix.

---

# ═══════════════════════════════════════════════════════════════════════
# COMPLETION CRITERIA
# ═══════════════════════════════════════════════════════════════════════

SPRINTS_v10.md is complete when:

**Filesystem walkers (Parts 1-3):**
- NtfsWalker opens NTFS, implements VirtualFilesystem, validated on Jean/Charlie/Terry
- ApfsWalker opens APFS containers, walks volumes + snapshots, validated on iOS CTF
- HfsPlusWalker opens HFS+, handles data + resource forks
- Ext4Walker opens ext4, reads files + xattrs + deleted inodes
- FatWalker opens FAT32/exFAT, walks LFNs + recovers deleted
- Filesystem auto-detection dispatches correctly

**Plugin integration (Part 4):**
- PluginContext extended with Optional VFS pointer
- All 26 plugins migrated to use ctx helpers
- All 3,633 existing tests still pass

**End-to-end (Part 5):**
- `strata ingest run` opens E01, parses partitions, mounts filesystems,
  builds VFS, runs plugins, persists artifacts
- Full Test Material matrix re-run with real artifact counts
- FIELD_VALIDATION_v10_REPORT.md documents real numbers
- Any gaps revealed are closed

**Quality gates:**
- Test count: 3,633+ plus new tests (likely 4,000+ total)
- All tests passing
- Clippy clean workspace-wide
- Zero `.unwrap()`, zero `unsafe{}`, zero `println!` introduced
- All 9 load-bearing tests preserved
- No public API regressions

**The moment:**
```
strata ingest run --source nps-2008-jean.E01 --case-dir ./jean --auto
```
produces a case directory with artifacts.sqlite containing hundreds of
real Windows artifacts extracted from real evidence by real plugins
walking a real NTFS filesystem.

Strata is a forensic tool.

---

*STRATA AUTONOMOUS BUILD QUEUE v10*
*Wolfmark Systems — 2026-04-18*
*Part 1: NTFS walker — unlocks 80% of Windows casework*
*Part 2: APFS + HFS+ walkers — Apple coverage*
*Part 3: ext4 + FAT walkers — Linux + removable media*
*Part 4: Plugin migration to VFS-aware APIs*
*Part 5: End-to-end validation + gap closure*
*Mission: Close the loop. Strata becomes a forensic tool.*
*Execute all incomplete sprints in order. Ship everything.*
