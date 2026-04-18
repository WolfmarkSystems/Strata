# SPRINTS_v11.md — STRATA EWF FIX + CLOSE THE INGESTION LOOP
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md, SESSION_STATE_v9_BLOCKER.md, SESSION_STATE_v10_BLOCKER.md,
#         FIELD_VALIDATION_v10_REPORT.md, RESEARCH_v10_CRATES.md, and SPRINTS_v11.md.
#         Execute all incomplete sprints in order. For each sprint: implement, test,
#         commit, then move to the next."
# Last updated: 2026-04-18
# Prerequisite: SPRINTS_v1.md through SPRINTS_v10.md complete (3,640 tests passing)
#
# ═══════════════════════════════════════════════════════════════════════
# THE MISSION
# ═══════════════════════════════════════════════════════════════════════
#
# v9 shipped the evidence reading foundation. v10 shipped the NTFS
# filesystem walker and proved the architecture is correct end-to-end
# through ground truth testing on real E01 images.
#
# v10's ground truth tests revealed a single specific bug: the EWF
# chunk-table accumulator in `strata-evidence::e01::read_table_section`
# doesn't cover offsets past a few hundred MiB. When the ntfs crate
# requests the MFT at byte 0xc0000000 from NPS Jean's E01, read_at
# returns zeros, the NTFS signature check fails with the diagnostic
# "[70,73,76,69] expected, [0,0,0,0] observed."
#
# This is not an architectural problem. This is a bounded bug in a
# specific function whose fix unblocks everything downstream.
#
# v11 closes the loop. When v11 completes:
#
#   strata ingest run --source nps-2008-jean.E01 --case-dir ./jean --auto
#
# produces a case directory with artifacts.sqlite containing hundreds of
# real Windows artifacts extracted from the real E01 image by real
# plugins walking real filesystems.
#
# That moment is when Strata becomes a forensic tool.
#
# ═══════════════════════════════════════════════════════════════════════
# SCOPE
# ═══════════════════════════════════════════════════════════════════════
#
# 12 sprints across 6 parts:
#
# Part 1 — EWF chunk-table accumulator fix (critical unblock) ...... 1 sprint
# Part 2 — Remaining filesystem walkers (APFS, HFS+, ext4, FAT) .... 5 sprints
# Part 3 — Filesystem auto-dispatch ................................ 1 sprint
# Part 4 — Plugin migration to VFS-aware APIs ...................... 2 sprints
# Part 5 — End-to-end CLI integration .............................. 1 sprint
# Part 6 — Validation + gap closure ................................ 2 sprints
#
# Part 1 is non-negotiable gate. Every sprint after it depends on E01
# ingestion actually working.
#
# ═══════════════════════════════════════════════════════════════════════
# DISCIPLINE — CARRIED FORWARD FROM v9/v10
# ═══════════════════════════════════════════════════════════════════════
#
# "Do not silently compromise the spec." If any sprint reveals an
# architectural blocker, stop, document in `SESSION_STATE_v11_BLOCKER.md`,
# continue with subsequent unblocked sprints.
#
# Ground truth validation is mandatory, not optional. Every filesystem
# walker must ship with integration tests against a real image before
# being declared shipped.
#
# "Plugin runs green" is not acceptance. Acceptance is "plugin extracts
# expected artifacts from mounted evidence." This discipline carries
# forward from v10.
#
# Quality gates: all tests pass from 3,640 start, clippy clean, zero
# new `.unwrap()` / `unsafe{}` / `println!`, all 9 load-bearing tests
# preserved, no public API regressions.

---

## HOW TO EXECUTE

Read CLAUDE.md, SESSION_STATE_v9_BLOCKER.md, SESSION_STATE_v10_BLOCKER.md,
FIELD_VALIDATION_v10_REPORT.md, RESEARCH_v10_CRATES.md, and SPRINTS_v11.md
in that order. Then execute each sprint below in order.

For each sprint:
1. Implement exactly as specified
2. Run `cargo test --workspace` — all tests must pass (starting from 3,640)
3. Run `cargo clippy --workspace -- -D warnings` — must be clean
4. Verify zero `.unwrap()`, zero `unsafe{}`, zero `println!` introduced
5. Commit with message: "feat: [sprint-id] [description]" or "fix: [sprint-id] [description]"
6. Move to next sprint immediately

---

## COMPLETED SPRINTS (skip these)

None yet — this is v11.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 1 — EWF CHUNK-TABLE ACCUMULATOR FIX (CRITICAL UNBLOCK)
# ═══════════════════════════════════════════════════════════════════════

## SPRINT EWF-FIX-1 — Complete the Chunk-Table Accumulator Walk

Fix `crates/strata-evidence/src/e01.rs::read_table_section` (or adjacent
function) so that the chunk-table accumulator walks every table section
across every segment, producing a complete chunk-location map covering
the full logical disk size.

**Problem statement (exact, from v10 ground truth validation):**

When NPS Jean Hobbes E01 (~1.5 GiB compressed, 4 GiB logical) is
opened via `strata-evidence::open_evidence`, the resulting
`E01Image::read_at` returns zeros for any offset past approximately
a few hundred MiB. The diagnostic surface is at the NTFS layer:

```
NTFS open failed: signature check — [70,73,76,69] expected, [0,0,0,0] observed
```

The `ntfs` crate requests the MFT at logical byte 0xc0000000
(≈3.2 GiB) from its `Read + Seek` adapter. Our adapter calls
`EvidenceImage::read_at(0xc0000000, buf)`. The E01 reader's chunk-table
lookup fails to find a chunk covering that offset. The reader returns
zero-filled bytes instead of real decompressed disk data.

**Root cause hypothesis (to verify during sprint):**

EWF files consist of multiple `table` sections (and in EnCase 2-7 also
`table2` mirror sections). Each table section maps a bounded range of
chunks. For a 4 GiB image split into 32 KiB chunks, there are 131,072
chunks — and EnCase limits table entries to 16,375 or 65,534 depending
on version, forcing the chunk map to span multiple table sections.

The current `read_table_section` implementation likely:

(a) Reads only the first `table` section it encounters, OR
(b) Stops walking the section chain after the first segment file, OR
(c) Fails to continue into `table2` entries when the primary `table`
    entry count is exhausted, OR
(d) Accumulates chunks into a `Vec<ChunkLocation>` indexed by chunk
    number, but the indexing is per-section rather than global,
    silently overwriting earlier entries.

The `next` section type in EWF spec is specifically the linked-list
mechanism for chaining sections across segments — if we stop walking
that chain too early, chunks beyond the first segment are unreachable.

**Implementation steps:**

1. **Read `SESSION_STATE_v10_BLOCKER.md`** for the exact diagnostic
   context Opus captured during v10.

2. **Read the current `read_table_section` implementation** and trace
   how chunks are accumulated. Identify where the walk terminates.

3. **Reference the EWF specification** at:
   https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc
   Specifically the `table`, `table2`, `sectors`, and `next` section
   definitions.

4. **Implement the fix.** The correct walk is:

   - For each segment file (E01, E02, E03, ...):
     - Walk section chain using `next` section pointers
     - Every `table` section encountered: parse its entries and
       accumulate into the global chunk map, indexed by absolute
       chunk number (not per-section number)
     - Every `table2` section: verify consistency (these are mirrors
       of the preceding `table`) or use as fallback if primary is
       corrupted
     - Stop walking when `done` section is found OR end of segment
       file is reached
   - Continue to next segment file and repeat

5. **Global chunk-number calculation.**
   Each `table` section header declares its base chunk number. The
   absolute chunk number for entry N in table section T is:
   `base_chunk_number(T) + N`. Do NOT assume entries in a table
   section start at chunk 0 — that was v9's implementation mistake.

6. **Add a diagnostic method for debugging future issues:**

   ```rust
   impl E01Image {
       pub fn chunk_table_stats(&self) -> ChunkTableStats {
           ChunkTableStats {
               total_chunks_expected: self.total_size / self.chunk_size as u64,
               chunks_mapped: self.chunk_table.len() as u64,
               first_unmapped_offset: self.find_first_unmapped_offset(),
               segments_count: self.segments.len(),
               table_sections_parsed: self.table_sections_count,
           }
       }
   }
   ```

   This is not required for the fix itself but is extremely useful for
   REGRESS-1 verification and future debugging.

**Tests required (new):**

1. `e01_chunk_table_covers_full_image` — Given the NPS Jean E01, parse
   the chunk table, assert that every offset from 0 to `total_size - chunk_size`
   is covered by some chunk entry. This is the single most important
   test — it would have caught the v9 bug at v9 implementation time.

2. `e01_read_at_returns_valid_ntfs_signature_mft` — Given the NPS Jean
   E01, open it, read bytes at the MFT offset (0xC0000 or wherever
   the $MFT is actually located — compute from boot sector), assert
   the first 4 bytes are `[0x46, 0x49, 0x4C, 0x45]` ("FILE" magic of
   NTFS MFT records).

3. `e01_read_at_at_high_offset_returns_real_data` — Read at offset
   0xc0000000 (the failing case from v10 ground truth) and assert
   the returned bytes are not all zero.

4. `e01_multi_table_section_walk` — Verify the chunk_table_stats
   diagnostic reports at least 2 table sections parsed for the NPS
   Jean image.

5. Preserve all existing E01 tests. They should still pass.

**Tests required (regression — existing v10 tests now un-skip):**

`crates/strata-fs/tests/ground_truth_ntfs.rs` contains three tests
that currently skip or fail with the signature diagnostic:

- `ntfs_walker_opens_jean_image`
- `ntfs_walker_finds_jean_hives`
- `ntfs_walker_full_walk_counts_jean`

After this sprint these must pass. If any still fail, stop, document
what the new diagnostic reveals, write `SESSION_STATE_v11_BLOCKER.md`,
continue with subsequent sprints only if they don't depend on EWF.

**Acceptance criteria — non-negotiable:**

- [ ] `cargo test -p strata-evidence` passes including new tests
- [ ] NPS Jean Hobbes E01 mounts as NTFS successfully
- [ ] NTFS signature check at byte 0xc0000000 returns "FILE" magic
- [ ] All three v10 NTFS ground truth tests pass (Jean, Charlie, Terry)
- [ ] `chunk_table_stats()` reports complete coverage
- [ ] Test count: 3,640 → 3,645+
- [ ] Clippy clean, no new unwrap/unsafe/println

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

**This sprint is the critical path. Until it lands, no other sprint
in this queue matters. Do not skip it. Do not defer it.**

---

# ═══════════════════════════════════════════════════════════════════════
# PART 2 — REMAINING FILESYSTEM WALKERS
# ═══════════════════════════════════════════════════════════════════════

## SPRINT FS-EXT4-1 — ext4 Filesystem Walker

Create `crates/strata-fs/src/ext4/mod.rs` using the `ext4-view` crate.

**Problem statement:**
Linux servers, Chromebook Crostini containers, Android userdata
partitions use ext4. Need pure-Rust read-only walker. Research in
RESEARCH_v10_CRATES.md identified `ext4-view` v0.9.2 as the correct
crate (NOT the older stale `ext4` crate by FauxFaux).

**Implementation approach:**

Add dependency to `crates/strata-fs/Cargo.toml`:
```toml
ext4-view = "0.9"
```

Wrap the crate in `Ext4Walker` implementing `VirtualFilesystem`.

```rust
pub struct Ext4Walker {
    fs: Mutex<Ext4>,  // ext4-view crate's Ext4 type
    partition_offset: u64,
    partition_size: u64,
}

impl Ext4Walker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> Ext4Result<Self> {
        let reader = PartitionReader::new(
            Arc::clone(&image),
            partition_offset,
            partition_size,
        );
        let ext4_read = Ext4ReadAdapter::new(reader);
        let fs = Ext4::load(Box::new(ext4_read))?;
        Ok(Self {
            fs: Mutex::new(fs),
            partition_offset,
            partition_size,
        })
    }
}
```

**`Ext4Read` adapter:**
The `ext4-view` crate requires an `Ext4Read` trait implementation.
Our `PartitionReader` (established in v10 for NTFS) provides `Read +
Seek` — adapt to `Ext4Read::read(offset, buf)` with seek+read.

**VirtualFilesystem trait implementation:**
Similar pattern to `NtfsWalker` from v10. The trait methods acquire
the `Mutex<Ext4>` briefly for each operation.

**ext4-specific VfsSpecific:**
Populate `VfsSpecific::Ext4 { inode, extents_based }` — extents_based
is determined by the EXT4_EXTENTS_FL flag on the inode.

**Extended attributes as alternate streams:**
ext4 xattrs are the ext4 analog of NTFS ADS. Expose them via
`alternate_streams(path)` and `read_alternate_stream(path, xattr_name)`.
Common xattrs: `security.selinux`, `user.*`, `trusted.*`.

**Deleted inode handling:**
Implement `list_deleted()` by scanning inodes with non-zero dtime.
`read_deleted()` reconstructs data from block pointers where still intact.

**Ground truth tests:**

Test against Linux images in Test Material:
- `digitalcorpora/linux-dc3dd/` (if extracts to ext4 partition)
- `2022 CTF - Linux.7z` (after unpack)

```rust
#[test]
fn ext4_walker_opens_linux_ctf() {
    // Skip if image not present
    // Open evidence → partitions → first ext4 partition
    // Walker must find /etc, /home, /var, /usr, /root common dirs
    // Must find /etc/passwd, /etc/shadow (readable)
    // Must find /home/*/\.bash_history entries
}
```

**Tests required:**
- Open ext4 partition
- List root directory (/etc, /home, /var, /usr, /root present)
- Read /etc/passwd (non-empty, contains root: entry)
- Walk full filesystem, count > 1000 entries
- Read extended attributes on a file that has them
- Find deleted inode
- Handle symlinks correctly

Zero unwrap, zero unsafe, Clippy clean, seven tests minimum.

---

## SPRINT FS-FAT-1 — FAT12/16/32/exFAT Walker (Native Implementation)

Create `crates/strata-fs/src/fat/mod.rs` — native read-only parser.

**Problem statement:**
FAT12/16/32/exFAT used on USB drives, SD cards, Windows recovery
partitions, Android external storage. v9 discovered `fatfs` crate
requires `ReadWriteSeek` which doesn't fit read-only forensic use.
RESEARCH_v10_CRATES.md recommends native implementation (~500 LOC).

**Implementation:**

Native parser covering:

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
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    reserved_sectors: u32,
    num_fats: u32,
    sectors_per_fat: u32,
    fat_offset: u64,           // Byte offset of first FAT
    data_offset: u64,          // Byte offset of cluster 2
    root_dir_offset: u64,      // Byte offset of root dir (FAT12/16 only)
    root_cluster: u32,         // FAT32/exFAT root cluster number
    total_clusters: u32,
}
```

**Parsing strategy:**

1. **Boot sector parsing (offset 0 of partition):**
   - Jump instruction + OEM name (11 bytes)
   - BIOS Parameter Block (BPB) — varies by FAT variant
   - Detect variant via file system type string at known offsets:
     - FAT12: "FAT12   " at offset 54
     - FAT16: "FAT16   " at offset 54
     - FAT32: "FAT32   " at offset 82
     - exFAT: "EXFAT   " at offset 3

2. **FAT table reading:**
   - FAT12: 12-bit entries packed (3 bytes = 2 entries)
   - FAT16: 16-bit entries
   - FAT32: 32-bit entries (top 4 bits reserved)
   - Walk cluster chains by following entries

3. **Directory entry parsing:**
   - Standard 8.3 entry: 32 bytes, filename + attributes + cluster +
     size + timestamps
   - VFAT Long File Name entries: 32 bytes each, preceding standard
     entry, contain UTF-16 filename portions
   - Deleted entry: first byte = 0xE5

4. **Cluster chain walking:**
   - Start from directory entry's cluster number
   - Follow FAT entries until end-of-chain marker (0xFF8-0xFFF for
     FAT12, 0xFFF8-0xFFFF for FAT16, 0x0FFFFFF8-0x0FFFFFFF for FAT32)
   - Concatenate cluster contents to form file data

5. **exFAT-specific:**
   - 32-byte entries grouped: File (0x85) + Stream Extension (0xC0) +
     File Name (0xC1) entries
   - UTF-16 filenames up to 255 chars (no 8.3 fallback needed)
   - Cluster allocation via Allocation Bitmap file (not FAT chain)
   - SHA-1 name hash for filename-based lookups

**Deleted file recovery:**
When first byte of 8.3 entry is 0xE5, file was deleted but directory
entry and cluster chain may still be recoverable if not overwritten.
Implement `list_deleted()` returning reconstructable file names.

**VirtualFilesystem trait implementation:**
Standard pattern matching NTFS and ext4 walkers.

**Ground truth tests:**
Test against any FAT image available:
- Synthetic FAT32 image created for tests (1 MB, known contents)
- USB stick image if available in Test Material

**Tests required:**
- Detect FAT12 / FAT16 / FAT32 / exFAT variants correctly
- Read root directory
- Walk cluster chains across multi-cluster file
- Parse LFN entries (UTF-16 long filenames)
- Recover deleted file from 0xE5 entry
- Handle exFAT filename up to 255 characters
- Reject corrupted boot sector gracefully

Zero unwrap, zero unsafe, Clippy clean, seven tests minimum.

---

## SPRINT FS-APFS-1 — APFS Filesystem Walker

Extend `crates/strata-fs/src/apfs/` to implement VirtualFilesystem.

**Problem statement:**
APFS is used on every modern Mac and iPhone. Research in
RESEARCH_v10_CRATES.md confirmed NO mature pure-Rust APFS crate
exists. Strata has an in-tree APFS walker (~850 lines, 6 tests
passing per v8 session state).

**Implementation approach:**

1. **Evaluate existing in-tree work:**
   ```bash
   find crates/strata-fs/src/apfs -name "*.rs" -exec wc -l {} \;
   cargo test -p strata-fs apfs
   ```

2. **Verify coverage against APFS spec:**
   - NXSB (Container Super Block) parsing ✓
   - APSB (Volume Super Block) parsing ✓
   - B-tree walking (root tree, extent tree, snapshot tree) ✓
   - OMAP (Object Map) resolution ✓
   - File/directory inode parsing ✓
   - Extended attributes (xattrs) — verify
   - Snapshots — verify
   - Sealed system volumes (Sonoma+) — verify

3. **Add missing pieces if any, then wrap in VirtualFilesystem trait.**

```rust
pub struct ApfsWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    container: ApfsContainer,        // In-tree type
    volumes: Vec<ApfsVolume>,
    active_volume: AtomicUsize,      // Which volume trait methods act on
}

pub struct ApfsVolume {
    pub name: String,
    pub role: ApfsVolumeRole,        // System/Data/Preboot/Recovery/VM/Update
    pub uuid: Uuid,
    pub case_sensitive: bool,
    pub encrypted: bool,
    pub snapshot_count: u32,
    pub sealed: bool,                // Sonoma+ sealed system volume
}

impl ApfsWalker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> ApfsResult<Self>;
    
    pub fn volumes(&self) -> &[ApfsVolume];
    pub fn set_active_volume(&self, name: &str) -> ApfsResult<()>;
    pub fn list_snapshots(&self, volume: &str) -> ApfsResult<Vec<ApfsSnapshot>>;
    pub fn walk_snapshot(&self, volume: &str, snapshot_id: u64) -> ApfsResult<...>;
}
```

**Multi-volume composite VFS:**

APFS containers typically hold multiple volumes. Standard macOS layout:
- Macintosh HD (System, read-only sealed in Sonoma+)
- Macintosh HD - Data (user data, writable)
- Preboot
- Recovery
- VM (swap)
- Update

When ApfsWalker is registered in CompositeVfs, expose each volume as
a named root:
- `/[Macintosh HD]/` → System volume
- `/[Macintosh HD - Data]/` → Data volume
- etc.

Plugins walking the composite see all volumes. Plugins can filter by
volume name prefix.

**Ground truth tests:**

Test against Apple images in Test Material:
- `2020 CTF - iOS` (iOS uses APFS)
- `Jess_CTF_iPhone8` (iOS device)
- Any macOS APFS image if available

```rust
#[test]
fn apfs_walker_opens_ios_ctf() {
    // Skip if image not present
    // Locate APFS container in the image
    // Open walker, list volumes
    // iOS typically has Data, System, Preboot, VM
    // Walk Data volume — must find /private/var/mobile/Library/
}
```

**Tests required:**
- Open APFS container
- List volumes correctly
- Walk active volume, count files
- Read a regular file via VFS trait
- List snapshots on a volume
- Walk a specific snapshot
- Handle sealed system volume (don't try to unseal)
- Extended attributes exposed as alternate streams

Zero unwrap, zero unsafe, Clippy clean, eight tests minimum.

---

## SPRINT FS-HFSPLUS-1 — HFS+ Filesystem Walker

Extend `crates/strata-fs/src/hfsplus/` to implement VirtualFilesystem.

**Problem statement:**
Pre-2017 Macs use HFS+. Still relevant for Time Machine backups (which
use HFS+ even on modern Macs) and older Mac casework. No mature Rust
crate exists. Strata has an in-tree HFS+ module per v8 session state.

**Implementation approach:**

1. **Evaluate existing in-tree module.**
2. **Complete any missing features:**
   - Catalog B-tree walking
   - Extents Overflow B-tree for fragmented files
   - Attributes B-tree for xattrs
   - Journal reading (optional)
   - Data fork + resource fork handling

3. **Wrap in VirtualFilesystem trait.**

```rust
pub struct HfsPlusWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    volume_header: HfsPlusVolumeHeader,
    catalog_tree: CatalogBtree,
    extents_tree: ExtentsBtree,
    attributes_tree: AttributesBtree,
    case_sensitive: bool,               // HFSX if true
}
```

**Resource fork as alternate stream:**

```rust
impl VirtualFilesystem for HfsPlusWalker {
    fn alternate_streams(&self, path: &str) -> VfsResult<Vec<String>> {
        let streams = self.list_xattrs(path)?;
        if self.has_resource_fork(path)? {
            let mut all = streams;
            all.push("rsrc".to_string());
            Ok(all)
        } else {
            Ok(streams)
        }
    }
    
    fn read_alternate_stream(&self, path: &str, stream: &str) -> VfsResult<Vec<u8>> {
        if stream == "rsrc" {
            self.read_resource_fork(path)
        } else {
            self.read_xattr(path, stream)
        }
    }
}
```

**Ground truth tests:**

If a Time Machine backup or older Mac image is available in Test
Material, test against it. Otherwise synthesize a minimal HFS+ test
image for unit tests.

**Tests required:**
- Open HFS+ partition
- List root directory
- Read data fork of regular file
- Read resource fork where present
- Walk full filesystem
- Handle hard links via indirect nodes
- Case-sensitive vs case-insensitive detection (HFSX)

Zero unwrap, zero unsafe, Clippy clean, six tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 3 — FILESYSTEM AUTO-DISPATCH
# ═══════════════════════════════════════════════════════════════════════

## SPRINT FS-DISPATCH-1 — Filesystem Auto-Detection and Dispatcher

Create `crates/strata-fs/src/dispatch.rs`.

**Problem statement:**
Given a partition on an evidence image, Strata must auto-detect what
filesystem is inside and return the appropriate walker. Without this,
the CLI can't route an E01 partition to the right walker automatically.

**Implementation:**

```rust
pub fn open_filesystem(
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
) -> FsResult<Box<dyn VirtualFilesystem>> {
    let fs_type = detect_filesystem(&*image, partition_offset)?;
    
    match fs_type {
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
        FsType::Ext4 | FsType::Ext3 | FsType::Ext2 => {
            let walker = Ext4Walker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Fat12 | FsType::Fat16 | FsType::Fat32 | FsType::ExFat => {
            let walker = FatWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Unknown => Err(FsError::UnknownFilesystem),
    }
}

pub enum FsType {
    Ntfs,
    Apfs,
    HfsPlus,
    Ext2, Ext3, Ext4,
    Fat12, Fat16, Fat32, ExFat,
    Unknown,
}

fn detect_filesystem(
    image: &dyn EvidenceImage,
    partition_offset: u64,
) -> FsResult<FsType> {
    // Read first 1024 bytes of partition for boot-sector-level signatures
    let mut boot = vec![0u8; 1024];
    image.read_at(partition_offset, &mut boot)?;
    
    // NTFS: "NTFS    " at offset 3 of boot sector
    if &boot[3..11] == b"NTFS    " {
        return Ok(FsType::Ntfs);
    }
    
    // FAT32: "FAT32   " at offset 82
    if boot.len() > 90 && &boot[82..90] == b"FAT32   " {
        return Ok(FsType::Fat32);
    }
    
    // FAT16: "FAT16   " at offset 54
    if boot.len() > 62 && &boot[54..62] == b"FAT16   " {
        return Ok(FsType::Fat16);
    }
    
    // FAT12: "FAT12   " at offset 54
    if boot.len() > 62 && &boot[54..62] == b"FAT12   " {
        return Ok(FsType::Fat12);
    }
    
    // exFAT: "EXFAT   " at offset 3
    if &boot[3..11] == b"EXFAT   " {
        return Ok(FsType::ExFat);
    }
    
    // APFS: "NXSB" magic at offset 32 of partition
    if boot.len() > 36 && &boot[32..36] == b"NXSB" {
        return Ok(FsType::Apfs);
    }
    
    // HFS+: Volume header at offset 0x400, "H+" (0x482B) or "HX" (0x4858) magic
    let mut vh = [0u8; 4];
    image.read_at(partition_offset + 0x400, &mut vh)?;
    if &vh[0..2] == b"H+" || &vh[0..2] == b"HX" {
        return Ok(FsType::HfsPlus);
    }
    
    // ext2/3/4: Superblock at offset 0x400 of partition
    // Magic 0xEF53 at offset 0x38 of superblock
    let mut sb = [0u8; 1024];
    image.read_at(partition_offset + 0x400, &mut sb)?;
    if sb.len() > 58 && u16::from_le_bytes([sb[56], sb[57]]) == 0xEF53 {
        // Distinguish ext2/3/4 by feature flags
        let compat_features = u32::from_le_bytes([sb[92], sb[93], sb[94], sb[95]]);
        let incompat_features = u32::from_le_bytes([sb[96], sb[97], sb[98], sb[99]]);
        // EXT4_FEATURE_INCOMPAT_EXTENTS = 0x40
        if incompat_features & 0x40 != 0 {
            return Ok(FsType::Ext4);
        }
        // EXT3 has journal (COMPAT_HAS_JOURNAL = 0x4)
        if compat_features & 0x4 != 0 {
            return Ok(FsType::Ext3);
        }
        return Ok(FsType::Ext2);
    }
    
    Ok(FsType::Unknown)
}
```

**Partition hint integration:**

MBR/GPT partition walkers already identify partition TYPES (e.g.,
MBR type 0x07 = "NTFS or exFAT", GPT GUID `EBD0A0A2-...` = "Microsoft
Basic Data"). The hint speeds detection and disambiguates ambiguous
cases. Accept an optional hint:

```rust
pub fn open_filesystem_with_hint(
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    hint: Option<PartitionTypeHint>,
) -> FsResult<Box<dyn VirtualFilesystem>>;
```

**Tests required:**
- Detect NTFS correctly
- Detect FAT32 correctly
- Detect FAT16 correctly  
- Detect FAT12 correctly
- Detect exFAT correctly
- Detect APFS correctly
- Detect HFS+ correctly
- Detect ext2/3/4 correctly (each)
- Reject unknown filesystem
- Dispatcher returns correct concrete walker for each type

Zero unwrap, zero unsafe, Clippy clean, ten tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 4 — PLUGIN MIGRATION TO VFS-AWARE APIs
# ═══════════════════════════════════════════════════════════════════════

## SPRINT VFS-PLUGIN-1 — PluginContext Gains VFS Reference

Extend `crates/strata-plugin-sdk/src/lib.rs` with VFS field.

**Problem statement:**
v9 deferred the circular-dependency resolution for adding VFS to
PluginContext. Now that all filesystem walkers exist and implement
the VFS trait, wire it through.

**Implementation:**

```rust
// Move VirtualFilesystem trait into strata-plugin-sdk
// (or use re-export pattern from strata-fs)

pub struct PluginContext {
    /// Path to evidence root (legacy, for host filesystem plugins)
    pub root_path: String,
    
    /// VFS for plugins to query (when evidence is a mounted image)
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

**Circular-dep resolution:**

The trait must live where both strata-fs (walkers implementing it)
and strata-plugin-sdk (consumers querying it) can depend on it.
Two options:

**Option A (preferred): Move trait to plugin-sdk.**
strata-plugin-sdk defines the trait. strata-fs depends on plugin-sdk.
Plugins only depend on plugin-sdk.

**Option B: Create strata-vfs-trait sub-crate.**
Defines only the trait. Both strata-fs and strata-plugin-sdk depend
on it. More crates but cleaner layering.

**Decision: Option A unless build reveals Option B is cleaner.**

**PluginContext helper methods (v9 established these for host-fs; now
extend to VFS-aware):**

```rust
impl PluginContext {
    /// Find files by exact name (case-insensitive)
    pub fn find_by_name(&self, name: &str) -> Vec<String> {
        if let Some(vfs) = &self.vfs {
            let lower = name.to_lowercase();
            let mut matches = Vec::new();
            let _ = vfs.walk(|entry| {
                if entry.name.to_lowercase() == lower {
                    matches.push(entry.path.clone());
                }
                WalkDecision::Descend
            });
            matches
        } else {
            // Existing host-fs fallback from v9
            walk_host_fs_for_name(&self.root_path, name)
        }
    }
    
    pub fn find_files(&self, glob_pattern: &str) -> Vec<String>;
    pub fn read_file(&self, path: &str) -> io::Result<Vec<u8>>;
    pub fn file_exists(&self, path: &str) -> bool;
    pub fn list_dir(&self, path: &str) -> io::Result<Vec<String>>;
    pub fn read_alternate_stream(&self, path: &str, stream: &str) -> io::Result<Vec<u8>>;
}
```

**Backward compatibility:**
All plugins currently work with `root_path`-only context. The VFS
field is `Option` — None means "no VFS mounted, fall back to host fs."
Existing plugins that call `std::fs::*` directly continue working
when VFS is None.

**Tests required:**
- PluginContext with VFS present: find_by_name uses VFS walk
- PluginContext with VFS present: read_file uses VFS
- PluginContext without VFS: falls back to host filesystem
- find_files glob pattern across both modes
- Alternate stream access via VFS

Zero unwrap, zero unsafe, Clippy clean, six tests minimum.

---

## SPRINT VFS-PLUGIN-2 — Migrate All Plugins to Context Helpers

Update every plugin's `run()` to use `ctx.*` helpers instead of
direct `std::fs` calls.

**Problem statement:**
Every plugin currently calls `std::fs::read_dir(ctx.root_path)` or
reads files via `Path::new(&ctx.root_path).join(...)`. These must be
migrated so plugins work transparently with both VFS and host fs.

**Migration methodology:**

Pilot with **Phantom** first (Windows registry — most complex, sets
the pattern). Once Phantom passes all tests with both VFS and host
fs backing, apply the same pattern to all other plugins.

**For each plugin:**

1. Identify `std::fs::read_dir`, `std::fs::read`, `Path::exists` calls
2. Replace with `ctx.list_dir()`, `ctx.read_file()`, `ctx.file_exists()`
3. Replace manual recursive file search with `ctx.find_by_name()`
4. Run the plugin's unit tests — must all pass
5. Run workspace tests — must all pass
6. Commit per plugin

**Migration order (strategic):**

Complex plugins first (establishes patterns), then simpler ones follow:

1. **Phantom** — Windows registry (most complex, sets pattern)
2. **Chronicle** — Windows user activity
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
21. **Sigma** — Correlation (uses prior_results, minimal change)
22. **CSAM scanner**
23-26. **Remaining helpers (index, tree-example, etc.)**

**Pattern for Phantom (reference for all others):**

```rust
// Before (v10):
fn run(&self, ctx: PluginContext) -> PluginResult {
    let root = Path::new(&ctx.root_path);
    let mut results = Vec::new();
    let files = match walk_dir(root) {
        Ok(f) => f,
        Err(_) => return Ok(results),
    };
    for path in files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
        if name == "system" {
            if let Some(data) = read_hive_gated(&path) {
                results.extend(parsers::system::parse(&path, &data));
            }
        }
        // ...
    }
    Ok(results)
}

// After (v11):
fn run(&self, ctx: PluginContext) -> PluginResult {
    let mut results = Vec::new();
    
    // Find hives via VFS or host fs transparently
    for system_path in ctx.find_by_name("SYSTEM") {
        if let Ok(data) = ctx.read_file(&system_path) {
            if data.len() <= 512 * 1024 * 1024 {  // 512 MB gate
                results.extend(parsers::system::parse(Path::new(&system_path), &data));
            }
        }
    }
    
    for path in ctx.find_by_name("SOFTWARE") { /* same pattern */ }
    for path in ctx.find_by_name("SAM") { /* same pattern */ }
    for path in ctx.find_by_name("SECURITY") { /* same pattern */ }
    for path in ctx.find_by_name("AmCache.hve") { /* same pattern */ }
    // ...
    
    Ok(results)
}
```

**Tests required:**
- All existing 3,640+ tests must pass after each plugin migration
- Per-plugin smoke test: run via VFS against a synthetic fixture,
  verify artifact count matches pre-migration baseline
- Phantom smoke test: run against mounted NPS Jean, verify >20 artifacts
  (hostname, users, timezone, installed programs, etc.)

**Acceptance criteria:**

- [ ] All 26 plugins migrated
- [ ] All existing tests pass (3,640 → 3,640+)
- [ ] New VFS-aware unit tests per plugin (minimum 1 each)
- [ ] Phantom smoke test against NPS Jean produces ≥20 artifacts
- [ ] Clippy clean, no new unwrap/unsafe/println
- [ ] No public API regressions

Zero unwrap, zero unsafe, Clippy clean, all existing tests preserved
plus 26+ new VFS-aware smoke tests.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 5 — END-TO-END CLI INTEGRATION
# ═══════════════════════════════════════════════════════════════════════

## SPRINT E2E-1 — CLI Ingest Run Wires Through Evidence + VFS + Persistence

Update `strata-shield-cli/src/commands/ingest.rs` (or appropriate
module) to use the complete pipeline.

**Problem statement:**
`strata ingest run` currently passes the raw source path to
`run_all_on_path`. Now it must orchestrate the full chain:

1. Open evidence image via `strata-evidence::open_evidence`
2. Parse partitions (MBR or GPT)
3. Open each partition's filesystem via `strata-fs::open_filesystem`
4. Build CompositeVfs across all partitions
5. Build file_index from the VFS
6. Open artifact SQLite database in case directory
7. Run all plugins with full PluginContext (VFS + file_index +
   case_dir + audit)
8. Persist artifacts to SQLite
9. Write run_summary.json

**Implementation:**

```rust
pub fn run_ingest(args: IngestArgs) -> Result<IngestResult> {
    let case_dir = &args.case_dir;
    fs::create_dir_all(case_dir)?;
    
    let audit = Arc::new(FileAuditLogger::new(case_dir.join("audit_log.jsonl"))?);
    
    let source = Path::new(&args.source);
    
    // Stage 1: Open evidence
    let (vfs, evidence_metadata) = if source.is_dir() {
        // Host filesystem directory (Takeout, extracted images, etc.)
        let vfs: Arc<dyn VirtualFilesystem> = Arc::new(HostVfs::new(source));
        (Some(vfs), None)
    } else {
        // Forensic image file
        let image = open_evidence(source)?;
        let evidence_metadata = Some(image.metadata());
        audit.log_evidence_opened(&args.source, &evidence_metadata);
        
        // Stage 2: Partition walker
        let partitions = read_partitions(image.as_ref())?;
        
        if partitions.is_empty() {
            // No partition table — try as single filesystem
            match open_filesystem(Arc::clone(&image), 0, image.size()) {
                Ok(walker) => (Some(walker.into()), evidence_metadata),
                Err(_) => (None, evidence_metadata),
            }
        } else {
            // Multi-partition — build CompositeVfs
            let mut composite = CompositeVfs::new();
            for (i, partition) in partitions.iter().enumerate() {
                match open_filesystem(
                    Arc::clone(&image),
                    partition.offset_bytes(),
                    partition.size_bytes(),
                ) {
                    Ok(walker) => {
                        let name = partition.display_name().unwrap_or_else(|| format!("partition_{}", i));
                        composite.add(&name, walker);
                        audit.log_partition_mounted(&name, &partition);
                    }
                    Err(e) => {
                        log::warn!("Partition {} unreadable: {}", i, e);
                        audit.log_partition_unreadable(i, &format!("{}", e));
                    }
                }
            }
            (Some(Arc::new(composite) as Arc<dyn VirtualFilesystem>), evidence_metadata)
        }
    };
    
    // Stage 3: Build file index
    let file_index = if let Some(vfs) = &vfs {
        log::info!("Building file index...");
        let start = Instant::now();
        let index = Arc::new(FileIndex::build_from_vfs(vfs.as_ref())?);
        log::info!("Indexed {} files in {:?}", index.len(), start.elapsed());
        Some(index)
    } else {
        None
    };
    
    // Stage 4: Open artifact database
    let mut db = ArtifactDatabase::open_or_create(case_dir, &args.case_name)?;
    
    // Stage 5: Run plugins with full context
    let start = Instant::now();
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
    let elapsed = start.elapsed();
    
    // Stage 6: Summary
    let total_artifacts: u64 = results.iter()
        .filter_map(|(_, r)| r.as_ref().ok().map(|o| o.artifacts.len() as u64))
        .sum();
    
    let summary = IngestSummary {
        case_name: args.case_name.clone(),
        examiner: args.examiner.clone(),
        source: args.source.clone(),
        evidence_metadata,
        plugin_count: results.len(),
        artifact_count: total_artifacts,
        elapsed_ms: elapsed.as_millis() as u64,
    };
    
    // Write run_summary.json
    if let Some(path) = &args.json_result {
        serde_json::to_writer_pretty(fs::File::create(path)?, &summary)?;
    }
    
    // Print text summary
    println!("=== Strata Ingest Run ===");
    println!("Case: {}", summary.case_name);
    println!("Examiner: {}", summary.examiner);
    println!("Source: {}", summary.source);
    println!("Elapsed: {} ms", summary.elapsed_ms);
    println!("Plugins: {} total", summary.plugin_count);
    println!("Artifacts: {} (persisted to {})", summary.artifact_count, db.path().display());
    
    Ok(IngestResult::from(summary))
}
```

**Integration tests:**

```rust
#[test]
fn ingest_run_on_nps_jean_produces_artifacts() {
    let image = "/Users/randolph/Wolfmark/Test Material/nps-2008-jean.E01";
    if !Path::new(image).exists() {
        return; // Skip cleanly
    }
    
    let case_dir = tempdir().unwrap();
    let args = IngestArgs {
        source: image.to_string(),
        case_dir: case_dir.path().to_path_buf(),
        case_name: "nps-jean-ingest-test".to_string(),
        examiner: "Integration Test".to_string(),
        auto: true,
        auto_unpack: true,
        ..Default::default()
    };
    
    let result = run_ingest(args).expect("ingest must succeed");
    
    assert!(result.artifact_count >= 100, "NPS Jean must produce ≥100 artifacts, got {}", result.artifact_count);
    assert!(Path::new(&case_dir.path().join("artifacts.sqlite")).exists());
    
    let db = ArtifactDatabase::open(case_dir.path(), "nps-jean-ingest-test").unwrap();
    assert!(db.count().unwrap() >= 100);
}
```

**Acceptance criteria:**

- [ ] `strata ingest run --source nps-2008-jean.E01 --case-dir /tmp/jean --auto` completes successfully
- [ ] artifacts.sqlite exists in case_dir with ≥100 rows
- [ ] audit_log.jsonl exists with evidence_opened entry
- [ ] run_summary.json written correctly
- [ ] Terminal output reports plugin count, artifact count, elapsed time
- [ ] Clippy clean, no new unwrap/unsafe/println

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 6 — VALIDATION + GAP CLOSURE
# ═══════════════════════════════════════════════════════════════════════

## SPRINT REGRESS-1 — Full Test Material Matrix Validation

Run `strata ingest run` against every image in Test Material and
measure real artifact output.

**Problem statement:**
This is the first honest field validation since the discovery that
"plugin runs green" was not equivalent to "plugin extracts real
artifacts." Must produce concrete numbers per image per plugin.

**Implementation:**

Create `tests/regression/matrix_v11.rs`:

```rust
#[test]
#[ignore] // Run manually: cargo test --release --ignored matrix_v11
fn v11_full_matrix_validation() {
    let test_material = "/Users/randolph/Wolfmark/Test Material";
    let results_root = PathBuf::from("/tmp/strata-v11-regression");
    let _ = fs::remove_dir_all(&results_root);
    fs::create_dir_all(&results_root).unwrap();
    
    struct Case {
        name: &'static str,
        path: String,
        min_artifacts_total: u64,
        min_per_plugin: &'static [(&'static str, u64)],
        expected_classification: &'static str,
    }
    
    let cases: Vec<Case> = vec![
        Case {
            name: "nps-jean",
            path: format!("{}/nps-2008-jean.E01", test_material),
            min_artifacts_total: 100,
            min_per_plugin: &[
                ("Strata Phantom", 20),
                ("Strata Chronicle", 10),
                ("Strata Trace", 5),
            ],
            expected_classification: "WindowsXp",
        },
        Case {
            name: "charlie",
            path: format!("{}/charlie-2009-11-12.E01", test_material),
            min_artifacts_total: 80,
            min_per_plugin: &[("Strata Phantom", 15)],
            expected_classification: "WindowsXp",
        },
        Case {
            name: "terry",
            path: format!("{}/terry-2009-12-03.E01", test_material),
            min_artifacts_total: 80,
            min_per_plugin: &[("Strata Phantom", 15)],
            expected_classification: "WindowsXp",
        },
        Case {
            name: "windows-ftk",
            path: format!("{}/windows-ftkimager-first.E01", test_material),
            min_artifacts_total: 150,
            min_per_plugin: &[
                ("Strata Phantom", 30),
                ("Strata Chronicle", 20),
            ],
            expected_classification: "Windows7Plus",
        },
        Case {
            name: "ctf-windows-2019",
            path: format!("{}/2019 CTF - Windows-Desktop/2019 CTF - Windows-Desktop-001.E01", test_material),
            min_artifacts_total: 500,
            min_per_plugin: &[
                ("Strata Phantom", 50),
                ("Strata Chronicle", 40),
                ("Strata Trace", 30),
                ("Strata Sentinel", 20),
            ],
            expected_classification: "Windows10Plus",
        },
        Case {
            name: "takeout",
            path: format!("{}/Takeout", test_material),
            min_artifacts_total: 4, // Baseline from v9
            min_per_plugin: &[("Strata Carbon", 2)],
            expected_classification: "GoogleTakeout",
        },
        Case {
            name: "cellebrite",
            path: format!("{}/Cellebrite.tar", test_material),
            min_artifacts_total: 50,
            min_per_plugin: &[],
            expected_classification: "UfedTar",
        },
        Case {
            name: "jess-iphone8",
            path: format!("{}/Jess_CTF_iPhone8", test_material),
            min_artifacts_total: 50,
            min_per_plugin: &[("Strata Pulse", 10)],
            expected_classification: "IosCtf",
        },
        Case {
            name: "android14",
            path: format!("{}/Android_14_Public_Image.tar", test_material),
            min_artifacts_total: 200,
            min_per_plugin: &[("Strata Carbon", 50)],
            expected_classification: "Android",
        },
        // ... more cases
    ];
    
    let mut report_lines = Vec::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    
    report_lines.push("# Field Validation v11 Report".to_string());
    report_lines.push(format!("Generated: {}", chrono::Utc::now()));
    report_lines.push(String::new());
    
    for case in &cases {
        if !Path::new(&case.path).exists() {
            report_lines.push(format!("## SKIP: {} (not present)", case.name));
            skipped += 1;
            continue;
        }
        
        let case_dir = results_root.join(case.name);
        let start = Instant::now();
        
        let args = IngestArgs {
            source: case.path.clone(),
            case_dir: case_dir.clone(),
            case_name: case.name.to_string(),
            examiner: "Regression Test".to_string(),
            auto: true,
            auto_unpack: true,
            ..Default::default()
        };
        
        let result = std::panic::catch_unwind(|| run_ingest(args));
        let elapsed = start.elapsed();
        
        match result {
            Ok(Ok(r)) => {
                let db = ArtifactDatabase::open(&case_dir, case.name).unwrap();
                let total = db.count().unwrap();
                let per_plugin = db.count_by_plugin().unwrap();
                
                report_lines.push(format!("## {} ({:?})", case.name, elapsed));
                report_lines.push(format!("Total artifacts: {} (min: {})", total, case.min_artifacts_total));
                
                let mut case_passed = total >= case.min_artifacts_total;
                
                for (plugin, min) in case.min_per_plugin {
                    let actual = per_plugin.get(*plugin).copied().unwrap_or(0);
                    let ok = actual >= *min;
                    if !ok {
                        case_passed = false;
                    }
                    report_lines.push(format!("  - {}: {} (min: {}) {}", plugin, actual, min, if ok { "✓" } else { "✗" }));
                }
                
                if case_passed {
                    report_lines.push("**PASS**".to_string());
                    passed += 1;
                } else {
                    report_lines.push("**FAIL**".to_string());
                    failed += 1;
                }
            }
            Ok(Err(e)) => {
                report_lines.push(format!("## ERROR: {} — {}", case.name, e));
                failed += 1;
            }
            Err(_) => {
                report_lines.push(format!("## PANIC: {}", case.name));
                failed += 1;
            }
        }
        report_lines.push(String::new());
    }
    
    report_lines.push(format!("## Summary: {} passed, {} failed, {} skipped", passed, failed, skipped));
    
    fs::write("FIELD_VALIDATION_v11_REPORT.md", report_lines.join("\n")).unwrap();
    
    // Print to stdout
    for line in &report_lines {
        eprintln!("{}", line);
    }
    
    // Test fails if any case failed (not just total count)
    assert_eq!(failed, 0, "Regression validation: {} cases failed", failed);
}
```

**Expected outcome:**

The moment Part 1 (EWF-FIX-1) lands and all filesystem walkers ship
and all plugins are migrated, this test will run the full matrix and
produce real numbers. The report becomes the first honest field
validation in the project's history.

**Compare against:**
- v10 report: showed E01 reading broken, 0 real artifacts
- v9 report: showed persistence wired but no filesystem mounting
- v6/v7/v8 reports: showed "plugin runs green" without real extraction

**Deliverable:**
`FIELD_VALIDATION_v11_REPORT.md` checked into repo.

---

## SPRINT REGRESS-2 — Gap Closure

Fix any plugins revealed as broken by REGRESS-1.

**Problem statement:**
Real evidence ingestion at full VFS scope may reveal plugins whose
parsers work on unit test fixtures but fail on real-world data.

**Methodology:**

For each plugin in REGRESS-1 that produced significantly fewer
artifacts than expected on its appropriate image type:

1. Open artifacts.sqlite for that case
2. Check what the plugin did emit (if anything)
3. Open the real target file with a known-good tool to confirm data exists
4. Debug plugin against real file
5. Write test case from real-file-derived fixture (redact sensitive data)
6. Fix parser
7. Verify fix preserves existing tests
8. Re-run REGRESS-1, confirm artifact count now meets minimum

**Common failure modes anticipated:**

- **Path case sensitivity** — NTFS paths may use different case than
  plugin expects
- **Path separator issues** — forward slash via VFS vs backslash in
  NTFS native format
- **Schema version mismatches** — plugin built for Win 10, image is XP
  (example: Chronicle looking for UserAssist key that doesn't exist
  on older Windows)
- **Missing field handling** — plugin assumes column exists in table
- **Encoding** — UTF-16LE vs UTF-8, BOM handling
- **Deleted file handling** — plugin reads allocated only, misses
  unallocated MFT entries

**No time box.** This sprint runs until every plugin performs as
expected on its appropriate image types. Update FIELD_VALIDATION_v11_REPORT.md
with final numbers after every fix.

**Acceptance criteria:**

- [ ] Every E01 in Test Material produces ≥50 artifacts
- [ ] Every mobile image (iOS/Android) produces ≥100 artifacts
- [ ] Every Takeout/Cellebrite produces ≥expected minimum
- [ ] FIELD_VALIDATION_v11_REPORT.md shows all-pass
- [ ] Test count: whatever REGRESS-1 count was, plus regression tests
  for every fix
- [ ] Clippy clean, no new unwrap/unsafe/println

Zero unwrap, zero unsafe, Clippy clean, regression tests for every fix.

---

# ═══════════════════════════════════════════════════════════════════════
# COMPLETION CRITERIA
# ═══════════════════════════════════════════════════════════════════════

SPRINTS_v11.md is complete when:

**EWF unblock (Part 1):**
- NPS Jean E01 reads past byte 0xc0000000 with real data
- All three v10 NTFS ground truth tests pass
- Chunk-table diagnostics confirm full coverage

**Filesystem walkers (Part 2):**
- Ext4Walker opens ext4, reads files + xattrs + deleted inodes
- FatWalker opens FAT32/exFAT, walks LFNs + recovers deleted
- ApfsWalker opens APFS, walks volumes + snapshots
- HfsPlusWalker opens HFS+, handles data + resource forks
- Each ships with integration tests against real images where available

**Auto-dispatch (Part 3):**
- Filesystem auto-detection correctly identifies all filesystem types
- Dispatcher returns correct concrete walker

**Plugin migration (Part 4):**
- PluginContext extended with Optional VFS pointer
- All 26 plugins migrated to use ctx helpers
- All existing tests still pass

**End-to-end (Part 5):**
- `strata ingest run` opens E01, parses partitions, mounts filesystems,
  builds VFS, runs plugins, persists artifacts
- Integration test against NPS Jean produces ≥100 artifacts

**Validation (Part 6):**
- Full Test Material matrix re-run with real artifact counts
- FIELD_VALIDATION_v11_REPORT.md documents real numbers
- Any gaps closed

**Quality gates:**
- Test count: 3,640+ plus many new tests (likely 4,200+ total)
- All tests passing
- Clippy clean workspace-wide
- Zero `.unwrap()`, zero `unsafe{}`, zero `println!` introduced
- All 9 load-bearing tests preserved
- No public API regressions

**The moment (unchanged from v10):**

```
strata ingest run --source nps-2008-jean.E01 --case-dir ./jean --auto
```

produces a case directory with artifacts.sqlite containing hundreds of
real Windows artifacts extracted from real evidence by real plugins
walking real NTFS, APFS, ext4, FAT, and HFS+ filesystems.

Strata is a forensic tool.

---

*STRATA AUTONOMOUS BUILD QUEUE v11*
*Wolfmark Systems — 2026-04-18*
*Part 1: EWF chunk-table accumulator fix — critical unblock*
*Part 2: Remaining filesystem walkers (ext4, FAT, APFS, HFS+)*
*Part 3: Filesystem auto-dispatch*
*Part 4: Plugin migration to VFS-aware APIs*
*Part 5: End-to-end CLI integration*
*Part 6: Validation + gap closure*
*Mission: Close the loop. Strata becomes a forensic tool.*
*Execute all incomplete sprints in order. Ship everything.*
