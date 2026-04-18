# SPRINTS_v14.md — STRATA FILESYSTEM WALKERS + INDEPENDENT UNBLOCKED WORK
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md, SESSION_STATE_v13_BLOCKER.md, docs/RESEARCH_v10_CRATES.md,
#         and SPRINTS_v14.md. Execute all incomplete sprints in order."
# Last updated: 2026-04-18
# Prerequisite: SPRINTS_v1.md through SPRINTS_v13.md complete (3,666 tests passing)
#
# ═══════════════════════════════════════════════════════════════════════
# WHERE STRATA IS AT THE START OF v14
# ═══════════════════════════════════════════════════════════════════════
#
# v13 shipped the non-negotiable gate (REGRESS-GUARD-1) and housekeeping.
# Charlie 3,400 and Jo 3,537 are now cargo-test-runnable regression
# guards. CLAUDE.md is reconciled to the actual 24-crate reality.
# docs/RESEARCH_v10_CRATES.md is committed. The H4 anti-pattern item was
# correctly voided — unwrap_or_default() is the clippy-preferred idiom.
#
# v13 deferred the walker sprints with documented pickup signals in
# SESSION_STATE_v13_BLOCKER.md. The reason was honest: each walker is
# 300-600 LOC of production code + integration tests. Shipping four
# simultaneously in one session would have required shallow stubs that
# silently compromise the spec.
#
# v14 picks up the walker work with the correct scope: one walker per
# sprint, with real test coverage, after satisfying any architectural
# prerequisites documented in the v13 blocker.
#
# ═══════════════════════════════════════════════════════════════════════
# THE MISSION
# ═══════════════════════════════════════════════════════════════════════
#
# v14 ships every remaining filesystem walker, activates the dispatcher,
# migrates the three highest-volume plugins to VFS-native reads, adds
# acquisition-trim diagnostics, ships the AST-aware quality gate, and
# validates the full Test Material matrix.
#
# When v14 completes:
#
#   - HfsPlusWalker ships (after Read + Seek refactor)
#   - FatWalker ships (with committed fixture)
#   - Ext4Walker ships (wrapping ext4-view v0.9, API verified)
#   - ApfsWalker ships (single-volume first, then multi-volume)
#   - Dispatcher routes all filesystem types to live walkers
#   - Vector, Chronicle, Trace migrate to VFS-native streaming reads
#   - EWF acquisition-trim warnings surface structurally
#   - AST-aware quality gate binary enforces meaningful violation counts
#   - Full Test Material matrix passes end-to-end with v14 scorecard
#
# ═══════════════════════════════════════════════════════════════════════
# SCOPE AND ORDERING RATIONALE
# ═══════════════════════════════════════════════════════════════════════
#
# 10 sprints. Ordering is strategic:
#
# Sprint 1 — EWF-TRIM-WARN-1 (fully independent; smallest scope; fast win)
# Sprint 2 — FS-HFSPLUS-1 (smallest walker refactor; establishes Read+Seek pattern)
# Sprint 3 — FS-FAT-1 (fixture-first; medium scope)
# Sprint 4 — FS-EXT4-1 (API verification first; wraps ext4-view crate)
# Sprint 5 — FS-APFS-SINGLE-1 (single-volume first; largest walker scope)
# Sprint 6 — FS-APFS-MULTI-1 (multi-volume CompositeVfs on top of single)
# Sprint 7 — FS-DISPATCH-FINAL (activates all live walkers)
# Sprint 8 — VFS-NATIVE-TOP3 (Vector, Chronicle, Trace migration)
# Sprint 9 — H3-AST-QUALITY-GATE (tools/strata-verify-quality/)
# Sprint 10 — REGRESS-V14-FINAL (full matrix + report)
#
# Why this order:
#   - Sprint 1 is fully independent — no dependencies, ships fast,
#     builds momentum
#   - Sprints 2-6 are the walker build-out, ordered from smallest
#     architectural risk (HFS+ refactor) to largest (APFS multi-volume)
#   - Sprint 7 activates everything — cannot ship before walkers exist
#   - Sprint 8 is mechanical migration — can ship any time but placed
#     after dispatcher so VFS-native plugins run against all FS types
#   - Sprint 9 is tooling, independent but placed before final matrix
#     so the matrix runs under the new quality gate
#   - Sprint 10 is capstone — validates everything shipped
#
# ═══════════════════════════════════════════════════════════════════════
# DISCIPLINE — CARRIED FORWARD FROM v9 THROUGH v13
# ═══════════════════════════════════════════════════════════════════════
#
# "Do not silently compromise the spec." If any sprint reveals a real
# blocker, stop, document in `SESSION_STATE_v14_BLOCKER.md`, continue
# with subsequent unblocked sprints.
#
# v13 proved the discipline works — REGRESS-GUARD-1 shipped non-
# negotiable, H4 was correctly voided when research showed the spec
# was wrong, and walker work deferred rather than shipping shallow
# stubs. Carry that forward.
#
# Ground truth validation is mandatory. Every walker ships with
# integration tests against a real image or committed test fixture
# before being declared shipped.
#
# Quality gates: all tests pass from 3,666 start, clippy clean, zero
# new unwrap/unsafe/println in production code, all 9 load-bearing
# tests preserved, no public API regressions. v14 also introduces the
# AST-aware quality check as a cargo-test-runnable gate.

---

## HOW TO EXECUTE

Read CLAUDE.md, SESSION_STATE_v13_BLOCKER.md, docs/RESEARCH_v10_CRATES.md,
FIELD_VALIDATION_v12_REPORT.md, and SPRINTS_v14.md in that order. Then
execute each sprint below in order.

For each sprint:
1. Implement exactly as specified
2. Run `cargo test --workspace` — all tests must pass (starting from 3,666)
3. Run `cargo clippy --workspace -- -D warnings` — must be clean
4. Verify zero `.unwrap()`, zero `unsafe{}`, zero `println!` added to
   library/parser crates
5. Commit with message: "feat: [sprint-id] [description]" or "fix: [sprint-id] [description]"
6. Move to next sprint immediately

---

## COMPLETED SPRINTS (skip these)

None yet — this is v14.

---

# ═══════════════════════════════════════════════════════════════════════
# SPRINT 1 — EWF-TRIM-WARN-1 — ACQUISITION-TRIM DIAGNOSTICS
# ═══════════════════════════════════════════════════════════════════════

Ships first because it's fully independent (no walker dependencies)
and delivers immediate examiner-facing value.

**Problem statement:**

Terry and NPS Jean E01s produce 4 artifacts in v12 field validation.
Diagnostic investigation confirmed the cause: both images are
acquisition-trimmed before the MFT offset. The EWF reader returns
zeros for offsets beyond the acquired range, which surfaces as a
silent 4-artifact result indistinguishable from a plugin bug.

Examiners reading field reports cannot tell "image truncated" from
"tool broken." This sprint makes the distinction structural.

**Implementation:**

Update `crates/strata-evidence/src/e01.rs`:

```rust
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EwfWarning {
    OffsetBeyondAcquired {
        requested_offset: u64,
        acquired_ceiling: u64,
        segment_count: u32,
    },
    ChunkOffsetInvalid {
        chunk_number: u64,
        stored_offset: u64,
    },
    HashMismatch {
        expected: String,
        observed: String,
        algorithm: &'static str,
    },
}

pub struct E01Image {
    // ... existing fields ...
    warnings: Mutex<Vec<EwfWarning>>,
    highest_mapped_offset: u64,  // For acquired_ceiling reporting
}

impl E01Image {
    pub fn warnings(&self) -> Vec<EwfWarning> {
        self.warnings.lock()
            .map(|w| w.clone())
            .unwrap_or_default()
    }
    
    fn record_warning(&self, w: EwfWarning) {
        if let Ok(mut warnings) = self.warnings.lock() {
            warnings.push(w);
        }
    }
}

impl EvidenceImage for E01Image {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        // ... existing chunk lookup logic ...
        
        // Replace silent zero-return with structured warning:
        match self.lookup_chunk(offset) {
            Some(chunk) => {
                // Normal read path
                self.read_chunk_into(chunk, buf)
            }
            None => {
                // Record structured warning, return zeros (backward-compat)
                self.record_warning(EwfWarning::OffsetBeyondAcquired {
                    requested_offset: offset,
                    acquired_ceiling: self.highest_mapped_offset,
                    segment_count: self.segments.len() as u32,
                });
                // Zero-fill and return len (existing behavior)
                buf.fill(0);
                Ok(buf.len())
            }
        }
    }
}
```

**CLI surface update:**

Update `strata-shield-cli/src/commands/ingest.rs` to report warnings
after ingestion completes:

```rust
fn print_summary(summary: &IngestSummary, warnings: &[EwfWarning]) {
    println!("=== Strata Ingest Run ===");
    println!("Case: {}", summary.case_name);
    // ... existing fields ...
    
    if !warnings.is_empty() {
        let trim_warnings = warnings.iter()
            .filter(|w| matches!(w, EwfWarning::OffsetBeyondAcquired { .. }))
            .count();
        if trim_warnings > 0 {
            println!();
            println!("Warnings: {}", warnings.len());
            println!("  - EWF reader: {} read(s) requested past acquired range", trim_warnings);
            println!("    Image may be acquisition-trimmed. Artifacts may be incomplete.");
            
            // Show first 3 concrete examples
            for (i, w) in warnings.iter()
                .filter(|w| matches!(w, EwfWarning::OffsetBeyondAcquired { .. }))
                .take(3)
                .enumerate()
            {
                if let EwfWarning::OffsetBeyondAcquired {
                    requested_offset,
                    acquired_ceiling,
                    ..
                } = w {
                    println!("      [{}] requested 0x{:x}, ceiling 0x{:x}",
                             i + 1, requested_offset, acquired_ceiling);
                }
            }
            if trim_warnings > 3 {
                println!("      ... and {} more", trim_warnings - 3);
            }
        }
    }
}
```

**Audit log integration:**

Warnings also flow to `audit_log.jsonl`:

```json
{"ts": "2026-04-18T...", "kind": "ewf_offset_beyond_acquired", "requested": 972488704, "ceiling": 469762048}
```

**JSON summary integration:**

The `run_summary.json` gains a `warnings` array so machine consumers
(CI, dashboards) can detect trim conditions programmatically.

**Tests required:**

- `ewf_warning_emitted_on_offset_beyond_acquired` — construct an E01,
  call read_at with offset beyond the mapped range, verify warning
  recorded
- `ewf_no_warning_on_normal_read` — read within range, verify warnings
  is empty
- `ewf_multiple_warnings_accumulate` — multiple out-of-range reads
  accumulate
- `ewf_warnings_thread_safe` — concurrent reads from multiple threads
  don't corrupt warnings vec
- `cli_prints_trim_warning_on_terry` — skip-guarded integration test
  running `strata ingest run` against Terry, verifying stderr/stdout
  contains the trim warning
- `audit_log_includes_trim_events` — same, verify audit_log.jsonl
  contains `ewf_offset_beyond_acquired` entries

**Acceptance criteria:**

- [ ] `E01Image::warnings()` returns populated vec for Terry/Jean
- [ ] `E01Image::warnings()` returns empty for Charlie/Jo
- [ ] CLI prints Warnings section when warnings present
- [ ] Audit log captures warning events
- [ ] run_summary.json includes warnings array
- [ ] Test count: 3,666 → 3,672+
- [ ] Clippy clean, no new unwrap/unsafe/println in library code

Zero unwrap, zero unsafe, Clippy clean, 6+ tests minimum.

**Why this sprint ships first:**

Fully independent of walker work. Examiners using Strata today
immediately benefit from structured trim diagnostics. Small scope
(~200 LOC), fast win, builds session momentum before tackling walker
refactors.

---

# ═══════════════════════════════════════════════════════════════════════
# SPRINT 2 — FS-HFSPLUS-1 — HFS+ WALKER (Read+Seek REFACTOR + WRAP)
# ═══════════════════════════════════════════════════════════════════════

Ships second because the pickup signal from v13 blocker is concrete:
refactor `hfsplus.rs` from file-path API to Read+Seek, then wrap.
This is the smallest walker architectural change.

**Problem statement:**

`crates/strata-fs/src/hfsplus.rs` exists as a parser-only module that
takes file paths as input. The NtfsWalker pattern requires a
Read+Seek consumer wrapped in `PartitionReader`. The hfsplus module
needs refactoring before it can be promoted to a walker.

**Implementation plan:**

**Phase A — Refactor hfsplus.rs to Read+Seek API:**

1. Identify every function in `hfsplus.rs` that takes `&Path` or
   `&str`:
   ```bash
   grep -n "fn.*Path\|fn.*\&str" crates/strata-fs/src/hfsplus.rs
   ```

2. For each, introduce a Read+Seek variant:
   ```rust
   // Before:
   pub fn parse_volume_header(path: &Path) -> HfsResult<HfsPlusVolumeHeader>;
   
   // After (keep both during transition):
   pub fn parse_volume_header_from_reader<R: Read + Seek>(
       reader: &mut R,
   ) -> HfsResult<HfsPlusVolumeHeader>;
   
   pub fn parse_volume_header(path: &Path) -> HfsResult<HfsPlusVolumeHeader> {
       let mut file = File::open(path)?;
       parse_volume_header_from_reader(&mut file)
   }
   ```

3. Ensure existing tests pass after refactor before moving to Phase B.

**Phase B — Create HfsPlusWalker wrapping refactored parser:**

Follow the NtfsWalker pattern from v10:

```rust
// crates/strata-fs/src/hfsplus_walker/mod.rs

use crate::hfsplus::*;  // Refactored parsers
use crate::vfs::*;
use std::sync::{Arc, Mutex};

pub struct HfsPlusWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    inner: Mutex<HfsPlusInner>,
}

struct HfsPlusInner {
    volume_header: HfsPlusVolumeHeader,
    catalog: CatalogBtree,
    extents: ExtentsBtree,
    attributes: AttributesBtree,
    case_sensitive: bool,
    reader: PartitionReader,
}

impl HfsPlusWalker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> HfsPlusResult<Self> {
        let mut reader = PartitionReader::new(
            Arc::clone(&image),
            partition_offset,
            partition_size,
        );
        let volume_header = parse_volume_header_from_reader(&mut reader)?;
        let catalog = parse_catalog_btree_from_reader(&mut reader, &volume_header)?;
        let extents = parse_extents_btree_from_reader(&mut reader, &volume_header)?;
        let attributes = parse_attributes_btree_from_reader(&mut reader, &volume_header)?;
        let case_sensitive = volume_header.signature == HFSX_SIGNATURE;
        
        Ok(Self {
            image,
            partition_offset,
            partition_size,
            inner: Mutex::new(HfsPlusInner {
                volume_header,
                catalog,
                extents,
                attributes,
                case_sensitive,
                reader,
            }),
        })
    }
}

impl VirtualFilesystem for HfsPlusWalker {
    fn fs_type(&self) -> &'static str { "hfsplus" }
    
    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        let inner = self.inner.lock().map_err(|_| VfsError::LockPoisoned)?;
        inner.catalog.list_dir(path, inner.case_sensitive)
            .map(|entries| entries.into_iter().map(hfsplus_entry_to_vfs).collect())
            .map_err(VfsError::from)
    }
    
    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        // Data fork by default
        self.read_data_fork(path)
    }
    
    fn alternate_streams(&self, path: &str) -> VfsResult<Vec<String>> {
        let mut streams = self.list_xattrs(path)?;
        if self.has_resource_fork(path)? {
            streams.push("rsrc".to_string());
        }
        Ok(streams)
    }
    
    fn read_alternate_stream(&self, path: &str, stream: &str) -> VfsResult<Vec<u8>> {
        if stream == "rsrc" {
            self.read_resource_fork(path)
        } else {
            self.read_xattr(path, stream)
        }
    }
    
    // ... remaining trait methods
}
```

**Special HFS+ considerations:**

- **Data fork vs resource fork:** HFS+ files have two data streams.
  Data fork is the default `read_file` target. Resource fork exposed
  as alternate stream `"rsrc"`.
- **Case sensitivity:** HFS+ is case-insensitive by default. HFSX
  (signature differs) is case-sensitive. Detect via volume header,
  honor in catalog lookups.
- **Hard links:** Resolved via `iNode` catalog entries at
  `\x00\x00\x00\x00HFS+ Private Data\x0D` directory.
- **Unicode normalization:** HFS+ stores filenames in Unicode NFC
  form. Lookup from external paths requires NFC normalization first.

**Ground truth tests:**

If no Time Machine backup or HFS+ image available in Test Material,
commit a minimal HFS+ test fixture:

```bash
# Optional build script or committed binary:
crates/strata-fs/tests/fixtures/hfsplus_small.img  # ~2 MB
```

Generate via `hformat` + `hcopy` on Linux if needed.

Tests:

```rust
#[test]
fn hfsplus_walker_opens_fixture() {
    let fixture = Path::new("crates/strata-fs/tests/fixtures/hfsplus_small.img");
    if !fixture.exists() { return; }
    
    let image = open_evidence(fixture).expect("open");
    let walker = HfsPlusWalker::open(Arc::clone(&image), 0, image.size())
        .expect("open HFS+");
    
    let root = walker.list_dir("/").expect("list root");
    assert!(!root.is_empty());
}

#[test]
fn hfsplus_walker_reads_data_fork() { /* ... */ }

#[test]
fn hfsplus_walker_reads_resource_fork() { /* ... */ }

#[test]
fn hfsplus_walker_resolves_hard_links() { /* ... */ }

#[test]
fn hfsplus_walker_handles_case_insensitive_lookup() { /* ... */ }

#[test]
fn hfsplus_walker_implements_vfs_trait() { /* ... */ }
```

**Tests required:**

- Refactored hfsplus.rs Read+Seek variants pass existing unit tests
- HfsPlusWalker::open on fixture succeeds
- List root directory
- Read data fork
- Read resource fork as alternate stream
- Hard link resolution
- Case-insensitive vs case-sensitive (HFSX)
- VirtualFilesystem trait compliance

Zero unwrap, zero unsafe, Clippy clean, 7+ tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# SPRINT 3 — FS-FAT-1 — FAT WALKER (FIXTURE-FIRST)
# ═══════════════════════════════════════════════════════════════════════

Ships third. v13 blocker pickup signal: "commit FAT32 fixture first,
then implement FatWalker." Existing fat.rs + exfat.rs are fast-scan
modules, not walkers — they need architectural extension.

**Problem statement:**

`crates/strata-fs/src/fat.rs` and `exfat.rs` exist as fast-scan
modules. Fast-scan means they can extract specific artifacts but
don't implement full directory walking, file reading, or cluster
chain traversal. v13 diagnostic confirmed they need extension before
they can be promoted to walkers.

v9 attempted `fatfs` crate integration but rolled back because
`fatfs` requires `ReadWriteSeek` even for read-only usage. Research
doc confirms native read-only implementation is correct path.

**Implementation plan:**

**Phase A — Commit FAT32 test fixture:**

Generate a 1 MB FAT32 image with known contents:

```bash
# Create the fixture (may require a build script using mtools):
dd if=/dev/zero of=fat32_small.img bs=1M count=1
mkfs.fat -F 32 -n TESTVOL fat32_small.img

# Populate via mtools:
mcopy -i fat32_small.img README.TXT ::README.TXT
mmd -i fat32_small.img ::/dir1
mcopy -i fat32_small.img file1.dat ::/dir1/file1.dat
mcopy -i fat32_small.img deleted.txt ::/deleted.txt
# Delete it to create 0xE5 entry:
mdel -i fat32_small.img ::/deleted.txt
mcopy -i fat32_small.img longfilename_testcase.txt ::/longfilename_testcase.txt
```

Commit to `crates/strata-fs/tests/fixtures/fat32_small.img`. Also
commit generation script at `crates/strata-fs/tests/fixtures/mkfat32.sh`
for reproducibility.

**Phase B — Extend existing fat.rs / exfat.rs to full walkers:**

Audit existing code:
```bash
grep -n "pub fn" crates/strata-fs/src/fat.rs crates/strata-fs/src/exfat.rs
```

Add missing functions:
- Boot sector full parsing (BPB + variant detection)
- FAT table full reading (12/16/32-bit cluster chains)
- Directory entry full parsing (8.3 + LFN)
- exFAT entry groups (File 0x85 + StreamExt 0xC0 + FileName 0xC1)
- Cluster chain walking
- Deleted entry detection (0xE5 first byte)
- exFAT allocation bitmap reading

**Phase C — Create FatWalker wrapping extended parsers:**

```rust
// crates/strata-fs/src/fat_walker/mod.rs

use crate::fat;
use crate::exfat;
use crate::vfs::*;
use std::sync::{Arc, Mutex};

pub enum FatVariant {
    Fat12,
    Fat16,
    Fat32,
    ExFat,
}

pub struct FatWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    variant: FatVariant,
    inner: Mutex<FatInner>,
}

enum FatInner {
    Standard(fat::FatState),    // FAT12/16/32
    ExFat(exfat::ExFatState),
}

impl FatWalker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> FatResult<Self> {
        let mut reader = PartitionReader::new(
            Arc::clone(&image),
            partition_offset,
            partition_size,
        );
        
        // Detect variant from boot sector
        let variant = detect_fat_variant(&mut reader)?;
        
        let inner = match variant {
            FatVariant::Fat12 | FatVariant::Fat16 | FatVariant::Fat32 => {
                FatInner::Standard(fat::FatState::open(reader, variant)?)
            }
            FatVariant::ExFat => {
                FatInner::ExFat(exfat::ExFatState::open(reader)?)
            }
        };
        
        Ok(Self {
            image,
            partition_offset,
            partition_size,
            variant,
            inner: Mutex::new(inner),
        })
    }
}

impl VirtualFilesystem for FatWalker {
    fn fs_type(&self) -> &'static str {
        match self.variant {
            FatVariant::Fat12 => "fat12",
            FatVariant::Fat16 => "fat16",
            FatVariant::Fat32 => "fat32",
            FatVariant::ExFat => "exfat",
        }
    }
    
    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        let inner = self.inner.lock().map_err(|_| VfsError::LockPoisoned)?;
        match &*inner {
            FatInner::Standard(state) => state.list_dir(path).map_err(VfsError::from),
            FatInner::ExFat(state) => state.list_dir(path).map_err(VfsError::from),
        }
    }
    
    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let inner = self.inner.lock().map_err(|_| VfsError::LockPoisoned)?;
        match &*inner {
            FatInner::Standard(state) => state.read_file(path).map_err(VfsError::from),
            FatInner::ExFat(state) => state.read_file(path).map_err(VfsError::from),
        }
    }
    
    fn list_deleted(&self) -> VfsResult<Vec<VfsDeletedEntry>> {
        let inner = self.inner.lock().map_err(|_| VfsError::LockPoisoned)?;
        match &*inner {
            FatInner::Standard(state) => state.recover_deleted().map_err(VfsError::from),
            FatInner::ExFat(state) => state.recover_deleted().map_err(VfsError::from),
        }
    }
    
    // ... remaining trait methods
}
```

**Deleted file recovery (FAT's forensic superpower):**

FAT is particularly forensics-friendly. Deleted directory entries
remain intact (marked with 0xE5). Cluster chains may be intact if
not overwritten. Implement:

```rust
fn recover_deleted(&self) -> FatResult<Vec<VfsDeletedEntry>> {
    // Scan all directory entries
    // For each entry starting with 0xE5:
    //   - Reconstruct filename from LFN entries + truncated 8.3
    //   - Check FAT entries for first cluster
    //   - If cluster chain still points to data, mark recoverable
    //   - Return VfsDeletedEntry with original path guess + content
}
```

**Tests required:**

- Fixture commits successfully to repo
- `mkfat32.sh` produces identical fixture when re-run
- FatWalker opens fixture
- Detect FAT12/FAT16/FAT32/exFAT variants correctly
- List root directory (/README.TXT present)
- Read /README.TXT content matches expected
- Walk /dir1/file1.dat (multi-cluster)
- Recover deleted /deleted.txt from 0xE5 entry
- Parse LFN entry for /longfilename_testcase.txt
- VirtualFilesystem trait compliance

Zero unwrap, zero unsafe, Clippy clean, 9+ tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# SPRINT 4 — FS-EXT4-1 — EXT4 WALKER (API VERIFIED FIRST)
# ═══════════════════════════════════════════════════════════════════════

Ships fourth. v13 blocker pickup signal: verify `ext4-view` v0.9 API
against pseudo-code type assumptions before implementing wrapper.

**Problem statement:**

`ext4-view` crate v0.9 (Nicholas Bishop, pure-Rust, read-only, no_std
compatible) is the correct choice per RESEARCH_v10_CRATES.md. But
v13's blocker note flags that the exact API needs verification — the
crate's `Ext4Read` trait signature, error types, and metadata methods
may differ from the v13 sprint's pseudo-code assumptions.

**Implementation plan:**

**Phase A — API verification:**

1. Add dependency to `crates/strata-fs/Cargo.toml`:
   ```toml
   ext4-view = "0.9"
   ```

2. Create a tiny verification binary or test at
   `crates/strata-fs/src/ext4_walker/api_check.rs`:
   ```rust
   #[cfg(test)]
   mod api_verification {
       use ext4_view::*;
       
       #[test]
       fn verify_ext4_read_trait_shape() {
           // Confirm Ext4Read::read signature
           // Confirm Ext4::load signature
           // Confirm DirEntry methods
           // Confirm Metadata methods (mtime/atime/ctime/crtime/dtime)
           // Confirm error types and conversion path
       }
   }
   ```

3. Cross-reference with https://docs.rs/ext4-view/0.9 docs. Note
   any differences from SPRINTS_v13.md pseudo-code and adjust
   implementation accordingly.

**Phase B — Implement Ext4Walker:**

Follow the NtfsWalker pattern adapted to verified API:

```rust
// crates/strata-fs/src/ext4_walker/mod.rs

use ext4_view::{Ext4, Ext4Read};
use crate::vfs::*;
use std::sync::{Arc, Mutex};

pub struct Ext4Walker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    fs: Mutex<Ext4>,
}

struct Ext4ReadAdapter {
    reader: PartitionReader,
}

impl Ext4Read for Ext4ReadAdapter {
    // Exact signature determined by Phase A verification
    fn read(
        &mut self,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), /* error type per API */> {
        use std::io::{Seek, SeekFrom, Read};
        self.reader.seek(SeekFrom::Start(offset))?;
        self.reader.read_exact(buf)?;
        Ok(())
    }
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
        let adapter = Ext4ReadAdapter { reader };
        let fs = Ext4::load(Box::new(adapter))?;
        Ok(Self {
            image,
            partition_offset,
            partition_size,
            fs: Mutex::new(fs),
        })
    }
}

impl VirtualFilesystem for Ext4Walker {
    fn fs_type(&self) -> &'static str { "ext4" }
    
    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        let fs = self.fs.lock().map_err(|_| VfsError::LockPoisoned)?;
        let mut entries = Vec::new();
        for entry in fs.read_dir(path)? {
            let entry = entry?;
            entries.push(ext4_entry_to_vfs(&entry, &fs)?);
        }
        Ok(entries)
    }
    
    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let fs = self.fs.lock().map_err(|_| VfsError::LockPoisoned)?;
        fs.read(path).map_err(VfsError::from)
    }
    
    fn alternate_streams(&self, path: &str) -> VfsResult<Vec<String>> {
        // ext4 xattrs: security.*, user.*, trusted.*
        let fs = self.fs.lock().map_err(|_| VfsError::LockPoisoned)?;
        let metadata = fs.metadata(path)?;
        // Call ext4-view's xattr accessor (exact method determined by
        // Phase A)
        Ok(metadata.xattr_names().collect())
    }
    
    fn read_alternate_stream(&self, path: &str, xattr: &str) -> VfsResult<Vec<u8>> {
        let fs = self.fs.lock().map_err(|_| VfsError::LockPoisoned)?;
        let metadata = fs.metadata(path)?;
        metadata.xattr(xattr).ok_or(VfsError::NotFound).map(|v| v.to_vec())
    }
    
    fn list_deleted(&self) -> VfsResult<Vec<VfsDeletedEntry>> {
        // ext4 deleted inode detection via dtime != 0
        // May or may not be exposed by ext4-view — verify in Phase A
        // If not, scan inodes manually via raw access
        todo!("Determine ext4-view capability during Phase A verification")
    }
    
    // ... remaining trait methods
}

fn ext4_entry_to_vfs(
    entry: &ext4_view::DirEntry,
    fs: &Ext4,
) -> VfsResult<VfsEntry> {
    // Mapping determined by Phase A API verification
    // VfsSpecific::Ext4 { inode, extents_based } populated from
    // metadata.ino() and metadata.flags() & EXT4_EXTENTS_FL
    todo!("Populate per verified API")
}
```

**Ground truth tests:**

Test against Linux images in Test Material:
- `2022 CTF - Linux.7z` — unpack to find ext4 partition
- `digitalcorpora/linux-dc3dd/` — verify if ext4

```rust
#[test]
fn ext4_walker_opens_ctf_linux() {
    // Unpack the 7z archive to a temp dir (one-time per test run)
    let archive = Path::new("/Users/randolph/Wolfmark/Test Material/2022 CTF - Linux.7z");
    if !archive.exists() { return; }
    
    let unpacked_dir = unpack_7z_to_temp(archive).expect("unpack");
    let image_file = find_dd_or_e01_in(&unpacked_dir).expect("find image");
    
    let image = open_evidence(&image_file).expect("open");
    let partitions = read_partitions(image.as_ref()).expect("partitions");
    
    let ext4_part = partitions.iter()
        .find(|p| matches!(
            p.fs_hint(),
            Some(FsType::Ext4) | Some(FsType::Ext3) | Some(FsType::Ext2)
        ))
        .expect("find ext4 partition");
    
    let walker = Ext4Walker::open(
        Arc::clone(&image),
        ext4_part.offset_bytes(),
        ext4_part.size_bytes(),
    ).expect("open ext4");
    
    let root = walker.list_dir("/").expect("list root");
    let names: std::collections::HashSet<String> =
        root.iter().map(|e| e.name.clone()).collect();
    
    assert!(names.contains("etc"), "must have /etc");
    assert!(names.contains("var"), "must have /var");
    
    let passwd = walker.read_file("/etc/passwd").expect("read passwd");
    assert!(!passwd.is_empty());
}
```

**Tests required:**

- Phase A API verification test passes
- Ext4Walker::open succeeds on Linux image
- List root directory
- Read /etc/passwd
- Walk full filesystem (count > 100 entries)
- Read extended attribute
- ext2 fallback works (ext4-view supports both)
- VirtualFilesystem trait compliance

Zero unwrap, zero unsafe, Clippy clean, 8+ tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# SPRINT 5 — FS-APFS-SINGLE-1 — APFS SINGLE-VOLUME WALKER
# ═══════════════════════════════════════════════════════════════════════

Ships fifth. v13 blocker pickup signal: the 1,283 LOC in-tree APFS
parser lacks VFS trait impl and multi-volume enumeration. Largest
walker scope. Split into single-volume (this sprint) and multi-volume
(next sprint) to keep each session tractable.

**Problem statement:**

Strata has 1,283 LOC of APFS parser code at
`crates/strata-fs/src/apfs.rs`, `apfs_advanced.rs`, and stub
`apfs_walker.rs`. No VirtualFilesystem trait impl exists. Multi-volume
enumeration isn't wired. This sprint handles the single-volume case
first to establish the pattern without simultaneously tackling the
CompositeVfs complexity.

**Scope limitation:**

This sprint ships ApfsWalker that:
- Opens an APFS container
- Operates on exactly one volume (the first Data-role volume found,
  or the first volume if no Data role present)
- Implements VirtualFilesystem trait
- Passes all trait methods through to that single volume

Multi-volume (CompositeVfs) ships in FS-APFS-MULTI-1 next sprint.

**Implementation:**

```rust
// crates/strata-fs/src/apfs_walker/mod.rs

use crate::apfs::*;
use crate::apfs_advanced::*;
use crate::vfs::*;
use std::sync::{Arc, Mutex};

pub struct ApfsWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    container: Mutex<ApfsContainer>,
    volumes: Vec<ApfsVolumeMetadata>,
    active_volume_index: Mutex<usize>,
}

#[derive(Debug, Clone)]
pub struct ApfsVolumeMetadata {
    pub name: String,
    pub role: ApfsVolumeRole,
    pub uuid: uuid::Uuid,
    pub case_sensitive: bool,
    pub encrypted: bool,
    pub snapshot_count: u32,
    pub sealed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApfsVolumeRole {
    None,
    System,
    Data,
    Preboot,
    Recovery,
    Vm,
    Update,
    Xart,
    Hardware,
    Backup,
    Reserved,
    Enterprise,
}

impl ApfsWalker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> ApfsResult<Self> {
        let reader = PartitionReader::new(
            Arc::clone(&image),
            partition_offset,
            partition_size,
        );
        
        let container = ApfsContainer::open_from_reader(reader)?;
        let volumes = container.enumerate_volumes()?
            .into_iter()
            .map(volume_to_metadata)
            .collect::<Vec<_>>();
        
        // Pick active volume: prefer Data role, else first volume
        let active_index = volumes.iter()
            .position(|v| matches!(v.role, ApfsVolumeRole::Data))
            .unwrap_or(0);
        
        if volumes.is_empty() {
            return Err(ApfsError::NoVolumesFound);
        }
        
        Ok(Self {
            image,
            partition_offset,
            partition_size,
            container: Mutex::new(container),
            volumes,
            active_volume_index: Mutex::new(active_index),
        })
    }
    
    pub fn volumes(&self) -> &[ApfsVolumeMetadata] {
        &self.volumes
    }
    
    pub fn active_volume(&self) -> ApfsResult<ApfsVolumeMetadata> {
        let idx = self.active_volume_index.lock()
            .map_err(|_| ApfsError::LockPoisoned)?;
        Ok(self.volumes[*idx].clone())
    }
    
    pub fn set_active_volume(&self, name: &str) -> ApfsResult<()> {
        let new_idx = self.volumes.iter()
            .position(|v| v.name == name)
            .ok_or_else(|| ApfsError::VolumeNotFound(name.to_string()))?;
        let mut idx = self.active_volume_index.lock()
            .map_err(|_| ApfsError::LockPoisoned)?;
        *idx = new_idx;
        Ok(())
    }
    
    pub fn list_snapshots(&self, volume_name: &str) -> ApfsResult<Vec<ApfsSnapshot>> {
        let container = self.container.lock()
            .map_err(|_| ApfsError::LockPoisoned)?;
        container.list_snapshots(volume_name)
    }
}

impl VirtualFilesystem for ApfsWalker {
    fn fs_type(&self) -> &'static str { "apfs" }
    
    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        let container = self.container.lock()
            .map_err(|_| VfsError::LockPoisoned)?;
        let idx = *self.active_volume_index.lock()
            .map_err(|_| VfsError::LockPoisoned)?;
        let volume = &self.volumes[idx];
        
        container.list_dir(&volume.name, path)
            .map(|entries| entries.into_iter().map(apfs_entry_to_vfs).collect())
            .map_err(VfsError::from)
    }
    
    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let container = self.container.lock()
            .map_err(|_| VfsError::LockPoisoned)?;
        let idx = *self.active_volume_index.lock()
            .map_err(|_| VfsError::LockPoisoned)?;
        let volume = &self.volumes[idx];
        
        container.read_file(&volume.name, path)
            .map_err(VfsError::from)
    }
    
    fn alternate_streams(&self, path: &str) -> VfsResult<Vec<String>> {
        // APFS xattrs are alternate streams equivalent
        let container = self.container.lock()
            .map_err(|_| VfsError::LockPoisoned)?;
        let idx = *self.active_volume_index.lock()
            .map_err(|_| VfsError::LockPoisoned)?;
        let volume = &self.volumes[idx];
        
        container.list_xattrs(&volume.name, path)
            .map_err(VfsError::from)
    }
    
    fn read_alternate_stream(&self, path: &str, xattr: &str) -> VfsResult<Vec<u8>> {
        let container = self.container.lock()
            .map_err(|_| VfsError::LockPoisoned)?;
        let idx = *self.active_volume_index.lock()
            .map_err(|_| VfsError::LockPoisoned)?;
        let volume = &self.volumes[idx];
        
        container.read_xattr(&volume.name, path, xattr)
            .map_err(VfsError::from)
    }
    
    // ... remaining trait methods
}
```

**Sealed system volume handling:**

macOS Sonoma+ seals the System volume. Detect via volume flags,
populate `ApfsVolumeMetadata.sealed`. Walk read-only (always true
for forensic use). Never attempt to unseal.

**Ground truth tests:**

Test against iOS CTF images (iOS uses APFS internally):

```rust
#[test]
fn apfs_walker_opens_ios_ctf() {
    let ios_dir = Path::new("/Users/randolph/Wolfmark/Test Material/2020 CTF - iOS");
    if !ios_dir.exists() { return; }
    
    let image_path = find_apfs_image_in_dir(ios_dir);
    let Some(image_path) = image_path else { return };
    
    let image = open_evidence(&image_path).expect("open");
    let partitions = read_partitions(image.as_ref()).expect("partitions");
    
    let apfs_part = partitions.iter()
        .find(|p| matches!(p.fs_hint(), Some(FsType::Apfs)))
        .expect("find APFS partition");
    
    let walker = ApfsWalker::open(
        Arc::clone(&image),
        apfs_part.offset_bytes(),
        apfs_part.size_bytes(),
    ).expect("open APFS");
    
    assert!(!walker.volumes().is_empty(), "must have volumes");
    
    let has_data = walker.volumes().iter().any(|v| {
        matches!(v.role, ApfsVolumeRole::Data) || v.name.contains("Data")
    });
    assert!(has_data, "iOS must have Data volume");
    
    // Single-volume trait methods operate on Data volume
    let root = walker.list_dir("/").expect("list root");
    // iOS Data volume root typically has /private/, /var/, etc.
    assert!(!root.is_empty());
}
```

**Tests required:**

- Open APFS container
- Enumerate volumes with correct roles
- Active volume defaults to Data if present
- set_active_volume changes operation target
- List root of active volume
- Read file from active volume
- List snapshots
- Handle sealed system volume gracefully
- VirtualFilesystem trait compliance

Zero unwrap, zero unsafe, Clippy clean, 8+ tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# SPRINT 6 — FS-APFS-MULTI-1 — APFS MULTI-VOLUME COMPOSITEVFS
# ═══════════════════════════════════════════════════════════════════════

Builds on the single-volume walker to support multi-volume APFS
containers via CompositeVfs (Design A from SPRINTS_v13.md — one VFS
per volume, composed under named roots).

**Problem statement:**

Standard macOS APFS layout has multiple volumes (System + Data +
Preboot + Recovery + VM + Update). iOS has System + Data at minimum.
v13's sprint v13 documented Design A (CompositeVfs with named roots
per volume) as the chosen architecture. This sprint implements it.

**Implementation:**

Add `with_active_volume` method to ApfsWalker that creates a new
walker instance scoped to a specific volume:

```rust
impl ApfsWalker {
    pub fn with_active_volume(
        &self,
        volume_name: &str,
    ) -> ApfsResult<Box<dyn VirtualFilesystem>> {
        let volume_idx = self.volumes.iter()
            .position(|v| v.name == volume_name)
            .ok_or_else(|| ApfsError::VolumeNotFound(volume_name.to_string()))?;
        
        // Create a scoped walker that shares the container but has
        // its own active_volume_index
        let scoped = ApfsWalker {
            image: Arc::clone(&self.image),
            partition_offset: self.partition_offset,
            partition_size: self.partition_size,
            // Share the container via Arc<Mutex<...>>? Or clone?
            // Design decision: share via Arc for memory efficiency
            container: Mutex::new(self.container.lock()
                .map_err(|_| ApfsError::LockPoisoned)?
                .clone()),
            volumes: self.volumes.clone(),
            active_volume_index: Mutex::new(volume_idx),
        };
        
        Ok(Box::new(scoped))
    }
}
```

**Note:** `ApfsContainer::clone()` may require implementation —
verify during sprint. If cloning is expensive or impossible, use
`Arc<Mutex<ApfsContainer>>` shared across scoped walkers.

**Dispatcher integration:**

The APFS arm in `fs_dispatch.rs` detects multi-volume and wraps in
CompositeVfs. This is technically part of FS-DISPATCH-FINAL but the
integration pattern lives here:

```rust
// In dispatcher:
FsType::Apfs => {
    let walker = ApfsWalker::open(Arc::clone(&image), partition_offset, partition_size)?;
    
    if walker.volumes().len() > 1 {
        // Multi-volume → build CompositeVfs with each volume as named root
        let mut composite = CompositeVfs::new();
        for volume_meta in walker.volumes() {
            let volume_walker = walker.with_active_volume(&volume_meta.name)?;
            composite.add(&volume_meta.name, volume_walker);
        }
        Ok(Box::new(composite))
    } else {
        // Single volume → return walker directly
        Ok(Box::new(walker))
    }
}
```

**Path semantics for composite:**

When ApfsWalker is inside CompositeVfs, paths become:
- `/[Macintosh HD]/System/Library/...`
- `/[Macintosh HD - Data]/Users/...`
- `/[Preboot]/...`

Plugins walking the composite see all volumes. Plugins wanting a
specific volume use `ctx.find_files("[Macintosh HD - Data]/**/*")`
glob patterns.

**Ground truth tests:**

```rust
#[test]
fn apfs_multi_volume_returns_composite() {
    let macos_image = find_macos_apfs_image(); // May not exist
    let Some(macos_image) = macos_image else { return };
    
    let image = open_evidence(&macos_image).expect("open");
    let partitions = read_partitions(image.as_ref()).expect("partitions");
    let apfs_part = partitions.iter()
        .find(|p| matches!(p.fs_hint(), Some(FsType::Apfs)))
        .expect("apfs");
    
    let vfs = open_filesystem(
        Arc::clone(&image),
        apfs_part.offset_bytes(),
        apfs_part.size_bytes(),
    ).expect("open");
    
    // Multi-volume macOS should return composite
    assert_eq!(vfs.fs_type(), "composite");
    
    let root = vfs.list_dir("/").expect("list root");
    let names: std::collections::HashSet<String> =
        root.iter().map(|e| e.name.clone()).collect();
    
    // Should contain at least System and Data volume roots
    let has_system = names.iter().any(|n| n.contains("System"));
    let has_data = names.iter().any(|n| n.contains("Data"));
    assert!(has_system || has_data);
}

#[test]
fn apfs_ios_ctf_composite_has_data_volume() {
    // iOS CTF typically has at least 2 volumes
    let ios_image = find_ios_ctf_image();
    let Some(ios_image) = ios_image else { return };
    
    // ... similar pattern
    // iOS Data volume contains /private/var/mobile/...
}

#[test]
fn apfs_single_volume_returns_walker_not_composite() {
    // Construct an APFS image with only 1 volume
    // Verify dispatcher returns ApfsWalker directly, not CompositeVfs
}
```

**Tests required:**

- `with_active_volume` creates scoped walker
- Scoped walker operates on correct volume
- Multi-volume iOS CTF returns CompositeVfs
- Composite root lists volumes as named roots
- Path resolution within a volume works
- Single-volume APFS returns walker directly (not composite)

Zero unwrap, zero unsafe, Clippy clean, 6+ tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# SPRINT 7 — FS-DISPATCH-FINAL — ACTIVATE LIVE WALKERS
# ═══════════════════════════════════════════════════════════════════════

Flips `fs_dispatch.rs` Unsupported arms to live walkers. Depends on
all previous walker sprints.

**Problem statement:**

v11's FS-DISPATCH-1 shipped `detect_filesystem` covering all 11 types
with 12 passing unit tests. `open_filesystem()` dispatches NTFS live
but returns `Err(VfsError::Unsupported)` for ext4, APFS, HFS+, FAT.

Sprints 2-6 shipped walkers for all four types. Now flip the arms.

**Implementation:**

Update `crates/strata-fs/src/fs_dispatch.rs`:

```rust
pub fn open_filesystem(
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
) -> VfsResult<Box<dyn VirtualFilesystem>> {
    let fs_type = detect_filesystem(image.as_ref(), partition_offset)?;
    open_filesystem_by_type(image, partition_offset, partition_size, fs_type)
}

pub fn open_filesystem_by_type(
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    fs_type: FsType,
) -> VfsResult<Box<dyn VirtualFilesystem>> {
    match fs_type {
        FsType::Ntfs => {
            let walker = NtfsWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Ext2 | FsType::Ext3 | FsType::Ext4 => {
            let walker = Ext4Walker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Apfs => {
            let walker = ApfsWalker::open(
                Arc::clone(&image),
                partition_offset,
                partition_size,
            )?;
            
            if walker.volumes().len() > 1 {
                let mut composite = CompositeVfs::new();
                for volume_meta in walker.volumes() {
                    let volume_walker = walker.with_active_volume(&volume_meta.name)?;
                    composite.add(&volume_meta.name, volume_walker);
                }
                Ok(Box::new(composite))
            } else {
                Ok(Box::new(walker))
            }
        }
        FsType::HfsPlus => {
            let walker = HfsPlusWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Fat12 | FsType::Fat16 | FsType::Fat32 | FsType::ExFat => {
            let walker = FatWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Unknown => Err(VfsError::Other(format!(
            "unknown filesystem at partition offset {}",
            partition_offset
        ))),
    }
}
```

**Integration tests:**

```rust
#[test]
fn dispatch_opens_ntfs_on_charlie() {
    let image_path = Path::new("/Users/randolph/Wolfmark/Test Material/charlie-2009-11-12.E01");
    if !image_path.exists() { return; }
    
    let image = open_evidence(image_path).expect("open");
    let partitions = read_partitions(image.as_ref()).expect("partitions");
    
    let mut opened = false;
    for p in partitions {
        if let Ok(fs) = open_filesystem(Arc::clone(&image), p.offset_bytes(), p.size_bytes()) {
            assert_eq!(fs.fs_type(), "ntfs");
            opened = true;
            break;
        }
    }
    assert!(opened);
}

#[test]
fn dispatch_opens_apfs_multi_volume_as_composite() { /* ... */ }
#[test]
fn dispatch_opens_ext4_on_linux_ctf() { /* ... */ }
#[test]
fn dispatch_opens_hfsplus_on_fixture() { /* ... */ }
#[test]
fn dispatch_opens_fat32_on_fixture() { /* ... */ }
#[test]
fn dispatch_returns_unknown_for_zero_bytes() { /* ... */ }
```

**Tests required:**

- NTFS dispatch (Charlie E01)
- ext4 dispatch (Linux CTF)
- APFS multi-volume → CompositeVfs (iOS CTF)
- APFS single-volume → walker directly
- HFS+ dispatch (fixture)
- FAT32 dispatch (fixture)
- Unknown filesystem returns Err cleanly

Zero unwrap, zero unsafe, Clippy clean, 7+ tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# SPRINT 8 — VFS-NATIVE-TOP3 — MIGRATE VECTOR, CHRONICLE, TRACE
# ═══════════════════════════════════════════════════════════════════════

Migrates the three highest-artifact-yield plugins from vfs_materialize
scratch-copy to VFS-native streaming reads.

**Problem statement:**

v12's vfs_materialize bridge works but has real performance ceilings
(512 MiB/file, 16 GiB total, 500k files). Vector (2,465 artifacts on
Charlie), Chronicle, and Trace are the three highest-yield plugins.
Migrating them delivers the largest per-run performance improvement
for smallest migration effort.

**The Phantom pattern (reference from v11):**

Unchanged from SPRINTS_v13.md specification. Mechanical rules:
1. `std::fs::read_dir(&ctx.root_path)` → `ctx.list_dir(path)`
2. `std::fs::read(path)` → `ctx.read_file(path_str)`
3. `Path::new(&ctx.root_path).join(...).exists()` → `ctx.file_exists(path_str)`
4. `walk_dir(root)` + filename-match → `ctx.find_by_name("filename")`
5. Glob searches → `ctx.find_files("**/*.pattern")`
6. Size gates and other logic stay exactly as they were
7. Parser calls stay exactly as they were
8. Keep host-fs fallback branch for backward compat

**Per-plugin migration:**

**Vector** at `plugins/strata-plugin-vector/src/lib.rs:230`:

Before:
```rust
let content = match std::fs::read_to_string(path) {
    Ok(c) => c,
    Err(_) => continue,
};
```

After:
```rust
let content = match ctx.read_file_as_string(path) {
    Ok(c) => c,
    Err(_) => continue,
};
```

Replace all walk_dir patterns with ctx.find_files glob calls matching
Vector's target patterns (PE headers need binary walk, IOC scanning
needs string walk).

**Chronicle** at `plugins/strata-plugin-chronicle/src/lib.rs:726`:

Chronicle reads Windows user activity artifacts. Most are already
delegated to Phantom's registry parsing via `prior_results`. The
filesystem walking is for Jump Lists (CFB files) and RecentDocs.
Apply find_by_name for specific filenames, find_files for glob
patterns.

**Trace** at `plugins/strata-plugin-trace/src/lib.rs:519`:

Trace reads execution artifacts. Primary targets:
- Prefetch files: `ctx.find_files("**/Prefetch/*.pf")`
- BAM/DAM entries: delegated to Phantom via prior_results
- Scheduled task XML: `ctx.find_files("**/Tasks/**/*.xml")`

**Per-plugin acceptance:**

- Pre-migration tests pass unchanged
- New VFS-aware smoke test added (minimum 1 per plugin)
- Plugin works when `ctx.vfs` is None (host-fs fallback)
- Plugin works when `ctx.vfs` is Some (VFS-backed)
- Charlie E01 re-run via matrix_regression shows:
  - Vector ≥ 2,300 artifacts
  - Chronicle ≥ 100 artifacts  
  - Trace ≥ 50 artifacts
- Clippy clean

**After this sprint:**

4 of 24 plugins are VFS-native (Phantom + Vector + Chronicle + Trace).
Bridge I/O pressure reduced for the highest-volume plugins. Remaining
20 plugin migrations defer to v15 (mechanical, non-blocking).

Zero unwrap, zero unsafe, Clippy clean, 3+ new smoke tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# SPRINT 9 — H3-AST-QUALITY-GATE — AST-AWARE VIOLATION CHECKS
# ═══════════════════════════════════════════════════════════════════════

Ship the `tools/strata-verify-quality/` binary that replaces grep-based
quality checks with AST-aware analysis.

**Problem statement:**

v12 diagnostic revealed raw grep counts 5,338 `.unwrap()` instances
which overstate production violations by including `#[cfg(test)] mod
tests { ... }` blocks inside `src/*.rs` files. 55 `unsafe{}` instances
exist in VHD/VMDK binding crates. 1,488 `println!` instances include
CLI command handlers where println! is the intended human-output
channel.

Current quality gates are grep-based noise. Real enforcement requires
AST walking.

**Implementation:**

Create `tools/strata-verify-quality/` binary:

```rust
// tools/strata-verify-quality/src/main.rs

use syn::visit::Visit;
use syn::{Expr, ItemMod};
use walkdir::WalkDir;
use std::path::Path;

#[derive(Default)]
struct ViolationCounts {
    production_unwrap: usize,
    production_unsafe: usize,
    production_println: usize,
    test_unwrap: usize,
    test_unsafe: usize,
    test_println: usize,
    cli_unwrap: usize,
    cli_unsafe: usize,
    cli_println: usize,
}

struct QualityVisitor<'a> {
    file_context: FileContext,  // Is this a library, test, or CLI?
    in_test_module: bool,
    counts: &'a mut ViolationCounts,
}

enum FileContext {
    Library,      // crates/*/src/*.rs (non-test)
    Test,         // crates/*/tests/*.rs or files under tests/
    CliBinary,    // strata-shield-cli/src/commands/*.rs
    Tool,         // tools/*/src/*.rs
}

impl<'ast> Visit<'ast> for QualityVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        // Check if this module is #[cfg(test)] gated
        let is_test_mod = node.attrs.iter().any(|attr| {
            attr.path().is_ident("cfg") && {
                let meta = attr.parse_args::<syn::Meta>().ok();
                meta.as_ref().is_some_and(|m| {
                    m.path().is_ident("test")
                })
            }
        }) || node.ident == "tests";
        
        if is_test_mod {
            let was_in_test = self.in_test_module;
            self.in_test_module = true;
            syn::visit::visit_item_mod(self, node);
            self.in_test_module = was_in_test;
        } else {
            syn::visit::visit_item_mod(self, node);
        }
    }
    
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "unwrap" && node.args.is_empty() {
            self.record_unwrap();
        }
        syn::visit::visit_expr_method_call(self, node);
    }
    
    fn visit_expr_unsafe(&mut self, _node: &'ast syn::ExprUnsafe) {
        self.record_unsafe();
        // Do not visit inside unsafe block — already counted
    }
    
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.is_ident("println") {
            self.record_println();
        }
        syn::visit::visit_macro(self, node);
    }
}

impl QualityVisitor<'_> {
    fn record_unwrap(&mut self) {
        if self.in_test_module {
            self.counts.test_unwrap += 1;
            return;
        }
        match self.file_context {
            FileContext::Library => self.counts.production_unwrap += 1,
            FileContext::Test => self.counts.test_unwrap += 1,
            FileContext::CliBinary => self.counts.cli_unwrap += 1,
            FileContext::Tool => self.counts.cli_unwrap += 1,
        }
    }
    
    fn record_unsafe(&mut self) {
        if self.in_test_module {
            self.counts.test_unsafe += 1;
            return;
        }
        match self.file_context {
            FileContext::Library => self.counts.production_unsafe += 1,
            FileContext::Test => self.counts.test_unsafe += 1,
            FileContext::CliBinary => self.counts.cli_unsafe += 1,
            FileContext::Tool => self.counts.cli_unsafe += 1,
        }
    }
    
    fn record_println(&mut self) {
        if self.in_test_module {
            self.counts.test_println += 1;
            return;
        }
        match self.file_context {
            FileContext::Library => self.counts.production_println += 1,
            FileContext::Test => self.counts.test_println += 1,
            FileContext::CliBinary => self.counts.cli_println += 1,
            FileContext::Tool => self.counts.cli_println += 1,
        }
    }
}

fn classify_file(path: &Path) -> FileContext {
    let s = path.to_string_lossy();
    if s.contains("/tests/") || s.ends_with("_tests.rs") {
        FileContext::Test
    } else if s.contains("strata-shield-cli/src/commands/") {
        FileContext::CliBinary
    } else if s.contains("tools/") {
        FileContext::Tool
    } else {
        FileContext::Library
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = ViolationCounts::default();
    
    for entry in WalkDir::new(".") {
        let entry = entry?;
        if !entry.path().extension().is_some_and(|e| e == "rs") {
            continue;
        }
        
        // Skip target/, vendored deps
        if entry.path().components().any(|c| {
            c.as_os_str() == "target" || c.as_os_str() == ".git"
        }) {
            continue;
        }
        
        let source = std::fs::read_to_string(entry.path())?;
        let syntax = syn::parse_file(&source)?;
        
        let file_context = classify_file(entry.path());
        let mut visitor = QualityVisitor {
            file_context,
            in_test_module: false,
            counts: &mut counts,
        };
        visitor.visit_file(&syntax);
    }
    
    println!("Quality gate report:");
    println!("  Production:");
    println!("    unwrap:  {}", counts.production_unwrap);
    println!("    unsafe:  {}", counts.production_unsafe);
    println!("    println: {}", counts.production_println);
    println!("  Test:");
    println!("    unwrap:  {}", counts.test_unwrap);
    println!("    unsafe:  {}", counts.test_unsafe);
    println!("    println: {}", counts.test_println);
    println!("  CLI/Tools:");
    println!("    unwrap:  {}", counts.cli_unwrap);
    println!("    unsafe:  {}", counts.cli_unsafe);
    println!("    println: {}", counts.cli_println);
    
    // Enforce: zero production violations (unless waived in known cases)
    let known_unsafe_waivers: u32 = /* VHD/VMDK binding count */;
    
    if counts.production_unwrap > 0 {
        eprintln!("FAIL: {} production unwrap() calls", counts.production_unwrap);
        std::process::exit(1);
    }
    if counts.production_unsafe as u32 > known_unsafe_waivers {
        eprintln!(
            "FAIL: {} production unsafe{{}} blocks (waiver allows {})",
            counts.production_unsafe, known_unsafe_waivers
        );
        std::process::exit(1);
    }
    if counts.production_println > 0 {
        eprintln!("FAIL: {} production println! calls", counts.production_println);
        std::process::exit(1);
    }
    
    println!("\nQuality gate: PASS");
    Ok(())
}
```

**Waiver mechanism:**

Some `unsafe{}` in production code is legitimate (VHD/VMDK memory
mapping bindings). Document the baseline count in a waiver file:

```toml
# tools/strata-verify-quality/waivers.toml
[unsafe]
known_count = 55
reason = "VHD/VMDK binding crates require unsafe for memory-mapped access"
```

Violations above the waiver count fail CI. This locks in the current
state and prevents new `unsafe{}` from sneaking in without
justification.

**CI integration:**

Add to workspace-level test via a wrapper test:

```rust
// crates/strata-shield-engine/tests/quality_gate.rs
#[test]
fn ast_quality_gate_passes() {
    let output = std::process::Command::new("cargo")
        .args(&["run", "--release", "-p", "strata-verify-quality", "--"])
        .output()
        .expect("run quality gate");
    
    assert!(
        output.status.success(),
        "Quality gate failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
```

**Tests required:**

- Binary compiles and runs
- Correctly classifies library vs test vs CLI files
- Counts production unwrap/unsafe/println accurately
- Excludes `#[cfg(test)] mod tests` contents
- Excludes inline `#[test]` functions
- Waiver mechanism works
- CI integration test passes on current main
- Adding a `.unwrap()` to a library file fails the gate
- Adding a `.unwrap()` to a test module passes the gate

Zero unwrap, zero unsafe, Clippy clean, 9+ tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# SPRINT 10 — REGRESS-V14-FINAL — FULL MATRIX + REPORT
# ═══════════════════════════════════════════════════════════════════════

Run the full Test Material matrix with all v14 capabilities enabled
and publish the definitive v14 field validation report.

**Problem statement:**

v14 unlocked ext4, APFS (single + multi), HFS+, and FAT. Vector,
Chronicle, Trace are VFS-native. EWF acquisition-trim warnings surface
structurally. AST-aware quality gate enforces meaningful violations.
Every image type in Test Material now has a working pipeline. Measure
what actually comes out.

**Implementation:**

Extend `matrix_regression.rs` (from v13) with new cases covering every
image type:

```rust
const V14_EXPANDED_CASES: &[RegressionCase] = &[
    // Windows (inherits v12 baselines)
    // ... v12 cases protected by v13 guard, now re-verified
    
    // Linux — new in v14
    RegressionCase {
        name: "ctf-linux-2022",
        image_subpath: "2022 CTF - Linux.7z",
        min_total_artifacts: 50,
        min_per_plugin: &[("Strata Arbor", 10)],
        reason_if_low: "ext4 walker or Arbor plugin regression",
    },
    
    // ChromeOS — new in v14
    RegressionCase {
        name: "ctf-chromebook-2021",
        image_subpath: "2021 CTF - Chromebook.tar",
        min_total_artifacts: 30,
        min_per_plugin: &[],
        reason_if_low: "ChromeOS detection or Carbon plugin regression",
    },
    
    // iOS — new in v14 (APFS)
    RegressionCase {
        name: "ios-ctf-2020",
        image_subpath: "2020 CTF - iOS",
        min_total_artifacts: 100,
        min_per_plugin: &[("Strata Pulse", 20)],
        reason_if_low: "APFS walker or Pulse plugin regression",
    },
    RegressionCase {
        name: "ios-ctf-2021",
        image_subpath: "2021 CTF - iOS.zip",
        min_total_artifacts: 100,
        min_per_plugin: &[("Strata Pulse", 20)],
        reason_if_low: "APFS walker or Pulse plugin regression",
    },
    RegressionCase {
        name: "jess-iphone8",
        image_subpath: "Jess_CTF_iPhone8",
        min_total_artifacts: 100,
        min_per_plugin: &[("Strata Pulse", 30)],
        reason_if_low: "APFS walker or mobile plugin regression",
    },
    
    // Android — new in v14 (tar unpack → ext4 or native)
    RegressionCase {
        name: "android-14",
        image_subpath: "Android_14_Public_Image.tar",
        min_total_artifacts: 500,
        min_per_plugin: &[("Strata Carbon", 100)],
        reason_if_low: "Carbon plugin regression",
    },
    RegressionCase {
        name: "android-ctf-2019",
        image_subpath: "2019 CTF - Android",
        min_total_artifacts: 200,
        min_per_plugin: &[("Strata Carbon", 50)],
        reason_if_low: "Carbon plugin regression",
    },
    RegressionCase {
        name: "android-ctf-2022",
        image_subpath: "2022 CTF - Android-001.tar",
        min_total_artifacts: 300,
        min_per_plugin: &[("Strata Carbon", 75)],
        reason_if_low: "Carbon plugin regression",
    },
    
    // Windows CTF (large modern image) — new in v14
    RegressionCase {
        name: "windows-ctf-2019",
        image_subpath: "2019 CTF - Windows-Desktop/2019 CTF - Windows-Desktop-001.E01",
        min_total_artifacts: 1000,
        min_per_plugin: &[
            ("Strata Phantom", 100),
            ("Strata Chronicle", 50),
        ],
        reason_if_low: "Windows 10 NTFS walker or modern Windows plugin regression",
    },
    
    // Other sources
    RegressionCase {
        name: "cellebrite-ufed",
        image_subpath: "Cellebrite.tar",
        min_total_artifacts: 100,
        min_per_plugin: &[],
        reason_if_low: "UFED unpack + mobile plugin regression",
    },
    RegressionCase {
        name: "memory-dump",
        image_subpath: "memdump-001.mem",
        min_total_artifacts: 5,
        min_per_plugin: &[("Strata Wraith", 3)],
        reason_if_low: "Wraith memory analysis regression",
    },
];
```

**Gap closure during this sprint:**

For any case producing fewer artifacts than expected:

1. Open artifacts.sqlite for that case
2. Identify which plugin underperformed
3. Debug with known-good reference tool
4. Fix the plugin
5. Re-run the case
6. Document fix in commit message
7. Update minimum to observed count minus 5% margin

No time box. This sprint runs until full matrix passes.

**Report:**

Publish `FIELD_VALIDATION_v14_REPORT.md` with:
- Per-image per-plugin artifact counts
- Acquisition-trim warnings (from EWF-TRIM-WARN-1)
- Performance numbers (total runtime per image)
- Plugin migration status (4/24 VFS-native after v14, 20/24 via bridge)
- Quality gate output (AST-aware counts)
- Comparison against v11/v12/v13 scorecards
- Open items for v15

**Acceptance criteria:**

- [ ] Every image in Test Material produces ≥expected artifacts
- [ ] FIELD_VALIDATION_v14_REPORT.md published
- [ ] matrix_regression.rs encodes all v14 cases as permanent guards
- [ ] AST quality gate passes
- [ ] Test count: 3,666 + substantial growth
- [ ] Clippy clean, no new production unwrap/unsafe/println
- [ ] All 9 load-bearing tests preserved
- [ ] No public API regressions

Zero unwrap, zero unsafe, Clippy clean, matrix passes end-to-end.

---

# ═══════════════════════════════════════════════════════════════════════
# COMPLETION CRITERIA
# ═══════════════════════════════════════════════════════════════════════

SPRINTS_v14.md is complete when:

**Acquisition diagnostics (Sprint 1):**
- EWF reader emits OffsetBeyondAcquired warnings
- CLI surface reports warnings
- Audit log captures warning events
- Terry / NPS Jean results clearly labeled as image-truncated

**Filesystem walkers (Sprints 2-6):**
- HfsPlusWalker ships after Read+Seek refactor
- FatWalker ships with committed FAT32 fixture
- Ext4Walker ships wrapping verified ext4-view API
- ApfsWalker ships single-volume (Sprint 5)
- APFS multi-volume via CompositeVfs ships (Sprint 6)
- Each has integration tests against real images or fixtures

**Dispatcher activation (Sprint 7):**
- open_filesystem routes to live walkers for all 10 filesystem types
- APFS multi-volume returns CompositeVfs
- No Unsupported arms remain

**High-leverage migrations (Sprint 8):**
- Vector, Chronicle, Trace are VFS-native
- Charlie artifact counts match or exceed v12 baseline
- Bridge-copy pressure reduced for 3 highest-volume plugins

**Quality tooling (Sprint 9):**
- tools/strata-verify-quality/ binary ships
- AST-aware violation counts replace grep
- Waiver mechanism for known unsafe{} (VHD/VMDK)
- CI test runs the quality gate

**Full matrix (Sprint 10):**
- Every Test Material image produces expected artifacts
- FIELD_VALIDATION_v14_REPORT.md published
- matrix_regression.rs encodes all v14 baselines

**Quality gates (non-negotiable):**
- Test count: 3,666 + substantial growth
- All tests passing
- Clippy clean workspace-wide
- Zero new `.unwrap()`, zero `unsafe{}`, zero `println!` in production
  code (now AST-enforced)
- All 9 load-bearing tests preserved
- No public API regressions

**The moment v14 ends:**

Every image type in Test Material produces real forensic artifacts
through the unified pipeline. Charlie/Jo baselines are regression-
guarded. ext4, APFS (single + multi), HFS+, FAT all ship as live
walkers. Three highest-volume plugins stream VFS-native. Acquisition-
trim issues diagnosed structurally. Quality gates are meaningful
(AST-enforced).

Strata covers the full forensic casework landscape. Remaining work
(20 plugin migrations, UI integration, new evidence sources) is
refinement — not foundational architecture.

After v14, Strata has completed its architectural build-out.

---

*STRATA AUTONOMOUS BUILD QUEUE v14*
*Wolfmark Systems — 2026-04-18*
*Sprint 1: EWF-TRIM-WARN-1 — acquisition-trim diagnostics (independent)*
*Sprint 2: FS-HFSPLUS-1 — smallest walker (Read+Seek refactor + wrap)*
*Sprint 3: FS-FAT-1 — fixture-first FAT/exFAT walker*
*Sprint 4: FS-EXT4-1 — ext4-view API verified first, then wrap*
*Sprint 5: FS-APFS-SINGLE-1 — single-volume APFS walker*
*Sprint 6: FS-APFS-MULTI-1 — multi-volume CompositeVfs*
*Sprint 7: FS-DISPATCH-FINAL — activate all live walkers*
*Sprint 8: VFS-NATIVE-TOP3 — migrate Vector, Chronicle, Trace*
*Sprint 9: H3-AST-QUALITY-GATE — replace grep with AST analysis*
*Sprint 10: REGRESS-V14-FINAL — full matrix + report*
*Mission: Complete the filesystem walker build-out and lock in quality.*
*Execute all incomplete sprints in order. Ship everything.*
