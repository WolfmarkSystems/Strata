# SPRINTS_v15.md — STRATA FILESYSTEM WALKER COMPLETION PHASE 1
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md, SESSION_STATE_v15_BLOCKER.md, docs/RESEARCH_v10_CRATES.md,
#         docs/RESEARCH_v15_EXT4_VIEW.md, and SPRINTS_v15.md.
#         Execute all SESSION B sprints in order, then stop."
# Last updated: 2026-04-19 (post-Session A reorganization)
# Prerequisite: SPRINTS_v1.md through SPRINTS_v14.md complete (3,684 tests passing)
# Status: Session 1 shipped FS-EXT4-1 Phase A (research). Three remaining sessions queued.
#
# ═══════════════════════════════════════════════════════════════════════
# WHERE STRATA IS AT THE START OF THIS REORGANIZATION
# ═══════════════════════════════════════════════════════════════════════
#
# v14 shipped two of its ten planned sprints:
#   - Sprint 1 EWF-TRIM-WARN-1 (acquisition-trim diagnostics)
#   - Sprint 9 H3-AST-QUALITY-GATE (AST-aware violation enforcement)
#
# v0.14.0 is tagged and pushed. 3,684 tests passing. NTFS walker live
# end-to-end through the dispatcher. Charlie 3,400 / Jo 3,537 locked as
# cargo-test regression guards. Public on GitHub.
#
# Session 1 of v15 (commits 76cf564 + d86c43d) shipped FS-EXT4-1 Phase A
# only — the research doc that verifies the ext4-view v0.9.3 API surface.
# The other three walker sprints + dispatcher activation were honestly
# deferred per the queue's "do not silently compromise the spec" clause.
#
# Critical favorable finding from Session 1:
#   ext4-view's `Ext4Read` trait is offset-addressed
#   (`fn read(start_byte, dst)`) — a direct fit for Strata's
#   `EvidenceImage::read_at`. The walker adapter collapses from the
#   speculative `BufReader<Mutex<PartitionReader>>` stack to ~10 lines
#   of direct delegation. Sprint 3 Phase B is now dramatically smaller.
#
# This unblock changes the optimal sprint ordering. ext4 was originally
# scheduled third due to API uncertainty. With the API verified and the
# adapter footprint shrunken, ext4 is now the lowest-risk walker to
# ship — making it the right pick to prove the dispatcher rewiring
# pattern before committing to the larger HFS+ refactor.
#
# ═══════════════════════════════════════════════════════════════════════
# REVISED PLAN — TWO REMAINING SESSIONS
# ═══════════════════════════════════════════════════════════════════════
#
# SESSION B (next) — ext4 walker + ext4-only dispatcher arm
#   Sprint 1 — FS-EXT4-1 Phase B/C (walker + fixture + tests)
#   Sprint 2 — FS-DISPATCH-PARTIAL-EXT4 (flip ext4 arm only)
#
#   Why this scope: Dispatcher rewiring is the architectural risk.
#   Doing it once with the simplest walker (ext4 wrapper is ~10 LOC)
#   proves the pattern before HFS+ and FAT need it. If anything weird
#   surfaces in dispatcher activation, you find it on the trivial
#   walker, not after a 500 LOC HFS+ refactor.
#
#   Scope: ~10 LOC adapter + Ext4Walker impl + 2 MB fixture + mkext4.sh
#          + ext4_small.expected.json + ≥6 walker tests + ≥1 dispatcher
#          E2E test + dispatcher arm flip for ext4 only.
#
#   Tag: NO. v0.15.0 commitment is three walkers + full dispatcher
#        partial. This session ships one walker + one dispatcher arm.
#
# SESSION C (after Session B) — HFS+ + FAT + full dispatcher partial
#   Sprint 1 — FS-HFSPLUS-1 (Read+Seek refactor + walker + fixture)
#   Sprint 2 — FS-FAT-1 (fixture + walker; exFAT deferrable)
#   Sprint 3 — FS-DISPATCH-PARTIAL-FULL (flip HFS+ and FAT arms,
#              APFS arms remain Unsupported with v16 pickup signal)
#
#   Tag: YES. v0.15.0 ships at the end of Session C with all four
#        walkers (NTFS from v11 + ext4 + HFS+ + FAT) live through the
#        dispatcher. Publish FIELD_VALIDATION_v15_REPORT.md, push.
#
# ═══════════════════════════════════════════════════════════════════════
# WHY THE REORDERING IS SAFE
# ═══════════════════════════════════════════════════════════════════════
#
# Original v15 ordering (HFS+ → FAT → ext4 → dispatcher) was based on
# architectural risk when ext4's API was unknown. HFS+ went first because
# its Read+Seek refactor "established the pattern every subsequent walker
# uses."
#
# That rationale held when ext4 was an unknown. Now:
#
#   - ext4 is fully known (Session 1 research doc)
#   - The Ext4Read offset-addressed trait means no Read+Seek wrapping
#     is needed at all for ext4 — it consumes EvidenceImage::read_at
#     directly
#   - HFS+ Read+Seek refactor is still needed but only for HFS+ and
#     potentially FAT — not for ext4
#
# So the "establish the pattern first" argument no longer applies to
# ext4. Doing ext4 first now means:
#
#   - The dispatcher rewiring pattern is proven on the simplest walker
#   - Session B is short and ship-everything-it-touches
#   - Session C focuses on the HFS+ refactor + FAT fixture work without
#     having to also activate the dispatcher for the first time
#
# The Read+Seek pattern still gets established in Session C (HFS+ Phase A)
# before FAT needs it. FAT Phase A in Session C uses the pattern HFS+
# established. Same discipline, sequenced around the new information.
#
# ═══════════════════════════════════════════════════════════════════════
# DISCIPLINE — CARRIED FORWARD FROM v9 THROUGH v14 + SESSION 1
# ═══════════════════════════════════════════════════════════════════════
#
# "Do not silently compromise the spec." Session 1 proved this clause
# works. The honest research-only output is exactly what the queue's
# strategic notes demanded.
#
# Ground truth validation is mandatory. Every walker ships with
# integration tests against either a real image or a committed test
# fixture before it can be declared shipped. "Tests pass" is not
# acceptance — acceptance is "walker enumerates expected files from a
# real or fixture image with verifiable counts matching the expected
# manifest."
#
# Quality gates (every session): all tests pass from 3,684 start, clippy
# clean, AST quality gate stays at v14 baseline (470 unwrap, 5 unsafe,
# 5 println — zero new), all 9 load-bearing tests preserved,
# Charlie/Jo regression guards pass.
#
# ---
#
# ## HOW TO EXECUTE — SESSION B
#
# Read CLAUDE.md, SESSION_STATE_v15_BLOCKER.md, docs/RESEARCH_v10_CRATES.md,
# docs/RESEARCH_v15_EXT4_VIEW.md, and SPRINTS_v15.md in that order. Then
# execute the SESSION B sprints below in order. Stop at the end of
# SESSION B — do not proceed into SESSION C sprints in the same run.
#
# For each sprint:
# 1. Implement exactly as specified
# 2. Run `cargo test --workspace` — all tests must pass
# 3. Run `cargo clippy --workspace -- -D warnings` — must be clean
# 4. Run the AST quality gate — must stay at v14 baseline
# 5. Verify Charlie/Jo regression guards still pass
# 6. Commit with message: "feat: [sprint-id] [description]"
# 7. Move to next sprint immediately
#
# If any sprint hits a real blocker:
# 1. Stop work on that sprint
# 2. Document the blocker, the pickup signal, and the recommended
#    architectural decision in SESSION_STATE_v15_BLOCKER.md
# 3. Continue with the next unblocked sprint in the SAME session
# 4. Surface the blocker in the session-end summary
#
# At the end of SESSION B:
# 1. Confirm both sprints shipped or documented as deferred
# 2. Do NOT tag v0.15.0 — that ships at end of SESSION C only
# 3. Write SESSION_STATE_v15_SESSION_B_COMPLETE.md summarizing what
#    shipped, with concrete pickup signals for SESSION C if anything
#    deferred
#
# ---

# ═══════════════════════════════════════════════════════════════════════
# █████████████████████████████  SESSION B  █████████████████████████████
# ═══════════════════════════════════════════════════════════════════════
# █  Execute these two sprints. Stop at end of SESSION B.              █
# █  Do not proceed to SESSION C sprints in the same run.              █
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# SESSION B — SPRINT 1 — FS-EXT4-1 PHASE B/C — EXT4 WALKER
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-EXT4-1 (Phases B and C)
**Status of Phase A:** SHIPPED in Session 1 (commit 76cf564) —
`docs/RESEARCH_v15_EXT4_VIEW.md` captures the verified API surface

**Why first:** Ext4 walker is now the lowest-risk filesystem to ship.
Phase A research collapsed the speculative wrapper stack to ~10 lines
of direct delegation. Doing ext4 first proves the dispatcher rewiring
pattern (Sprint 2) on the trivial walker before HFS+ and FAT need it.

## Phase B — Implement Ext4Walker

Create `crates/strata-fs/src/walkers/ext4_walker.rs` against the
verified API in `docs/RESEARCH_v15_EXT4_VIEW.md`.

**The adapter is small.** `Ext4Read` is offset-addressed:

```rust
fn read(&self, start_byte: u64, dst: &mut [u8]) -> Result<(), Self::Err>
```

This maps directly onto Strata's `EvidenceImage::read_at`. The wrapper
should be a struct holding the partition reader plus an `Ext4Read` impl
that delegates `read(offset, dst)` to `self.image.read_at(self.partition_offset + offset, dst)`.
Roughly ten lines plus error mapping.

**Walker requirements:**

- Implements the existing `Vfs` trait
- `Ext4Walker::open(image: Arc<EvidenceImage>, partition: PartitionInfo) -> Result<Self>`
- Internally constructs the `Ext4Read` adapter, then `Ext4::load(adapter)`
- `walk()` returns iterator of VfsEntry items
- Handles ext4 features: extents (almost always present), htree
  directories, inline data, 64-bit feature flag
- Handles symbolic links — VfsEntry exposes link target separately
  from regular file content
- Surfaces extended attributes (xattrs) including
  `system.posix_acl_access` and `security.selinux` for forensic
  completeness
- Marks encrypted entries explicitly when EXT4_ENCRYPT_FL is set —
  examiners need to know to do offline key recovery
- Surfaces deleted inodes when `--include-deleted` is set
  (forensic recovery)
- Preserves nanosecond-precision timestamps (crtime/mtime/atime/dtime)
- Errors map cleanly into `StrataError` — no `.unwrap()`, no `panic!`,
  no `println!`

**What NOT to do in this sprint:**

- Do not attempt journal (jbd2) replay — flag presence of unfinalized
  transactions as a metadata note only
- Do not attempt encrypted file content recovery — mark encrypted
  flag and move on
- Do not stream-decompress compressed file fragments unless ext4-view
  surfaces them as plain bytes already

## Phase C — Test fixture

Commit a minimal ext4 test fixture:

```
crates/strata-fs/tests/fixtures/ext4_small.img         # ~2 MB
crates/strata-fs/tests/fixtures/mkext4.sh              # generation script
crates/strata-fs/tests/fixtures/ext4_small.expected.json
```

**Generation script (`mkext4.sh`) should be reproducible:**

```bash
#!/bin/bash
set -euo pipefail
dd if=/dev/zero of=ext4_small.img bs=1M count=2
mkfs.ext4 -F -L "STRATA-EXT4" ext4_small.img
# Mount, populate with known content, unmount
# Reproducible content:
#   - 5 root files including one with extended attributes
#   - 1 nested directory three levels deep with one file at each level
#   - 1 symbolic link pointing to a real file
#   - 1 sparse file (holes) to exercise extent handling
#   - 1 file with selinux xattr set
```

**Expected manifest (`ext4_small.expected.json`):**

```json
{
  "volume_label": "STRATA-EXT4",
  "fs_type": "ext4",
  "expected_entries": [
    {"path": "/readme.txt", "size": 256},
    {"path": "/with_xattrs.bin", "size": 128, "xattrs": ["user.test"]},
    {"path": "/dir1/dir2/dir3/deep.txt", "size": 64},
    {"path": "/symlink_to_readme", "type": "symlink", "target": "/readme.txt"},
    {"path": "/sparse_file.bin", "size": 1048576}
  ]
}
```

## Acceptance criteria (Sprint 1)

- [ ] `mkext4.sh` produces deterministic fixture when re-run
- [ ] Ext4Walker::open on fixture succeeds
- [ ] Walker enumeration matches `ext4_small.expected.json` exactly
- [ ] Symbolic link target exposed correctly via VfsEntry
- [ ] Extended attributes accessible via VfsEntry
- [ ] Sparse file content reads correctly (zero-filled in holes)
- [ ] Encrypted entry test (if achievable) marks ENCRYPT flag without
      attempting decryption
- [ ] Test count grows by ≥6
- [ ] AST quality gate stays at v14 baseline (470/5/5, zero new)
- [ ] Clippy clean workspace-wide
- [ ] Charlie/Jo regression guards pass

If `mkext4.sh` cannot run in the build environment (e.g., requires root
for mkfs.ext4 mount), document the blocker and ship a pre-built
fixture committed directly with deterministic generation steps in a
README in the fixtures directory.

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# SESSION B — SPRINT 2 — FS-DISPATCH-PARTIAL-EXT4 — EXT4 ARM ONLY
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-DISPATCH-PARTIAL-EXT4
**Why now:** Proves the dispatcher rewiring pattern on the trivial
walker before HFS+ and FAT need it. Cannot ship before Sprint 1.

**Scope is deliberately narrow:** flip ONLY the ext4 dispatcher arm.
HFS+, FAT, exFAT, and APFS arms all remain Unsupported in this
sprint. Session C will flip HFS+ and FAT after those walkers ship.
APFS waits for v16.

## Phase A — Locate and audit the dispatcher

Find the dispatcher function (likely `crates/strata-fs/src/dispatcher.rs`).
Confirm the current shape:

```rust
pub fn open_filesystem(
    fs_type: FilesystemType,
    image: Arc<EvidenceImage>,
    partition: PartitionInfo,
) -> Result<Box<dyn Vfs>> {
    match fs_type {
        FilesystemType::Ntfs => Ok(Box::new(NtfsWalker::open(image, partition)?)),
        FilesystemType::HfsPlus => Err(StrataError::Unsupported(...)),  // KEEP — Session C
        FilesystemType::Fat | FilesystemType::ExFat => Err(StrataError::Unsupported(...)),  // KEEP — Session C
        FilesystemType::Ext4 => Err(StrataError::Unsupported(...)),  // FLIP THIS
        FilesystemType::Apfs => Err(StrataError::Unsupported(...)),  // KEEP — v16
        FilesystemType::ApfsMulti => Err(StrataError::Unsupported(...)),  // KEEP — v16
        // ...
    }
}
```

Note: actual signature may differ. Adapt to whatever Ext4Walker::open
takes from Sprint 1.

## Phase B — Activate the ext4 arm

Replace the Unsupported return for ext4 with live walker construction:

```rust
FilesystemType::Ext4 => Ok(Box::new(Ext4Walker::open(image, partition)?)),
```

Map any Ext4Walker error into `StrataError` cleanly with full context
preservation. Do not panic on bad input.

## Phase C — Confirm filesystem detection

Find the filesystem-type detection code (likely
`crates/strata-fs/src/detect.rs`). Confirm:

- ext4 detection looks for superblock magic `0xEF53` at byte 1080
  of the partition (not the disk)
- If detection logic was previously stubbed pending walker availability,
  activate it for ext4

## Phase D — End-to-end integration test

Add to `crates/strata-cli/tests/dispatch_partial_e2e.rs` (create if
doesn't exist):

```rust
#[test]
fn dispatcher_routes_ext4_to_live_walker() {
    let fixture = "crates/strata-fs/tests/fixtures/ext4_small.img";
    if !Path::new(fixture).exists() { return; }

    let image = Arc::new(EvidenceImage::open(fixture)?);
    let partition = detect_first_partition(&image)?;
    let result = open_filesystem(FilesystemType::Ext4, image, partition);

    assert!(result.is_ok(), "ext4 dispatcher arm must route to live walker");

    let mut vfs = result?;
    let entries: Vec<_> = vfs.walk().collect();
    assert!(!entries.is_empty(), "ext4 walker must enumerate fixture entries");
}

#[test]
fn dispatcher_still_returns_unsupported_for_hfsplus() {
    // Confirm Session C work has not started prematurely
    let result = open_filesystem(FilesystemType::HfsPlus, ...);
    assert!(matches!(result, Err(StrataError::Unsupported(_))));
}

#[test]
fn dispatcher_still_returns_unsupported_for_apfs_with_v16_message() {
    let result = open_filesystem(FilesystemType::Apfs, ...);
    let err = result.unwrap_err();
    assert!(format!("{}", err).contains("v0.16"),
        "APFS unsupported message must reference v16 roadmap");
}
```

## Phase E — Update CLI surface

Find the `strata ingest run` command-line entry point. Confirm:

- `strata ingest run --source ext4_image.img --case-dir ./case --auto`
  now succeeds end-to-end on ext4 sources instead of failing with
  Unsupported
- HFS+ and FAT sources still fail with the existing Unsupported message
  (Session C territory)
- APFS sources still fail with explicit v16 message:
  "APFS walker shipping in v0.16 — see roadmap"

## Acceptance criteria (Sprint 2)

- [ ] Dispatcher ext4 arm routes to live Ext4Walker
- [ ] Dispatcher HFS+, FAT/exFAT arms still return Unsupported
- [ ] Dispatcher APFS arms still return Unsupported with v16 message
- [ ] Filesystem detection identifies ext4 from superblock magic
- [ ] `strata ingest run` succeeds on ext4 fixture end-to-end
- [ ] dispatch_partial_e2e.rs ext4 test passes
- [ ] dispatch_partial_e2e.rs negative tests pass (HFS+ and APFS still
      Unsupported)
- [ ] Test count grows by ≥3
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] Charlie/Jo regression guards pass — NTFS path unchanged

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# END OF SESSION B
# ═══════════════════════════════════════════════════════════════════════
#
# At end of SESSION B, do not proceed into SESSION C. Instead:
#
# 1. Verify both Sprint 1 and Sprint 2 shipped (or documented deferred)
# 2. Do NOT tag v0.15.0 — that lands at end of SESSION C only
# 3. Write SESSION_STATE_v15_SESSION_B_COMPLETE.md with:
#    - What shipped (commits)
#    - What deferred (with concrete pickup signals for SESSION C)
#    - Quality gate state
#    - Test count growth
#    - Notes for the SESSION C runner
# 4. Push commits to origin/main
# 5. Stop. SESSION C is a separate run.
#
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# █████████████████████████████  SESSION C  █████████████████████████████
# ═══════════════════════════════════════════════════════════════════════
# █  These sprints belong to a future session. Do NOT execute them in   █
# █  the same run as SESSION B sprints above. They are documented here  █
# █  so SESSION C can pick up without re-deriving context.              █
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# SESSION C — SPRINT 1 — FS-HFSPLUS-1 — HFS+ WALKER (Read+Seek REFACTOR + WRAP)
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-HFSPLUS-1
**Pickup signal from v14 blocker:** "Refactor `hfsplus.rs` from
file-path API to Read+Seek, then wrap"

**Why first in Session C:** HFS+ Read+Seek refactor establishes the
pattern that FAT (Sprint 2) will follow. The dispatcher rewiring
pattern is already proven from Session B.

## Phase A — Refactor hfsplus.rs to Read+Seek API

The existing `crates/strata-fs/src/hfsplus.rs` (~256 LOC) operates on
file paths. Refactor to operate on `Read + Seek` consumers wrapped in
`PartitionReader` so the dispatcher can hand it a partition slice from
any image format without round-tripping through a temp file.

Tasks:

1. Identify every public function in `hfsplus.rs` taking
   `impl AsRef<Path>` or `&Path`
2. For each, introduce a `Read + Seek` variant taking `R: Read + Seek`
3. Keep path-based variants as thin wrappers delegating to the
   Read+Seek variant — preserves backward compatibility for existing
   tests
4. Internal parser must read all volume header, B-tree, and catalog
   file structures through the Read+Seek interface
5. Buffer reads sensibly — HFS+ B-tree node reads are 4K aligned
6. Update existing unit tests to exercise both variants

## Phase B — Implement HfsPlusWalker

Create `crates/strata-fs/src/walkers/hfsplus_walker.rs`:

- Implements the existing `Vfs` trait
- `HfsPlusWalker::open(reader: impl Read + Seek) -> Result<Self>`
- `walk()` returns iterator of VfsEntry items (path, size, timestamps,
  fork type)
- `read(path) -> Result<Vec<u8>>` reads file content through Read+Seek
- Errors: explicit error types — never `.unwrap()` or `panic!`

**Special HFS+ considerations:**

- **Data fork vs resource fork:** HFS+ files have two data streams.
  Walker should expose both as separate VfsEntry items with `.rsrc`
  suffix on the fork stream
- **Case sensitivity:** HFS+ case-insensitive by default. HFSX is
  case-sensitive. Walker must respect the volume's `case_sensitive` flag
- **Special files:** Skip the
  `\x00\x00\x00\x00HFS+ Private Data\x0D` directory by default
- **Unicode normalization:** HFS+ stores filenames in Unicode NFC.
  Return as-is — examiners need original bytes

## Phase C — Test fixture

If no real HFS+ image available in Test Material, commit:

```
crates/strata-fs/tests/fixtures/hfsplus_small.img  # ~2 MB
crates/strata-fs/tests/fixtures/mkhfsplus.sh
```

Fixture content:
- Root directory with at least 5 files
- One file with a resource fork
- One nested directory three levels deep
- One file larger than the B-tree node size to exercise extent overflow

## Acceptance criteria

- [ ] Refactored hfsplus.rs Read+Seek variants pass existing unit tests
- [ ] Path-based variants still pass (backward compatibility)
- [ ] HfsPlusWalker::open on fixture succeeds
- [ ] Walker enumerates expected file count
- [ ] Walker reads file contents matching fixture-known bytes
- [ ] Resource forks exposed correctly with `.rsrc` suffix
- [ ] Test count grows by ≥8
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] Charlie/Jo regression guards pass

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# SESSION C — SPRINT 2 — FS-FAT-1 — FAT WALKER (FIXTURE-FIRST)
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-FAT-1
**Pickup signal from v14 blocker:** "Commit FAT32 fixture first,
then walker"

**Why second in Session C:** FAT uses the Read+Seek pattern HFS+
established in Sprint 1. Forensically critical — most USB drives, SD
cards, and embedded device storage are FAT-family.

## Phase A — Commit FAT32 test fixture

Generate a 1 MB FAT32 image with known contents:

```bash
# crates/strata-fs/tests/fixtures/mkfat32.sh
dd if=/dev/zero of=fat32_small.img bs=1M count=1
mkfs.fat -F 32 -n "STRATA-FAT" fat32_small.img
# Mount, populate with known content, unmount
# Reproducible content: 5 root files, 1 nested dir 3 levels deep,
# 1 file with name needing LFN entries,
# 1 file with FAT cluster chain spanning multiple clusters
```

Commit `crates/strata-fs/tests/fixtures/fat32_small.img`,
`mkfat32.sh`, and `fat32_small.expected.json` describing expected
enumeration.

## Phase B — Implement FatWalker

Create `crates/strata-fs/src/walkers/fat_walker.rs`:

- Implements the existing `Vfs` trait
- `FatWalker::open(reader: impl Read + Seek) -> Result<Self>`
- Auto-detects FAT12 / FAT16 / FAT32 / exFAT from boot sector
- Handles short filenames (8.3) and long filenames (LFN UTF-16 chains)
- Handles deleted entries (first byte 0xE5) — by default skip; expose
  via `--include-deleted` flag for forensic recovery
- Handles cluster chain following correctly including bad-cluster
  sentinels

**FAT-specific considerations:**

- **FAT12 packed entries:** FAT12 cluster numbers are 12 bits packed
- **exFAT:** Different on-disk format. Acceptable to ship FAT12/16/32
  in this sprint and defer exFAT to a follow-up if scope balloons
- **Date/time encoding:** FAT timestamps are local time, 2-second
  resolution. Walker exposes UTC where possible but preserves raw
  local-time values
- **Attribute byte:** Hidden, System, Read-only, Volume Label,
  Directory, Archive — expose as VfsEntry attributes

## Acceptance criteria

- [ ] `mkfat32.sh` produces deterministic fixture when re-run
- [ ] FatWalker opens fixture
- [ ] Walker correctly detects FAT12/FAT16/FAT32 variants
- [ ] Walker enumeration matches expected manifest exactly
- [ ] Long filenames decoded correctly
- [ ] Cluster chains followed through multi-cluster files
- [ ] Test count grows by ≥6
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] Charlie/Jo regression guards pass

If exFAT proves out of scope, document in
`SESSION_STATE_v15_BLOCKER.md` and ship FAT12/16/32 only.

---

# ═══════════════════════════════════════════════════════════════════════
# SESSION C — SPRINT 3 — FS-DISPATCH-PARTIAL-FULL — HFS+ AND FAT ARMS
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-DISPATCH-PARTIAL-FULL
**Why last:** Cannot ship before Sprints 1 and 2 succeed. Pattern
already proven from Session B's ext4 dispatcher work.

## Phase A — Activate the HFS+ and FAT arms

Replace the Unsupported returns for HFS+ and FAT/exFAT with live
walker constructions following the Session B ext4 pattern:

```rust
FilesystemType::HfsPlus => Ok(Box::new(HfsPlusWalker::open(reader)?)),
FilesystemType::Fat | FilesystemType::ExFat => Ok(Box::new(FatWalker::open(reader)?)),
```

If exFAT was deferred in Sprint 2, gate it with a separate match arm
returning Unsupported with explicit pickup signal.

Keep the APFS arms explicit Unsupported with v16 message.

## Phase B — Confirm filesystem detection

Confirm:
- HFS+ detection: wrapper signature `0x482B` at byte 1024
- FAT detection: BPB signature, OEM name patterns, FAT signatures

## Phase C — Extend E2E integration test

Add to existing `dispatch_partial_e2e.rs`:

```rust
#[test]
fn dispatcher_routes_hfsplus_to_live_walker() { /* ... */ }

#[test]
fn dispatcher_routes_fat_to_live_walker() { /* ... */ }

// Negative test: APFS still Unsupported with v16 message
```

## Phase D — CLI surface

Confirm `strata ingest run` succeeds end-to-end on:
- HFS+ images
- FAT images
- (still ext4 from Session B)
- (still NTFS from v11)

APFS still fails with v16 message.

## Acceptance criteria

- [ ] Dispatcher HFS+ arm routes to live HfsPlusWalker
- [ ] Dispatcher FAT/exFAT arms route to live FatWalker (or exFAT
      gated separately)
- [ ] Dispatcher APFS arms still return Unsupported with v16 message
- [ ] All four filesystem detections active (NTFS, HFS+, FAT, ext4)
- [ ] `strata ingest run` succeeds on HFS+ and FAT fixtures end-to-end
- [ ] dispatch_partial_e2e.rs all tests pass
- [ ] Test count grows by ≥3
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] Charlie/Jo regression guards pass

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# END OF SESSION C — v0.15.0 RELEASE
# ═══════════════════════════════════════════════════════════════════════

After all SESSION C sprints complete (or are documented as deferred):

1. Update CLAUDE.md key numbers section to reflect new test count and
   walker availability
2. Publish FIELD_VALIDATION_v15_REPORT.md covering:
   - Per-walker test counts and fixture validation results
   - Dispatcher activation status for each filesystem type
   - Charlie/Jo regression guard status (must show pass)
   - AST quality gate output (counts vs v14 baseline)
   - Any deferred items with pickup signals for v16
   - Comparison against v14 scorecard
3. Tag v0.15.0 with annotated tag message describing what shipped
4. Push commits and tag to origin/main

# ═══════════════════════════════════════════════════════════════════════
# COMPLETION CRITERIA — ENTIRE v15
# ═══════════════════════════════════════════════════════════════════════

SPRINTS_v15.md is complete (across all sessions) when:

**Filesystem walkers:**
- Ext4Walker ships wrapping verified ext4-view v0.9.3 API (Session B)
- HfsPlusWalker ships after Read+Seek refactor (Session C)
- FatWalker ships with committed FAT32 fixture (Session C)
- Each has integration tests against committed fixtures

**Dispatcher partial activation:**
- ext4 routes to live walker (Session B)
- HFS+ and FAT/exFAT route to live walkers (Session C)
- APFS arms remain explicit Unsupported with v16 pickup signal
- All four filesystems work end-to-end through `strata ingest run`

**Quality gates (non-negotiable, every session):**
- Test count: 3,684 + substantial growth (≥18 new tests across both
  remaining sessions)
- All tests passing
- Clippy clean workspace-wide
- AST quality gate stays at v14 baseline (zero new
  unwrap/unsafe/println)
- All 9 load-bearing tests preserved
- Charlie/Jo regression guards pass — NTFS extraction unchanged
- No public API regressions

**The moment v15 ends (post-Session C):**

Strata's NTFS, ext4, HFS+, and FAT walkers all ship live through the
unified dispatcher pipeline. Four of five major filesystem types
covered. Only APFS (single + multi via CompositeVfs) remains for v16.
The dispatcher CLI flow works end-to-end on Windows NTFS, Linux ext4,
macOS HFS+ legacy, and FAT/exFAT removable media evidence.

After v15, Strata covers the realistic forensic casework filesystem
landscape minus modern macOS APFS — which v16 closes.

---

*STRATA AUTONOMOUS BUILD QUEUE v15 — Reorganized post-Session 1*
*Wolfmark Systems — 2026-04-19*
*Session 1 (shipped): FS-EXT4-1 Phase A — research doc verifying ext4-view v0.9.3 API*
*Session B: FS-EXT4-1 Phase B/C + FS-DISPATCH-PARTIAL-EXT4*
*Session C: FS-HFSPLUS-1 + FS-FAT-1 + FS-DISPATCH-PARTIAL-FULL + v0.15.0 tag*
*Mission: Ship three filesystem walkers and partially activate the dispatcher.*
*Discipline: Do not silently compromise the spec. APFS waits for v16.*
