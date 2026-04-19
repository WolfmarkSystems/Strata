# v16 Session 5 — COMPLETE (v0.16.0 tag)

**Date:** 2026-04-19
**Scope:** Ship `ApfsMultiWalker` CompositeVfs, flip the APFS-multi
dispatcher arm with auto-detection, update CLAUDE.md, publish
FIELD_VALIDATION_v16_REPORT.md, tag v0.16.0.
**Tag:** v0.16.0 (annotated, pushed).

## What shipped

### Sprint 1 — FS-APFS-MULTI-COMPOSITE (commit `5230cab`)

`crates/strata-fs/src/apfs_walker/multi.rs` (new, ~600 LOC)
— `ApfsMultiWalker` holding `Mutex<PartitionReader>` + `Vec<VolumeState>`.

Key decisions:

- **Path convention.** `/vol{N}:/path` per research doc §5. Numeric
  index, colon separator, deterministic, POSIX-unambiguous.
- **Strata-owned state, crate-owned parser.** The external `apfs`
  crate's `ApfsVolume::open` hardcodes first-non-zero fs_oid.
  `ApfsMultiWalker` resolves each volume's `vol_omap_root_block`
  + `catalog_root_block` via the crate's public submodule helpers
  (`omap::read_omap_tree_root`, `omap::omap_lookup`,
  `ApfsSuperblock::parse`), then delegates `list_dir`/`read_file`/
  `metadata` to `catalog::list_directory` / `resolve_path` /
  `lookup_extents` and `extents::read_file_data` with per-volume
  parameters. No parser duplication.
- **Snapshot/fusion parity with single.** Same
  `_pending_snapshot_enumeration` tripwire; fusion-reject at
  `open()`; encryption marks per-volume via
  `ApfsSuperblock.fs_flags`.
- **Container-root stubs.** `list_dir("/")` returns one entry
  per volume (`vol0:`, `vol1:`, ...) marked as directories so
  standard tree-walking tools descend into them.

8 exhaustive `parse_volume_scope` unit tests, Send/Sync probe,
15 fixture-gated integration tests that skip gracefully when
`apfs_multi.img` is absent (see §Fixture limitation below).

### Sprint 2 — FS-DISPATCH-APFS-MULTI (commit `f316d08`)

`open_filesystem` APFS arm now reads the container NxSuperblock
in a new `open_apfs` helper, counts non-zero `fs_oids`, and routes:

- `count >= 2` → `ApfsMultiWalker`
- `count == 1` → `ApfsSingleWalker` (unchanged behavior)
- `count == 0` → `ApfsSingleWalker` (surfaces apfs-crate NoVolume)

Positive tripwire conversions:
- `dispatch_apfs_single_volume_fixture_routes_to_apfs_single_walker`
  — committed `apfs_small.img` routes to single walker; verified
  by `list_dir("/")` returning `alpha.txt` directly (not
  `/vol0:` scope stubs)
- `dispatch_apfs_multi_arm_routes_to_live_walker` — when
  `apfs_multi.img` is committed (physical-drive fixture), routing
  verified; skips gracefully otherwise
- `open_apfs_counts_volumes_via_nxsb` — zero-buffer regression
  test confirming the count logic fires (error carries
  `"apfs dispatcher:"` prefix)

### Sprint 3 — V16-MILESTONE (this commit)

- CLAUDE.md key numbers updated to v0.16.0 state (3,836 tests,
  6 live filesystem families, explicit tripwired deferrals)
- `FIELD_VALIDATION_v16_REPORT.md` published covering all five
  v16 sessions, quality-gate comparison, methodology lessons,
  post-v16 roadmap
- v0.16.0 annotated tag created + pushed

## Fixture limitation — documented honestly

macOS `hdiutil`/`newfs_apfs`/`diskutil eraseDisk` produce
DMG/sparseimage/RAM-disk-backed APFS containers with
`NxSuperblock.max_file_systems = 1`. `diskutil apfs addVolume`
fails with error -69493 ("can't add any more APFS Volumes") on
any second attempt. Verified at 20/60/100/200 MB across UDIF DMG,
sparseimage, and RAM disk backing. This is a macOS disk-image
infrastructure limitation, not a Strata or apfs-crate bug;
physical APFS drives ship with `max_file_systems ≈ 100` and
support `addVolume` cleanly.

**Consequences:**

- `apfs_multi.img` NOT committed
- `crates/strata-fs/tests/fixtures/mkapfs_multi.sh` documents
  the manual physical-drive regeneration recipe
- 12 fixture-gated integration tests in `apfs_walker::multi::tests`
  gracefully skip; will flip active when a physical-drive
  fixture is committed in v17
- Walker logic still validated via: parse_volume_scope unit
  tests (8), Send/Sync probe, shared catalog/omap/extents
  helpers real-fixture-validated via `apfs_small.img` in
  Sessions 1.5 and 4, dispatcher routing decision unit test

The v15 Lesson 2 discipline is preserved by refusing to
synthesize a multi-volume fixture via byte-patching. The gap is
named, tripwired, and carried forward into v17.

## Gate status

- **Clippy workspace:** clean (`-D warnings`)
- **Tests:** 3,836 passing (3,811 baseline + 25 new Session 5
  tests)
- **AST quality gate:** PASS
  - Library unwrap: 424 (≤ 470 ceiling)
  - Library unsafe: 5 (= 5 ceiling)
  - Library println: 5 (= 5 ceiling)
- **9 load-bearing tests:** preserved
- **Charlie/Jo regression guards:** unchanged
- **All dispatcher arms route live:** NTFS (v11), ext (v15 S B),
  HFS+ (v15 S D + v16 S3 read_file), FAT (v15 S E), APFS-single
  (v16 S4), APFS-multi (v16 S5)
- **exFAT:** deferred, tripwire live
  (`dispatch_exfat_returns_explicit_deferral_message`)

## Commits shipped this session

- `5230cab` feat: FS-APFS-MULTI-COMPOSITE ApfsMultiWalker CompositeVfs
- `f316d08` feat: FS-DISPATCH-APFS-MULTI auto-detect single vs multi via fs_oids
- (milestone commit) docs: v16 milestone — CLAUDE.md + FIELD_VALIDATION + SESSION_STATE

## v0.16.0 tag

Annotated tag covering all five v16 sessions. Names the five
sessions, references the v15 → v16 arc, documents the fixture
limitation, lists tripwired deferrals. Pushed to `origin/main`.

## Post-v16 pickup signals

Each carries a named tripwire test for v17 flip:

1. **FS-EXFAT-1** — `dispatch_exfat_returns_explicit_deferral_message`
2. **FS-APFS-MULTI-FIXTURE** — 12 gracefully-skipping tests in
   `apfs_walker::multi::tests` flip from skip→active on
   `apfs_multi.img` commit
3. **FS-APFS-SNAPSHOTS** — `apfs_walker_walks_current_state_only_pending_snapshot_enumeration`
   (single walker) + `apfs_multi_walker_walks_current_state_only_pending_snapshot_enumeration`
   (multi walker)
4. **FS-APFS-XATTRS** — no tripwire (gap noted in
   RESEARCH_v16_APFS_RUST_ECOSYSTEM.md §2)

---

**Strata's architectural filesystem build-out is complete.**
After v0.16.0, future forensic work is depth (snapshots,
historical checkpoints, physical-drive fixtures, optional
decryption with examiner-supplied keys), not breadth. No more
major filesystem families remain to add.
