# SPRINTS_v16 Session 3 — complete

v16 Session 3 shipped the two sprints per the queue: APFS parser
foundation via external crate adoption, and HFS+ read_file extent
reading closing the v15 Session D deferral. Plus a pre-existing-
bug fix (fixture gitignore).

**`v0.16.0` NOT tagged.** That's Session 5.

## Sprint scorecard

| # | Sprint | Status | Commit |
|---|---|---|---|
| — | In-tree APFS retirement | **shipped** | `39e8239` |
| 1 | FS-APFS-OBJMAP (adopt external crate + wrapper) | **shipped** | `2395c3e` |
| — | Fixture gitignore repair | **shipped** | `e8dbf5f` |
| 2 | FS-HFSPLUS-READFILE (close v15 Session D deferral) | **shipped** | `312be50` |

## Commit graph

```
312be50  feat: FS-HFSPLUS-READFILE close v15 Session D deferral via extent reading
e8dbf5f  fix: un-ignore walker test fixtures silently blocked by *.img
2395c3e  feat: FS-APFS-OBJMAP adopt external apfs crate + Strata wrapper
39e8239  refactor: retire in-tree APFS modules (v16 Session 3 cleanup)
```

## What shipped

### Retirement (`39e8239`)

Deleted three in-tree APFS modules + associated Send/Sync probes
and unit tests, per the Session 1.5 retirement plan:

- `crates/strata-fs/src/apfs.rs` (601 LOC, heuristic scanners +
  stub `resolve_oid` + stub `read_file` + hardcoded placeholders)
- `crates/strata-fs/src/apfs_walker.rs` (1,283 LOC, working
  OMAP/fs-tree but never real-fixture validated + heuristic_scan
  fallback liability)
- `crates/strata-fs/src/apfs_advanced.rs` (70 LOC, entirely stubs)
- 13 Send/Sync probes under `#[cfg(test)]` in apfs.rs
- 6 unit tests in apfs_walker.rs

Plus consumer migrations:
- `lib.rs` — removed `pub mod apfs;` etc + the `pub use apfs::{...}`
  re-export block.
- `virtualization/mod.rs` — stubbed both pre-dispatcher
  `enumerate_apfs_directory` impls to `Ok(Vec::new())` matching
  the already-stubbed NTFS/ext4 paths on the same type. APFS
  snapshot heuristic enumeration retired in favor of the
  deferred-to-v17 structural walk.

Net: **~1,954 LOC + 19 tests retired** in a dedicated commit so
git blame cleanly attributes the deletion.

### FS-APFS-OBJMAP (`2395c3e`)

Adopts `apfs = "0.2"` MIT-licensed external crate per the
Session 1.5 research doc. Creates the Strata-owned wrapper at
`crates/strata-fs/src/apfs_walker/mod.rs`:

- `detect_fusion(nxsb)` — reads
  `incompatible_features & NX_INCOMPAT_FUSION_FLAG (0x100)`.
  Session 4 dispatcher arm consumes this to return
  `VfsError::Other("APFS fusion drives not yet supported —
  see roadmap")` before any walker constructs.
- `enumerate_volume_oids(nxsb)` — filters `fs_oids` for non-zero
  entries. Session 5's `ApfsMultiWalker` iterates the result.
- `read_container_superblock(reader)` — thin convenience over
  `read_nxsb` + `find_latest_nxsb` from the crate.
- `apfs_error_to_forensic(e)` — lossy mapping preserving Io
  passthrough, folding non-Io into `MalformedData(format!("apfs:
  {other:?}"))` for traceability.

**17 new tests:**
- 5 Send/Sync probes against external crate types
  (`ApfsVolume<File>`, `NxSuperblock`, `ApfsSuperblock`,
  `ApfsError`). Path A held-handle architecture confirmed in
  code.
- 10 unit tests on the wrapper helpers (fusion-detect true/false
  plus flag-isolation, OID enumeration with various shapes,
  error-mapping preserves Io, folds non-Io into MalformedData).
  `nx_incompat_fusion_flag_literal_matches_spec` pins the
  literal 0x100 value per research doc §7.
- 2 real-fixture integration tests against committed
  `apfs_small.img`:
  `read_container_superblock_succeeds_on_fixture` and
  `fixture_fusion_detect_matches_known_non_fusion_origin`.

### Fixture gitignore repair (`e8dbf5f`)

**Pre-existing bug found during Session 3 fixture move.**
`.gitignore` line 28 `*.img` has silently blocked EVERY
filesystem walker fixture. Sessions D (HFS+) and E (FAT16)
session state docs claimed "committed one-time snapshot" but
`git ls-files` showed only the expected.json + *.sh files. The
binary fixtures existed on local dev disks but never reached
origin.

**Impact:** skip-guarded integration tests silently SKIP on any
fresh clone. Session 1.5's v15 Lesson 2 discipline ("real-
fixture validation catches synth-test-lockstep bugs") only
applied on the dev box that generated the fixture.

**Fix:** Added un-ignore rule
`!crates/strata-fs/tests/fixtures/*.img` after the existing
`*.img` pattern. Negation is path-scoped — top-level `*.img`
files remain ignored per forensic-image policy. Force-added
three fixtures:
- `apfs_small.img` (10 MiB, Session 1.5 probe fixture)
- `hfsplus_small.img` (2 MiB, Session D)
- `fat16_small.img` (16 MiB, Session E)

`ext4_small.img` still absent (Session B Linux-only generation
per `mkext4.sh`; will be force-added when a Linux CI runner
commits one).

### FS-HFSPLUS-READFILE (`312be50`)

Closes the v15 Session D deferral — HfsPlusWalker::read_file no
longer returns `VfsError::Unsupported`.

**Parser extensions (hfsplus.rs):**
- `HfsPlusCatalogEntry` gains `data_fork: Option<HfsPlusForkData>`
  + `resource_fork: Option<HfsPlusForkData>` fields.
- New `HfsPlusForkData { logical_size: u64, extents: [...; 8] }`
  struct (HFSPlusForkData per TN1150, 80 bytes on wire).
- `parse_catalog_record` REC_TYPE_FILE branch now decodes both
  forks at data offsets 88..168 (data) + 168..248 (resource).
  Truncated records (<248 bytes) leave forks as `None` —
  preserves backward compat for synth tests.
- `parse_fork_data(buf)` helper — BE u64 size + 8 extent pairs.
- `HfsPlusFilesystem::read_fork_content(&HfsPlusForkData)` walks
  the 8 inline extents, reads blocks, truncates at
  `logical_size`. Handles sparse holes (start_block == 0 + non-
  zero block_count fills zeros). Returns MalformedData when a
  file exceeds 8 inline extents (extents-overflow B-tree
  traversal is v17 follow-on).

**Walker wiring (hfsplus_walker/mod.rs):**
- `fn read_file(path)` — resolves path → entry via catalog walk,
  reads data fork via `read_fork_content`. NotAFile on
  directories, NotFound on missing, Other on malformed
  (missing data fork).
- `fn alternate_streams(path)` — returns `["rsrc"]` iff the
  resource fork's `logical_size > 0`, else empty vec.
- `fn read_alternate_stream(path, "rsrc")` — reads resource
  fork content. Any other stream name returns Other with
  accepted-set documented.

**Tripwire flip:** Session D's
`walker_read_file_is_pinned_as_unsupported_until_phase_b_part_3`
renamed + rewritten as
`walker_read_file_succeeds_via_fork_extent_reading`. Pins the
NEW behavior (empty-fork case returns empty Vec, not
Unsupported). Rename convention preserves audit trail.

**5 real-fixture integration tests** against the committed
`hfsplus_small.img`:
- `walker_reads_readme_txt_matches_populated_bytes`
- `walker_reads_nested_deep_file` (3-level nested)
- `walker_surfaces_resource_fork_as_rsrc_alternate_stream` —
  first successful resource-fork read since v15 Session D
  shipped the fixture
- `walker_reports_no_alternate_streams_for_non_fork_file`
- `walker_reads_forky_data_fork_matches_populated_bytes` — pins
  the committed fixture's ACTUAL bytes (15 bytes including
  trailing newline) rather than what `mkhfsplus.sh`'s header
  comment claimed. Real bytes win per v15 Lesson 2.

## Quality gates end-of-session

- **Test count:** **3,798** (from 3,795 at session start; -19
  from retirement + 17 new apfs_walker + 5 new ground_truth_hfsplus
  = +3 net on top of the retirement delta, which is correct).
- `cargo clippy --workspace -- -D warnings`: **clean** (after
  `repeat_n` + `#[derive(Default)]` refactors in Sprint 2).
- AST quality gate: **PASS** at v14 baseline (470/5/5, zero new).
- All 9 load-bearing tests preserved.
- **All four v15 dispatcher arms still route live**
  (`fs_dispatch` tests unchanged by this session — dispatcher
  rewiring for APFS is Session 4).
- **APFS dispatcher arm still returns literal `"v0.16"` message**
  (`dispatch_apfs_returns_explicit_v016_message` still passes).
- **exFAT arm still returns deferral message**.
- **All four Session 2 advisory plugin tripwires still pass**.
- Charlie/Jo regression guards: unchanged.
- No public API regressions. `HfsPlusCatalogEntry`'s new
  `Option<HfsPlusForkData>` fields are additive. The retired
  `apfs::*` re-exports had zero external consumers per the
  retirement commit's grep.

## Pickup signals for Session 4

The Strata wrapper's fusion-detect + volume-oid-enumeration
helpers + the external `apfs` crate's `ApfsVolume<R>` are both
ready. Session 4 Sprint 1 builds `ApfsSingleWalker` on top:

1. **Create `crates/strata-fs/src/apfs_walker/single.rs`** with
   `ApfsSingleWalker` holding `Mutex<ApfsVolume<PartitionReader>>`
   per the Path A architecture confirmed in Session 1.5.
2. **Implement VirtualFilesystem trait** delegating to
   `ApfsVolume::{list_directory, read_file, stat, exists}`.
3. **Wire encryption marking** — read `ApfsSuperblock` flags
   post-volume-open; surface `is_encrypted: true` on
   `VfsAttributes` when set.
4. **Wire xattr exposure** — use the crate's
   `catalog::J_TYPE_XATTR = 4` record-type constant to decode
   xattr records via low-level B-tree traversal. Walker's
   `alternate_streams(path)` returns the xattr names.
5. **Dispatcher arm flip** (`fs_dispatch.rs`): route
   `FsType::Apfs` to `ApfsSingleWalker::open_on_partition`
   when `detect_fusion(nxsb) == false`, else return
   `VfsError::Other("APFS fusion drives not yet supported —
   see roadmap")`.
6. **Convert the Session B negative test**
   `dispatch_apfs_returns_explicit_v016_message` to
   `dispatch_apfs_arm_attempts_live_walker_construction` —
   matches the ext4/HFS+/FAT conversion pattern from v15
   Sessions B/D/E.
7. **Snapshot tripwire**
   `apfs_walker_walks_current_state_only_pending_snapshot_enumeration`
   per Session 1 research doc §4 — pins v16 behavior (latest
   XID only); Session 4 fixture has at least one snapshot so
   the walker's non-enumeration-of-snapshots is verifiable.
8. **Fusion-rejection tripwire**
   `apfs_walker_rejects_fusion_container_with_pickup_signal`
   per Session 1 research doc §7 — synthesizes (or selectively
   sets) the NX_INCOMPAT_FUSION bit and confirms the walker
   returns the exact "fusion" pickup-signal string.

Fixture for Session 4 integration tests is **already committed**
at `crates/strata-fs/tests/fixtures/apfs_small.img` (10 MiB,
Session 1.5 probe fixture). Expected manifest at
`apfs_small.expected.json`.

Session 4 Sprint 3 (exFAT walker — opportunistic per queue tag
policy) is independent of the APFS work and can ship in the
same session if scope permits.

## Pickup signals for Session 5

`ApfsMultiWalker` uses the `enumerate_volume_oids` helper from
Sprint 1 of this session + the crate's public submodule helpers
(`omap::omap_lookup`, `ApfsSuperblock::parse`) to construct
per-volume walkers on a shared `PartitionReader`. Path scoping
convention `/vol{N}:/path` per Session 1 research doc §5.

Session 5 also publishes `FIELD_VALIDATION_v16_REPORT.md`,
updates CLAUDE.md key numbers, and tags `v0.16.0`.

## Methodology note — real fixture vs script comment

Session 3 Sprint 2 surfaced a small real-vs-synth discrepancy:
`mkhfsplus.sh`'s inline comment claimed `forky.txt` was 15
bytes, but the `printf 'file with fork'` command doesn't
produce a trailing newline. The committed fixture has 15 bytes
INCLUDING a trailing newline, so somewhere between the script
comment and the actual population step on the macOS run that
produced the committed fixture, the bytes diverged.

Per v15 Lesson 2: **real bytes win.** The integration test pins
the committed fixture's actual content
(`b"file with fork\n"`) with an inline comment documenting the
discrepancy. Future regenerations of the fixture via
`mkhfsplus.sh` would produce a slightly different file (14
bytes, no newline) — which would break this test and surface
the inconsistency for resolution. That's the correct forensic-
discipline behavior.

## The bottom line

v16 Session 3 materialized the Session 1.5 research doc's multi-
layer adoption decision. The in-tree APFS code (heuristic +
stubs, never real-fixture validated) is retired; the external
crate (real-fixture validated, zero heuristic fallback) is
adopted behind a Strata-owned wrapper. HFS+ read_file closes
the v15 Session D deferral with inline extent reading and
real-fixture-validated data + resource fork support.

Plus a pre-existing gitignore bug fix that silently blocked
every filesystem walker fixture from reaching origin. Sessions
D and E claimed "committed" but the bytes never left local
dev boxes — now they do.

Session 4 picks up with `ApfsSingleWalker` on top of the
wrapper. Session 5 closes with multi-volume + v0.16.0 tag.

Strata is a forensic tool.
