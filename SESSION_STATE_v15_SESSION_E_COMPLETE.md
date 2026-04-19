# SPRINTS_v15 Session E — complete

Session E of v15 shipped all four in-scope sprints exactly as the
queue specified: FAT12/16/32 parser + walker, FAT16 fixture with
real-fixture integration, dispatcher FAT arm flip. Plus the
v0.15.0 milestone artifacts: CLAUDE.md key-numbers update,
`FIELD_VALIDATION_v15_REPORT.md`, annotated `v0.15.0` tag pushed.

## Sprint scorecard

| # | Sprint | Status | Commit |
|---|---|---|---|
| 1A | FS-FAT-1 Phase A research | shipped | `6cd8056` (folded) |
| 1B | FS-FAT-1 Phase B parser + walker | shipped | `6cd8056` |
| 3 | FS-FAT-1 Phase C fixture + ground_truth_fat.rs | shipped | `6cd8056` |
| 4 | FS-DISPATCH-FAT arm flip + test conversion | shipped | `eb4a710` |
| — | CLAUDE.md key numbers update | shipped | (this commit) |
| — | FIELD_VALIDATION_v15_REPORT.md | shipped | (this commit) |
| — | v0.15.0 annotated tag | pushed | (this commit) |

## What shipped this session

See `FIELD_VALIDATION_v15_REPORT.md` for the detailed walker
contribution narrative. Headline items:

1. **FatWalker ships live**, wrapping a new FAT12/16/32 parser
   (~700 LOC) built on top of the existing boot-sector-only
   `fat.rs`. All four `VirtualFilesystem` trait methods work:
   `list_dir`, `read_file`, `metadata`, `exists`. Path resolution
   is case-insensitive per FAT semantics; LFN chain assembly with
   checksum validation surfaces the real filename; NT/macOS
   case-preservation flag byte honored.
2. **`fat16_small.img` committed** (16 MiB, macOS-native via
   `hdiutil` + `newfs_msdos`). 9 real-fixture integration tests
   cover every critical walker path.
3. **Dispatcher FAT12/16/32 arms live**. Pattern follows Sessions
   B (ext4) and D (HFS+). Session B's negative test
   `dispatch_fat32_still_unsupported_until_session_c` converted to
   positive `dispatch_fat32_arm_attempts_live_walker_construction`.
   exFAT arm deferred with explicit `"exFAT walker deferred — see
   roadmap"` pickup signal; APFS arm unchanged with literal
   `"v0.16"` message.

### Two parser bugs caught by the real fixture

Continuing the Session D discipline, real-fixture integration
caught two latent bugs that synth-only testing would have hidden:

1. **BPB field overlap.** `sectors_per_fat_32` read unconditionally
   from offset 36 picked up FAT16's drive_num/signature/volume_id
   bytes as garbage. `walker_opens_committed_fixture` caught this
   with `fs_type() == "fat12"` instead of `"fat16"`. Fixed by
   reading `sectors_per_fat_16` first and falling through to FAT32
   offsets only when `_16 == 0` (the canonical Microsoft rule).
2. **Case-preservation flag byte ignored.** NT and macOS use
   directory-entry byte 12's bits 0x08 / 0x10 to avoid LFN chains
   for 8.3-compatible lowercase names. My walker ignored them,
   surfacing `README.TXT` / `DIR1` / `BIG.BIN` instead of the
   user's `readme.txt` / `dir1` / `big.bin`. Fixed by adding
   `case_flags` parameter to `format_short_name`.

Both bugs land in commit `6cd8056` because they were caught when
the ground_truth_fat integration test first ran against the
committed fixture. Session D's discipline (generate fixture, test
against real bytes, fix parser when synth and real disagree)
again caught exactly what it's designed to catch.

## Quality gates at end of session

- **Test count:** **3,771** (from 3,745 at Session E start; +26 net).
- **Final v15 growth:** 3,684 → 3,771 (+87 across all five sessions).
- `cargo clippy --workspace -- -D warnings`: clean.
- AST quality gate: **PASS** at v14 baseline (470 library unwrap /
  5 unsafe / 5 println — zero new across all five v15 sessions).
- All 9 load-bearing tests preserved.
- Charlie/Jo regression guards: unchanged — NTFS path untouched.
- Session B ext4 dispatcher arm: unchanged — tests pass.
- Session D HFS+ dispatcher arm: unchanged — tests pass.
- No public API regressions. `FatWalker`, `fat_walker/` module,
  and the dispatcher FAT arm flip are all additive.

## Final v15 commit graph

```
eb4a710  feat: FS-DISPATCH-FAT activate FAT arm; exFAT deferred
6cd8056  feat: FS-FAT-1 Phases A+B+C FatWalker + fixture + real tests
cd8e195  docs: SESSION_STATE_v15_SESSION_D_COMPLETE
a760cad  feat: FS-DISPATCH-HFSPLUS activate HFS+ dispatcher arm
94a7a89  feat: FS-HFSPLUS-1 Phase C fixture + fix two latent B-tree bugs
1c163f5  feat: FS-HFSPLUS-1 Phase B Part 2 HfsPlusWalker VFS trait impl
e43d0a2  feat: FS-HFSPLUS-1 Phase B Part 1 real B-tree leaf-node iteration
965fde3  docs: SESSION_STATE_v15_SESSION_C_PARTIAL
a1b929a  feat: FS-HFSPLUS-1 Phase 0 + Phase A Read+Seek refactor
2fa9989  docs: RESEARCH_v15_HFSPLUS_SHAPE — Session C Phase 0 research
00a6054  docs: SESSION_STATE_v15_SESSION_B_COMPLETE
1ee193d  feat: FS-DISPATCH-EXT4 route ext4 to live walker
f1ded09  feat: FS-EXT4-1 Phase B/C Ext4Walker live + fixture scaffolding
d86c43d  docs: SESSION_STATE_v15_BLOCKER — walker sprints deferred
76cf564  feat: FS-EXT4-1 Phase A ext4-view v0.9 API verified
```

## v0.15.0 tag

The annotated tag message covers the full five-session arc:

- Session A: ext4-view v0.9 API verified
- Session B: ext4 walker live + dispatcher arm
- Session C: HFS+ Phase 0 probes + Phase A Read+Seek refactor
- Session D: HFS+ B-tree iteration + walker + dispatcher arm (2
  latent parser bugs caught by real fixture)
- Session E: FAT walker + dispatcher arm (2 more latent parser
  bugs caught by real fixture); CLAUDE.md + FIELD_VALIDATION +
  v0.15.0 tag

## Notes for whoever picks up v0.16

1. **APFS is the only remaining major filesystem.** Dispatcher
   arm already returns the literal `"v0.16"` pickup signal —
   protected by `dispatch_apfs_returns_explicit_v016_message`
   (courtroom-relevant assertion, do not relax). Scope comparable
   to HFS+ Session D: container super-block + volume super-block
   parse, B-tree iteration over the object-map + file-system trees,
   snapshot handling. The in-tree `apfs.rs` + `apfs_walker.rs`
   have some existing state but — learning from Session D's HFS+
   experience — **generate a real APFS fixture (macOS `hdiutil
   create -fs APFS`) BEFORE writing parser code**, and let real
   bytes drive spec-conformance.
2. **exFAT is a smaller separate follow-up.** Different on-disk
   format from FAT12/16/32. ~400 LOC new parser. Dispatcher arm
   already carries a deferral message. Can ship as v0.15.1 or fold
   into v0.16 scope depending on preference.
3. **HFS+ Phase B Part 3** remains pinned by
   `walker_read_file_is_pinned_as_unsupported_until_phase_b_part_3`.
   Fork-data extent reading + resource fork + timestamps + BSD
   permissions. Decoupled from v0.16's APFS scope — can run in
   parallel as a targeted sprint whenever a successor session has
   bandwidth.
4. **AST quality gate ratchet.** Every v15 session shipped zero
   new library-code unwrap/unsafe/println. The discipline works.
   The v14 baseline (470/5/5) could be ratcheted down by a cleanup
   sprint — largest offenders are `strata-fs::apfs` (30 unwraps),
   `strata-fs::container::vhd` (29), `strata-core::case::repository`
   (17). Cleaning `strata-fs::apfs` is a natural prerequisite to
   v0.16's APFS walker sprint.
5. **Discipline carries forward.** "Do not silently compromise the
   spec." Research before implementation. Real fixtures before
   shipping. Tripwire tests pinning stub behavior. When synth and
   real disagree, the real fixture wins. Five sessions of this
   pattern produced four correct walkers — worth continuing into
   v0.16.

## The bottom line

v0.15.0 ships four of five major filesystem walkers live through
the unified dispatcher pipeline. The architectural build-out
promised in the original v14 plan (two shipped, eight deferred) is
now **twelve sessions further along**, with the remaining work
narrowed to one filesystem (APFS) plus three well-scoped
follow-ups (exFAT, HFS+ Phase B Part 3, ext4 Linux-side fixture
commit).

Only APFS waits for v0.16 to complete the realistic forensic
filesystem coverage. Strata is a forensic tool.
