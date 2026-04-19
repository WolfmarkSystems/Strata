# FIELD_VALIDATION_v15_REPORT — v0.15.0 filesystem walker coverage

*Published at end of v15 Session E, 2026-04-19.*
*Tag: `v0.15.0` (pushed to origin/main)*

## Executive summary

v15 extended Strata's dispatcher from one live walker (NTFS, v11) to
four, adding ext2/3/4, HFS+, and FAT12/16/32. The dispatcher
pipeline — `open_filesystem(image, offset, size)` →
`Box<dyn VirtualFilesystem>` → plugin pipeline — now handles the
realistic forensic casework filesystem landscape minus APFS.

**Three walker commitments met.** Sessions B, D, and E each shipped
one walker live end-to-end with a committed (or skip-guarded) test
fixture and a positive dispatcher routing test. exFAT deferred per
SPRINTS_v15's scope-balloon clause with explicit pickup signal.
APFS deferred to v0.16.

Test count: **3,684 → 3,771** across five sessions (+87 net). Every
session ended with clippy clean, AST quality gate passing at v14
baseline, all 9 load-bearing tests preserved, and Charlie/Jo NTFS
regression guards unchanged.

## Walker scorecard

| Walker | Shipped in | Committed fixture? | Integration tests | Dispatcher live? |
|---|---|:---:|:---:|:---:|
| NTFS | v11 | NPS corpora (skip-guarded) | 3,400+ artifact pipeline | **yes** |
| ext4 | v15 Session B | no (Linux-only gen) | skip-guarded | **yes** |
| HFS+ | v15 Session D | yes (2 MiB) | 5 ground-truth | **yes** |
| FAT16 | v15 Session E | yes (16 MiB) | 9 ground-truth | **yes** (FAT12/16/32) |
| exFAT | — | — | — | deferred (explicit message) |
| APFS | v0.16 | — | — | deferred to v0.16 (explicit message) |

## Per-session contribution

### Session A — `76cf564`

`docs/RESEARCH_v15_EXT4_VIEW.md`. Verified `ext4-view v0.9.3` API
surface. Critical finding: `Ext4Read` is offset-addressed, a direct
fit for `EvidenceImage::read_at` — adapter is ~10 lines, not the
`BufReader<Mutex<PartitionReader>>` stack the v14 plan assumed.

### Session B — `f1ded09`, `1ee193d`, `00a6054`

- `Ext4Walker` + `Ext4PartitionReader` + fixture scaffolding.
- Dispatcher ext4 arm flipped to live walker.
- APFS arm now carries the literal `"v0.16"` pickup signal per the
  queue's examiner-facing requirement.
- **Design decision captured in code:** `Ext4Walker` does NOT cache
  an `Ext4` instance because `ext4-view`'s `Ext4` uses `Rc<Ext4Inner>`
  (`!Send + !Sync`). Walker stores only `Arc<dyn EvidenceImage>` and
  opens a fresh `Ext4::load` per trait method. The ~2 KB superblock
  re-parse is acceptable for forensic pipeline workloads; ext4-view's
  block cache absorbs subsequent reads within one invocation.
- Tests: 3,684 → 3,699 (+15).

### Session C — `2fa9989`, `a1b929a`, `965fde3`

- `docs/RESEARCH_v15_HFSPLUS_SHAPE.md` Phase 0 research: `Send +
  Sync` probes on `HfsPlusFilesystem`, `HfsPlusCatalogEntry`,
  `VfsEntry`. All pass — Path A (held handle) is viable.
- Read+Seek refactor of `HfsPlusFilesystem`: primary constructor is
  now `open_reader<R: Read + Seek + Send + 'static>`, path-based
  constructors preserved as thin wrappers via an `OffsetReader` shim.
- Session C ended partial — `read_catalog` was still a stub; Session
  D's Sprint 1 replaced it with real B-tree traversal.
- Tests: 3,699 → 3,711 (+12).

### Session D — `e43d0a2`, `1c163f5`, `94a7a89`, `a760cad`, `cd8e195`

- `docs/RESEARCH_v15_HFSPLUS_BTREE_SHAPE.md` — Apple TN1150 audit +
  implementation scope for B-tree leaf iteration.
- Real `read_catalog` implementation: sibling-chain iteration
  starting at `first_leaf_node`, tail-packed record offset table
  decode, catalog record type dispatch (folder/file/thread), UTF-16BE
  NFC-preserving filename decode, safety bounds (every slice access
  `.get(range).ok_or()`, 100k-node cycle cap).
- `HfsPlusWalker` VFS trait impl via Path A + `Mutex<HfsPlusFilesystem>`.
- `hfsplus_small.img` (2 MiB, macOS-native generation via `hdiutil` +
  `newfs_hfs`).
- `ground_truth_hfsplus.rs` — 5 integration tests.
- Dispatcher HFS+ arm flipped to live walker.
- **Real-fixture integration surfaced two latent parser bugs** that
  had survived v14 + Session C because synth tests mirrored the
  reader's offset mistakes in lockstep:
  1. Catalog fork at volume-header offset 288 → should be 272 per
     TN1150.
  2. B-tree header record field offsets all wrong: node_size at 8→18,
     rootNode at 16→2, firstLeafNode at 24→10, lastLeafNode at 28→14.
  Both fixes plus the synth-test offset updates plus a corrected
  Private-Data filter all land in `94a7a89`.
- Tests: 3,711 → 3,745 (+34).

### Session E — `6cd8056`, `eb4a710`, (this session's final commits)

- `docs/RESEARCH_v15_FAT_SHAPE.md` — FAT12/16/32 shape audit.
- `FatWalker` + `FatFilesystem` + `FatBpb` + LFN-aware directory
  decoder in `crates/strata-fs/src/fat_walker/`. ~700 LOC new parser
  code covering variant discrimination by cluster count, FAT12
  packed-entry decode, cluster chain following with EOC sentinel
  handling per variant, LFN chain assembly with
  `short_name_checksum` validation, NT/macOS case-preservation flag
  byte at directory entry offset 12.
- `fat16_small.img` (16 MiB, macOS-native generation via `hdiutil` +
  `newfs_msdos`). FAT16 chosen over FAT32 for committable size (FAT32
  minimum is ~33 MiB).
- `ground_truth_fat.rs` — 9 real-fixture integration tests covering
  every critical path: single-cluster read, multi-cluster chain
  following (5000-byte `big.bin` spanning 3 clusters), LFN assembly
  (`/Long Filename Example.txt`), 3-level nested directory traversal.
- Dispatcher FAT12/16/32 arms flipped to live walker.
- exFAT arm deferred with explicit pickup signal; APFS unchanged.
- **Real-fixture integration again surfaced two latent parser bugs**,
  same discipline win Session D booked:
  1. BPB variant-overlap: `sectors_per_fat_32` read unconditionally
     from offset 36 picked up FAT16's drive_num/signature/volume_id
     bytes as garbage, causing cluster-count math to return ~0 and
     incorrectly detect FAT12.
  2. NT/macOS case-preservation flag byte at offset 12 ignored — all
     lowercase-named files surfaced as uppercase short-name form.
- Tests: 3,745 → 3,771 (+26).

## Quality gate state

- `cargo test --workspace`: **3,771 passed, 0 failed**.
- `cargo clippy --workspace -- -D warnings`: **clean**.
- AST quality gate (`tools/strata-verify-quality`): **PASS** at
  v14 baseline — 470 library `.unwrap()` / 5 `unsafe{}` / 5
  `println!`, zero new across all five v15 sessions.
- **9 load-bearing tests** all still present and passing:
  `build_lines_includes_no_image_payload`,
  `hash_recipe_byte_compat_with_strata_tree`,
  `rule_28_does_not_fire_with_no_csam_hits`,
  `advisory_notice_present_in_all_findings`,
  `is_advisory_always_true` (×3 — strata-ml-anomaly, strata-ml-charges,
   third instance),
  `advisory_notice_always_present_in_output`,
  `examiner_approved_defaults_to_false`,
  `summary_status_defaults_to_draft`.
- Charlie/Jo NTFS regression guards (3,400+ artifacts): **pass**
  (NTFS path untouched across the entire v15 cycle).

## Comparison against v14 scorecard

| Dimension | End of v14 | End of v15 |
|---|---|---|
| Live dispatcher arms | 1 (NTFS) | 4 (NTFS, ext4, HFS+, FAT12/16/32) |
| Deferred arms with explicit message | 5 | 2 (exFAT, APFS) |
| Test count | 3,684 | 3,771 (+87) |
| AST quality gate | baseline captured | baseline held, zero new violations |
| Research docs committed | 1 (ext4-view API) | 4 (ext4-view, hfsplus-shape, hfsplus-btree-shape, fat-shape) |
| Binary fixtures committed | 0 | 2 (hfsplus_small.img, fat16_small.img) |
| Latent parser bugs caught by real-fixture integration | 0 | 4 (2× HFS+ in Session D, 2× FAT in Session E) |

The "bugs caught by real-fixture integration" row is the most
important. Sessions B, C, and D's research-and-unit-test discipline
was necessary but not sufficient — synth-test-lockstep (where the
test fixture builder and parser under test are written in the same
session against the same spec reference) hid bugs through entire
sessions in both HFS+ and FAT. Committing real-tool-generated
fixtures (via `newfs_hfs` and `newfs_msdos` on macOS) caught every
one of them immediately.

## Deferred items for v0.16 and beyond

### APFS (v0.16)

Sole remaining major filesystem. Scope comparable to HFS+ Session D:
container + volume super-block parse, B-tree iteration, snapshot
handling. Dispatcher arm returns `VfsError::Other("APFS walker
deferred to v0.16 — see roadmap")` — the literal `"v0.16"` substring
is enforced by the `dispatch_apfs_returns_explicit_v016_message`
test to protect the examiner-facing pickup signal from refactor
drift.

### exFAT (v0.15.1 or a follow-up sprint)

Distinct on-disk format from FAT12/16/32 — new parser, not an
extension. Dispatcher arm returns `VfsError::Other("exFAT walker
deferred — see roadmap")`. Scope: ~400 LOC for boot sector + entry
groups (File / StreamExtension / FileName) + allocation bitmap. Not
required for v0.15.0 per SPRINTS_v15's scope-balloon clause.

### HFS+ Phase B Part 3 (post-v15)

The `HfsPlusWalker::read_file` method currently returns
`VfsError::Unsupported`. Fork-data extent resolution +
resource-fork exposure as `.rsrc` alternate stream + BSD
permissions + timestamps are the follow-on scope. Pinned in
`walker_read_file_is_pinned_as_unsupported_until_phase_b_part_3`.

### FAT walker follow-ups

- FAT32 fixture (requires ≥33 MiB image — synth unit tests cover
  the root-cluster-as-chain path).
- FAT12 fixture (unusual in modern forensic evidence; synth tests
  cover the packed-entry decode).
- Date/time decoding into `VfsEntry.created/modified/accessed`
  fields (Phase B Part 3 equivalent).
- Deleted-entry forensic recovery via `list_deleted` + matching
  `read_deleted`.
- ext4 binary fixture on a Linux host (`mkext4.sh` is ready to run).

### Quality gate ratchet

The v14 baseline (470 / 5 / 5) held through all five v15 sessions
with zero new violations — discipline works. The current library
`.unwrap()` count is legitimately 470; a future cleanup sprint
could ratchet it down. Largest offenders per the AST gate output:
`strata-fs::apfs` (30), `strata-fs::container::vhd` (29),
`strata-core::case::repository` (17). The APFS cleanup is a
natural prerequisite to v0.16's APFS walker sprint.

## Closing

The v0.15.0 tag reflects five sessions of disciplined work:
research before implementation, real fixtures before shipping,
honest deferrals when scope exceeded one session. Four live
walkers, two explicit deferrals, zero silent stubs. The
dispatcher rewiring pattern — proven on ext4 in Session B,
HFS+ in Session D, FAT in Session E — is now templated enough
that APFS in v0.16 should follow the same shape with no
architectural surprises.

Strata is a forensic tool.
