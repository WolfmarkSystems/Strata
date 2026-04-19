# SPRINTS_v15 Session D — complete

Session D of v15 shipped all four in-scope sprints exactly as the
queue specified: real HFS+ B-tree leaf-node iteration, the
`HfsPlusWalker` VFS trait impl wrapping it, a committed HFS+
fixture with macOS-native generation, and the dispatcher HFS+ arm
flip from Unsupported to live walker routing.

**`v0.15.0` tag NOT applied** per the queue's explicit instruction.
The tag lands at end of Session E after the FAT walker ships. v15
commitment is three walkers (ext4 + HFS+ + FAT) plus full
dispatcher partial; Session B + Session D deliver two of three.

## Sprint scorecard

| # | Sprint | Status | Commit |
|---|---|---|---|
| 1 Phase A | FS-HFSPLUS-1 B-tree research (`RESEARCH_v15_HFSPLUS_BTREE_SHAPE.md`) | shipped | `e43d0a2` |
| 1 Phase B Part 1 | FS-HFSPLUS-1 real B-tree leaf iteration | shipped | `e43d0a2` |
| 2 | FS-HFSPLUS-1 Phase B Part 2 `HfsPlusWalker` VFS trait impl | shipped | `1c163f5` |
| 3 | FS-HFSPLUS-1 Phase C fixture + bug fixes | shipped | `94a7a89` |
| 4 | FS-DISPATCH-HFSPLUS activate HFS+ dispatcher arm | shipped | `a760cad` |

Sessions A + B + C + D shipped to date:

| Session | Commit | Deliverable |
|---|---|---|
| A | `76cf564` | `docs/RESEARCH_v15_EXT4_VIEW.md` — ext4-view v0.9 API verified |
| B | `f1ded09` | `Ext4Walker` + `ext4_walker/` module + fixture scaffolding |
| B | `1ee193d` | Dispatcher ext4 arm live; APFS v0.16 message |
| B | `00a6054` | `SESSION_STATE_v15_SESSION_B_COMPLETE.md` |
| C | `2fa9989` | `docs/RESEARCH_v15_HFSPLUS_SHAPE.md` Phase 0 research |
| C | `a1b929a` | HFS+ Send probes + Phase A Read+Seek refactor |
| C | `965fde3` | `SESSION_STATE_v15_SESSION_C_PARTIAL.md` |
| D | `e43d0a2` | HFS+ B-tree shape research + real leaf iteration |
| D | `1c163f5` | `HfsPlusWalker` VFS trait impl |
| D | `94a7a89` | HFS+ fixture + two latent B-tree bug fixes |
| D | `a760cad` | HFS+ dispatcher arm live |
| D | (this commit) | `SESSION_STATE_v15_SESSION_D_COMPLETE.md` |

## What shipped this session

### Sprint 1 Phase B Part 1 — real read_catalog

The pre-existing `read_catalog` stub (returning one placeholder
`"root"` entry) is replaced with actual B-tree leaf-node iteration
per Apple TN1150:

- `read_catalog_node(node_idx)` reads a node by index from the
  catalog file's first extent.
- Sibling-chain iteration starts at `first_leaf_node`, follows
  `fLink`, skips non-leaf nodes, caps at 100,000 nodes to prevent
  malicious cycles.
- `parse_node_descriptor` decodes the 14-byte header with explicit
  kind validation (rejects unknown kinds).
- `parse_record_offsets` reverses the on-disk tail offset table
  into ascending order.
- `parse_catalog_record` dispatches on record-type discriminator:
  folder (1) / file (2) → `HfsPlusCatalogEntry`; folder-thread (3)
  / file-thread (4) → skip for flat enumeration.
- `decode_utf16be_name` preserves HFS+ NFC without re-normalization
  per forensic-preservation discipline.

Safety: every byte-slice access is `.get(range).ok_or(...)` — zero
`.unwrap()`, zero panic paths on hostile input.

The Session C tripwire `read_catalog_stub_still_returns_placeholder`
is renamed + rewritten as
`read_catalog_returns_empty_when_first_leaf_zero`. The assertion
flip is deliberate: the limitation is removed in this commit, and
the commit message explicitly documents the transition per the
queue's tripwire-convention instruction.

### Sprint 2 — HfsPlusWalker VFS trait impl

New module `crates/strata-fs/src/hfsplus_walker/mod.rs`. Path A
(held handle) per the Session C research — walker holds
`Mutex<HfsPlusFilesystem>`, not the ext4 reopen-per-call pattern.
`HfsPlusFilesystem` is `Send` per Phase 0 probes.

VFS trait impl covers `fs_type / list_dir / read_file / metadata /
exists`. `read_file` currently returns `Unsupported` (pinned by
test) — fork-data extent resolution is Phase B Part 3 work. The
walker filters out HFS+ Private Data sentinel directories by
substring match on `"HFS+ Private"`, which covers both variants
macOS creates (`"\0\0\0\0HFS+ Private Data"` for file hard links
and `".HFS+ Private Directory Data\r"` for directory hard links).

`HfsPlusWalker::open_on_partition(image, offset, size)` matches
the signature the NTFS and ext4 walkers use, so the dispatcher
rewiring lands as a one-line match-arm change.

### Sprint 3 — fixture + two latent bug fixes

`crates/strata-fs/tests/fixtures/hfsplus_small.img` is committed
(2 MiB, HFS+, label `STRATA-HFS`). Population includes
`/readme.txt`, `/forky.txt` (with resource fork via
`/path/..namedfork/rsrc`), and `/docs/nested/buried.txt` three
levels deep.

`mkhfsplus.sh` uses macOS-native `hdiutil` + `newfs_hfs` — no
Linux host required (unlike ext4). HFS+ generation isn't
byte-stable (newfs_hfs doesn't offer deterministic UUID/timestamp
options), so the fixture is committed as a one-time snapshot and
tests validate structural invariants rather than byte hashes.

`tests/ground_truth_hfsplus.rs` — five skip-guarded integration
tests that walk the committed `.img` and verify the expected
structure.

**Latent bugs surfaced by running against a real HFS+ volume for
the first time:**

1. **Catalog fork offset was 288, should be 272** per Apple
   TN1150. Pre-existing code read 16 bytes into the catalog fork
   (picking up the tail of logicalSize mixed with clumpSize).
   Synth tests passed because they wrote the same wrong offsets
   in lockstep with the reader.

2. **B-tree header record field offsets were all wrong:**
   node_size at 8→18, rootNode at 16→2, firstLeafNode at 24→10,
   lastLeafNode at 28→14. Same lockstep-with-synth-tests
   phenomenon.

3. **Private Data filter matched only one of two sentinel
   directories** macOS newfs_hfs creates. Fixed to substring-
   match on `"HFS+ Private"`.

All three fixes are in commit `94a7a89` because they are
collectively what takes ground_truth_hfsplus.rs from FAIL to PASS.

### Sprint 4 — dispatcher HFS+ arm flip

`fs_dispatch::open_filesystem` now routes `FsType::HfsPlus` to
`HfsPlusWalker::open_on_partition`. Session B's negative test
`dispatch_hfsplus_still_unsupported_until_session_c` converted to
positive `dispatch_hfsplus_arm_attempts_live_walker_construction`
— the pattern exactly matches the Session B ext4 conversion. FAT
/ exFAT arms continue returning Unsupported (Session E territory
preserved). APFS still returns the literal `"v0.16"` pickup
signal.

## Quality gates at end of session

- **Test count:** **3,745** (from 3,711 at Session D start; +34 net
  across Sprints 1+2+3+4 with the Sprint 1 Phase B Part 1 test
  count growth dominating).
- `cargo clippy --workspace -- -D warnings`: clean.
- AST quality gate: **PASS** at v14 baseline (470 library unwrap /
  5 unsafe / 5 println — zero new).
- All 9 load-bearing tests preserved.
- Charlie/Jo regression guards: unchanged — NTFS path untouched.
- Session B ext4 dispatcher arm: unchanged — the
  `dispatch_ext4_arm_attempts_live_walker_construction` test
  continues to pass.
- No public API regressions. `HfsPlusWalker` and the new
  `hfsplus_walker/` module are additive.

## What deferred to Session E

Exactly what was out of scope when Session D started — no scope
drift.

### FS-FAT-1 walker + fixture (Session E)

Per the v15 queue, Session E ships the FAT12/16/32 walker.
Pickup signals unchanged from Session C blocker §2 and SPRINTS_v15
Sprint 2:

- Existing `crates/strata-fs/src/fat.rs` (227 LOC) is boot-sector
  + FSInfo parsing only. Real walker is new code: FAT table
  reader (12/16/32-bit entry decode), cluster-chain follower,
  directory-entry parser (11-byte 8.3 + LFN UTF-16 reassembly),
  deleted-entry surfacing, `VirtualFilesystem` trait impl.
  ~500 LOC.
- Fixture generation is macOS-native (same discipline as HFS+):
  `newfs_msdos` + `hdiutil` create FAT32 volumes without Linux
  host. Reference: Session D's `mkhfsplus.sh` pattern.
- exFAT remains deferrable per queue — ship FAT12/16/32 cleanly
  and document exFAT as follow-up if scope balloons.
- Dispatcher flip is ~10 LOC once the walker exists, mirrors
  this session's HFS+ arm flip exactly.

### HFS+ Phase B Part 3 (post-v15)

Fork-data extent resolution + resource-fork exposure as `.rsrc`
alternate stream + timestamps + BSD permissions. Pinned by the
`walker_read_file_is_pinned_as_unsupported_until_phase_b_part_3`
test. Not gating for v0.15.0 — forensic directory enumeration is
the primary walker value and it ships complete for HFS+ in this
session.

### CLAUDE.md key numbers + FIELD_VALIDATION_v15_REPORT.md + v0.15.0 tag

All three are Session E milestone artifacts per queue
instruction. Session D ships the second walker + second dispatcher
arm; the tag requires the third walker (FAT) + full dispatcher
partial (FAT arm flipped, negative tests converted). After Session
E's walker + dispatcher work lands:

1. Update CLAUDE.md key numbers (walker list, test count)
2. Publish `FIELD_VALIDATION_v15_REPORT.md` with per-walker
   numbers + Charlie/Jo guards + AST gate status
3. Tag `v0.15.0` with annotated message covering Sessions A/B/C/D/E
4. Push tag to origin/main

## Notes for the Session E runner

1. **FAT fixture generation on macOS:**
   ```bash
   dd if=/dev/zero of=fat32_small.img bs=1048576 count=1
   DEV=$(hdiutil attach -nomount -nobrowse fat32_small.img | head -1 | awk '{print $1}')
   newfs_msdos -F 32 -v STRATA-FAT "$DEV"
   hdiutil detach "$DEV"
   # re-attach for mount + populate + unmount
   ```
   Session D's `mkhfsplus.sh` is a working reference for the
   hdiutil pattern. FAT is byte-less-variable than HFS+ under
   `newfs_msdos` but still not perfectly deterministic — commit
   one snapshot.

2. **The Session D real-fixture integration test caught two latent
   bugs** in the pre-existing hfsplus.rs parser that synth tests
   had hidden. Expect the same discipline for FAT: write
   ground_truth_fat.rs that walks a real newfs_msdos volume. Do
   not skip the real-fixture test even if unit tests pass —
   Session D proved its value.

3. **The dispatcher FAT arm flip pattern is proven** by Sessions
   B and D. Copy the HFS+ arm conversion from commit `a760cad`:
   flip the arm, convert
   `dispatch_fat32_still_unsupported_until_session_c` →
   `dispatch_fat32_arm_attempts_live_walker_construction` and same
   for exFAT. APFS arm must stay untouched with the literal
   `"v0.16"` assertion.

4. **AST baseline locked at 470 library unwrap / 5 unsafe / 5
   println.** Every session so far has shipped zero new
   violations. Session D added substantial parser code (B-tree
   decoder + walker) without needing a single new `.unwrap()` — use
   `.get(range).ok_or(...)` for slice access, explicit enum match
   for discriminator dispatch, and `String::from_utf16` for the
   encoder error path.

5. **Catalog `read_file` is still Unsupported.** That's Phase B
   Part 3 post-v15. Do not feel pressured to implement data-fork
   extent resolution in Session E — the pinning test keeps it
   honest and forensic directory enumeration is what the
   dispatcher promises today.

## The bottom line

v15 Sessions A+B+C+D shipped:

- ext4 walker + dispatcher arm live (Session B)
- HFS+ walker with real B-tree iteration + dispatcher arm live
  (Session D)
- Two latent HFS+ parser bugs (catalog fork offset, B-tree header
  field offsets) identified and fixed thanks to the Session D
  real-fixture integration test — bugs that had silently survived
  because synth tests mirrored the reader's mistakes

Three of five major filesystem types ship through live walkers:
NTFS (v11), ext4 (Session B), HFS+ (this session). Only FAT
remains for the v0.15.0 commitment. Session E closes.

Strata is a forensic tool.
