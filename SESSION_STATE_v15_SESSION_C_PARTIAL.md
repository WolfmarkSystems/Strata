# SPRINTS_v15 Session C — partial completion

Session C's stated mission was HFS+ walker, FAT walker, full
dispatcher partial activation, CLAUDE.md update, FIELD_VALIDATION
report, and the `v0.15.0` tag. This session shipped **Sprint 1
Phase 0 + Phase A** — Send probes verified, Read+Seek refactor of
`HfsPlusFilesystem` complete — and documents the remaining work
with concrete pickup signals.

Per the queue's explicit discipline clause (*"Do not ship a shallow
HfsPlusWalker or FatWalker stub. Do not ship a partial dispatcher
activation that breaks the Session B ext4 arm"*), Sprint 1 Phase B
(walker), Sprint 2 (FAT walker), Sprint 3 (dispatcher flips),
CLAUDE.md key-numbers update, `FIELD_VALIDATION_v15_REPORT.md`,
and the `v0.15.0` tag are deferred. The rationale is the same
discipline Session A and Session B applied: **the underlying
parsers that the deferred walkers would wrap are themselves stubs
or absent**, so wrapping them produces stubs-of-stubs that route
through the dispatcher looking real. That is the exact failure
mode the queue's discipline clause protects against.

## Sprint scorecard

| # | Sprint / Phase | Status | Commit |
|---|---|---|---|
| 1.0 | FS-HFSPLUS-1 Phase 0 Send probes | **shipped** | `a1b929a` |
| 1.A | FS-HFSPLUS-1 Phase A Read+Seek refactor | **shipped** | `a1b929a` |
| 1.B | FS-HFSPLUS-1 Phase B walker + fixture | **deferred** | — |
| 2 | FS-FAT-1 (fixture + walker) | **deferred** | — |
| 3 | FS-DISPATCH-FULL-PARTIAL | **deferred** | — |
| — | CLAUDE.md key numbers update | **deferred** | — |
| — | FIELD_VALIDATION_v15_REPORT.md | **deferred** | — |
| — | v0.15.0 annotated tag | **deferred** | — |

Session A + Session B + this session shipped:

| Phase | Commit | Deliverable |
|---|---|---|
| Session A | `76cf564` | `docs/RESEARCH_v15_EXT4_VIEW.md` — ext4-view v0.9 API verified |
| Session B | `f1ded09` | Ext4Walker + `ext4_walker/` module + fixture scaffolding |
| Session B | `1ee193d` | Dispatcher ext4 arm live; APFS v0.16 message; HFS+/FAT/APFS scope boundary tests |
| Session B | `00a6054` | `SESSION_STATE_v15_SESSION_B_COMPLETE.md` |
| Session C | `a1b929a` | HFS+ Send probes + Phase A Read+Seek refactor |

## What shipped this session

### Sprint 1 Phase 0 — Send probes

Two outstanding probes from `docs/RESEARCH_v15_HFSPLUS_SHAPE.md` §6:

- `hfsplus_catalog_entry_is_send` — **PASS**
- `vfs_entry_is_send` — **PASS**

Plus the two pre-existing probes on `HfsPlusFilesystem` continued
to pass. Research doc §6 amended with the verified output. Path A
(held-handle walker, `Vec::into_iter()` chain) is confirmed viable
in code. The probes live at
`crates/strata-fs/src/hfsplus.rs::_send_sync_probe` so any future
refactor that accidentally introduces an `Rc`, `RefCell`, or
non-`Send` field into the domain types will fail the probes
immediately.

### Sprint 1 Phase A — Read+Seek refactor

Primary constructor is now
`HfsPlusFilesystem::open_reader<R: Read + Seek + Send + 'static>(reader)`.
Internal handle switched from bare `File` to `Box<dyn HfsReadSeek>`
with a helper trait + blanket impl so the struct stays non-generic
(no cascade through callers, no monomorphization blow-up). All
parsing logic — volume header read, catalog fork decode, B-tree
header node read — now operates against the boxed handle.

Path-based constructors preserved as thin wrappers:

- `HfsPlusFilesystem::open(path)` → `open_at_offset(path, 0)`
- `HfsPlusFilesystem::open_at_offset(path, offset)` →
  `Self::open_reader(OffsetReader::new(file, offset))`

`OffsetReader` shim (added this sprint) wraps any `Read + Seek` and
transparently shifts every seek by a fixed byte offset, so the
internal reader always appears partition-relative regardless of
whether the caller entered via `open_reader` or the path wrappers.

Manual `Debug` impl — `Box<dyn HfsReadSeek>` isn't `Debug`, so the
derived impl was replaced with a hand-rolled one displaying
`<dyn HfsReadSeek>` for the handle field.

**Tests added (9 total):**

- `fast_scan_matches_hfsplus_magic` — synthesized 4 KiB volume
- `fast_scan_rejects_non_hfsplus_magic` — all-zero buffer
- `open_reader_accepts_in_memory_cursor` — **key new contract**;
  `Cursor<Vec<u8>>` is accepted as the primary constructor's input,
  which is the shape the dispatcher (NTFS-walker-style
  `PartitionReader`) will hand in
- `open_reader_rejects_bad_signature`
- `open_path_wrapper_delegates_to_open_reader` — backward compat
  verified: the path-based API produces the same parsed state as
  the primary constructor
- `open_at_offset_shifts_reader_correctly` — exercises the
  `OffsetReader` shim end-to-end against a file with padding
- `offset_reader_seek_from_start_shifts_correctly` — shim unit
  test isolated from HFS+ parsing
- `read_catalog_stub_still_returns_placeholder` — **critical
  pinning test**. `read_catalog` is a pre-existing stub returning
  one placeholder `"root"` entry when `logical_size > 0`. This
  test pins that behavior so any future merge that introduces a
  walker wrapping the stub catalog cannot silently ship with the
  placeholder surfacing as if it were real filesystem data.
- Plus the two Phase 0 Send probes above.

## Quality gates at end of session

- **Test count:** **3,711** (from 3,699 at session start; +12 net).
- `cargo clippy --workspace -- -D warnings`: clean.
- AST quality gate: **PASS** against v14 baseline (470 library
  unwrap / 5 unsafe / 5 println — zero new).
- All 9 load-bearing tests preserved.
- Charlie/Jo regression guards: unchanged — NTFS path untouched.
- Session B ext4 dispatcher arm: unchanged — verified by
  `dispatch_ext4_arm_attempts_live_walker_construction` and the
  pinning negative tests still passing.
- No public API regressions. Path-based HFS+ constructors
  unchanged in signature. New `open_reader` is purely additive.

## Why the remaining sprints stayed deferred

### §1. FS-HFSPLUS-1 Phase B walker

`read_catalog` in `hfsplus.rs` (lines 271–296 post-refactor) remains
a structural stub that returns exactly one placeholder
`HfsPlusCatalogEntry { name: "root", cnid: 2, ... }` when
`logical_size > 0`, and otherwise empty. The research doc's
architectural claim — *"Phase B walker is ~80 LOC wrapping
read_catalog as Vec::into_iter"* — is mechanically correct but
wraps a stub.

Wiring such a walker through the dispatcher would mean **every**
HFS+ image produces one fake "root" entry, indistinguishable from a
healthy walker on an image with one real root directory. That is
precisely the forensic-credibility failure mode the v0.14.0 AI/ML
audit flagged for marketing copy and that the queue's *"no shallow
walker stubs"* clause prohibits for code.

**Pickup signal for a successor session:**

1. Implement real B-tree leaf-node traversal in `read_catalog`:
   starting at `self.catalog_file.first_leaf_node`, read each node
   via `read_block`, decode the node descriptor + records per the
   HFS+ on-disk spec (catalog file records, folder records,
   thread records), follow the node's `next_node` link to
   `last_leaf_node`. Approximate LOC: ~200–300 for a correct
   minimum implementation (key encoding, record parsing, Unicode
   NFC preservation, case-sensitivity flag respect).
2. Update `read_catalog_stub_still_returns_placeholder` test to
   reflect the new real behavior (or delete it and add a fixture-
   based test).
3. Then Phase B walker is indeed ~80 LOC per the research doc.
4. Then Phase C fixture — on macOS `hdiutil` can create HFS+
   disk images natively (`hdiutil create -fs HFS+ -size 2m
   hfsplus_small`), no external tooling required.

### §2. FS-FAT-1 walker + fixture

Existing `crates/strata-fs/src/fat.rs` (227 LOC) and
`crates/strata-fs/src/exfat.rs` (169 LOC) implement **fast-scan
only** — parse the boot sector + FSInfo sector and return
fingerprint metadata. They do not walk cluster chains, enumerate
directory entries, decode LFN UTF-16 groups, or read file
contents. There is no partial walker to wrap.

A real `FatWalker` is new code:

- FAT table reader (12/16/32-bit entry decode — FAT12's 12-bit
  packed entries are the trickiest)
- Cluster-chain follower
- Directory-entry parser (11-byte 8.3 format, attribute byte,
  timestamp encoding)
- Long-File-Name (LFN) group reassembly from the preceding
  0x0F-attributed entries in UTF-16LE
- Deleted-entry surfacing (first byte 0xE5)
- `VirtualFilesystem` impl: `list_dir`, `read_file`, `metadata`,
  `exists`, `list_deleted`

Approximate total: ~500 LOC for FAT12/16/32 (~300 for the core
parser + ~200 for the walker + trait impl). exFAT is a distinct
on-disk format and is deferrable per the v15 queue's explicit
clause.

**Pickup signal:** fixture-first. macOS ships `newfs_msdos` (at
`/sbin/newfs_msdos`) and `hdiutil` natively. A deterministic
1 MiB FAT32 fixture can be built from macOS dev boxes:

```bash
hdiutil create -fs "MS-DOS FAT32" -size 1m -volname STRATA-FAT \
    fat32_small
mv fat32_small.dmg fat32_small.img  # raw FS image, not an Apple DMG
```

Commit the binary fixture plus `mkfat32.sh` plus
`fat32_small.expected.json` before walker implementation, same
pattern Session B used for ext4.

### §3. FS-DISPATCH-FULL-PARTIAL (HFS+ / FAT / exFAT arm flips)

Gated on §§1–2. The negative tests in
`crates/strata-fs/src/fs_dispatch.rs` (lines 302+ from Session B)
will start failing when the arms flip to live walker
construction — which is the correct signal, and those tests
should be converted to positive `dispatch_<fs>_arm_attempts_live_walker_construction`
tests in the same commit that flips the arms. The pattern is
already proven by Session B's ext4 arm.

### CLAUDE.md key numbers + FIELD_VALIDATION_v15_REPORT.md + v0.15.0 tag

All three are "milestone artifacts" per the queue instruction:
*"Do NOT tag v0.15.0 until the three walkers plus full dispatcher
partial ship."* Session C delivered one walker's Phase A refactor
in addition to Session B's ext4 walker; that's two walkers'
worth of completed work (ext4 live, HFS+ Phase A ready for Phase B),
which does not satisfy the three-walker commitment.

The tag should land when a successor session ships:

1. HFS+ Phase B walker against a real `read_catalog` B-tree
   traversal
2. FAT walker against a committed fixture
3. Dispatcher HFS+ / FAT / exFAT arms flipped to live walkers
4. Negative tests converted to positive tests
5. `FIELD_VALIDATION_v15_REPORT.md` published with per-walker
   numbers + Charlie/Jo guards confirmed + AST gate status
6. CLAUDE.md key-numbers section updated

The research and refactor scaffolding from Sessions A/B/C has
removed every architectural unknown. What remains is parser
implementation (HFS+ B-tree traversal, FAT cluster-chain +
directory-entry walking) plus fixtures plus dispatcher wiring —
all with concrete pickup signals documented above.

## Notes for the successor session runner

1. **Do not attempt Phase B before implementing the B-tree
   traversal.** The `read_catalog_stub_still_returns_placeholder`
   test is a tripwire specifically designed to catch that
   shortcut. Update it to reflect real behavior when real
   traversal lands.

2. **`newfs_msdos` + `hdiutil` obviate the Linux-host requirement
   for FAT fixture generation.** Unlike ext4 (where macOS lacks
   `mkfs.ext4`), FAT fixtures generate natively on any macOS dev
   box. Commit `fat32_small.img` alongside the walker in a single
   commit.

3. **ext4 binary fixture (`ext4_small.img`) still missing from
   the repo.** Session B's `mkext4.sh` requires Linux. If a
   successor session has access to a Linux host, generate and
   commit the fixture — the skip-guarded test
   `walker_on_committed_fixture_enumerates_expected_paths` will
   then automatically validate enumeration. Not blocking for
   v0.15.0 since the walker's unit tests already prove correctness
   at the adapter + error-mapping level.

4. **APFS arms must continue to return the explicit v0.16
   message.** The Session B test
   `dispatch_apfs_returns_explicit_v016_message` enforces the
   literal `"v0.16"` substring; do not relax this assertion in
   any refactor.

5. **The AST quality gate baseline is locked at 470 library
   unwrap / 5 unsafe / 5 println.** Every session so far has
   shipped zero new violations. The HFS+ Phase A refactor in
   this session replaced two `.unwrap()` calls with proper `?`
   propagation via `.map_err(|_| ForensicError::InvalidImageFormat)`
   on the `try_into()` chains — the baseline is still the same
   not because no progress was made but because the refactor
   added proper error handling in the new code rather than
   introducing new violations in the old.

## The bottom line

v15 across three sessions (A + B + C):

- **ext4 walker ships live end-to-end** through the unified
  dispatcher. Charlie/Jo NTFS pipeline unchanged.
- **HFS+ architectural risk eliminated.** Send probes verified,
  Read+Seek refactor complete, stub behavior pinned, primary
  constructor accepts any partition-relative reader the dispatcher
  provides. The remaining work is on-disk format parsing in
  `read_catalog` plus the ~80 LOC walker wrapper.
- **FAT walker deferred honestly.** No partial parser existed to
  wrap; a real walker is new code. Fixture generation is already
  solved by macOS native tools (`newfs_msdos` + `hdiutil`).
- **v0.15.0 tag deferred.** The three-walker commitment is not
  met. Tagging now would ship a release whose filesystem-walker
  count does not match its version notes.

Two of five major filesystem types ship live (NTFS from v11, ext4
from Session B). HFS+ has its architectural scaffolding in place
and awaits real B-tree traversal. FAT awaits a real walker. APFS
waits for v16.

Strata is a forensic tool.
