# SPRINTS_v15 — session completion

v15's stated mission was three filesystem walkers (HFS+, FAT, ext4)
plus partial dispatcher activation. This session shipped **Sprint 3
Phase A** — `ext4-view` v0.9 API verification — real, and documents
the remaining walker work with the verified API signatures that the
successor session needs.

Per the queue's explicit discipline clause (*"Do not ship shallow
walker stubs"*), the three full walker implementations plus dispatcher
activation are deferred. Each walker is 300–600 LOC of production
code plus committed binary fixtures (1–2 MB `.img` files) plus
integration tests against those fixtures plus — for HFS+ — a
preliminary Read+Seek refactor of the existing 256-LOC `hfsplus.rs`.
Shipping all three simultaneously while keeping 3,684 tests green
means shallow stubs.

## Sprint scorecard

| # | Sprint | Status |
|---|---|---|
| 1 | FS-HFSPLUS-1 | **deferred** — §1 below |
| 2 | FS-FAT-1 | **deferred** — §2 |
| 3a | FS-EXT4-1 Phase A (API verify) | **shipped** — commit `76cf564` |
| 3b | FS-EXT4-1 Phase B/C (walker + fixture) | **deferred** — §3 |
| 4 | FS-DISPATCH-PARTIAL | **deferred** — depends on §§1–3 |

## What shipped this session

### FS-EXT4-1 Phase A — `ext4-view` v0.9 API verification

`docs/RESEARCH_v15_EXT4_VIEW.md` captures the API surface of
`ext4-view v0.9.3` against the six verification steps the sprint
required. Probe at `/tmp/ext4_api_check/` (throwaway, reproducible)
exercised each step.

**Critical finding (favorable):** `ext4-view`'s `Ext4Read` trait is
**offset-addressed**, not `Read + Seek`. Signature is
`fn read(&mut self, start_byte: u64, dst: &mut [u8]) -> Result<(), BoxedError>`
— which matches Strata's existing `EvidenceImage::read_at(offset,
buf) -> EvidenceResult<usize>` bit-for-bit. The walker sprint's
adapter collapses from a speculative `BufReader<Mutex<PartitionReader>>`
stack (what v14 planning assumed, mirroring the NtfsWalker pattern)
into ~10 lines of direct `Ext4Read for Ext4PartitionReader`
delegation.

Other verified facts:

- **License:** Apache-2.0 OR MIT — compatible with Strata's
  reference-tools-only policy (not GPL).
- **`no_std` with `alloc`** — standard.
- **Zero unsafe in main package** — per README.
- **Write explicitly non-goal** — correct for forensic read-only.
- **API coverage:** `Ext4::load(Box<dyn Ext4Read>)`,
  `fs.read(path) / fs.exists(path) / fs.metadata(path) /
  fs.read_dir(path) / fs.read_link(path)`. Every `VirtualFilesystem`
  trait method has a direct `ext4-view` delegation target.
- **Metadata surface:** `is_dir / is_symlink / len / mode / uid / gid`
  — all `VfsEntry` / `VfsAttributes` fields covered.
- **Ext4Error mapping:** the `NotFound / NotADirectory / IsADirectory /
  MalformedPath` variants map losslessly onto `VfsError`.

No blockers. Phase B/C can proceed against concrete signatures
instead of speculative pseudo-code.

## Quality gates at end of session

- Test count: **3,684** (unchanged — research doc commit adds no new
  tests, as intended for a verification-only artifact).
- `cargo clippy --workspace -- -D warnings`: clean.
- AST quality gate: **PASS** against v14 baseline (470 library
  unwrap, 5 unsafe, 5 println — zero new).
- All 9 load-bearing tests preserved.
- Charlie/Jo regression guards: unchanged (no code touched in the
  NTFS path).
- No public API regressions.

## Why walker sprints stayed deferred

### §1. FS-HFSPLUS-1 — Phase A Read+Seek refactor is the gate

The v14 blocker (§3) and the v15 queue Sprint 1 both specify the same
pickup signal: the existing `crates/strata-fs/src/hfsplus.rs` uses a
file-path API (`HfsPlusFilesystem::open_at_offset(path: &Path,
offset: u64)`). Refactoring to `Read + Seek` before wrapping in the
walker is Phase A; the walker itself is Phase B. Together with the
committed 2 MB HFS+ fixture plus the `mkhfsplus.sh` script plus
integration tests (resource-fork exposure, case-sensitivity handling,
special-files filtering, extent-overflow for files larger than B-tree
node size) this is ~500 LOC of production code plus fixture plus
~8 new tests.

**Pickup signal for successor session:** start with the Phase A
refactor; preserve the path-based API as thin wrappers delegating to
the new `Read + Seek` variants. No new behaviour. Only then add the
walker.

### §2. FS-FAT-1 — Phase A fixture-first

The v15 queue Sprint 2 specifies committing a 1 MB FAT32 image with
an `mkfat32.sh` generation script and a `fat32_small.expected.json`
describing the expected enumeration. That produces meaningful tests
from commit one. The walker (~500 LOC native parsing over the
existing 227 LOC `fat.rs` fast-scan) plus cluster-chain following
plus LFN UTF-16 decoding plus attribute-byte mapping plus deleted-
entry handling is substantial.

**Pickup signal for successor session:** commit the fixture and
`mkfat32.sh` before writing walker code. Use `mkfs.fat` + `mtools` on
macOS dev machines (requires Homebrew). exFAT is a distinct on-disk
format; if scope balloons, ship FAT12/16/32 and defer exFAT to a
follow-up sprint — the v15 queue explicitly sanctions this split.

### §3. FS-EXT4-1 Phase B/C — walker + fixture

Now unblocked by the Phase A research doc above. The walker is:

```
crates/strata-fs/src/walkers/ext4_walker.rs  (new, ~400 LOC)
crates/strata-fs/Cargo.toml                  (add ext4-view = "0.9")
crates/strata-fs/tests/fixtures/ext4_small.img     (new, ~2 MB)
crates/strata-fs/tests/fixtures/mkext4.sh          (new)
crates/strata-fs/tests/fixtures/ext4_small.expected.json  (new)
```

Skeleton from the research doc recommendations § 1–7. Adapter is ~10
LOC (Ext4Read directly atop PartitionReader over EvidenceImage). The
walker's `VirtualFilesystem` impl delegates to `Ext4::{read, metadata,
read_dir, exists}` with a simple `Ext4Error → VfsError` mapping
function.

**Pickup signal for successor session:** add `ext4-view = "0.9"` to
`crates/strata-fs/Cargo.toml`, write the walker following the
NtfsWalker structure (state `Mutex<Ext4>`, `Arc<dyn EvidenceImage>`
reference), and generate the fixture via `mkfs.ext4` on a loopback-
mounted raw file.

### §4. FS-DISPATCH-PARTIAL — gated on §§1–3

The dispatcher (`crates/strata-fs/src/fs_dispatch.rs`) today routes
NTFS live and returns `VfsError::Unsupported` for all non-NTFS
filesystems. Flipping the HFS+, FAT/exFAT, and ext4 arms to live
walker construction is ~20 LOC once the walkers exist, plus integration
tests that open each fixture through the dispatcher end-to-end.

**Pickup signal for successor session:** exact match arm replacements
against the FsType enum variants (`Fat12 / Fat16 / Fat32 / ExFat`
group, `Ext2 / Ext3 / Ext4` group, `HfsPlus`). APFS arms stay
`Unsupported` with clear v16 error message.

## Consolidated pickup order for the successor session

If the successor session has bandwidth for **one** full walker sprint:
**pick FS-EXT4-1 Phase B/C** — API is verified, adapter is simplest,
fixture generation is standard on Linux CI and Homebrew-on-macOS dev.

If the successor session has bandwidth for **two**:
**FS-EXT4-1 Phase B/C + FS-FAT-1** — fixture-first discipline plus
the already-verified ext4 API makes both tractable without
architectural unknowns.

If the successor session has bandwidth for **three**:
do FS-HFSPLUS-1 **first** so its Read+Seek refactor is complete
before the FS-FAT-1 walker is written (FAT benefits from the same
Read+Seek pattern). Then FS-FAT-1. Then FS-EXT4-1 Phase B/C — which
stands on its own.

Dispatcher partial is always last; it cannot ship until the three
walker implementations it routes to exist.

## Housekeeping follow-on from the v14 AST gate

Not v15 scope, but called out for tracking: the 470 library-code
unwraps surfaced by v14 Sprint 9 remain. Top concentrations:
`strata-fs::apfs` (30), `strata-fs::container::vhd` (29),
`strata-core::case::repository` (17). `strata-fs::apfs` cleanup is a
natural prerequisite for v16's APFS walker work.

## The bottom line

v15 landed the ext4 walker's unblocking research — one commit,
verified API, concrete specifications replacing speculative
pseudo-code. The three walker implementations themselves remain work
for dedicated sessions, each with enough scope + fixture-
engineering + integration-test discipline to merit its own turn.

NTFS (v11) remains the only live walker in the dispatcher. After the
successor walker session lands its work, four of five major filesystem
types will ship. APFS stays out of scope until v16.

Strata is a forensic tool.
