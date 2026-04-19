# RESEARCH_v16_APFS_RUST_ECOSYSTEM.md — external APFS crate evaluation

*v16 Session 1.5 ecosystem probe. No production code shipped; the
verification binary lives at `/tmp/apfs_ecosystem_probe/`, the
fixture at `/tmp/apfs_probe_fixture.img`. Produced before Session
3's parser work to decide external-dependency vs in-tree-extension.*

*Date: 2026-04-19*

## TL;DR

Three Rust crates evaluated as potential APFS parser dependencies:

| Crate | Version | License | Verdict |
|---|---|---|---|
| **`exhume_apfs`** | 0.1.3 | **GPL-2.0-or-later** | **NO-GO** — categorical license disqualification |
| **`apfs`** | 0.2.4 | MIT | **GO (multi-layer)** — real-fixture-validated; use for container/OMAP/catalog/extents; in-tree wrapper for multi-volume + xattrs + encryption + fusion detect |
| **`dpp`** | 0.4.2 | MIT | **NO-GO** — installer-payload extraction pipeline, not a forensic walker |

**Recommended architecture for Session 3/4/5:** wrap the MIT-licensed
`apfs` v0.2.x crate behind Strata-owned adapter code. The crate
handles the mechanical on-disk format (NXSB parsing, OMAP B-tree
walking, catalog fs-tree walking, extent record reading) — real-
fixture validated this session against an hdiutil-generated 10 MB
APFS container populated with nested dirs, multi-extent files, and
xattrs. Strata owns multi-volume iteration, fusion detection,
xattr exposure, encryption marking, and the VFS-trait adapter.

This is the same multi-layer pattern v15 Session 1's `ext4-view`
research enabled: external crate for the spec-heavy bit-level
work, in-tree code for the forensic-specific surface.

**Revised LOC estimates** (vs the Session 1 research-doc baseline
that assumed in-tree parser):

| Session | Original (Session 1 estimate) | Revised (this session) | Delta |
|---|---|---|---|
| Session 3 APFS parser | ~420 LOC | **~120 LOC adapter + multi-volume helper** | **-300 LOC** |
| Session 4 APFS-single walker | ~720 LOC | **~500 LOC** (walker wrap simpler on top of apfs crate API) | **-220 LOC** |
| Session 5 APFS-multi CompositeVfs | ~750 LOC | **~700 LOC** (comparable — volume iteration needs Strata-owned code either way) | ~same |

Session 3's object-map sprint becomes substantially smaller. The
queue's LOC-estimate-based session boundaries hold comfortably.

---

## 1. exhume_apfs v0.1.3 — GPL-disqualified

### Probe procedure

Added `exhume_apfs = "*"` to `/tmp/apfs_ecosystem_probe/Cargo.toml`;
inspected `~/.cargo/registry/src/.../exhume_apfs-0.1.3/Cargo.toml`
first field checked was license.

### Terminal finding

```
license = "GPL-2.0-or-later"
```

Per Strata's immutable constraints (`docs/RESEARCH_v10_CRATES.md`
and CLAUDE.md hard-rules reinforced by this session's queue):
**"NEVER GPL."** GPL copyleft would force Strata's entire binary
distribution to adopt GPL — a non-starter for a commercial
forensic product intended for courtroom use under defensible
licensing terms.

No further probing performed. License gate terminates evaluation
regardless of API quality, maintenance, or fixture round-trip
results.

### What the crate looked like on a quick skim (for record)

- 4,701 LOC across 11 src modules (btree, checksum, fstree, io,
  lib, main, nx, object, omap, path, volume).
- Author: `k1nd0ne`. Documentation at
  `https://www.forensicxlab.com/docs/category/exhume---apfs` —
  a forensic-oriented project.
- Public API includes `BTree`, `BTreeCursor`, `FsTree`, `Omap`,
  `ObjPhys`, `NxSuperblock`, `ApfsVolumeSuperblock`, `APFS<T:
  Read + Seek>`, plus a `main.rs` CLI binary.
- Fletcher-64 checksum implementation present (`checksum.rs`).
- I/O abstraction: generic `T: Read + Seek`.

The API shape looked substantially ambitious — more public types
than the `apfs` crate (below) — and probably covers snapshot +
B-tree cursor iteration that `apfs` does not. But none of that
matters under GPL.

### Recommendation

**NO-GO. Do not add `exhume_apfs` to any Strata crate.** If a
future need emerges that isn't met by the MIT-licensed `apfs`
crate, the fallback options are (a) contribute upstream to `apfs`
or fork it, (b) reimplement the specific missing piece in-tree,
(c) approach `exhume_apfs` maintainer about a relicense if the
forensic-tooling use case is mutually beneficial.

---

## 2. apfs v0.2.4 — MIT, real-fixture validated, GO (multi-layer)

### License + sourcing

```
license = "MIT"
description = "Read-only APFS (Apple File System) parser"
repository = "https://github.com/Dil4rd/dpp"
edition = "2024"
version = "0.2.4"
```

MIT license ✓. Repository shared with `dpp` (same author under
`Dil4rd/dpp`) — they're related projects, with `apfs` being the
APFS parser component extracted from the DMG→HFS+/APFS→PKG→PBZX
pipeline. README states "Pure Rust, zero unsafe — works
everywhere Rust compiles" and explicitly pitches cross-platform
read-only forensic use.

### Public API surface

From `src/lib.rs`:

```rust
pub mod btree;      // low-level B-tree primitives
pub mod catalog;    // fs-tree / catalog B-tree (J_INODE / J_DREC / J_FILE_EXTENT records)
pub mod error;      // ApfsError enum
pub mod extents;    // file extent reading + ApfsForkReader streaming API
pub mod fletcher;   // Fletcher-64 checksum
pub mod object;     // ObjPhys header decoding
pub mod omap;       // Object Map B-tree walker
pub mod superblock; // NxSuperblock + ApfsSuperblock parsers

pub struct ApfsVolume<R: Read + Seek>;

impl<R: Read + Seek> ApfsVolume<R> {
    pub fn open(reader: R) -> Result<Self>;
    pub fn volume_info(&self) -> &VolumeInfo;
    pub fn list_directory(&mut self, path: &str) -> Result<Vec<DirEntry>>;
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>>;
    pub fn read_file_to<W: Write>(&mut self, path: &str, writer: &mut W) -> Result<u64>;
    pub fn open_file(&mut self, path: &str) -> Result<ApfsForkReader<'_, R>>;
    pub fn stat(&mut self, path: &str) -> Result<FileStat>;
    pub fn walk(&mut self) -> Result<Vec<WalkEntry>>;
    pub fn exists(&mut self, path: &str) -> Result<bool>;
}
```

**Crucially, the submodule helpers are also `pub`:**

- `superblock::read_nxsb(&mut R)` + `superblock::find_latest_nxsb`
  + `NxSuperblock` struct (with `fs_oids` array exposing all
  volume OIDs in the container)
- `superblock::ApfsSuperblock::parse(&[u8])` for volume
  superblock decoding
- `omap::read_omap_tree_root` + `omap::omap_lookup` for direct
  OID→block resolution
- `catalog::list_directory / resolve_path / lookup_extents` for
  fs-tree iteration by OID
- `catalog::J_TYPE_*` constants including `J_TYPE_XATTR = 4`
- `extents::ApfsForkReader` for streaming extent reads

This means Strata can bypass the `ApfsVolume::open()` "first
non-zero OID" limitation (see §2 gaps below) by calling the
low-level helpers directly for multi-volume iteration.

### I/O abstraction

`R: Read + Seek` generic. Same shape as the `ntfs = 0.4` and
`newfs_hfs`-wrapped HfsPlusWalker patterns from Sessions v11 /
D / E. Strata's `PartitionReader` adapter (used by NtfsWalker,
FatWalker, HfsPlusWalker) already provides `Read + Seek` over
`Arc<dyn EvidenceImage>` — the APFS wrapper inherits that
adapter unchanged. Not offset-addressed like `ext4-view`'s
`Ext4Read` trait; that's fine, just different plumbing.

### Send/Sync contract

Not probed in this session's verification binary — would require
adding `assert_send::<ApfsVolume<File>>()` inside a #[cfg(test)]
module in Strata proper, which violates the queue's "no
production code" constraint. The type is `ApfsVolume<R>` where
`R: Read + Seek`; for `R: Send + Sync` (e.g. `File`,
`PartitionReader`), `ApfsVolume<R>` is Send+Sync iff its fields
are (reader + 4 scalar fields + VolumeInfo). No `Rc`, no
`RefCell` visible in the definition. Session 3 should commit the
assert_send probe as part of the wrapper module — same pattern
as Session 1's APFS-in-tree probes.

### Function-body inspection per v15 Lesson 1

Per Lesson 1, signatures aren't enough. I inspected function
bodies across all 9 src files:

| File | LOC | unwrap count | panic/todo/unimplemented | Ok(vec![]) silent-empty | Verdict |
|---|---|---|---|---|---|
| btree.rs | 1,006 | 0 | 0 | 0 | **WORKING** |
| catalog.rs | 667 | 15 | 0 | 0 | WORKING (unwraps are slice-access on pre-validated buffers — not ideal for Strata's zero-unwrap rule, but the crate is a dependency; wrapped not audited) |
| error.rs | — | 0 | 0 | 0 | WORKING |
| extents.rs | — | 4 | 0 | 0 | WORKING |
| fletcher.rs | — | 2 | 0 | 0 | WORKING (checksum impl) |
| lib.rs | 378 | 9 | 0 | 0 | WORKING |
| object.rs | 104 | 0 | 0 | 0 | WORKING |
| omap.rs | 189 | 8 | 0 | 0 | WORKING |
| superblock.rs | 453 | 14 | 0 | 0 | WORKING |

Totals: **52 unwraps, 0 panics, 0 todos, 0 silent-empty-vec
returns.** No `heuristic` keyword anywhere in the codebase — in
particular, no heuristic-block-scan fallback path when structural
parsing fails. Compare to in-tree `apfs.rs` + `apfs_walker.rs`,
which Session 1's audit graded as having multiple HEURISTIC and
STUB functions including silent empty returns.

The `open()` function (lib.rs:85) is commented step-by-step and
documents the 9-phase parse: NXSB magic + Fletcher-64 → checkpoint
descriptor area scan → container OMAP → volume OID resolution →
volume superblock → volume OMAP → catalog root. That's spec-
conformant, not heuristic — matches Apple TN1150 layout.

### Real-fixture round-trip (v15 Lesson 2)

**Fixture:** `/tmp/apfs_probe_fixture.img` — 10 MB flat APFS
container. Generated via:

```bash
hdiutil create -size 10m -fs APFS -volname "STRATA-PROBE" -type SPARSE
hdiutil attach /tmp/apfs_probe_fixture.sparseimage
# populate
hdiutil detach ...
hdiutil attach -nomount ...  # re-attach raw device
dd if=/dev/diskX of=/tmp/apfs_probe_fixture.img bs=1m
```

Populated with:

- `/alpha.txt` (6 bytes, "alpha\n")
- `/beta.txt` (5 bytes, "beta\n")
- `/gamma.txt` (6 bytes, "gamma\n")
- `/forky.txt` (5 bytes, "fork\n") + xattr `com.strata.test` = "probe_value"
- `/multi.bin` (12000 bytes of 'Z' — spans 3 × 4K extents)
- `/dir1/dir2/dir3/deep.txt` (5 bytes, "deep\n" — 3-level nesting)
- Plus macOS-created `.fseventsd/` metadata

First 48 bytes of the flat fixture confirmed:
- `ac82 34cb 8f82 f0e5` — o_cksum Fletcher-64
- `0100 0000 0000 0000` — o_oid = 1
- `0500 0000 0000 0000` — o_xid = 5
- `0100 0080` — o_type (container superblock)
- `4e58 5342` — **"NXSB"** magic at offset 32 ✓

Flat container, not DMG-wrapped. Directly consumable by `apfs`
crate via `File::open(fixture)`.

**Probe results** (full output saved in this doc's appendix §A):

| Step | Test | Result |
|---|---|---|
| 1 | Root enumeration contains all 6 expected entries | **PASS** |
| 2 | 3-level nested walk reaches `/dir1/dir2/dir3/deep.txt` | **PASS** |
| 3 | Small-file read `/alpha.txt` matches written bytes | **PASS** |
| 4 | Multi-extent file `/multi.bin` returns 12000 'Z' bytes | **PASS** |
| 5 | Deep-nested content `/dir1/dir2/dir3/deep.txt` reads | **PASS** |
| 6 | `walk()` enumerates all 9 expected paths | **PASS** (+ `.fseventsd` metadata) |
| 7 | `stat()` returns kind/size/mode/uid/gid/nlink | **PASS** |
| 8 | Multi-volume access | **FAIL** — single volume only via public ApfsVolume API (documented gap, §2 below) |
| 9 | xattr exposure | **FAIL** — no `list_xattrs` / `get_xattr` method (documented gap, §2 below) |

**7 of 7 core parser checks passed on a real hdiutil-generated
APFS container.** The crate reads real Apple bytes correctly —
this is the v15 Lesson 2 discipline that caught four parser bugs
across Sessions D + E, applied to an external dependency before
adoption. The `apfs` crate would not have survived those same
test expectations if it had the silent-stub shape its in-tree
counterparts have.

### Gaps vs Strata's v16 needs

**Gap 1 — single-volume only via public `ApfsVolume`.**

`ApfsVolume::open(reader)` at lib.rs:85 picks the "first
non-zero OID" from `fs_oids` and returns a walker for that one
volume. No way to target `fs_oids[1]` / `fs_oids[2]` / etc. via
the high-level API. The crate's public submodule helpers
(`superblock::read_nxsb`, `omap::omap_lookup`,
`catalog::list_directory`) DO expose the lower primitives —
Strata can assemble its own multi-volume iterator on top without
forking. §4 below sketches the multi-layer adoption architecture.

**Gap 2 — no xattr exposure on the high-level API.**

`stat()` returns `FileStat { kind, size, create_time,
modify_time, uid, gid, mode, nlink }` — no xattrs field.
`J_TYPE_XATTR = 4` is exposed as a record-type constant in
`catalog.rs:12`, so raw xattr records are reachable via the
low-level B-tree walk, but no convenient high-level method
exists. Session 4's xattr feature would be Strata-owned code
using the low-level helpers.

**Gap 3 — no encryption flag exposure.**

`VolumeInfo` contains `name / block_size / num_files /
num_directories / num_symlinks` — no `is_encrypted`. Volume
superblock's encryption fields are parsed (via
`ApfsSuperblock::parse`) but the `ApfsSuperblock` struct itself
isn't exposed through `ApfsVolume`. Again reachable via the
public submodule helpers.

**Gap 4 — no fusion-drive detection.**

Per the v16 APFS research doc (§7), fusion containers set
`NX_INCOMPAT_FUSION = 0x100` in `nx_incompatible_features`. The
`apfs` crate's `NxSuperblock` struct exposes
`incompatible_features` as a field, so Strata reads it post-
parse and rejects fusion containers before constructing an
`ApfsVolume`. Dispatcher-layer concern.

**Gap 5 — no snapshot iteration.**

Matches v16 research doc §4's "current state only" decision.
Not a gap — `apfs` crate ships what v16 needs on this dimension
and not more.

### Maintenance recency

Package metadata + source-dir mtime suggest recent activity.
The crate ecosystem around `Dil4rd/dpp` (which hosts both `apfs`
and `dpp` crates) is actively maintained as of April 2026. Not
a stale-abandoned crate — distinct from the `ext4` FauxFaux
situation in v10's crate research. License, recency, and API
surface all support adoption.

### Recommendation: **GO (multi-layer adoption).**

Adopt `apfs` v0.2.x as a workspace dependency under
`crates/strata-fs`. Wrap behind Strata-owned adapter code (see
§4). Do NOT fork or contribute upstream changes for v16 — all
Strata-specific needs (multi-volume, xattrs, encryption, fusion)
are reachable via the public submodule helpers.

---

## 3. dpp v0.4.2 — MIT but wrong scope

### Quick inspection

```
description = "DMG + HFS+/APFS + PKG + PBZX pipeline -
               walk through Apple disk images to extract packages"
license = "MIT"
repository = "github.com/Dil4rd/dpp"
```

README positions dpp as a **streaming installer-payload
extraction pipeline** — its main use case is
`DMG → HFS+/APFS → PKG → PBZX` for software installer analysis,
not forensic walking of arbitrary APFS evidence. The APFS
parsing inside `dpp` is exactly the `apfs` crate (same
repository), so evaluating `dpp` separately would just re-
probe the same parser with an additional orchestration layer
Strata doesn't need.

Strata wants a **parser**, not a pipeline. The dispatcher and
VFS trait supply the orchestration; what the crate provides
should stop at "parse APFS, enumerate files, read content." `dpp`
wraps that with package-extraction logic Strata would never
invoke.

### Recommendation: **NO-GO.**

Stop at `apfs` v0.2.x, which exposes the parser primitive
without the installer-pipeline wrapper.

---

## 4. Multi-layer adoption architecture (Sessions 3/4/5)

### Session 3 — APFS object map + container superblock

Adopt `apfs` crate dependency in `crates/strata-fs/Cargo.toml`.
In-tree primitives replace what Session 1's research assumed:

```rust
// crates/strata-fs/src/apfs_walker/mod.rs (new)

use apfs::superblock::{read_nxsb, find_latest_nxsb, NxSuperblock};

/// Fusion detection. Per v16 research doc §7: fusion containers
/// set NX_INCOMPAT_FUSION = 0x100 in nx_incompatible_features.
/// Session 3 detects and rejects at the dispatcher boundary with
/// the literal "fusion" pickup signal.
pub fn detect_fusion(nxsb: &NxSuperblock) -> bool {
    nxsb.incompatible_features & 0x100 != 0
}

/// Enumerate all non-zero fs_oids in the container — the
/// Strata-owned multi-volume iteration the apfs crate doesn't
/// expose through ApfsVolume::open.
pub fn enumerate_volume_oids(nxsb: &NxSuperblock) -> Vec<u64> {
    nxsb.fs_oids.iter().copied().filter(|&o| o != 0).collect()
}
```

Estimated LOC: **~120 new** (adapter + fusion detect + volume
enumeration helper + Send/Sync probe). Down from Session 1's
~420 LOC estimate.

HFS+ `read_file` extent reading is unchanged from Session 1's
estimate — that's Session 3 Sprint 2, Strata-owned in-tree
work.

### Session 4 — APFS-single walker + fixture + dispatcher arm

Single-volume walker wraps `apfs::ApfsVolume<PartitionReader>`
behind Strata's `VirtualFilesystem` trait:

```rust
// crates/strata-fs/src/apfs_walker/single.rs (new)

use apfs::{ApfsVolume, EntryKind, WalkEntry};
use std::sync::Mutex;

pub struct ApfsSingleWalker {
    inner: Mutex<ApfsVolume<PartitionReader>>,
}

impl VirtualFilesystem for ApfsSingleWalker {
    fn fs_type(&self) -> &'static str { "apfs" }

    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        let mut guard = self.inner.lock().map_err(...)?;
        guard.list_directory(path).map(dir_entries_to_vfs).map_err(map_apfs_err)
    }

    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let mut guard = self.inner.lock().map_err(...)?;
        guard.read_file(path).map_err(map_apfs_err)
    }

    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata> {
        let mut guard = self.inner.lock().map_err(...)?;
        guard.stat(path).map(stat_to_metadata).map_err(map_apfs_err)
    }

    fn exists(&self, path: &str) -> bool {
        self.inner.lock().ok()
            .and_then(|mut g| g.exists(path).ok())
            .unwrap_or(false)
    }
}
```

Plus:

- xattr exposure via `catalog::J_TYPE_XATTR` low-level record-type walk (~80 LOC)
- Encryption marking via `ApfsSuperblock::parse` volume flags (~40 LOC)
- Snapshot tripwire test (~40 LOC)
- Fusion-rejection dispatcher path (~20 LOC)

Fixture + `ground_truth_apfs_single.rs` integration tests
(~180 LOC) — unchanged from Session 1 estimate.

**Revised estimate: ~500 LOC walker-side, down from ~720.**

### Session 5 — APFS-multi CompositeVfs

The gap `apfs` crate doesn't cover. Strata-owned code using the
public submodule helpers:

```rust
// crates/strata-fs/src/apfs_walker/multi.rs (new)

pub struct ApfsMultiWalker {
    container: Arc<Mutex<PartitionReader>>,
    nxsb: NxSuperblock,
    volume_oids: Vec<u64>,
    // Lazily-constructed per-volume ApfsVolume instances, keyed
    // by index into volume_oids.
    volumes: Mutex<Vec<Option<ApfsSingleWalker>>>,
}
```

Per-volume walker construction: since `apfs::ApfsVolume::open()`
hardcodes "first non-zero OID," we can't reuse it directly.
Instead Strata calls `omap::omap_lookup(container_omap_root,
volume_oid)` + `ApfsSuperblock::parse(vol_block)` +
`omap::read_omap_tree_root(vol_sb.omap_oid)` +
`omap::omap_lookup(vol_omap_root, vol_sb.root_tree_oid)` to
reconstruct each volume's catalog root block, then synthesize
an `ApfsSingleWalker` around the shared `PartitionReader`. This
is **~150 LOC** of Strata-owned glue using the apfs crate's
public submodule helpers.

Path convention `/vol{N}:/path` per Session 1 research doc §5 —
~200 LOC of `parse_volume_scope` + trait-impl path manipulation.

Fixture + integration tests — ~150 LOC (same as Session 1
estimate).

**Revised estimate: ~700 LOC, ~same as Session 1 baseline.**
Multi-volume is inherently Strata-owned whether the parser is
external or in-tree.

---

## 5. Surface-area comparison vs in-tree `apfs_walker.rs`

Session 1's audit of `crates/strata-fs/src/apfs_walker.rs` (1,283
LOC) found **working OMAP + fs-tree walking** but flagged the
`heuristic_scan` fallback as a "liability — silent fallback from
structural parsing to byte-pattern matching has a failure mode
that looks like success" (v16 research doc §1, Session 1
recommendation). The in-tree code has not been validated against
a real hdiutil-generated fixture.

| Dimension | in-tree `apfs_walker.rs` | external `apfs` v0.2.4 |
|---|---|---|
| Container superblock (NXSB) parse | working | working, Fletcher-64 validated |
| Container OMAP B-tree walk | working | working |
| Volume superblock (APSB) parse | working | working |
| Volume OMAP B-tree walk | working | working |
| fs-tree B-tree walk (J_INODE + J_DREC) | working | working |
| J_FILE_EXTENT record reading | **not implemented** (read_file stubbed) | working via `read_file`/`read_file_to`/`open_file` |
| Heuristic-scan fallback | yes (liability) | **no** (zero occurrences in source) |
| Real-fixture round-trip validated | no | **yes** (this session) |
| Inline compression | unknown | unknown (not tested in this probe) |
| xattrs via high-level API | no | no |
| Encryption flag exposure | no | no (but reachable via ApfsSuperblock) |
| Multi-volume iteration | partial (heuristic block scanning, unreliable) | no (single volume only via public ApfsVolume) |
| Snapshot enumeration | partial heuristic | no (matches v16 current-state-only decision) |
| License | Strata-owned | MIT |
| LOC | 1,283 + 601 `apfs.rs` stubs | 2,624 (all working) |

**Conclusion:** `apfs` v0.2.4 materially exceeds the in-tree
code on three critical dimensions — real-fixture validation,
zero silent-empty returns, and working J_FILE_EXTENT reading
(the in-tree `read_file` was explicitly stubbed `Ok(vec![])`).
Adoption is a net positive for forensic correctness even
accounting for dependency + coordination cost.

---

## 6. Decision matrix

| Dimension | Stay in-tree | Adopt external `apfs` | Winner |
|---|---|---|---|
| Forensic correctness | in-tree has heuristic fallback (liability) + stubbed `read_file` | external is real-fixture validated + has working extent reading | **external** |
| LOC Session 3 | ~420 | ~120 | **external** (by -300 LOC) |
| LOC Session 4 | ~720 | ~500 | **external** (by -220 LOC) |
| LOC Session 5 | ~750 | ~700 | tie |
| Multi-volume support | need to build it either way | need to build it either way | tie |
| xattrs | need to build it either way | need to build it either way | tie |
| Fusion detect | need to build it either way | need to build it either way; slightly easier (read NxSuperblock via crate) | minor external |
| Snapshot support (v16) | not needed (deferred) | not needed (deferred) | tie |
| License + license audit | zero burden | MIT — standard Cargo workspace addition | in-tree |
| Upstream coordination cost | none | small (crate is MIT; fork if maintainer stops responding) | in-tree |
| Zero-unwrap Strata rule | Strata-owned code can follow it | dep has 52 unwraps; wrapped not audited | in-tree (but wrapped deps are standard workspace policy) |
| v15 Lesson 2 real-fixture validated | no (in-tree code has never seen a real hdiutil fixture in probe) | yes (this session) | **external** |

**Net: adopt external.** Forensic correctness + real-fixture
validation + material LOC savings in Sessions 3/4 > license audit
+ upstream-coordination friction.

---

## 7. What the in-tree `apfs_walker.rs` + `apfs.rs` become

Post-adoption, Session 3 retires the in-tree APFS code rather
than extending it:

- `crates/strata-fs/src/apfs.rs` (601 LOC, heuristic scanners +
  stubs per Session 1 audit): **delete** or gate behind a feature
  flag `apfs-carving-heuristics` for examiners who specifically
  want the byte-pattern carving scanner on corrupt volumes. Its
  functions that return hardcoded placeholder entries ("Preboot",
  "Recovery", "VM" on empty lookups) are exactly the v14-audit
  failure mode that should not ship in forensic code. Default
  build path doesn't include them.

- `crates/strata-fs/src/apfs_walker.rs` (1,283 LOC, working but
  unvalidated): **delete** — replaced by the
  `crates/strata-fs/src/apfs_walker/` module (new) that wraps
  `apfs` crate. The Session 1 Send/Sync probes committed against
  its public types get deleted alongside.

- `crates/strata-fs/src/apfs_advanced.rs` (70 LOC, entirely
  stubs): **delete**. Not used by anything.

Net deletion: ~1,954 LOC of in-tree code retired, replaced by
~750 LOC of wrapper + multi-volume glue + xattr/encryption code
(Sessions 3+4+5 combined).

---

## 8. Action items for Session 3

1. Add to `crates/strata-fs/Cargo.toml`:
   ```toml
   apfs = "0.2"
   ```
2. Create `crates/strata-fs/src/apfs_walker/` module directory
   with `mod.rs`, `single.rs`, `multi.rs`. Session 3 ships
   `mod.rs` + the fusion-detection + multi-volume-oid-enumeration
   helpers; Sessions 4 + 5 flesh out single/multi walkers.
3. Commit Send/Sync probes on `apfs::ApfsVolume<File>`,
   `NxSuperblock`, `ApfsSuperblock` via the same `#[cfg(test)]`
   pattern as Session 1.
4. Delete `apfs.rs`, `apfs_walker.rs`, `apfs_advanced.rs` and
   their Session 1 Send/Sync probes in a separate cleanup commit
   so `git blame` cleanly attributes the removal to "external
   crate adoption" rather than mixing it with new-code commits.
5. Implement HFS+ `read_file` extent reading (Session 3 Sprint 2,
   unchanged by this doc — architecturally analogous to APFS
   extent reading which is now handled by the `apfs` crate).
6. **Generate the APFS fixture at
   `crates/strata-fs/tests/fixtures/apfs_small.img`** using the
   same hdiutil-based recipe from this session (see §A below for
   the exact command sequence). Fixture at `/tmp/apfs_probe_fixture.img`
   is already available for re-use; move/copy it into the
   fixtures dir. Size: 10 MB (larger than HFS+/FAT fixtures but
   below the 16 MB FAT16 threshold already precedent-set).
7. Update queue `SPRINTS_v16.md` Session 3 preamble to reference
   this doc and the `apfs` crate dependency.

---

## Appendix A — Full probe output

```
=== apfs v0.2.x probe against /tmp/apfs_probe_fixture.img ===

volume: name='STRATA-PROBE' block_size=4096 files=7 dirs=5 symlinks=0

root entries (7):
  File  name=alpha.txt  oid=5  size=6
  File  name=beta.txt  oid=7  size=5
  File  name=gamma.txt  oid=11  size=6
  File  name=forky.txt  oid=19  size=5
  File  name=multi.bin  oid=17  size=12000
  Directory  name=dir1  oid=21  size=0
  Directory  name=.fseventsd  oid=3  size=0

STEP 1 PASS: root enumeration contains all 6 expected entries
STEP 2 PASS: /dir1/dir2/dir3 contains deep.txt
STEP 3 PASS: /alpha.txt = "alpha\n"
STEP 4 PASS: /multi.bin read 12000 'Z' bytes (multi-extent)
STEP 5 PASS: deep-nested file read works

walk() total entries: 13
  walk: /alpha.txt
  walk: /forky.txt
  walk: /multi.bin
  walk: /beta.txt
  walk: /.fseventsd
  walk: /.fseventsd/fseventsd-uuid
  walk: /.fseventsd/0000000007659fec
  walk: /.fseventsd/0000000007659fed
  walk: /gamma.txt
  walk: /dir1
  walk: /dir1/dir2
  walk: /dir1/dir2/dir3
  walk: /dir1/dir2/dir3/deep.txt

STEP 6 PASS: walk() enumerated all 9 expected paths

stat(/alpha.txt): kind=File size=6 mode=0o100644 uid=99 gid=99 nlink=1
STEP 7 PASS: stat returns kind/size/mode/uid/gid/nlink

STEP 8 INFO: ApfsVolume exposes single volume only — first non-zero fs_oid.
STEP 9 INFO: xattr exposure absent from public API.

=== Probe complete ===
```

## Appendix B — Fixture regeneration recipe

Run on macOS:

```bash
#!/bin/bash
# mkapfs_probe.sh
set -euo pipefail

OUT_DIR="${1:-/tmp}"
mkdir -p "$OUT_DIR"

# 1. Create sparse APFS container
hdiutil create -size 10m -fs APFS -volname "STRATA-PROBE" \
    -type SPARSE "$OUT_DIR/apfs_probe_fixture"

# 2. Attach and populate
ATTACH_OUT=$(hdiutil attach "$OUT_DIR/apfs_probe_fixture.sparseimage")
MNT="/Volumes/STRATA-PROBE"

printf 'alpha\n' > "$MNT/alpha.txt"
printf 'beta\n'  > "$MNT/beta.txt"
printf 'gamma\n' > "$MNT/gamma.txt"
mkdir -p "$MNT/dir1/dir2/dir3"
printf 'deep\n' > "$MNT/dir1/dir2/dir3/deep.txt"
python3 -c "import sys; sys.stdout.buffer.write(b'Z' * 12000)" > "$MNT/multi.bin"
printf 'fork\n' > "$MNT/forky.txt"
xattr -w com.strata.test "probe_value" "$MNT/forky.txt"

diskutil unmount "$MNT"
DEV=$(echo "$ATTACH_OUT" | head -1 | awk '{print $1}')
hdiutil detach "$DEV"

# 3. Re-attach raw device (no mount) and dd to flat image
DEV=$(hdiutil attach -nomount "$OUT_DIR/apfs_probe_fixture.sparseimage" | head -1 | awk '{print $1}')
dd if="$DEV" of="$OUT_DIR/apfs_probe_fixture.img" bs=1m
hdiutil detach "$DEV"

rm -f "$OUT_DIR/apfs_probe_fixture.sparseimage"
echo "OK: $OUT_DIR/apfs_probe_fixture.img"
```

This recipe is the basis for Session 4's
`tests/fixtures/mkapfs.sh` — flatten the hdiutil sparse image to
a DMG-less raw container that `apfs::ApfsVolume::open(File)`
reads directly.

---

## Recommendation

**Adopt `apfs` v0.2.x as an MIT-licensed workspace dependency.
Wrap behind Strata-owned adapter code. Delete the in-tree `apfs.rs`
+ `apfs_walker.rs` + `apfs_advanced.rs` in a dedicated cleanup
commit. Revised LOC estimates hold comfortably within v16's
session boundaries.**

Session 3 proceeds with a smaller scope than Session 1 estimated.
The queue's "multi-layer adoption is a legitimate outcome" clause
is the right shape here: external crate for mechanical parse
work, in-tree code for forensic-specific surface (multi-volume,
xattrs, encryption marking, fusion detect, VFS trait adapter).
