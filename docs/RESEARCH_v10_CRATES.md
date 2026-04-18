# RESEARCH_v10_CRATES.md — filesystem-walker crate selection rationale

*Recreated in v13 after the v12 diagnostic found this document was
referenced throughout v10/v11/v12 session state but not committed to
the repo. Content reconstructed from the session-state trail and
verified against current crate availability.*

*Last updated: 2026-04-18 (v13, REGRESS-FULL-V13 housekeeping H2).*

---

## Context

Strata mounts forensic evidence images (E01/AFF4/VMDK/VHD/…) and
exposes each mounted filesystem through the `VirtualFilesystem` trait
in `strata-fs::vfs`. Each real filesystem family (NTFS, ext*, APFS,
HFS+, FAT/exFAT) needs a walker that takes a `Read + Seek` stream
(provided by `PartitionReader`) and implements `VirtualFilesystem`.

v10 opened the question: for each family, do we use an existing
crate, adapt an in-tree module, or write native code? The answer
shapes every subsequent walker sprint (FS-NTFS-1, FS-EXT4-1,
FS-APFS-1, FS-HFSPLUS-1, FS-FAT-1).

## Immutable constraints

These are hard requirements from CLAUDE.md and the forensic stance:

1. **Pure Rust, no FFI.** Dependencies like libewf / libtsk / libfsapfs
   are disqualified. FFI adds build complexity, licensing questions,
   and undefined-behavior vectors that CLAUDE.md's `zero unsafe{}`
   rule intentionally blocks.
2. **Read-only.** Forensic tools must never write to evidence. Crates
   that require `ReadWriteSeek` or expose write APIs are
   category-disqualified even if the writes would never fire.
3. **No-std-friendly preferred.** Reduces dependency trees and
   ensures we can embed walkers in no-std host contexts if needed.
4. **Zero `.unwrap()`, zero `unsafe{}`, zero `println!`** in library
   code (CLAUDE.md § Hard Rules).
5. **Workspace dependency inheritance** — anything added must either
   already be in workspace-root `Cargo.toml` or carry a clear
   justification per CLAUDE.md "every new Cargo.toml entry must
   justify itself."

## Per-family decisions

### NTFS — **crate: `ntfs = "0.4"`** (Colin Finck)

- MIT / Apache-2.0 dual-licensed. Pure Rust. Read-only by design.
  no_std-compatible.
- Takes any `Read + Seek`. Clean fit for `PartitionReader` wrapped in
  `Mutex<BufReader<...>>` so `&self` trait methods can mutate the
  reader during attribute walks.
- Matured against real Windows disks; handles resident/non-resident
  $DATA, $INDEX_ALLOCATION, alternate data streams, compression
  attributes, and DOS-8.3-only skip logic.
- **Shipped in v10/FS-NTFS-1.**
  `crates/strata-fs/src/ntfs_walker/mod.rs` is the reference pattern
  for every other walker.

Rejected alternatives:
- **`ntfs-fs` / `fuser-ntfs`** — write-capable, FUSE-oriented.
  Violates constraint 2.
- **In-tree port of libfsntfs** — orders of magnitude more code than
  `ntfs = "0.4"` with no material capability gain for our use-case.

### ext2/3/4 — **crate: `ext4-view = "0.9"`** (Google)

- Apache-2.0. Pure Rust. Read-only by construction (no write API
  exists). Covers ext2, ext3, and ext4 — feature-flag detection is
  internal.
- Custom `Ext4Read` trait for the backing storage rather than `io::Read
  + Seek`, so the walker provides an adapter that translates into
  `PartitionReader` seek+read.
- Supports extents, inline data, symbolic links, extended attributes,
  directories (including hash-tree `htree` indexed), sparse files.
- **Planned for v12/v13 FS-EXT4-1.**

Rejected alternatives:
- **`ext4` by FauxFaux** (last published 2019) — stale, incomplete
  extent support, gaps on modern mkfs defaults.
- **`rustix-fsext` / `ext4fs`** — either FUSE-oriented or write-
  capable.
- **In-tree port of e2fsprogs** — enormous code volume; ext4-view
  already covers the forensic read path.

There is an in-tree `crates/strata-fs/src/ext4.rs` + `ext4_advanced.rs`
from earlier exploration (559+ LOC). These contain partial work and
may be retained for signature/fast-scan paths but the VFS walker
delegates to `ext4-view`.

### APFS — **in-tree module** (`crates/strata-fs/src/apfs_walker.rs`)

- No production-grade pure-Rust APFS crate exists as of 2026-04.
  `apfs-rs` experimental, `apfs-parser` abandoned. The dense binary
  format (NXSB container + APSB volumes + OMAP B-tree +
  snapshot/extent trees + Fletcher-64 checksums) is substantial but
  tractable.
- Strata has an in-tree implementation at `apfs.rs` (601 LOC) and
  `apfs_walker.rs` (1,283 LOC) built over previous versions with
  `ApfsWalker<R: Read + Seek>` and `enumerate_with_paths` already
  exposed. Promote this to a full `VirtualFilesystem` impl rather
  than start over.
- **Multi-volume decision:** *Design A — one VFS per volume composed
  via `CompositeVfs`.* APFS containers hold System / Data / VM /
  Preboot / Recovery; on Big Sur+ System and Data are firmlinked into
  a unified root. Design A (separate VFS per volume) is strictly
  correct (iOS has no firmlinks) and forensically transparent — the
  examiner sees which volume each artifact came from. A firmlink-
  fused root can be layered on top in a future version without
  breaking changes.

Rejected alternatives:
- **`libfsapfs` via FFI (libyal)** — constraint 1 (no FFI).
- **Wrap `fsapfsinfo` binary** — same, plus process-spawn overhead
  per query.

### HFS+ — **in-tree module** (`crates/strata-fs/src/hfsplus.rs`)

- Relevant for pre-2017 Macs and Time Machine backups (which still
  use HFS+ on modern Macs). No mature pure-Rust HFS+ crate exists.
- Strata has an in-tree parser (256 LOC) exposing
  `HfsPlusFilesystem::open_at_offset(path, offset)`. It currently
  takes a `&Path` rather than a `Read + Seek`, so the v13 walker
  sprint refactors it to accept a `PartitionReader`.
- Handles the catalog B-tree, extents overflow B-tree, and attributes
  B-tree. Resource forks surface as the `"rsrc"` alternate stream
  (mapped by the walker in the VFS trait impl).
- Journal reading is optional — v13 exposes a stub, implements later
  if a real case needs journal evidence.

### FAT12/16/32/exFAT — **native read-only parser**

- **`fatfs` crate is disqualified** — requires `ReadWriteSeek` for
  initialization (its `FileSystem::new` signature) which directly
  violates constraint 2, even though we never call write methods.
- No other maintained pure-Rust FAT crate accepts a read-only stream.
- FAT is simple enough (boot sector + FAT table + cluster chains +
  8.3 + LFN + exFAT entry groups) that a native read-only walker is
  ~500 LOC — roughly the same volume as a wrapper around a hostile-
  API crate would be.
- Strata has in-tree fast-scan modules at `fat.rs` (227 LOC) and
  `exfat.rs` (169 LOC). These cover boot-sector parsing and
  fingerprinting but don't expose cluster-chain walking / directory
  iteration. The v13 walker sprint extends them into a full
  `VirtualFilesystem` impl.

FAT's unique forensic value: deleted file directory entries remain
intact (marked 0xE5) and the FAT-table cluster chain is often still
intact until overwritten. The walker's `list_deleted` /
`read_deleted` methods are particularly important here.

### exFAT (separately)

Covered by the same FAT walker with `FatVariant::ExFat`. Shares boot-
sector parsing code with FAT32 but uses a distinct entry-group format
(File / StreamExt / FileName set) and allocation bitmap instead of
FAT tables.

## Summary table

| Family | Source | Status (end of v12) | v13 sprint |
|---|---|---|---|
| NTFS | `ntfs = "0.4"` crate | shipped, live in dispatcher | n/a |
| ext2/3/4 | `ext4-view = "0.9"` crate | not wrapped | FS-EXT4-1 |
| APFS | in-tree (`apfs_walker.rs`) | walker struct exists, no VFS impl | FS-APFS-1 |
| HFS+ | in-tree (`hfsplus.rs`) | parser-only, path-based API | FS-HFSPLUS-1 |
| FAT/exFAT | in-tree (`fat.rs` + `exfat.rs`) | fast-scan only, no walker | FS-FAT-1 |

## Discipline note

The v12 universal `vfs_materialize` bridge means plugins produce real
artifacts through the pipeline *today* for NTFS evidence, even though
the other four walkers haven't landed. The scratch-directory approach
is a correctness-first stopgap; the walkers above remove the scratch-
copy I/O cost for the affected image types. Until the walkers ship,
non-NTFS images dispatch to `VfsError::Unsupported` and the examiner
sees an honest "filesystem not yet supported" error rather than a
silent 0-artifact result.

Per CLAUDE.md: *"Do not silently compromise the spec."* Every walker
above ships with integration tests against a real image in Test
Material or a committed binary fixture before its dispatcher arm
flips.
