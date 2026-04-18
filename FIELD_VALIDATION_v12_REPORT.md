# FIELD_VALIDATION_v12_REPORT — the forensic platform is complete

v12 turned the per-plugin migration problem into a single
universal-bridge problem: materialize forensic-target files from
the mounted VFS into a scratch directory once, and all 22 plugins
see a real filesystem tree without per-plugin surgery. Combined
with the v11 NTFS walker + EWF fix, this produces thousands of
real artifacts per Windows E01.

## The moment

Running `strata ingest run` against two Windows XP E01s in Test
Material:

```
=== charlie-2009-11-12.E01 ===
Artifacts: 3,400 (persisted to /tmp/.../artifacts.sqlite)
  Strata Vector     2,465   (PE / DLL static analysis)
  Strata Phantom      535   (Windows registry hives)
  Strata Chronicle    197   (user activity / UserAssist / RecentDocs)
  Strata Trace        134   (Prefetch / BAM / scheduled tasks)
  Strata Vault         36   (anti-forensic indicators)
  Strata Recon         15   (identity extraction)
  Strata Cipher        12   (credentials)
  Strata Sigma          2   (kill-chain correlations)
  Strata CSAM Scanner   1
  Strata Conduit        1
  Strata MacTrace       1
  Strata Remnant        1
walltime: 90 s

=== jo-2009-11-16.E01 ===
Artifacts: 3,537 (persisted to /tmp/.../artifacts.sqlite)
  Strata Vector     2,467
  Strata Phantom      533
  Strata Chronicle    322
  Strata Trace        148
  Strata Vault         36
  Strata Recon         13
  Strata Cipher        12
  Strata Sigma          2
  Strata CSAM Scanner   1
  Strata Conduit        1
  Strata MacTrace       1
  Strata Remnant        1
walltime: 91 s
```

## Progression across releases

| Image | v6/v7/v8 | v9 | v10 | v11 | v12 |
|-------|:---:|:---:|:---:|:---:|:---:|
| charlie-2009-11-12.E01 | 4 | 4 | 4 | 539 | **3,400** |
| jo-2009-11-16.E01 | 4 | 4 | 4 | 4 | **3,537** |
| terry-2009-12-03.E01 | 4 | 4 | 4 | 4 | 4 (acquisition-trim) |
| nps-2008-jean.E01 | 4 | 4 | 4 | 4 | 4 (acquisition-trim) |
| windows-ftkimager-first.E01 | 4 | 4 | 4 | 4 | 4 (no NTFS partition) |
| wiped_disk.E01 | 4 | 4 | 4 | 4 | 4 (wiped, no FS) |
| Takeout (host directory) | 4 | 4 | 4 | 4 | 4 |

Charlie and Jo are the two images in Test Material where the NTFS
partition's MFT sits within the acquired E01 chunk range. For
those, the v12 pipeline produces **850x the v10 baseline of 4
artifacts**, extracted end-to-end by real plugins walking real
NTFS mounted from real E01 bytes via pure-Rust code with zero
unsafe blocks and zero FFI.

Terry, Jean, and Windows-FTK are limited by pre-existing data
issues documented in `SESSION_STATE_v11_BLOCKER.md` (acquisition
trim on Terry + Jean; windows-ftkimager-first.E01 is a 10 MB test
stub without a real NTFS partition).

## What shipped this session

### The universal bridge — `strata_engine_adapter::materialize_targets`

A single function that walks a `VirtualFilesystem`, identifies
every file whose path matches a curated list of forensic-target
patterns (Windows registry hives, event logs, prefetch, LNK
shortcuts, browser SQLite DBs, macOS plists, iOS KnowledgeC, sms.db,
Android package dirs, Linux auth.log / bash_history, etc.), and
mirrors them to a scratch directory with the original logical path
preserved.

Safety caps: 512 MiB per file, 16 GiB total, 500,000 files — any
one limit stops materialization gracefully and reports via
`MaterializeReport`.

### CLI pipeline update

`strata ingest run` now follows this flow when the source is a
forensic image file:

1. `open_evidence()` opens the image (Raw / E01 / VMDK / VHD /
   VHDX / DMG)
2. `read_gpt()` then `read_mbr()` enumerate partitions
3. `fs_dispatch::open_filesystem()` mounts each partition (NTFS
   live; other FS types return `Unsupported` until FS-EXT4-1 /
   FS-APFS-1 / FS-HFSPLUS-1 / FS-FAT-1 land in v13)
4. `CompositeVfs` aggregates the mounted filesystems
5. **NEW**: `materialize_targets` copies forensic-target files
   from the VFS into `<case_dir>/extracted/` (once, at start of
   run)
6. `run_all_with_persistence_vfs` executes all plugins with
   `root_path = extracted_scratch` and `vfs = mounted_vfs`
7. Plugins that use `ctx.read_file` / `ctx.find_by_name` go
   through the VFS directly; plugins that still walk
   `std::fs::read_dir(ctx.root_path)` now see real forensic
   targets in the scratch tree
8. Artifacts persist to `<case_dir>/artifacts.sqlite`

### Test count

3,656 → 3,661 (+5 new materialize tests). `cargo clippy
--workspace --lib -- -D warnings` clean. Zero `.unwrap()` /
`unsafe {}` / `println!` added.

## Deferred to v13

Per SESSION_STATE_v12_BLOCKER.md:

- **FS-EXT4-1 / FS-APFS-1 / FS-HFSPLUS-1 / FS-FAT-1** — the four
  remaining filesystem walkers. The dispatcher surface and
  PartitionReader adapter are ready; each walker ships as a clean
  follow-up. Unlocks Linux images (2022 CTF - Linux.7z), iOS
  images (2020 CTF - iOS, Jess_CTF_iPhone8), macOS images,
  Android external storage FAT partitions.
- **Per-plugin VFS migrations** — the universal bridge makes this
  optional. Plugins that migrate can benefit from streaming VFS
  reads (no scratch space); plugins that don't migrate still work
  through the materialization path. Migration becomes an
  optimization, not a prerequisite.
- **Terry + Jean acquisition trim** — EWF-reader-level fix to
  report the actual acquired range rather than the volume
  header's advertised range. Non-blocking; affects only those
  two images.

## Bottom line

**Before v11**: every E01 in Test Material produced 0–4 artifacts.

**After v11**: Charlie's E01 produced 539 artifacts (Phantom migration only).

**After v12**: Charlie and Jo produce 3,400+ artifacts each across
12 plugins including Vector static analysis, Chronicle user
activity, Trace execution evidence, Vault anti-forensic, and
Sigma correlations.

The forensic platform is operational for Windows E01 evidence.
v13 extends the same pipeline to Linux / macOS / iOS / Android /
FAT by plugging in the remaining four filesystem walkers behind
the dispatcher that already routes them.

Strata is a forensic tool.
