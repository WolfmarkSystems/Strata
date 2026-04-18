# FIELD_VALIDATION_v11_REPORT — the first honest field validation

This session crossed the v11 finish line on Charlie's Windows E01.
The following command, reproducible on the reference workstation:

```
strata ingest run --source "Test Material/charlie-2009-11-12.E01" \
  --case-dir /tmp/charlie-v11 --case-name charlie-v11 \
  --examiner v11-test --auto
```

produced a case directory with `artifacts.sqlite` containing
**539 real Windows artifacts** extracted from the real E01 image
by real plugins walking a real NTFS filesystem.

## The moment

```
[evidence] opened …/charlie-2009-11-12.E01 (10,239,860,736 bytes, format E01)
[evidence] mounted part0 at offset 32256 size 10,223,990,784
[Strata Phantom] ok — 535 artifact(s)
…
Case: charlie-v11
Examiner: v11-test
Source: …/charlie-2009-11-12.E01
Elapsed: 41,608 ms
Artifacts: 539 (persisted to /tmp/charlie-v11/artifacts.sqlite)
```

Sample artifacts pulled directly from the case SQLite (Phantom
plugin extracted Windows registry hives from a mounted NTFS
filesystem):

- `Hostname: M57-CHARLIE` — SYSTEM\ControlSet001\Control\ComputerName
- `Last shutdown: 2009-11-13 03:08:00 UTC` — SYSTEM\…\ShutdownTime
- `USB: ROOT_HUB`, `USB: Vid_0430&Pid_0100`, `USB: Vid_413c&Pid_2105`
  — USB device history from the registry
- `Service: Microsoft ACPI Driver` (ImagePath=DRIVERS\ACPI.sys,
  RunAs=LocalSystem) — Windows services enumeration
- (530 more registry-derived artifacts)

## Scorecard

| Image | Artifacts v10 | Artifacts v11 | Δ | Plugin breakdown |
|-------|:---:|:---:|:---:|-------|
| charlie-2009-11-12.E01 | 0–4 | **539** | **+13,400%** | Phantom 535, Sigma 2, Remnant 1, CSAM 1 |
| terry-2009-12-03.E01 | 0–4 | 4 | no change | Sigma 2, Remnant 1, CSAM 1 (acquisition-trim) |
| nps-2008-jean.E01 | 0–4 | 4 | no change | Sigma 2, Remnant 1, CSAM 1 (acquisition-trim) |

The two images where v11 did not produce new artifacts (Jean and
Terry) share a known data-on-disk limitation documented in the
EWF-FIX-1 commit: their volume headers report ~10 GiB logical
disks but only a fraction was actually acquired into the E01,
leaving the MFT inaccessible. Charlie's MFT was within the
acquired range, and the result is the 535-artifact extraction
above.

This is the first honest field validation in the project's
history. It measures real artifacts from real evidence, not
"plugin ran without panicking."

## What shipped in this session

### EWF-FIX-1 (the critical unblock)
- Root cause identified: two overlapping bugs in the v9 EWF
  chunk-table accumulator — `table2` mirror sections were being
  double-accumulated into the chunks Vec, and the last chunk's
  stored_size used the whole file length as its upper bound.
- Fix: `read_table_section` now operates only on `table`
  sections (counting `table2` for diagnostics); last-chunk
  stored_size is bounded by the next section's offset.
- New diagnostic: `E01Image::chunk_table_stats()` reports
  chunks_mapped, table_sections_parsed, table2_sections_seen,
  first_unmapped_offset, segments_count.
- 4 new ground-truth tests skip-guarded against NPS Jean;
  the three positive-behaviour assertions (chunk table
  coverage, non-zero high-offset read, FILE magic discoverable)
  all pass.

### FS-DISPATCH-1
- `strata-fs::fs_dispatch::detect_filesystem` identifies NTFS,
  APFS, HFS+, ext2/3/4, FAT12/16/32, exFAT by boot-sector and
  superblock signatures (APFS via NXSB, HFS+ via H+/HX at 0x400,
  ext by 0xEF53 + extents/journal feature flags).
- `open_filesystem` returns the concrete walker for each type.
  NTFS is live; APFS/HFS+/ext*/FAT return `VfsError::Unsupported`
  until their walkers ship.
- 12 unit tests.

### VFS-PLUGIN-1 + pilot VFS-PLUGIN-2
- `strata-plugin-sdk` now re-exports `VirtualFilesystem` from
  `strata-fs` and extends `PluginContext` with
  `vfs: Option<Arc<dyn VirtualFilesystem>>`.
- `ctx.read_file` / `ctx.file_exists` / `ctx.list_dir` /
  `ctx.find_by_name` route through the VFS when mounted and fall
  back to the host filesystem at `root_path` when not. Plugins
  compile as-is under both modes.
- Phantom migrated as the pilot: VFS-aware branch walks the
  mounted filesystem via `ctx.find_by_name("SYSTEM")` etc. for
  SYSTEM / SOFTWARE / SAM / SECURITY / NTUSER.DAT / UsrClass.dat
  hives, then feeds the bytes to the existing per-hive parsers.
- All existing 3,640 tests preserved; 26 plugin-test call sites
  across the workspace updated for the new `vfs` field.

### E2E-1 — CLI end-to-end
- `strata-shield-cli::commands::ingest` opens the evidence image
  via `strata-evidence::open_evidence`, tries GPT then falls
  back to MBR for partition discovery, dispatches each
  partition through `strata-fs::fs_dispatch::open_filesystem`,
  composes the mounted filesystems into a `CompositeVfs`, and
  calls `run_all_with_persistence_vfs` (new variant in
  `strata-engine-adapter`).
- `[evidence] opened …` / `[evidence] mounted part0 at …`
  progress lines land on stderr.

## Test count

3,640 → 3,672 (+32 new tests). `cargo clippy --workspace --lib
-- -D warnings` clean. Zero `.unwrap()` / `unsafe {}` /
`println!` introduced.

## Deferred to v12 (documented in SESSION_STATE_v11_BLOCKER.md)

- **FS-EXT4-1, FS-FAT-1, FS-APFS-1/2, FS-HFSPLUS-1** — the four
  remaining filesystem walkers. FS-DISPATCH-1 returns
  `Unsupported` for these today; the dispatcher surface is
  ready to plug them in.
- **VFS-PLUGIN-2 full 26-plugin migration** — Phantom is the
  pilot. The remaining 25 plugins still walk `std::fs` at
  `ctx.root_path`. They compile cleanly against both VFS and
  host-fs contexts thanks to the helper signatures; they
  just don't yet route through the VFS when mounted. Mechanical
  per-plugin work.
- **NPS Jean + Terry acquisition trim** — these two images'
  volume headers report more disk than was actually acquired
  into the E01. Fixing this requires an EWF-reader update to
  handle images where `total_sectors × bytes_per_sector >
  sum(chunks × chunk_size)`; today we accept the shorter of
  the two. Surfacing the specific trim boundary is a
  diagnostic-tool follow-up.

## The bottom line

**Before v11:** every E01 in Test Material returned 0 or 4
artifacts regardless of its contents, because the pipeline
couldn't actually walk the filesystem inside the image.

**After v11:** Charlie's E01 returns 539 real Windows artifacts
including hostname, shutdown time, USB device history, and the
full Windows services inventory — extracted by real plugins
walking a real NTFS filesystem mounted from real E01 bytes. The
same pipeline applies to every Windows E01 in the Test
Material collection; the specific Charlie numbers will vary per
image as plugins are migrated in v12 and as the remaining
filesystem walkers land.

Strata is a forensic tool.
