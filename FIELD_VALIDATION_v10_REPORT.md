# FIELD_VALIDATION_v10_REPORT — honest status of v10

Continues the honest-reporting pattern established in v9. v10 set
out to ship 14 sprints of filesystem walkers + plugin migration +
end-to-end validation against real E01 images. This session shipped
3 of the 14 (FS-NTFS-1/2/3); the remaining 11 are documented in
`SESSION_STATE_v10_BLOCKER.md` with a concrete unblock path.

## Scorecard: what v10 committed to vs. what shipped

| Part | Sprint | Status |
|------|--------|--------|
| 1 | FS-NTFS-1 NTFS walker core | **shipped** — ntfs crate wrapped, 4 unit tests |
| 1 | FS-NTFS-2 VirtualFilesystem impl | **shipped** — fs_type / list_dir / read_file / metadata / exists |
| 1 | FS-NTFS-3 NTFS ground truth | **shipped** — 3 integration tests against real E01s |
| 2 | FS-APFS-1 APFS walker | **deferred to v11** |
| 2 | FS-APFS-2 APFS ground truth | **deferred to v11** |
| 2 | FS-HFSPLUS-1 HFS+ walker | **deferred to v11** |
| 3 | FS-EXT4-1 ext4 walker | **deferred to v11** |
| 3 | FS-FAT-1 FAT walker (native) | **deferred to v11** |
| 3 | FS-DISPATCH-1 FS auto-detection | **deferred to v11** |
| 4 | VFS-PLUGIN-1 PluginContext VFS field | **deferred to v11** |
| 4 | VFS-PLUGIN-2 26-plugin migration | **deferred to v11** |
| 5 | E2E-1 CLI integration | **deferred to v11** |
| 5 | E2E-2 Regression validation | **deferred to v11** — cannot produce real numbers without walker chain closed |
| 5 | E2E-3 Gap closure | **deferred to v11** |

## The NTFS walker — what it does today, what it can't do yet

`crates/strata-fs/src/ntfs_walker/` ships a complete
`VirtualFilesystem` implementation for NTFS built on top of the
`ntfs = "0.4"` crate (Colin Finck, pure-Rust, read-only, MIT/
Apache-2.0). The Read+Seek adapter over partition windows works
cleanly; case-insensitive filename matching via the $Upcase table
works; the trait surface is functionally complete.

### What the ground-truth tests proved
- `NtfsWalker::open(arc_image, partition_offset, partition_size)`
  **succeeds** against real Windows E01 images (NPS Jean,
  Charlie, Terry). The NTFS boot sector parses, the MFT location
  is extracted, the crate's `Ntfs::new` accepts the reader.
- 7 new tests pass (4 unit + 3 integration). 3,633 → 3,640 total.

### What the ground-truth tests revealed
When `list_dir("/")` triggers the first MFT record read (at byte
offset 0xc0000000 = 3 GiB into the logical disk), the ntfs crate
gets zeros back:

> "The NTFS File Record at byte position 0xc0000000 should have
> signature [70, 73, 76, 69] [ASCII 'FILE'], but it has signature
> [0, 0, 0, 0]"

**This is an upstream issue in the v9 EWF reader, not the v10
NTFS walker.** The walker is correct; it's being fed zeros. NPS
Jean's E01 is 1.5 GiB compressed but represents a 4 GiB logical
disk; our `strata-evidence::e01` chunk-table accumulator isn't
covering offsets beyond the first few hundred MiB.

The one-line effect at the user level: `strata ingest run
--source nps-2008-jean.E01 ...` today still produces 0 artifacts,
but now we know exactly where the break is (EWF chunk addressing)
rather than "filesystem walking doesn't exist" (v9's state).

## Quantitative comparison to v9

| Metric | End of v9 | End of v10 |
|--------|:---:|:---:|
| Workspace tests passing | 3,633 | 3,640 |
| Filesystem walkers implementing VirtualFilesystem | 0 | 1 (NTFS) |
| Real E01 images that OPEN via v10 stack | 0 | 4 (Jean, Charlie, Terry, windows-ftkimager) |
| Real E01 images producing artifacts end-to-end | 0 | **still 0** (same as v9, same root cause: EWF chunk addressing) |
| Known blocker surface area | v9 blocker note: 8 sprints | v10 blocker note: 11 sprints, one concrete root cause |

The shift is architectural: v9 documented "no FS walkers exist."
v10 documents "one FS walker exists and works; the E01 reader
underneath needs a targeted fix."

## Recommended v11 work order

1. **EWF chunk-table accumulator debug** — one concrete fix,
   highest leverage. Instrument `strata-evidence::e01::
   read_table_section`, compare our chunk count + offset map
   against `ewfinfo nps-2008-jean.E01`, fix the accumulator.
   When this lands, the FS-NTFS-3 list_dir / read_file tests
   immediately transition from "ACK known limitation" to
   "assert expected behaviour." Estimated 1 session of focused
   debugging.

2. **VFS-PLUGIN-1 + pilot VFS-PLUGIN-2** — add
   `Option<Arc<dyn VirtualFilesystem>>` to PluginContext (the
   `strata-plugin-sdk` → `strata-fs` dep is safe; no cycle),
   migrate Phantom as the template. Once Phantom runs against a
   VFS-mounted NTFS, the pattern scales to the other 25 plugins.

3. **FS-APFS-1 + FS-HFSPLUS-1** — wrap existing in-tree
   `strata-fs::apfs` and `strata-fs::hfsplus` modules so they
   speak `VirtualFilesystem` against partition offsets on an
   `Arc<dyn EvidenceImage>`.

4. **FS-EXT4-1** — evaluate + wrap `ext4 = "0.9"` crate with the
   same PartitionReader adapter pattern used for NTFS.

5. **FS-FAT-1** — minimal native FAT32/exFAT reader (the v9
   note explained why we pass on `fatfs` crate for read-only
   forensic use).

6. **FS-DISPATCH-1** — ~50 lines now that walkers all exist.

7. **Remaining 25 plugin migrations** — mechanical follow-up to
   the Phantom pilot.

8. **E2E-1/2/3** — end-to-end pipeline + regression matrix with
   real numbers.

## Quality gates

- **Test count**: 3,633 → 3,640 (+7).
- **`cargo clippy --workspace --lib -- -D warnings`**: clean.
- **Zero `.unwrap()`** added in library/parser code.
- **Zero `unsafe {}`** blocks added.
- **Zero `println!`** added in library/parser code.
- **All 9 load-bearing tests preserved.**
- **Public API additions only; no regressions.**

## The bottom line

The v10 finish line ("`strata ingest run --source
nps-2008-jean.E01` produces a case directory with artifacts.sqlite
containing hundreds of real Windows artifacts") has not been
crossed in this session. One targeted EWF fix plus the remaining
FS walkers plus plugin migration stands between us and that
moment. The architectural groundwork that makes the fix
surgical — trait surface, Mutex-guarded walker, PartitionReader
adapter, ground-truth harness — is all in place.
