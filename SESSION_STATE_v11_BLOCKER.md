# SPRINTS_v11 — session completion + v12 queue

v11 crossed the finish line on Charlie's Windows E01 this session:
end-to-end `strata ingest run` → 539 real Windows artifacts
extracted from a mounted NTFS filesystem inside an E01. See
FIELD_VALIDATION_v11_REPORT.md for the scorecard.

Not every sprint in SPRINTS_v11.md landed in this session; the
remaining work is mechanical, queued below with effort estimates.

## Sprint scorecard

| Sprint | Status |
|--------|--------|
| EWF-FIX-1 | **shipped** — root cause fixed, Charlie + Terry + Jean all open |
| FS-EXT4-1 | **deferred to v12** — evaluate `ext4-view = "0.9"`, wrap in VFS |
| FS-FAT-1 | **deferred to v12** — native read-only parser per RESEARCH_v10_CRATES.md |
| FS-APFS-1 | **deferred to v12** — wrap existing in-tree APFS module |
| FS-APFS-2 | **deferred to v12** — ground truth against iOS CTF |
| FS-HFSPLUS-1 | **deferred to v12** — wrap existing in-tree HFS+ module |
| FS-DISPATCH-1 | **shipped** — 10-FS signature detection + NTFS live, rest Unsupported |
| VFS-PLUGIN-1 | **shipped** — PluginContext gains `vfs: Option<Arc<dyn VirtualFilesystem>>` |
| VFS-PLUGIN-2 | **partial (pilot)** — Phantom migrated; 25 plugins remain |
| E2E-1 | **shipped** — CLI opens image → partitions → FS → VFS → plugins |
| REGRESS-1 | **partial** — FIELD_VALIDATION_v11_REPORT.md covers the 3 XP E01s |
| REGRESS-2 | **deferred to v12** — depends on full VFS-PLUGIN-2 migration |

## v12 work order (recommended)

1. **Complete VFS-PLUGIN-2.** 25 plugins remain. The pattern is
   identical to the Phantom pilot: wrap the existing `run()` in a
   `if ctx.vfs.is_some() { ... }` branch that uses
   `ctx.find_by_name(target)` + `ctx.read_file(path_str)` to drive
   the same per-file parsers that the host-fs branch runs today.
   Estimated 1–2 plugins per hour; ~2 focused sessions to finish.
   Run `cargo test --workspace` after each plugin — any failure
   is a migration regression and must be fixed before moving on.

2. **Ship FS-EXT4-1.** Evaluate the `ext4-view = "0.9"` crate via
   the same `PartitionReader<EvidenceImage>` adapter NTFS uses.
   If the crate fits `VirtualFilesystem`, 200–400 LOC of wrapper.
   Ground-truth against `2022 CTF - Linux.7z` (unpack first).

3. **Ship FS-APFS-1 + FS-HFSPLUS-1.** Strata has in-tree APFS /
   HFS+ modules from v8 session state. The work is adapting them
   to the `PartitionReader` pattern and implementing the
   `VirtualFilesystem` trait methods against their existing APIs.

4. **Ship FS-FAT-1.** Native minimal read-only FAT12/16/32 /
   exFAT parser. ~500 LOC per RESEARCH_v10_CRATES.md. Good
   candidate for the v9 lesson — `fatfs` crate needs
   `ReadWriteSeek` which doesn't fit our read-only forensic
   stance.

5. **Fill in FS-DISPATCH-1 routing.** Once 2–4 land, the
   `Err(VfsError::Unsupported)` arms in `open_filesystem` flip
   to live walker construction.

6. **REGRESS-2 full Test Material matrix.** Re-run every image
   after the walkers land; document in
   `FIELD_VALIDATION_v12_REPORT.md`.

## NPS Jean / Terry acquisition-trim note

These two specific images have a pre-existing "acquisition
trimmed" anomaly: their EWF volume headers advertise 10 GiB
logical disks but only ~4 GiB of chunks were actually acquired.
Our EWF reader covers the mapped chunks correctly (verified by
`ChunkTableStats` — 141,800 chunks mapped, 3 table sections
parsed, 3 table2 mirrors seen and skipped), but the MFT on these
specific images sits in the unacquired range for the ntfs
crate's root-index walk, so `list_dir("/")` returns empty.

Charlie's MFT happens to sit within the acquired range and the
pipeline produces 539 artifacts against it. Terry and Jean will
produce artifacts once a future EWF acquisition includes their
MFT (the pipeline itself is not the blocker).

## Quality gates at end of session

- Test count 3,640 → 3,672 (+32).
- `cargo clippy --workspace --lib -- -D warnings`: clean.
- Zero `.unwrap()` / `unsafe {}` / `println!` added.
- All 9 load-bearing tests preserved.
- Public API extensions only (new `vfs` field on PluginContext,
  new re-exports from `strata-plugin-sdk`, new
  `run_all_on_vfs` / `run_all_with_persistence_vfs` in
  `strata-engine-adapter`). No regressions.

## The bottom line

Strata can now ingest a Windows E01 and produce hundreds of real
artifacts from registry hives via the full pure-Rust pipeline.
That has never been true in this project before. The remaining
v12 work extends the win to macOS/iOS/Android/Linux images and
completes the plugin migration; the architectural heavy lifting
is done.
