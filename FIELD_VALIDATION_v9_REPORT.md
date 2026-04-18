# FIELD_VALIDATION_v9_REPORT — honest status of v9

This is the honest v9 validation report. It documents what v9
shipped this session, what is deferred to v10 with specific
reasoning, and why the queue cannot yet produce "the first honest
artifact counts against real E01 images" that the sprint queue set
as the strategic outcome.

## Scorecard: what v9 committed to vs. what shipped

| Part | Sprint | Status |
|------|--------|--------|
| 1 | EVIDENCE-1 Raw/DD reader | **shipped** — 5 tests |
| 1 | EVIDENCE-2 E01/EWF pure-Rust reader | **shipped** — 7 tests |
| 1 | EVIDENCE-3 VMDK (flat + sparse) | **shipped** — 3 tests |
| 1 | EVIDENCE-4 VHD + VHDX | **shipped** — 4 tests |
| 1 | EVIDENCE-5 Unified dispatcher | **shipped** — 6 tests |
| 2 | PARTITION-1 MBR walker | **shipped** — 5 tests |
| 2 | PARTITION-2 GPT walker | **shipped** — 5 tests |
| 3 | FS-1 NTFS walker | **deferred to v10** |
| 3 | FS-2 APFS walker | **deferred to v10** |
| 3 | FS-3 ext4 walker | **deferred to v10** |
| 3 | FS-4 FAT/exFAT walker | **deferred to v10** (integration attempt rolled back — see blocker note) |
| 3 | FS-5 HFS+ walker | **deferred to v10** |
| 4 | VFS-1 VirtualFilesystem trait | **shipped** — 6 tests |
| 4 | VFS-2 File index from VFS | **partially** — HostVfs covers it today; full wiring when FS walkers ship |
| 4 | VFS-3 PluginContext helpers | **shipped** — 5 tests (host-fs surface; VFS pointer in v10) |
| 4 | VFS-4 All-plugin migration | **deferred to v10** (helpers shipped so migration is mechanical) |
| 5 | PERSIST-1 Artifact database | **shipped** — 7 tests |
| 5 | PERSIST-2 Persistence pipeline | **shipped** — CLI writes artifacts.sqlite every run |
| 6 | TRUTH-1 NPS Jean ground truth | **shipped** as skip-guarded integration test |
| 6 | TRUTH-2 Count-based regression | **shipped** as skip-guarded integration test |
| 7 | REGRESS-1 Full matrix re-run | **deferred** — E01 images still produce 0 artifacts without FS walkers |
| 7 | REGRESS-2 Gap closure | **deferred** |

14 of 22 sprints shipped; the 8 deferred sprints are documented in
`SESSION_STATE_v9_BLOCKER.md` with rationale and recommended v10
work order. Silent compromise was explicitly rejected per the
user's directive.

## Why REGRESS-1 cannot run yet

`strata ingest run --source nps-2008-jean.E01 ...` today:

1. `strata-evidence::open_evidence()` correctly identifies the
   file as EWF, opens it, parses the section chain, and exposes
   `read_at(offset, buf)` over the decompressed disk bytes. **The
   E01 reader works end-to-end.**
2. `strata-evidence::partition::read_gpt()` / `read_mbr()` can
   correctly enumerate partitions inside that image. **Partition
   parsing works end-to-end.**
3. **At this point we have partition byte ranges but no
   filesystem walker**, so there is no way to present the NTFS
   contents of Jean's Windows XP C:\ drive as a walkable tree.
4. Plugins still receive the top-level directory they were passed
   on the CLI (the E01's parent directory, which contains only
   the E01 file itself). **They find nothing Windows-shaped to
   parse, so they emit 0 artifacts**, same as in the pre-v9
   baseline.

The `strata-fs::vfs::VirtualFilesystem` trait is ready to receive
an NTFS walker; wiring it + running the end-to-end pipeline is the
first v10 sprint.

## What DID change for the examiner this session

Even without FS walkers, three things are materially better:

1. **Artifacts now persist to disk.** Every `strata ingest run`
   writes a `<case_dir>/artifacts.sqlite` database with full-schema
   artifact records. Previously, artifacts were returned in memory
   and dropped on process exit. This is the single biggest user-
   visible change of the queue; the database works today against
   HostVfs and Takeout-style unpacked directories.

2. **Evidence images can be opened** — `strata-evidence::open_evidence`
   auto-detects raw / E01 / VMDK / VHD / VHDX / DMG, hands back an
   `Arc<dyn EvidenceImage>`. The rest of the chain can start plugging
   into that.

3. **Partition-aware metadata.** Given any image, `read_mbr()` /
   `read_gpt()` produce a structured partition list with human-
   readable type names. This lets future case-report generation
   describe a disk's layout without running a single plugin.

## Quantitative comparison to v6/v7/v8 reports

| Report | "Plugin runs green" | Actual artifact counts on E01 |
|--------|:-------------------:|:---:|
| v6 FIELD_VALIDATION_v6 | 506/506 | 4 per E01 (informational fallbacks) |
| v7 FIELD_VALIDATION_v7 | 506/506 | 4 per E01 (same) |
| v8 FIELD_VALIDATION_v8 | 506/506 | 4 per E01 (same) |
| **v9 (this report)** | 506/506 | **4 per E01 (still)** — but NOW WRITTEN TO artifacts.sqlite |

The honest metric has not moved for E01 images this session. It
will move in v10 when any FS walker lands — at which point the
documented minimums in `crates/strata-core/tests/ground_truth_v9.rs`
(flip `WALKERS_LANDED = true`) will start asserting real counts.

## Quality gates

- **Test count**: 3,574 → 3,633 (+59 new tests across evidence
  readers, partition walkers, VFS trait, PluginContext helpers,
  artifact database, and ground-truth scaffolding).
- **clippy --workspace --lib**: clean with `-D warnings`.
- **Zero `.unwrap()`** added in library/parser code.
- **Zero `unsafe {}`** blocks added (the memmap2 attempt was
  explicitly rolled back to preserve this rule; raw.rs uses
  `Mutex<File>` + seek/read).
- **Zero `println!`** added in library code.
- **All 9 load-bearing tests preserved** — verified by the full
  3,633-test workspace run.

## Recommended v10 work order

1. Wrap the `ntfs = "0.4"` crate in an `NtfsWalker`
   implementing `VirtualFilesystem`. Wire into
   `run_all_with_persistence` so `strata ingest run nps-jean.E01`
   mounts the NTFS partition via the existing `PARTITION_1` /
   `PARTITION_2` output + the new walker, passes the resulting
   VFS to plugins through `PluginContext`, and persists real
   artifacts to `artifacts.sqlite`. Flip `WALKERS_LANDED = true`
   in the ground-truth tests once counts exceed the minimums.

2. Migrate Phantom / Chronicle / Trace / Sentinel to use
   `ctx.find_by_name()` / `ctx.read_file()` instead of the raw
   `std::fs` calls they still use. (The PluginContext helpers
   shipped this session. A VFS pointer can be added to
   PluginContext in the same sprint, with HostVfs as the default.)

3. Wrap existing `strata-fs::apfs` / `strata-fs::hfsplus`
   modules in VFS implementations so macOS images exercise the
   same pipeline.

4. Wrap the `ext4 = "0.9"` crate for Linux images.

5. Resolve the FAT read-only wrapping question (upstream PR to
   fatfs, or minimal native FAT32 + exFAT reader).

6. Run REGRESS-1 end-to-end: re-ingest the full Test Material
   matrix with real filesystems and publish the first honest
   artifact-count field validation report.

Every architectural piece needed for step 6 is already in the
codebase at the end of this session.
