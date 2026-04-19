# v16 Session 4 — COMPLETE

**Date:** 2026-04-18
**Scope:** Ship ApfsSingleWalker on top of the external `apfs` crate
adopted in Session 3, flip the APFS-single dispatcher arm from the
`"v0.16"` Unsupported sentinel to live walker routing.
**Tag:** NOT tagged (Session 5 ships v0.16.0 after APFS-multi branch).

## What shipped

### Sprint 1 — FS-APFS-SINGLE-WALKER (commit `2dd303c`)

`crates/strata-fs/src/apfs_walker/single.rs` (new, ~450 LOC) — Path A
(held handle) walker built on `apfs::ApfsVolume<PartitionReader>` held
behind `Mutex<...>` for `Send + Sync`. Strategic calls:

- **Path A confirmed correct.** Session 1 Send+Sync survey carried
  forward unchanged; apfs crate types held the audit.
- **Strata-owned encryption probe.** External crate's `VolumeInfo`
  does not expose encryption; probe walks container omap → first
  volume superblock → reads `APFS_FS_UNENCRYPTED` bit. Implemented
  as `probe_first_volume_encryption` in `apfs_walker/mod.rs`.
- **Fusion-drive gate.** `NX_INCOMPAT_FUSION = 0x100` bit rejected
  at `open()` with explicit roadmap message.
- **Encryption is surfaced, not decrypted.** If `is_encrypted`,
  `read_file()` returns `VfsError::Other("apfs encrypted volume —
  offline key recovery required")`. `list_dir` / `metadata` /
  `exists` still function (metadata-level analysis permitted on
  encrypted volumes).
- **VfsSpecific::Apfs tagging.** Entries carry `{ object_id,
  snapshot: None }`. `snapshot` stays `None` — current-state-only
  per Session 1 research doc; snapshot enumeration is a separate
  future sprint with its own tripwire.

13 new tests (walker_is_send_and_sync through
apfs_walker_walks_current_state_only_pending_snapshot_enumeration).
All use the committed `apfs_single.img` fixture generated in
Session 1.5 (labeled `STRATA-PROBE` — real bytes win over script
comments, v15 Lesson 2 applied).

**Sprint 1 result:** 3,798 → 3,811 tests passing.

### Sprint 2 — FS-DISPATCH-APFS-SINGLE (commit `578b971`)

`FsType::Apfs` arm in `open_filesystem` flipped from:

```rust
Err(VfsError::Other("APFS walker deferred to v0.16 — see roadmap".into()))
```

to:

```rust
Ok(Box::new(ApfsSingleWalker::open_on_partition(image, partition_offset, partition_size)?))
```

Retired pickup-signal test
`dispatch_apfs_returns_explicit_v016_message` converted to the arm-
routing tripwire `dispatch_apfs_single_arm_routes_to_live_walker`,
following the ext4 / HFS+ / FAT pattern from v15 Sessions B/D/E.
Asserts:

1. No `"v0.16"` substring in error surface (retired pickup signal).
2. Walker-originated error text present (confirms dispatch occurred
   rather than short-circuit).

**Sprint 2 result:** 17/17 fs_dispatch tests pass; 3,811 total.

## Deferred (Session 5 pickup)

- **APFS-multi dispatcher branch.** Current dispatcher does not
  differentiate single-vs-multi — any multi-volume container routes
  through `ApfsSingleWalker` and surfaces whatever error the `apfs`
  crate raises. Session 5 teaches the dispatcher to count
  `nxsb.fs_oids` and route multi to an explicit Unsupported arm with
  a `dispatch_apfs_multi_still_returns_v16_session_5` tripwire.
- **Snapshot enumeration.** Pinned as current-state-only per
  `apfs_walker_walks_current_state_only_pending_snapshot_enumeration`
  tripwire. Live in Session 5+ as a separate walker feature.
- **Decryption.** Out of scope permanently; offline key-recovery
  workflow is user-supplied.

## Deferred (Session 3 bandwidth — still pending)

- **Sprint 3 FS-EXFAT-1 / ExfatWalker.** Scope-guard invoked per
  user directive ("exFAT does NOT block the v0.16 tag — defer
  cleanly with pickup signal if scope balloons"). Existing tripwire
  `dispatch_exfat_returns_explicit_deferral_message` (fs_dispatch.rs
  line 419) still green and will flip to an arm-routing test the
  session that ships the walker. No changes this session.

## Gate status

- **Clippy workspace:** clean (`-D warnings`).
- **Tests:** 3,811 passing (3,798 baseline + 13 new).
- **AST quality gate:** PASS.
  - Library unwrap: 424 (≤ 470 ceiling).
  - Library unsafe: 5 (= 5 ceiling).
  - Library println: 5 (= 5 ceiling).
- **v15 advisory tripwires (Session 2):** all four still green.
- **Dispatcher arm-routing tripwires:** ext4, HFS+, FAT, and now
  APFS-single all pass live-walker routing assertions. NTFS was
  already live pre-v15.
- **Charlie / Jo:** untouched.

## Next session pickup signals

1. `dispatch_apfs_multi_still_returns_v16_session_5` — ADD in
   Session 5 when dispatcher grows the fs_oids-counting branch.
2. `apfs_walker_walks_current_state_only_pending_snapshot_enumeration`
   — FLIPS when snapshot walker ships.
3. `dispatch_exfat_returns_explicit_deferral_message` — FLIPS to
   `dispatch_exfat_arm_routes_to_live_walker` when ExfatWalker
   ships.

## Commits shipped this session

- `2dd303c` feat: FS-APFS-SINGLE-WALKER ApfsSingleWalker on top of the apfs crate
- `578b971` feat: FS-DISPATCH-APFS-SINGLE flip APFS arm to live ApfsSingleWalker

Do NOT tag v0.16.0 — Session 5 does that after APFS-multi branches
the dispatcher.
