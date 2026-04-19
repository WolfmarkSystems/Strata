# SPRINTS_v16 Session 1 — complete

v16 Session 1 (research-only) shipped the research artifact the
queue required plus 13 compiler probes committed under
`#[cfg(test)]`. Zero production code. All quality gates green.

**`v0.16.0` NOT tagged** — that's Session 5. Session 1 is the
foundation the remaining four sessions build on.

## Sprint scorecard

| # | Sprint | Status | Commit |
|---|---|---|---|
| 1 | FS-APFS-RESEARCH | **shipped** | `89c3003` |

Follow-up sessions (this session does not execute them):

| Session | Deliverable | Status |
|---|---|---|
| 2 | ML-WIRE-1 (wire advisory analytics into ingest pipeline) | queued, orthogonal to APFS |
| 3 | FS-APFS-OBJMAP + FS-HFSPLUS-READFILE | queued, unblocked by Session 1 |
| 4 | FS-APFS-SINGLE-WALKER + exFAT (opportunistic) + dispatcher arm | queued, gated on Session 3 |
| 5 | FS-APFS-MULTI-COMPOSITE + v0.16 milestone tag | queued, gated on Session 4 |

## What shipped this session

### `docs/RESEARCH_v16_APFS_SHAPE.md` — nine sections complete

1. **Existing parser surface** — full inventory of `apfs.rs`
   (601 LOC), `apfs_walker.rs` (1,283 LOC), and `apfs_advanced.rs`
   (70 LOC). Every function body inspected per v15 Lesson 1.
   Status marked `STUB` / `HEURISTIC` / `WORKING` per item.
2. **Threading contract** — 13 probes document every APFS public
   type is `Send + Sync`. Walker architecture decision: **Path A
   (held handle) via `Mutex<ApfsWalker<PartitionReader>>`** —
   matches HFS+/NTFS/FAT precedent, not ext4's reopen-per-call.
3. **Object map traversal** — planned `resolve_object(oid, xid)`
   primitive. Forensic implication of XID-parameterized resolution
   (snapshot semantics) documented.
4. **Snapshot strategy for v16** — current state only. Tripwire
   test sketch:
   `apfs_walker_walks_current_state_only_pending_snapshot_enumeration`.
5. **Multi-volume container strategy** — `/vol{N}:/path` numeric
   index convention with justification. `parse_volume_scope`
   helper sketched.
6. **Encryption awareness** — `VfsAttributes.encrypted` surfaced
   per entry; `read_file` returns `Err` on encrypted content,
   never ciphertext. Tripwire test
   `apfs_walker_marks_encrypted_volumes_does_not_decrypt`
   sketched.
7. **Fusion drives OUT OF SCOPE** — detection via
   `nx_incompatible_features & 0x100`. Returns
   `VfsError::Other("APFS fusion drives not yet supported — see
   roadmap")`. Tripwire
   `apfs_walker_rejects_fusion_container_with_pickup_signal`
   sketched.
8. **Checkpoints/space-manager/FSEvents/firmlinks/keys OUT OF
   SCOPE** — documented. Walker does not pretend these don't
   exist; simply doesn't parse them.
9. **LOC estimates for Sessions 3–5** —
   - Session 3: ~680 LOC (APFS ~420 + HFS+ ~260)
   - Session 4: ~720 LOC APFS-single only, ~1,480 LOC with exFAT
   - Session 5: ~750 LOC + ~220 prose
   Session 4's dual-sprint structure flagged as highest
   boundary risk; the queue's existing exFAT-defer clause is
   the correct escape valve.

### 13 Send/Sync probes under `#[cfg(test)]`

Committed at `crates/strata-fs/src/apfs.rs::_apfs_send_sync_probe`.
Probe every APFS public type in-tree:

**apfs.rs types (8):** `ApfsReader`, `ApfsSuperblock`,
`ApfsSnapshot`, `ApfsVolume`, `ApfsBtreeNode`, `BtreeTocEntry`,
`ApfsDirEntry`, `ApfsFileType`.

**apfs_walker.rs types (4):** `ApfsBootParams`, `ApfsFileEntry`,
`ApfsPathEntry`, `ApfsWalker<std::fs::File>`.

**apfs_advanced.rs types (6 tests in one fn):**
`ApfsAdvancedAnalyzer`, `ApfsSnapshot` (adv), `FSEventRecord`,
`Firmlink`, `SpaceMetrics`, `Xattr`.

**All 13 pass.** No `Rc`/`RefCell`/`Cell` anywhere. Path A
architecture viable throughout.

## Probe results table

| Type | Send | Sync | Notes |
|---|:---:|:---:|---|
| `apfs::ApfsReader` | ✅ | ✅ | holds `File`; no Rc/RefCell |
| `apfs::ApfsSuperblock` | ✅ | ✅ | plain data |
| `apfs::ApfsVolume` | ✅ | ✅ | `Vec<u8>` UUID + `Vec<ApfsSnapshot>` |
| `apfs::ApfsSnapshot` | ✅ | ✅ | plain data |
| `apfs::ApfsBtreeNode` | ✅ | ✅ | `Vec<BtreeTocEntry>` |
| `apfs::BtreeTocEntry` | ✅ | ✅ | plain data |
| `apfs::ApfsDirEntry` | ✅ | ✅ | plain data |
| `apfs::ApfsFileType` | ✅ | ✅ | enum |
| `apfs_walker::ApfsBootParams` | ✅ | ✅ | `Vec<u64>` volume offsets |
| `apfs_walker::ApfsFileEntry` | ✅ | ✅ | plain data with `Option<i64>` timestamps |
| `apfs_walker::ApfsPathEntry` | ✅ | ✅ | plain data |
| `apfs_walker::ApfsWalker<File>` | ✅ | ✅ | generic over `R`; Send+Sync when R is |
| `apfs_advanced::*` (6 types) | ✅ | ✅ | all ZSTs or plain data |

## Architectural decisions locked in research doc

1. **Walker architecture:** Path A (held handle) via
   `Mutex<ApfsWalker<PartitionReader>>`.
2. **Snapshot strategy:** Current state only for v16;
   snapshots deferred to v17 with tripwire.
3. **Multi-volume path convention:** `/vol{N}:/path` (numeric
   index, colon separator).
4. **Encryption:** `VfsAttributes.encrypted` on entries;
   `read_file` errors on encrypted content.
5. **Fusion drives:** Detected at superblock, return
   `Unsupported` with literal `"fusion"` pickup signal.
6. **Historical checkpoints / space manager / FSEvents /
   firmlinks / encryption keys:** out of scope for v16,
   documented deferrals.
7. **Heuristic scanners:** retirement recommended, not
   wrapping. Options documented (delete / feature-gate /
   CLI-flag).
8. **Starting point for Session 3:** `apfs_walker.rs` (real
   parser), not `apfs.rs` (heuristic + stubs).

## Deferrals documented with pickup signals for v17+

- **APFS snapshot enumeration** — tripwire
  `apfs_walker_walks_current_state_only_pending_snapshot_enumeration`
  pins v16 behavior. Flipping this test is a v17 sprint.
- **APFS historical checkpoint walking** — same pattern.
- **APFS fusion drives** — literal-substring assertion in
  error message carries pickup signal to CLI users.
- **APFS space manager** — for unallocated carving.
- **APFS FSEvents parser** — walker enables extraction,
  parser is application-layer.
- **APFS firmlink resolution** — cross-volume path resolution
  is application-layer.
- **APFS encryption key recovery** — offline, outside walker
  scope.

## Quality gates end-of-session

- **Test count:** **3,784** (from 3,771 at session start; +13
  Send/Sync probes, 0 failed).
- `cargo clippy --workspace -- -D warnings`: **clean**.
- AST quality gate: **PASS** at v14 baseline (470 library
  `.unwrap()` / 5 `unsafe{}` / 5 `println!` — zero new).
- All 9 load-bearing tests preserved.
- Charlie/Jo regression guards: unchanged.
- **All four v15 dispatcher arms still route live:**
  - NTFS (v11): `dispatch_*_ntfs_*` tests pass
  - ext4 (Session B):
    `dispatch_ext4_arm_attempts_live_walker_construction` passes
  - HFS+ (Session D):
    `dispatch_hfsplus_arm_attempts_live_walker_construction` passes
  - FAT12/16/32 (Session E):
    `dispatch_fat32_arm_attempts_live_walker_construction` passes
  - APFS still returns the literal `"v0.16"` message (unchanged
    from v15 — this session adds research, not dispatcher arm).
- No public API regressions. The `_apfs_send_sync_probe` module
  is additive under `#[cfg(test)]`.

## Pickup signals for Session 2 (ML wiring — orthogonal)

Session 2 is entirely orthogonal to APFS work. No Session 1
dependencies. Runner can pick up immediately when ready.

Queue-verbatim deliverables for Session 2:

1. Wire `strata-ml-anomaly`, `strata-ml-obstruction`,
   `strata-ml-summary` modules into `strata ingest run`.
2. Wire them into `apps/strata-desktop/`.
3. Restore Sigma Rules 30/31/32 to firing state.
4. Update website index.html + README with framed-accurate
   Advisory Analytics section (deterministic statistics +
   templates, NOT "AI-powered").
5. Tripwire test pinning the pre-v16 dead-rule behavior as
   closed.

Session 2 closes audit debt from the pre-v0.14 website/README
rewrite cycle (Opus audit found the ML modules were real code
called only from legacy `apps/tree/`).

## Pickup signals for Session 3 (APFS object map — this session's primary downstream)

Session 3 picks up the research doc's architectural decisions
and starts implementing:

1. **Start from `apfs_walker.rs`.** It has working OMAP +
   fs-tree walking. Evolve it into the primary parser via
   `Read + Seek + Send + 'static` constructor; retire or
   feature-gate the `apfs.rs` heuristics rather than wrapping
   them.
2. **Expose public `resolve_object(oid, xid)` API.** Existing
   `walk_omap_btree` does most of the work; Session 3 wraps it
   for walker consumption.
3. **Fusion detection at container-superblock time.** Research
   doc §7 has the exact flag (`nx_incompatible_features & 0x100`).
4. **Latest-checkpoint-only with tripwire test.** Research doc
   §8 sketch.
5. **HFS+ read_file extent reading** pairs with APFS extent-
   record work in the same session per queue instruction —
   architecturally analogous (both walk extent tables).
6. **Honest retirement of heuristic scanners** — research doc
   recommends delete or feature-gate, not wrap.

## The bottom line

v16 Session 1 delivered what research sessions are supposed to
deliver: a doc that makes the subsequent implementation sessions
smaller. The key discoveries:

- `apfs_walker.rs` is substantially more real than expected —
  1,283 LOC with working OMAP + fs-tree B-tree walking.
  Sessions 3–4 build on top, not from scratch.
- Every APFS type is `Send + Sync`. Path A walker architecture
  is unambiguously correct. Ext4's reopen-per-call workaround
  is not needed.
- `apfs.rs` is a liability, not an asset — heuristic scanners
  and stubbed `resolve_oid` / `read_file`. Session 3 should
  retire or feature-gate rather than wrap.
- Multi-volume path convention, snapshot strategy, fusion-drive
  scope, encryption handling are all decided in the research doc,
  not deferred.
- LOC estimates land within v15 precedent. Session 4's dual-
  sprint structure is the highest-risk boundary; exFAT defers
  cleanly per queue.

Strata is a forensic tool.
