# RESEARCH_v16_APFS_SHAPE.md — APFS architectural research

*v16 Session 1. Research-only artifact. Produced before any
production code lands in Sessions 3–5.*

*Date: 2026-04-19*

## TL;DR

The existing in-tree APFS code is substantially larger than the
boot-sector-only baselines that preceded ext4 (Session B), HFS+
(Session D), and FAT (Session E). Two modules exist side-by-side:

- `apfs.rs` (601 LOC) — a `File`-based reader + **heuristic block
  scanner** that admits its own limitations inline (`// Heuristic
  scan for volume headers`, `// For stub behavior, if OID equals
  Root Directory Inode`, `// Normally accesses FS B-tree for
  J_EXTENT records mapped to the inode` followed by `Ok(vec![])`).
  Not walker-grade parser code.
- `apfs_walker.rs` (1,283 LOC) — a serious parser with real
  container superblock parsing, OMAP B-tree walking, volume
  superblock decoding, and fs-tree B-tree walking. Has 6 unit
  tests. Generic over `R: Read + Seek`.

**All 13 APFS public types are `Send + Sync`** (verified by
compiler probes committed under `#[cfg(test)]` in `apfs.rs`).
**Path A (held-handle walker) is viable** — no `Rc`, no `RefCell`,
no architectural blockers. Sessions 4 and 5 follow the HFS+ /
NTFS / FAT walker pattern via `Mutex<ApfsWalker<PartitionReader>>`
rather than the ext4 reopen-per-call workaround.

The two modules diverge on architectural intent. `apfs_walker.rs`
is the clear starting point for Session 4; `apfs.rs`'s heuristic
scanner is a liability that should be retired (or isolated behind
an explicit "forensic carving" feature) rather than wrapped.

## 1. Existing parser surface (per Phase A audit)

### Inventory — `crates/strata-fs/src/apfs.rs` (601 LOC)

Per Lesson 1 (Session C discipline), every function body inspected
— not just signatures. Status marked `STUB`, `HEURISTIC`, or
`WORKING`.

| Item | LOC | Status | Notes |
|---|---|---|---|
| `APFS_MAGIC`, `APFS_VOL_MAGIC` constants | 7–8 | WORKING | `NXSB` / `APSB` little-endian u32 |
| `pub struct ApfsReader { file: File, superblock, volumes, ... }` | 10 | WORKING | File-based (not Read+Seek) |
| `pub struct ApfsSuperblock` | 20 | WORKING | Field set for container header |
| `ApfsReader::open(path)` / `open_at_offset` | 36–58 | WORKING | File I/O + parse |
| `ApfsReader::read_superblock` | 60–105 | WORKING | Magic check at offset 32; falls through to block 1; reads `fs_volumes[8]` at offset 168 |
| `ApfsReader::parse_volumes` | 107–122 | **HEURISTIC** — "Heuristic scan for volume headers - increased scan range" — iterates blocks 0..1000 looking for APSB magic. Not OMAP-resolved. |
| `ApfsReader::read_volume_header` | 124–163 | WORKING (for a block known to be APSB) |
| `ApfsReader::scan_for_snapshots` | 165–182 | **HEURISTIC** — comment: "In a full implementation, we walk the snap_meta_tree_oid B-Tree. Heuristic: identify common snapshot naming patterns in nearby blocks." Looks for `"com."` + `".snapshot"` byte patterns. |
| `ApfsReader::read_block_at` / `read_block` | 184–211 | WORKING |
| `ApfsReader::resolve_oid` | 214–224 | **STUB** — comment: "In a complete implementation, this walks the B-Tree starting at vol.omap_oid's root. For stub behavior, if OID equals Root Directory Inode (usually 2), return dummy offset." |
| `ApfsReader::read_btree_node` | 226–264 | WORKING (decodes node header + TOC entries) |
| `ApfsReader::list_volumes` | 266–268 | WORKING |
| `ApfsReader::enumerate_root` / `enumerate_directory` | 270–314 | **HEURISTIC** + **STUB** fallback — scans blocks for J_DREC patterns; if root lookup yields nothing, pushes hardcoded `"Preboot"`, `"Recovery"`, `"VM"` placeholder entries |
| `ApfsReader::heuristic_scan_for_files` | 316–357 | **HEURISTIC** — scans up to 5000 blocks |
| `ApfsReader::extract_dirents_from_node` | 359–422 | WORKING (for a correctly identified leaf) |
| `ApfsReader::read_file` | 424–433 | **STUB** — body: `Ok(vec![])` with comment "Normally accesses FS B-tree for J_EXTENT records mapped to the inode" |
| `ApfsReader::carve_deleted_inodes` | 435–486 | HEURISTIC — 20k-block byte-pattern scanner |
| `ApfsSnapshot`, `ApfsVolume`, `ApfsBtreeNode`, `BtreeTocEntry`, `ApfsDirEntry`, `ApfsFileType` | 489–551 | Data structs, WORKING |
| `apfs_detect`, `apfs_open`, `apfs_list_volumes`, `apfs_enumerate_directory`, `apfs_read_file` | 553–601 | Thin `&Path` wrappers |

**Assessment:** `apfs.rs` is the APFS equivalent of what `fat.rs`
was before Session E — not a full walker, but worse than that,
because its stub functions are *callable with apparently-valid
return types*. A future walker that depended on `resolve_oid`
would silently see "root inode returns dummy offset" and every
other OID returns an error. The heuristic scanners may surface
real entries on some volumes but are not spec-conformant.

### Inventory — `crates/strata-fs/src/apfs_walker.rs` (1,283 LOC)

This is the substantially real parser.

| Item | LOC | Status | Notes |
|---|---|---|---|
| `NX_MAGIC`, `APSB_MAGIC`, `APFS_EPOCH_OFFSET`, `ROOT_DIR_INODE`, `BTNODE_LEAF`, `BTNODE_FIXED_KV`, `APFS_TYPE_INODE`, `APFS_TYPE_DIR_REC`, `MAX_BTREE_DEPTH` | 23–43 | WORKING |
| `pub struct ApfsBootParams { block_size, total_blocks, num_volumes, volume_offsets }` | 48 | WORKING |
| `pub struct ApfsFileEntry { inode, name, parent_inode, size, is_directory, is_symlink, timestamps }` | 56 | WORKING |
| `pub struct ApfsPathEntry { inode, path, name, size, is_directory, timestamps }` | 70 | WORKING |
| `struct VolumeSuperblock { omap_oid, root_tree_oid, vol_name, role }` (private) | 83 | WORKING |
| `struct OmapCache { entries: HashMap<u64, u64> }` (private) | 92 | WORKING |
| `pub struct ApfsWalker<R: Read + Seek> { reader, boot, partition_offset }` | 98 | WORKING. Generic over `R`; stores reader directly. |
| `ApfsWalker::new(reader, partition_offset)` | 106 | WORKING |
| `ApfsWalker::read_container_superblock` | 119 | WORKING — reads 4 KB at offset, validates magic, extracts block_size / total_blocks |
| `ApfsWalker::read_block` | 169 | WORKING |
| `ApfsWalker::read_container_omap` | 190 | WORKING — reads container OMAP root block OID from header offset 160 |
| `ApfsWalker::read_omap_tree` | 205 | WORKING — invokes `walk_omap_btree` |
| `ApfsWalker::walk_omap_btree` | 234 | WORKING — **real** B-tree walk with level-based recursion on index nodes, leaf-node value extraction, proper TOC entry iteration respecting `tspace_off` |
| `ApfsWalker::parse_volume_superblock` | 327 | WORKING — magic check, omap_oid at 128, root_tree_oid at 136, vol_name at 704, role at 964 |
| `ApfsWalker::enumerate(max_entries)` | 393 | PARTIAL — B-tree walk path exists but **falls back to `heuristic_scan`** when OMAP resolution or B-tree walk returns no entries. The heuristic path is a carving scanner, not a spec-conformant walker. |
| `ApfsWalker::walk_fs_btree` | 549 | WORKING — decodes J_INODE (type 3) and J_DREC (type 9) records; extracts inode size/timestamps + dir record parent+name+inode |
| `ApfsWalker::heuristic_scan` | 825 | **HEURISTIC FALLBACK** — byte-pattern block scanner. Used when structural walk fails. |
| `ApfsWalker::enumerate_with_paths` | 867 | WORKING — wraps `enumerate` with `build_apfs_path_tree` |
| `ApfsWalker::boot_params` | 880 | WORKING |
| `extract_leaf_drec_entries`, `extract_leaf_inode_entries` (private helpers) | 900+ | HEURISTIC — "heuristic scanner fallback" comments |
| `build_apfs_path_tree` (private) | ~1100 | WORKING |
| `apfs_ns_to_unix` (private) | ~1130 | WORKING — 2001-epoch to Unix-epoch conversion |
| 6 unit tests | 1141–1290 | All pass, all test isolated primitives (ns conversion, container magic, volume-superblock offsets, path building) |

**Assessment:** The structural walker (`walk_omap_btree`,
`walk_fs_btree`, `parse_volume_superblock`) is real code that
could be the foundation for Session 4. The heuristic fallbacks
are a liability — if structural walking fails on a real volume,
the walker silently degrades to byte-scanning which can surface
false-positive records on any high-entropy block.

### Inventory — `crates/strata-fs/src/apfs_advanced.rs` (70 LOC)

Every method body is `Ok(vec![])` / `Ok(SpaceMetrics::default())`.
This file is **entirely stubs** providing an API surface
(`extract_snapshots`, `analyze_space_manager`, `parse_fsevents`,
`synthesize_firmlinks`, `index_xattrs`) with no implementation
behind it. Not used by `apfs_walker.rs`. Safe to leave untouched
in v16 — Session 4 won't depend on it.

### Gap summary

What Session 3's object-map sprint must establish:

1. **A Read+Seek-based reader constructor** replacing
   `ApfsReader::open(&Path)` with `open_reader<R: Read + Seek +
   Send + 'static>(reader)` (per v15 walker convention). Likely
   evolves `apfs_walker.rs` rather than `apfs.rs`.
2. **A real `resolve_object(oid, xid)` primitive** replacing the
   stub in `apfs.rs:214` and the OMAP-cache approach in
   `apfs_walker.rs` (which caches but doesn't expose
   OID→offset resolution as a public API).
3. **Extent record reading** replacing the `Ok(vec![])` stub in
   `apfs.rs:424`. `apfs_walker.rs::walk_fs_btree` parses J_INODE
   records including size; extent records (J_EXTENT, type 8) are
   NOT currently decoded.
4. **Honest disposition of heuristic scanners.** Options: (a)
   delete them entirely, (b) move them to a separate
   `apfs_carving` module and flag output as
   "heuristic carving — examiner review required", (c) keep them
   gated behind a `--include-carved` CLI flag. The queue's
   discipline clause suggests (a) or (b); silently shipping
   heuristic results as if they were spec-conformant would repeat
   the v14 audit's "shipping stubs as features" failure mode.

## 2. Threading contract (per Phase B probes)

All 13 APFS public types probe `Send + Sync`. Tests live in
`crates/strata-fs/src/apfs.rs::_apfs_send_sync_probe` (13 tests,
all passing):

```
apfs_superblock_is_send_and_sync
apfs_volume_is_send_and_sync
apfs_snapshot_is_send_and_sync
apfs_btree_node_is_send_and_sync
btree_toc_entry_is_send_and_sync
apfs_dir_entry_is_send_and_sync
apfs_file_type_is_send_and_sync
apfs_reader_is_send_and_sync
apfs_boot_params_is_send_and_sync
apfs_file_entry_is_send_and_sync
apfs_path_entry_is_send_and_sync
apfs_walker_over_file_is_send_and_sync
apfs_advanced_types_are_send_and_sync (covers 6 types in one fn)
```

None of the APFS types use `Rc`, `RefCell`, or other single-
threaded primitives. The `ApfsReader`'s internal `File` and the
`ApfsWalker<R>`'s generic `R` are both `Send + Sync` when `R:
Send + Sync` (standard for `std::fs::File`,
`Cursor<Vec<u8>>`, and `PartitionReader`).

### Walker architecture decision — **Path A (held handle)**

**Decision:** Session 4 walker follows the HFS+ / NTFS / FAT
precedent — `Mutex<ApfsWalker<PartitionReader>>` held in the
`VirtualFilesystem` impl. No reopen-per-call.

**Justification:**

- APFS parsing is significantly more expensive than HFS+ or FAT
  (multi-level B-tree walks over OMAP + fs-tree, potentially
  thousands of blocks per enumeration). Reopen-per-call would
  re-read the container superblock + container OMAP + volume
  superblock on every VFS trait method invocation. The v15
  Session B cost-model for ext4's reopen-per-call (~2 KB
  superblock re-parse + the crate's block cache absorbing
  subsequent reads) does NOT generalize here — APFS OMAP trees
  can be hundreds of KB.
- `Send + Sync` on every type removes the architectural reason
  the ext4 walker had to reopen. There's no `Rc` to leak.
- The `Mutex<ApfsWalker<...>>` pattern is already proven at
  production scale by the HFS+ walker in Session D.

### Failure-mode contingency

If Session 3's extent-record implementation surfaces a newly-
introduced `!Send` type (e.g., a Rayon-based parallel block reader,
or a `tokio::sync::Mutex`), the probes committed this session will
catch it at test time. The research doc's decision is locked;
deviations get flagged by failing tests, not silent regressions.

## 3. Object map traversal

APFS is object-based. Every structural element (volume superblock,
fs-tree root, checkpoint descriptor) has an object ID (`oid: u64`)
and a transaction ID (`xid: u64`). The container's **object map
(OMAP)** is the B-tree that resolves `(oid, xid)` pairs to physical
block numbers.

`apfs_walker.rs` already implements a walking OMAP:

- `read_container_omap()` reads the root block OID from container
  superblock offset 160.
- `read_omap_tree(root_block)` opens the root B-tree node.
- `walk_omap_btree(node_block, depth)` recurses level-by-level
  from root (highest `btn_level`) down to leaves (`btn_level == 0`),
  decoding the TOC entries via `tspace_off` (variable-length-key
  space offset from node start).

What's **missing** is a public `resolve_object(oid, xid)` primitive.
Session 3 exposes that API on top of the existing OMAP walker:

```rust
// Planned for Session 3, crates/strata-fs/src/apfs_walker.rs
impl<R: Read + Seek> ApfsWalker<R> {
    /// Resolve (OID, XID) → physical block. For XID queries,
    /// returns the record with the highest XID ≤ target; for v16,
    /// callers pass the container's next_xid - 1 to get the
    /// current-state mapping.
    pub fn resolve_object(
        &mut self,
        oid: u64,
        xid: u64,
    ) -> Result<u64, ApfsError>;
}
```

The existing `OmapCache` stores resolved `(oid → physical_block)`
mappings built up-front during volume enumeration. Session 3
either promotes that cache to a pub API or walks the B-tree
on-demand for each resolution (latter is simpler, costs one
B-tree traversal per lookup; cache can be added as an optimization
after correctness is proven against the fixture).

### Forensic implication

OID lookups at different XIDs walk different historical states.
Snapshots record an XID at capture time; walking with
`xid == snapshot.xid` gives the filesystem's state at that moment.
**This has real evidentiary value** — deleted files often survive
in older XIDs because APFS's copy-on-write semantics preserve the
old pages until the space is reclaimed. v16 ships current-state
only (see §4), but the resolution primitive is XID-parameterized
so that snapshot enumeration is a thin follow-on sprint.

## 4. Snapshot strategy for v16

**Decision:** v16 walker iterates the **current state only** —
latest XID per volume. Snapshot enumeration is deferred beyond v16.

**Tripwire sketch (to be committed in Session 4):**

```rust
#[test]
fn apfs_walker_walks_current_state_only_pending_snapshot_enumeration() {
    // Open a volume with at least one snapshot. Confirm walk()
    // returns entries from the latest XID only — NOT the
    // concatenation of all XIDs. The fixture's snap_count is
    // validated separately; this test pins the walker's behavior.
    //
    // When snapshot enumeration ships, this test must be
    // intentionally changed or deleted with the commit message
    // explicitly noting "snapshot iteration shipped in [commit]".
    let walker = ApfsWalker::new(fixture_with_snapshot(), 0).unwrap();
    let entries = walker.enumerate(10_000).unwrap();
    let inodes: HashSet<u64> = entries.iter().map(|e| e.inode).collect();
    // A snapshotted volume where a file was deleted between snapshot
    // and current would see the deleted file in the snapshot's XID
    // but NOT in current. Walker must surface current-state only.
    assert!(!inodes.contains(&KNOWN_DELETED_INODE_PRESENT_IN_SNAPSHOT));
}
```

The tripwire name embeds the deferral (`_pending_snapshot_enumeration`)
per the v15 convention. Session 4 ships this test against the real
APFS fixture once the walker is wired.

Fixture construction for the test: `hdiutil create -fs APFS`
followed by `diskutil apfs addSnapshot` or equivalent, then delete
a file before capturing the flat image. The snapshot carries the
pre-delete state; the current volume carries the post-delete state.

## 5. Multi-volume container strategy

A single APFS container holds 1..N volumes. Typical macOS boot
layouts:

- **Macintosh HD** (System — read-only sealed on Big Sur+)
- **Macintosh HD - Data** (user data, firmlinked into System's
  mount point)
- **Preboot** (APFS bootloader + recovery tooling)
- **Recovery** (Recovery OS)
- **VM** (swap + sleep image; present only when VM pressure
  occurred)

**Decision:** v16 ships two walker types:

- **Session 4 `ApfsSingleWalker`** — takes a container reader +
  a `volume_index: usize`, walks that one volume. Matches the
  single-volume semantics every other v15 walker provides.
- **Session 5 `ApfsMultiWalker` (`CompositeVfs`-style)** —
  iterates all volumes in the container, exposing each through
  the `VirtualFilesystem` trait with volume-scoped paths.

### Volume-scoped path convention — **pick: `/vol{index}:{path}`**

**Decision:** paths are scoped by numeric index, not by volume
name. Format:

- `/vol0:/etc/passwd` — the first volume's `/etc/passwd`
- `/vol1:/Users/admin/Library/Safari/History.db` — second volume
- `/vol0:/` lists the first volume's root

**Justification:**

- **Determinism.** Numeric indices are stable across renames.
  Volume names can collide (two volumes both labeled "Untitled"
  is legal) or contain characters that require quoting in path
  strings.
- **Forensic reproducibility.** A finding that reads "file at
  `/vol1:/Library/Preferences/com.apple.Bluetooth.plist`" points
  at a specific on-disk location independent of whether the
  examiner renamed the volume during analysis.
- **Ext4/HFS+/FAT parity.** The existing single-volume walkers
  use `/` as their root. Prepending `/vol{index}:` to that
  convention preserves invariants — each volume's sub-walker sees
  a path starting with `/`, the multi-walker just strips/adds the
  `/vol{N}:` prefix at the boundary.
- **Unambiguous parsing.** The `:` separator is reserved from
  appearing in POSIX paths (FAT, HFS+, APFS, ext4 all reject
  `:` in filenames on most configurations). `{N}:{path}` always
  parses unambiguously even for paths containing spaces, colons
  in non-leading positions, or unicode.

Alternative considered: `/@volume_name/path` form. Rejected for
the collision + determinism reasons above. If future CLI users
want name-based access, a `--volume-by-name` alias can resolve
name → index at the dispatcher layer without changing the walker
path convention.

### CompositeVfs design

```rust
pub struct ApfsMultiWalker {
    container: Arc<Mutex<ApfsWalker<PartitionReader>>>,
    volume_walkers: Vec<ApfsSingleWalker>,
}

impl VirtualFilesystem for ApfsMultiWalker {
    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        match parse_volume_scope(path) {
            None => {
                // Root: list "volN:" directory entries, one per volume
                Ok(self.volume_walkers.iter().enumerate().map(|(i, _)| {
                    VfsEntry::directory(format!("/vol{i}:"))
                }).collect())
            }
            Some((index, inner_path)) => {
                self.volume_walkers.get(index)
                    .ok_or(VfsError::NotFound(path.into()))?
                    .list_dir(&inner_path)
                    // Re-prefix paths as the sub-walker sees them
                    .map(|entries| entries.into_iter().map(|mut e| {
                        e.path = format!("/vol{index}:{}", e.path);
                        e
                    }).collect())
            }
        }
    }

    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let (index, inner) = parse_volume_scope(path)
            .ok_or(VfsError::NotFound(path.into()))?;
        self.volume_walkers.get(index)
            .ok_or(VfsError::NotFound(path.into()))?
            .read_file(&inner)
    }

    // metadata / exists mirror read_file's resolution pattern.
}

fn parse_volume_scope(path: &str) -> Option<(usize, String)> {
    // "/volN:rest" → (N, "/rest"), otherwise None.
    let rest = path.strip_prefix("/vol")?;
    let colon = rest.find(':')?;
    let index: usize = rest[..colon].parse().ok()?;
    let inner = &rest[colon + 1..];
    let normalized = if inner.is_empty() || !inner.starts_with('/') {
        format!("/{inner}")
    } else {
        inner.to_string()
    };
    Some((index, normalized))
}
```

## 6. Encryption awareness

APFS supports FileVault per-volume encryption. Walker behavior
per the queue:

1. **Identify encrypted volumes** via volume superblock flags
   (`apsb_incompatible_features` bit 0x2 =
   `APFS_INCOMPAT_CASE_INSENSITIVE`; encryption is a separate
   set of `encryption_rolling_state` fields at offset 928 in
   APSB). Session 3's volume-superblock parser extends
   `parse_volume_superblock` to surface `is_encrypted: bool`.
2. **Expose `is_encrypted` on `VfsEntry` metadata.** Add to
   `VfsAttributes` struct if not already present (it's a
   `VfsAttributes` field today — `encrypted: bool`, already
   wired through the ext4 + HFS+ walkers for the forensic mark).
3. **Do NOT attempt decryption.** Offline key recovery is a
   separate examination step with a key bundle provided by the
   examiner. Walker returns encrypted content as-is (ciphertext)
   or — cleaner — returns `VfsError::Other("encrypted content —
   offline key recovery required")` on `read_file`.
4. **Do NOT silently skip encrypted content.** Enumeration must
   still list encrypted entries so examiners see that encryption
   is present. `list_dir` continues to work (directory entry
   keys are typically not encrypted even when file contents are);
   `read_file` is the spot that refuses decryption.

Session 4 tripwire test:

```rust
#[test]
fn apfs_walker_marks_encrypted_volumes_does_not_decrypt() {
    // Open fixture with encrypted volume. Enumeration must succeed
    // and surface is_encrypted=true on entries within the volume.
    // read_file on an encrypted entry must return Err(Other(...))
    // — NOT Ok(ciphertext) and NOT Ok(zeros).
}
```

## 7. Fusion drives — OUT OF SCOPE

A fusion drive is Apple's logical-volume manager spanning an SSD
(small, fast) and an HDD (large, slow) presented as a single APFS
container. Walking a fusion container requires additional logic
beyond what Sessions 3–5 will implement.

**Decision:** v16 detects fusion containers at the container
superblock level (Session 3) and returns `VfsError::Unsupported`
with a clear pickup signal. Specifically:

- NXSuperblock's `nx_incompatible_features` field includes
  `NX_INCOMPAT_FUSION = 0x100`. If that bit is set, the Session
  3 parser returns `Err(ApfsError::FusionUnsupported)` which the
  Session 4 walker maps to
  `VfsError::Other("APFS fusion drives not yet supported — see roadmap")`.
- The walker does **not** panic, does **not** silently read only
  the SSD portion, does **not** fall through to the heuristic
  scanner.

### Tripwire sketch

```rust
#[test]
fn apfs_walker_rejects_fusion_container_with_pickup_signal() {
    // If we ever ship a fixture with NX_INCOMPAT_FUSION set,
    // ApfsWalker::new must return Err with the literal "fusion"
    // substring so CLI users and log consumers see the roadmap
    // pickup signal.
}
```

## 8. Checkpoints, space manager, encryption keys — OUT OF SCOPE

Forensically interesting structures that v16 does not parse:

- **Historical checkpoint descriptors.** The container's
  checkpoint descriptor area is a ring buffer; v16 uses only
  the **latest** checkpoint. Historical checkpoint walking
  (for deleted-file recovery via older XIDs) is a v17 candidate.
  Tripwire name: `apfs_uses_latest_checkpoint_only_pending_historical_walk`
  (Session 3).
- **Space manager.** Allocation bitmap + free-space tree. Tells
  you which blocks are in-use vs free at the current checkpoint.
  Useful for unallocated-space carving. Not needed for
  walk/read.
- **Encryption keys.** The volume-manager key records and per-
  class key bags. Not parsed — decryption is out of scope.
- **FSEvents stream.** A ~1 MB circular buffer of recent
  filesystem events. Useful for timeline reconstruction. Can be
  extracted by walking the fs-tree for `.fseventsd` and reading
  file content — walker enables this, a separate parser consumes
  the bytes.
- **Firmlinks.** macOS Big Sur+ `/System` and `/` are cross-
  linked via firmlinks. Walker exposes each volume's raw
  filesystem tree; firmlink resolution across volumes is an
  application-layer concern.

Walker **does not pretend these structures don't exist** — it
simply doesn't parse them. The container superblock fields
referencing checkpoint descriptor area / space manager / key bag
OIDs are read and stored in `ApfsBootParams` extensions so that
follow-on sprints can consume them without re-parsing.

## 9. LOC estimates for Sessions 3–5

Grounded in the Phase A audit + v15 equivalent work.

### Session 3 — FS-APFS-OBJMAP + FS-HFSPLUS-READFILE

| Item | LOC (new) | Comp | Notes |
|---|---|---|---|
| NXSuperblock parse + fusion detection | ~60 | vs v15 Ext4Walker adapter (~100) | mostly already in `apfs_walker::read_container_superblock`; add `nx_incompatible_features` check for fusion |
| Checkpoint descriptor ring walk (latest only) | ~100 | new | find latest descriptor in ring, decode CP map/CP SB ptrs |
| Public `resolve_object(oid, xid)` API | ~120 | vs HFS+ `read_catalog` (~200) | existing `walk_omap_btree` does most of the work; promote to public API, accept XID parameter |
| OID→offset via object map (expose primitive) | ~60 | | wraps OmapCache or walks tree on-demand |
| APFS tripwire tests (fusion + latest-checkpoint) | ~80 | | ~40 LOC per test |
| **APFS Session 3 subtotal** | **~420** | | ~350–500 range |
| HFS+ read_file: inline extents (first 8) | ~60 | existing `HfsPlusCatalogFile.extents` field surfaces these | |
| HFS+ read_file: extents overflow B-tree walk | ~100 | vs Session D B-tree iter (~200) | overflow file structure similar to catalog |
| HFS+ read_file: sparse-file handling | ~30 | | |
| HFS+ resource-fork support | ~40 | | same extent-walk pattern, different record field |
| HFS+ tripwire flip + positive test | ~30 | | |
| **HFS+ Session 3 subtotal** | **~260** | | ~200–300 range |
| **Session 3 grand total** | **~680 LOC** | v15 Session D was ~500 for comparable scope | reasonable for one session |

### Session 4 — FS-APFS-SINGLE-WALKER + fixture + dispatcher arm + exFAT (opportunistic)

| Item | LOC (new) | Comp | Notes |
|---|---|---|---|
| `ApfsSingleWalker` struct + `open` | ~50 | vs `HfsPlusWalker::open` | |
| `VirtualFilesystem` trait impl | ~120 | vs `HfsPlusWalker` trait impl | path→inode resolution via fs-tree walk |
| `read_file` via extent records | ~80 | | J_EXTENT record type decode + block read chain |
| Encryption marking in `VfsEntry` | ~20 | | |
| Snapshot tripwire test | ~60 | | fixture setup heavy |
| Fusion rejection test | ~30 | | |
| `apfs_single.img` fixture + `mkapfs.sh` + manifest | ~80 | vs `mkhfsplus.sh` (~110) | `hdiutil create -fs APFS` native |
| `ground_truth_apfs_single.rs` integration tests | ~250 | vs `ground_truth_hfsplus.rs` (~170) | ~8 tests; more diverse content than HFS+ |
| Dispatcher APFS-single arm + test conversion | ~30 | vs Session D dispatcher change (~30) | |
| **APFS-single Session 4 subtotal** | **~720** | ~600–800 range | |
| exFAT parser layer | ~300 | vs Session E FAT parser (~500) | smaller because boot sector + directory-entry format only |
| ExfatWalker | ~150 | vs `FatWalker` (~200) | simpler, no LFN 13-char-per-entry chain |
| exFAT fixture + manifest | ~80 | vs FAT16 fixture | `newfs_exfat` on macOS |
| `ground_truth_exfat.rs` | ~200 | | ~6 tests |
| Dispatcher exFAT arm + test conversion | ~30 | | |
| **exFAT Session 4 subtotal (opportunistic)** | **~760** | | |
| **Session 4 grand total** | **~1,480 if both ship, ~720 if exFAT defers** | | |

**Flag for the queue-keeper:** Session 4 is the biggest of the
cycle. If both APFS-single and exFAT ship, 1,480 LOC is within
precedent (Session D landed ~900 LOC including fixture + tests;
Session E landed ~1,000 LOC). If scope balloons, exFAT defers
cleanly per the queue's explicit scope-guard.

### Session 5 — FS-APFS-MULTI-COMPOSITE + final dispatcher + v0.16 tag

| Item | LOC (new) | Comp | Notes |
|---|---|---|---|
| `ApfsMultiWalker` with shared container state | ~150 | vs HFS+ walker (~300) | per-volume `ApfsSingleWalker` sharing an Arc'd container reader |
| `parse_volume_scope` helper | ~30 | | |
| CompositeVfs `VirtualFilesystem` impl | ~200 | vs Session B ext4 adapter (~10 — ext4 was trivially simple via Ext4Read) | 4 trait methods × ~50 LOC each |
| Auto-detect single vs multi at dispatcher | ~30 | | check volume count in NXSuperblock |
| `apfs_multi.img` fixture | ~80 | | requires `diskutil apfs addVolume` |
| `ground_truth_apfs_multi.rs` | ~200 | | cross-volume path resolution tests |
| Dispatcher APFS-multi arm + test conversion | ~40 | | |
| FIELD_VALIDATION_v16_REPORT.md | ~200 lines prose | | five-session narrative |
| CLAUDE.md key numbers update | ~20 | | |
| **Session 5 grand total** | **~750 LOC + ~220 prose lines** | | precedent: Session D + SESSION_STATE_COMPLETE narrative |

### Summary

- **Session 3:** ~680 LOC (APFS ~420 + HFS+ ~260) — reasonable.
- **Session 4:** ~720 LOC if exFAT defers, ~1,480 if both ship —
  exFAT deferral is the escape valve per the queue's own tag-
  policy clause.
- **Session 5:** ~750 LOC + milestone prose — reasonable.

**Flag for the queue-keeper:** Session 4's dual-sprint structure
carries real session-boundary risk. Recommend Session 4 ships
APFS-single first as a hard-priority sprint, and treats exFAT as
a bonus sprint that can cleanly defer to a follow-up session
without blocking the v0.16 tag. The queue already says this —
reiterating here because the LOC analysis confirms the tag-policy
caveat is load-bearing.

## Notes for Session 3 runner

1. **Start from `apfs_walker.rs`, not `apfs.rs`.** The former has
   real OMAP + fs-tree walking; the latter has heuristic scanners
   and stubs. Evolve `apfs_walker.rs` into the Read+Seek-based
   primary parser; reduce `apfs.rs` to a deprecation stub or
   feature-gated carving module.
2. **Public `resolve_object(oid, xid)` is the keystone.** Every
   walker trait method depends on it. Get it working against the
   real APFS fixture (from Session 4 hdiutil generation) before
   building the fs-tree walker on top.
3. **Fusion detection at superblock time, not later.** The moment
   `nx_incompatible_features & 0x100 != 0`, return
   `Err(ApfsError::FusionUnsupported)` — don't let the walker
   proceed to the point where it might read the SSD tier and
   pretend that's the whole filesystem.
4. **The heuristic scanners in `apfs_walker.rs::heuristic_scan`
   should be retired** (or feature-gated with a clear marker on
   returned entries). Silent fallback from structural parsing to
   byte-pattern matching has a failure mode that looks like success
   — exactly the v14 audit pattern this methodology exists to
   prevent.
5. **Real fixture discipline.** Per Lesson 2 + v15's four-bugs-
   caught track record: commit an `hdiutil create -fs APFS`
   fixture in Session 4 Phase C and trust the real bytes over
   synth round-trips. The APFS on-disk format has more
   opportunities for byte-offset errors than any v15 filesystem
   (OID descriptors, B-tree node layouts, fsroot records, J_EXTENT
   records, OMAP mappings, CP descriptor ring).

## Recommendation

Sessions 3–5 are unblocked. The architectural decisions are:

- Path A (held handle, `Mutex<ApfsWalker<PartitionReader>>`)
- Current-state only for v16; snapshots deferred to v17 with
  tripwire
- Multi-volume path convention `/vol{N}:{path}` (numeric index,
  deterministic, POSIX-compatible colon separator)
- Encryption surfaced via `VfsAttributes.encrypted`; `read_file`
  returns `Err` on encrypted content, never ciphertext
- Fusion containers return `Unsupported` at superblock-detection
  time with literal `"fusion"` pickup signal
- Heuristic scanners in the existing code retired or feature-
  gated, not wrapped into the walker

LOC estimates land within v15 precedent. Session 4's dual-sprint
structure is the highest-risk piece; the queue's existing exFAT-
defer clause is the correct escape valve if scope balloons.

The 13 Send/Sync probes live at
`crates/strata-fs/src/apfs.rs::_apfs_send_sync_probe`. They will
guard against any future refactor that introduces a `!Send` type
— if a new `Rc` / `RefCell` / `Cell` / `parking_lot` primitive
appears in an APFS public type, the probes fail and the architect
revisits the research doc before shipping.

**No blockers identified. Proceed with Session 3 as scheduled.**
