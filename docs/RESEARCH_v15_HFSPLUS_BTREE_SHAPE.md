# RESEARCH_v15_HFSPLUS_BTREE_SHAPE.md — HFS+ Catalog B-tree audit

*v15 Session D Sprint 1 Phase A. Produced before writing the
replacement implementation for `read_catalog`'s stub body.*

*Date: 2026-04-19*

## 1. Existing parser surface (audit)

### `parse_hfsplus_btree(_data: &[u8])` — stub

`crates/strata-fs/src/hfsplus.rs:399`. The `_data` leading-underscore
parameter is the Rust convention for "unused." Body returns
`Ok(HfsPlusBtree::default())`. **Stub. No real node parsing.**

### `HfsPlusBtree` struct — metadata-only surface

```rust
pub struct HfsPlusBtree {
    pub node_size: u16,
    pub max_key_length: u16,
    pub node_count: u32,
}
```

No iteration state, no records field, no node cache. This struct is
a fingerprint surface intended for fast-scan reporting, not a
walker-grade parser. Extending it to carry leaf-iteration state would
be a design change — the cleaner move is to ship a new
iterator-shaped primitive inside `HfsPlusFilesystem` rather than
inflating the existing fingerprint struct.

### B-tree header node read (already correct)

`HfsPlusFilesystem::open_reader` at lines 222–249 (post-Phase-A
refactor) correctly reads the B-tree header node from the first
extent of the catalog file, decodes the 14-byte node descriptor, and
parses the 106-byte B-tree header record into:

- `node_size` (offset 8–9, u16 BE)
- `root_node` (offset 16–19, u32 BE)
- `first_leaf_node` (offset 24–27, u32 BE)
- `last_leaf_node` (offset 28–31, u32 BE)

These four fields are the exact entry points into real leaf-node
iteration. **Phase B does not need to re-parse the header** — it
can start from `first_leaf_node` using the already-populated
`HfsPlusCatalogFile` state.

### What's missing

- Node reading by node-index (current code reads "node 0" = header
  only)
- Node-descriptor decode for leaves (to discover `fLink`,
  `numRecords`)
- Record-offset-table decode (variable-length records are located
  via offsets stored at the end of each node)
- Catalog record-type dispatch (folder / file / thread)
- UTF-16BE filename decode preserving NFC
- Sibling-link iteration (`fLink` follows the next leaf)

## 2. HFS+ on-disk format facts (per Apple Tech Note TN1150)

### Endianness

**HFS+ is big-endian on disk.** Every multi-byte integer
(descriptor, key length, parent CNID, record type, CNID, size field,
block pointer, extent startBlock, extent blockCount, date) is stored
big-endian. Existing code in `hfsplus.rs` consistently uses
`u16::from_be_bytes` / `u32::from_be_bytes` / `u64::from_be_bytes`.
Maintain this discipline — a single `from_le_bytes` leak is a silent
data-corruption bug.

### Node structure

Every node is exactly `node_size` bytes (typically 4096 or 8192,
populated in `HfsPlusCatalogFile::node_size` at volume open time).

```
byte 0 ..= 13     BTNodeDescriptor (14 bytes)
byte 14 ..= ?     Record area (variable)
byte ? ..= end-2  Free space (possibly)
byte end-2..end   Offset table (u16 BE pointers, one per record
                  plus one sentinel pointing at first free byte)
```

### `BTNodeDescriptor` (14 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `fLink` | BE u32 — next sibling node index |
| 4 | 4 | `bLink` | BE u32 — previous sibling node index |
| 8 | 1 | `kind` | **signed i8** — see below |
| 9 | 1 | `height` | u8 — tree height at this node (leaves are 1) |
| 10 | 2 | `numRecords` | BE u16 |
| 12 | 2 | `reserved` | skip |

**`kind` discrimination:**

| Value | i8 | Kind |
|---|---|---|
| `0xFF` | `-1` | **Leaf node** ← only one that matters for walker |
| `0x00` | `0` | Index node (skip — walker uses sibling-link iteration, not tree traversal) |
| `0x01` | `1` | Header node |
| `0x02` | `2` | Map node |

### Record offset table

At the tail of each node sits an array of `numRecords + 1` big-endian
u16 values. The array is ordered **last-record-first**, so:

```
offset_at(n) = u16::from_be_bytes(node[node_size - 2*(n+1) .. node_size - 2*n])
```

Where `n` ranges `0 ..= numRecords`. Entry `0` points to the first
record; entry `numRecords` is the sentinel pointing at the first
free byte (= end of used space in the record area).

### Catalog record key (HFSPlusCatalogKey)

Each leaf record begins with a variable-length key:

```
byte 0 ..= 1     keyLength (BE u16; does NOT include itself)
byte 2 ..= 5     parentID (BE u32 — aka CNID)
byte 6 ..= 7     nodeName.length (BE u16 — count of UTF-16 units)
byte 8 ..        nodeName.unicode (length × u16 BE)
```

Total key bytes on the wire: `keyLength + 2`. The record data follows
at an **even byte boundary** — some documents specify 2-byte alignment
after the key. Safe to always align the start-of-data offset up to
the next even value.

### Catalog record data

First 2 bytes of data = record type (BE i16):

| Type | Value | Meaning | Walker treatment |
|---|---|---|---|
| `kHFSPlusFolderRecord` | 1 | Folder | Yield as directory |
| `kHFSPlusFileRecord` | 2 | File | Yield as regular file; data fork + optional resource fork |
| `kHFSPlusFolderThreadRecord` | 3 | Folder thread | **Skip for enumeration**; retain for CNID→parent-name resolution |
| `kHFSPlusFileThreadRecord` | 4 | File thread | **Skip for enumeration** |

**Thread records** are back-pointers from a CNID to `(parentID, name)`.
Used for path reconstruction. For flat enumeration (current walker
scope), skip them — they would duplicate the parent-side listing.

### HFSPlusCatalogFolder data layout

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | recordType (= 1) |
| 2 | 2 | flags |
| 4 | 4 | valence (child count) |
| 8 | 4 | folderID (this folder's CNID) |
| 12 | 4 | createDate |
| 16 | 4 | contentModDate |
| 20 | 4 | attributeModDate |
| 24 | 4 | accessDate |
| 28 | 4 | backupDate |
| 32 | 16 | permissions |
| 48 | 16 | userInfo (DInfo) |
| 64 | 16 | finderInfo (DXInfo) |
| 80 | 4 | textEncoding |
| 84 | 4 | reserved |

Total: 88 bytes.

### HFSPlusCatalogFile data layout

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | recordType (= 2) |
| 2 | 2 | flags |
| 4 | 4 | reserved1 |
| 8 | 4 | fileID (CNID) |
| 12 | 4 | createDate |
| 16 | 4 | contentModDate |
| 20 | 4 | attributeModDate |
| 24 | 4 | accessDate |
| 28 | 4 | backupDate |
| 32 | 16 | permissions |
| 48 | 16 | userInfo (FInfo) |
| 64 | 16 | finderInfo (FXInfo) |
| 80 | 4 | textEncoding |
| 84 | 4 | reserved2 |
| 88 | 80 | **dataFork** (HFSPlusForkData) |
| 168 | 80 | **resourceFork** (HFSPlusForkData) |

Total: 248 bytes. The two forks are where HFS+ "data fork vs resource
fork" handling lives at the walker layer.

### HFSPlusForkData layout (80 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | logicalSize (u64 BE) |
| 8 | 4 | clumpSize |
| 12 | 4 | totalBlocks |
| 16 | 64 | extents: 8 × { startBlock u32, blockCount u32 } |

A fork with `logicalSize == 0` has no data. This is how we detect
"no resource fork on this file" — the resource fork struct is
always present in the record but empty.

### Filename encoding

`nodeName.unicode` is **UTF-16 big-endian** with NFC-like
normalization per Apple's custom rules. For walker enumeration, the
safe path is:

1. Decode UTF-16BE units into a `String`.
2. Return the decoded string **as-is** — do NOT re-normalize. The
   queue's note on HFS+ considerations is explicit: examiners need
   original bytes preserved.

## 3. Implementation scope for Sprint 1 Phase B Part 1

### Surface to add in `hfsplus.rs`

1. Private helper `read_node(&mut self, node_idx: u32) -> Result<Vec<u8>>`
   that computes the byte offset via `node_idx * node_size` inside
   the catalog file's first extent and delegates to `read_block`
   repeatedly until the node is fully buffered (or, since block_size
   and node_size are both typically ≥512, a single aligned read may
   suffice — but implement the multi-block path correctly).
2. Private helper `parse_node_descriptor(node: &[u8]) -> BTNodeDescriptor`
   returning `{fLink, kind, numRecords}` via `try_into + from_be_bytes`.
3. Private helper `record_offsets(node: &[u8], num_records: u16) -> Vec<u16>`
   reading the tail offset table.
4. Private helper `parse_catalog_key(record: &[u8]) -> (parent_cnid,
   name, key_length)` returning the key fields.
5. Private helper `parse_catalog_record(data: &[u8]) -> Option<HfsPlusCatalogEntry>`
   dispatching on the record-type discriminator and populating the
   struct. Returns `None` for thread records (skip).
6. Replace the `read_catalog` body with:
   - Iterate nodes starting at `self.catalog_file.first_leaf_node`
   - For each node, skip non-leaf nodes (continue via fLink)
   - For leaf nodes, decode each record via offset table
   - Parse key + data into `HfsPlusCatalogEntry`
   - Follow `fLink` until `0` or we hit `last_leaf_node`
   - Return owned `Vec<HfsPlusCatalogEntry>`.

### Scope estimate

~150–250 LOC. Mechanical byte-slicing; no complex algorithms. The
discipline is correctness (endianness, offsets, alignment) not
novelty.

### Safety bounds

The catalog file could be hostile or corrupt. Every byte-slice access
must be bounds-checked (use `.get(range)` + `ok_or` rather than
direct indexing) so a malformed leaf node produces a `Result::Err`
rather than a panic. Zero `.unwrap()` tolerance per the CLAUDE.md
discipline continues.

Additionally: guard against B-tree cycles. Set an iteration cap
(e.g. 100,000 nodes) so a malicious `fLink` ring doesn't loop
forever. Documented choice in the code.

### What NOT to implement in Phase B Part 1

- Index-node traversal for name-based lookup (walker uses sibling-
  link scan for flat enumeration; name lookup is a separate
  follow-on).
- Attributes B-tree iteration (xattrs — separate B-tree, separate
  sprint).
- Extents overflow B-tree iteration (handle via resource-fork /
  data-fork's inline 8 extents; overflow chasing is a follow-on).
- Journal replay (out of walker scope per v14/v15 decisions).
- B-tree node checksum verification (not part of HFS+ spec; HFSX
  adds some but not most examiners encounter).

## 4. Ext4 vs HFS+ B-tree comparison (for context)

| Dimension | ext4 (via `ext4-view`) | HFS+ (this sprint) |
|---|---|---|
| Parser lives where? | External crate | In-tree — we own the bytes |
| Iteration primitive exists? | Yes — `fs.read_dir(path)` | No — we write it here |
| Endianness gotchas? | Little-endian | **Big-endian** — every multi-byte read |
| Record layout | Regular (fixed inode records) | Variable-length (offset table tail-packed) |
| Walker LOC | ~400 total | ~150 new parser + ~100 walker = ~250 |

The HFS+ walker ships lighter than ext4 despite being from-scratch
parser code, because there's no external-crate impedance mismatch to
adapt around.

## 5. Recommendation

**Proceed directly to Sprint 1 Phase B Part 1.** The existing B-tree
header-node decode in `open_reader` already provides the four entry
fields real iteration needs (`node_size`, `root_node`,
`first_leaf_node`, `last_leaf_node`). The B-tree record-layout audit
above captures every byte offset the decode helpers need. Safety
bounds (panic-free slice access + cycle cap) are straightforward to
enforce with `.get(range).ok_or()` patterns. Filename NFC
preservation is a function of not re-normalizing after UTF-16BE
decode.

No blockers. Expected delta: ~200 LOC of new parser + test coverage,
replacing the 28-LOC stub body of `read_catalog`.
