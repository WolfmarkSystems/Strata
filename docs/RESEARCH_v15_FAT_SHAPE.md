# RESEARCH_v15_FAT_SHAPE.md — FAT12/FAT16/FAT32 parser audit

*v15 Session E Sprint 1 Phase A. Produced before writing the FAT
walker implementation — same discipline that caught two latent
HFS+ bugs in Session D.*

*Date: 2026-04-19*

## 1. Existing parser surface (audit)

`crates/strata-fs/src/fat.rs` (227 LOC) and
`crates/strata-fs/src/exfat.rs` (169 LOC) are **boot-sector + FSInfo
fingerprint parsers only**. They do not walk the FAT table, follow
cluster chains, parse directory entries, decode LFN chains, or read
file content.

### `Fat32BootSector` struct — FAT32-biased but largely reusable

The existing struct name is misleading — its field set covers both
FAT16 and FAT32 BPBs, with FAT32-specific fields (`fsinfo_sector`,
`root_cluster`, `sectors_per_fat_32`) populated only when relevant.
Methods `total_sectors`, `cluster_size_bytes`, `fat_size_sectors`,
`first_data_sector`, `data_sectors`, `clusters`, `volume_label_str`
already handle the FAT12/16/32 distinction correctly via the
if-nonzero fallback pattern (e.g. `sectors_per_fat_32 != 0 ? _32 :
_16`).

**Walker can consume the existing struct unchanged** for variant
discrimination and geometry calculation. Parser implementation adds
FAT-table reading + cluster-chain walking + directory-entry decoding
+ LFN assembly on top.

### `fat32_fast_scan` — one-shot boot-sector parser

Takes an `EvidenceContainerRO`, reads the first 512 bytes, populates
the boot sector struct, and reads FSInfo if FAT32. Not reusable as-is
for walker construction because the walker wants a `Read + Seek +
Send + 'static` reader (matching the NtfsWalker / Ext4Walker /
HfsPlusWalker pattern), not an evidence container.

### `exfat.rs` — out of scope

exFAT on-disk format is distinct from FAT12/16/32. Per the SPRINTS_v15
explicit clause: **defer exFAT if scope balloons.** This audit carries
that decision forward — Session E ships FAT12/16/32 and leaves exFAT
for a follow-up sprint.

## 2. FAT spec facts (from Microsoft FAT32 File System Specification)

### Endianness

**FAT is little-endian on disk.** Opposite of HFS+. Every multi-byte
integer in the BPB, FAT table, and directory entry is stored LE. Use
`u16::from_le_bytes` / `u32::from_le_bytes` throughout.

### FAT variant discrimination (the canonical rule)

```
let root_dir_sectors = ((root_entries * 32) + (bytes_per_sector - 1)) / bytes_per_sector;
let data_sectors = total_sectors - (reserved_sectors + num_fats * fat_size + root_dir_sectors);
let cluster_count = data_sectors / sectors_per_cluster;

match cluster_count {
    _ if cluster_count < 4085  => FatVariant::Fat12,
    _ if cluster_count < 65525 => FatVariant::Fat16,
    _                          => FatVariant::Fat32,
}
```

Rationale: these exact cluster-count thresholds are how Microsoft's
reference implementation determines FAT type. FAT12 and FAT16 each
have their own on-disk cluster-entry width; FAT32 uses 32-bit
entries. **Do NOT discriminate via the `fs_type` label** at BPB
offset 0x36 (for FAT12/16) or 0x52 (for FAT32) — that label is
informational, sometimes wrong, and legally not authoritative per
the spec.

### FAT table layout

- **FAT12:** each entry is 12 bits, two entries packed in 3 bytes.
- **FAT16:** each entry is a 16-bit LE integer.
- **FAT32:** each entry is a 32-bit LE integer, but only the low 28
  bits are meaningful. Mask with `0x0FFFFFFF` when reading.

FAT12 packed entry read (critical bit-manipulation):

```rust
let byte_offset = (cluster * 3) / 2;
let packed = u16::from_le_bytes([fat[byte_offset], fat[byte_offset + 1]]);
let entry = if cluster % 2 == 0 {
    packed & 0x0FFF            // even cluster: low 12 bits
} else {
    packed >> 4                // odd cluster: high 12 bits
};
```

Getting `% 2` direction wrong is a classic off-by-one FAT12 bug —
the fixture must exercise both parities to catch it.

### End-of-chain and bad-cluster sentinels

| Variant | Normal range | EOC (end of chain) | Bad cluster |
|---|---|---|---|
| FAT12 | 0x002..0xFEF | 0xFF8..0xFFF | 0xFF7 |
| FAT16 | 0x0002..0xFFEF | 0xFFF8..0xFFFF | 0xFFF7 |
| FAT32 | 0x0000_0002..0x0FFF_FFEF | 0x0FFF_FFF8..0x0FFF_FFFF | 0x0FFF_FFF7 |

Cluster 0 and cluster 1 are reserved — they never appear as
filesystem content. Cluster 0's entry contains the media descriptor
(informational); cluster 1's entry has dirty-state and error flags
(FAT16/32 only).

When walking a chain: stop on any value ≥ EOC_LOW. Flag bad-cluster
sentinel (0xFF7 / 0xFFF7 / 0x0FFF_FFF7) distinctly — those mean
"corrupt sectors inside the file" and examiners need the signal.

### Root directory

- **FAT12/FAT16:** fixed-size region starting immediately after the
  FAT tables. Size = `root_entries * 32` bytes. NOT a cluster chain.
- **FAT32:** root is a normal cluster chain starting at
  `boot.root_cluster` (typically cluster 2). Size unlimited.

Walker must branch on variant here.

### Directory entry (32 bytes, fixed)

| Offset | Size | Field |
|---|---|---|
| 0 | 11 | name (8.3 form — first 8 chars + 3-char extension, space-padded) |
| 11 | 1 | attributes |
| 12 | 1 | reserved (case info on some implementations) |
| 13 | 1 | creation time (tenths of second) |
| 14 | 2 | creation time (HMS packed, LE u16) |
| 16 | 2 | creation date (packed, LE u16) |
| 18 | 2 | last access date |
| 20 | 2 | high 16 bits of first cluster (FAT32; 0 on FAT12/16) |
| 22 | 2 | last write time |
| 24 | 2 | last write date |
| 26 | 2 | low 16 bits of first cluster |
| 28 | 4 | file size (u32 LE) |

Attribute byte bits:

| Bit | Mask | Meaning |
|---|---|---|
| 0 | 0x01 | read-only |
| 1 | 0x02 | hidden |
| 2 | 0x04 | system |
| 3 | 0x08 | volume label |
| 4 | 0x10 | directory |
| 5 | 0x20 | archive |

**`0x0F = read-only + hidden + system + volume` is the LFN sentinel**
— any entry with attribute byte exactly 0x0F is a long filename
fragment, not a real file.

### Deleted entries

First byte of name = `0xE5` means the entry was deleted. The rest of
the entry is typically intact and the cluster chain is usually still
reachable until overwritten — key forensic recovery vector. Walker
surface: skip by default, expose via `list_deleted` / future
`--include-deleted` flag.

First byte = `0x00` means "end of directory" — no entries follow in
this cluster.

### Long filename (LFN) entries

Each LFN entry holds 13 UTF-16LE units (name fragment). Multiple
entries chain together to form one long filename, stored in reverse
order *immediately preceding* the short-name entry.

LFN entry layout (attribute byte 0x0F):

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | ordinal (0x40 | sequence number on last-in-chain; sequence only otherwise) |
| 1 | 10 | name chars 1–5 (UTF-16LE × 5) |
| 11 | 1 | attributes = 0x0F |
| 12 | 1 | type (0) |
| 13 | 1 | **checksum** (of corresponding 8.3 name) |
| 14 | 12 | name chars 6–11 |
| 26 | 2 | cluster (0 — ignored) |
| 28 | 4 | name chars 12–13 |

LFN checksum algorithm (cross-validates LFN chain against the
short-name it describes):

```rust
fn short_name_checksum(eight_three: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in eight_three {
        sum = ((sum & 1) << 7)
            .wrapping_add(sum >> 1)
            .wrapping_add(b);
    }
    sum
}
```

**Getting this wrong is classic defense-attorney territory.** The
right-shift-plus-low-bit-rotate is easy to misread. The committed
fixture will exercise this via the "Long Filename Example.txt" entry
— if the checksum math is wrong, the walker surfaces the short name
(e.g. "LONGFI~1.TXT") instead of the long name, and the real-fixture
test fails immediately.

### Date/time encoding

Packed u16s, little-endian:

```
date = (year - 1980) << 9 | month << 5 | day
time = hour << 11 | minute << 5 | (second >> 1)
```

The 2-second resolution on time is lossy; walker stores raw u16s +
derived chrono::NaiveDateTime in local time (FAT doesn't record
timezone — everything is local-time to the host that wrote the
entry).

## 3. Real-fixture sanity

A 16 MiB FAT16 volume generated this session via `newfs_msdos -F 16`
produces a BPB with:

- `bytes_per_sector = 512`
- `sectors_per_cluster = 4` → cluster size 2048 bytes
- `reserved_sectors = 1`
- `fat_count = 2`
- `root_entries = 512`
- `total_sectors = 32768`
- `sectors_per_fat_16 = 32`

Computed: FAT region covers sectors 1–64, root directory covers
sectors 65–96, data region starts at sector 97. Cluster count =
(32768 - 97) / 4 = 8167 — which correctly identifies as FAT16 (8167
< 65525, > 4085).

The populated fixture contains:

- `/readme.txt` (12 bytes, fits in one cluster)
- `/big.bin` (5000 bytes, spans 3 clusters at 2048 bytes/cluster)
- `/Long Filename Example.txt` (20 bytes, uses LFN chain)
- `/dir1/dir2/dir3/deep.txt` (7 bytes, exercises nested directory
  cluster chain walking)

Four test cases — short name, multi-cluster, LFN, nested three
levels — cover the parser's critical paths.

## 4. Scope for Sprint 1 Phase B implementation

### Module layout

- `crates/strata-fs/src/fat_walker/mod.rs` — `FatWalker`,
  `FatFilesystem`, VFS trait impl
- `crates/strata-fs/src/fat_walker/adapter.rs` — reuses
  `PartitionReader` from `ntfs_walker::adapter` (no new adapter
  type needed)

### New types

- `FatVariant { Fat12, Fat16, Fat32 }` — discrimination enum
- `FatBpb` — BPB + computed geometry (reuse `Fat32BootSector` as
  inner, add variant + layout fields)
- `FatDirEntry` — parsed 32-byte directory entry
- `FatFilesystem` — parsed volume state with held `Read + Seek`
  handle behind the struct (Path A — same as HfsPlusFilesystem)

### Safety bounds

Same discipline as HFS+ and ext4:

- `.get(range).ok_or(VfsError::Other)` on every slice access
- Iteration cap on cluster chains (e.g. 1,000,000 clusters) to
  prevent a hostile cycle from looping forever
- UTF-16LE decoding via `String::from_utf16` → `Err` on invalid
  surrogates (not lossy)
- LFN checksum **validated** before accepting the long name;
  checksum mismatch → fall back to short name

### Estimated LOC

~500 lines:

- ~150 BPB + variant + geometry parsing
- ~100 FAT table reader (12-bit packed is the trickiest)
- ~150 directory iterator + LFN assembler + attribute mapping
- ~100 walker VFS trait impl + path resolution

Plus ~200 LOC of tests (synth + real-fixture integration).

## 5. Session D lesson carried forward

The synth-test-lockstep hazard that hid two HFS+ parser bugs through
v14 + Session C: when the test fixture builder and the parser are
both written in the same session against the same spec reference,
unit tests prove only internal consistency, not spec conformance.

**Mitigation applied for FAT:**

1. **Generate the real fixture FIRST** — done this session before
   writing any parser code. The committed `fat16_small.img` is
   produced by macOS's `newfs_msdos` with macOS's native kernel
   file-copy path, so its bytes reflect a reference implementation.
2. **Synth tests written to match real-tool output** — when writing
   Phase B, any synth test bytes should be derived from hex-dumping
   the real fixture's corresponding structure, not re-derived from
   the spec.
3. **Real-fixture integration tests are the source of truth** —
   if synth and real disagree, the real fixture wins. The parser
   bug gets fixed; the synth test gets regenerated from real bytes.

## 6. Recommendation

Proceed with Phase B implementation. The existing fat.rs boot-sector
parser is a clean starting point; the walker module is new code
~500 LOC. Fixture is already committed. FAT12 packed-entry reads
and LFN checksum validation are the two spec-sensitive spots that
need real-fixture test coverage from commit one.

**No blockers.**
