# strata-fs walker test fixtures

Binary filesystem images + reproducible generation scripts +
expected-enumeration manifests consumed by the `Ext4Walker`,
`HfsPlusWalker`, and `FatWalker` integration tests.

## Layout

| Filesystem | Fixture image | Generator | Manifest | Committed? |
|---|---|---|---|:---:|
| ext4 | `ext4_small.img` (2 MiB) | `mkext4.sh` | `ext4_small.expected.json` | **no** — Linux-only generation |
| HFS+ | `hfsplus_small.img` (2 MiB) | `mkhfsplus.sh` | `hfsplus_small.expected.json` | **yes** — committed one-time snapshot |
| FAT16 | `fat16_small.img` (16 MiB) | `mkfat16.sh` | `fat16_small.expected.json` | **yes** — committed one-time snapshot |

## FAT16 — macOS-native generation, fixture committed

`fat16_small.img` IS committed directly (16 MiB). Generation uses
macOS base-system tools (`hdiutil` + `newfs_msdos`), no Homebrew
or Linux VM required.

FAT16 chosen over FAT32 for committable size: FAT32 requires
≥65525 clusters which at 512-byte sectors forces ≥33 MiB image
size. A 16 MiB FAT16 volume exercises every walker code path
except the FAT32-root-is-a-cluster-chain case (covered by synth
unit tests inside `fat_walker/mod.rs`).

Like HFS+, `newfs_msdos` isn't byte-stable across regenerations
(volume ID + FAT entries allocated slightly differently); tests
match on structural invariants + file content, not byte hashes.

### Regenerating FAT16

```bash
cd crates/strata-fs/tests/fixtures
./mkfat16.sh   # macOS host; produces fat16_small.img
```

## ext4 — Linux-only generation, fixture not committed

`ext4_small.img` must be generated on a Linux host with `e2fsprogs`
installed (`mkfs.ext4`) and loopback-mount privileges. macOS
developer machines lack `mkfs.ext4`, Docker, and QEMU, so the
binary fixture generation is deferred to a Linux CI runner or a
Linux developer machine.

Integration tests
(`ext4_walker::tests::walker_on_committed_fixture_enumerates_expected_paths`)
skip-guard on `ext4_small.img` presence: when absent, the test
prints `SKIP` and exits 0; when present, it validates enumeration
against `ext4_small.expected.json` exactly.

`mkext4.sh` is deterministic (fixed UUID, fixed label,
`SOURCE_DATE_EPOCH=0`) — running it twice on the same platform
yields byte-identical output.

### Regenerating ext4

```bash
cd crates/strata-fs/tests/fixtures
./mkext4.sh     # Linux host; produces ext4_small.img
```

## HFS+ — macOS-native generation, fixture committed

`hfsplus_small.img` IS committed directly as a one-time snapshot.
Generation uses macOS base-system tools (`hdiutil` + `newfs_hfs`),
no Homebrew or Linux VM required.

Unlike ext4, HFS+ generation via `newfs_hfs` is **not byte-stable** —
every regeneration produces a new volume UUID and new inode
timestamps. Committing one snapshot + testing against structural
invariants (file/folder names, parent-child relationships,
directory structure) is the honest discipline here.

Integration tests
(`hfsplus_walker::tests::walker_on_committed_fixture_enumerates_expected_structure`)
walk the committed image and cross-reference
`hfsplus_small.expected.json`.

### Regenerating HFS+

```bash
cd crates/strata-fs/tests/fixtures
./mkhfsplus.sh   # macOS host; produces hfsplus_small.img
```

The script refuses to overwrite an existing `.img` — delete it
manually if you intend to regenerate, and expect the new snapshot
to differ from the committed one in UUID/timestamp fields even
though the user-visible file/folder tree is identical.

## Acceptance contracts

A committed `ext4_small.img` SHALL:

- Be exactly 2 MiB (2,097,152 bytes)
- Contain a valid ext4 filesystem (`mkfs.ext4 -L strata-ext4`)
- Populate the root directory and nested directories per
  `ext4_small.expected.json`
- Reproduce bit-for-bit given the script + its environment

A committed `hfsplus_small.img` SHALL:

- Be exactly 2 MiB (2,097,152 bytes)
- Contain a valid HFS+ filesystem with label `STRATA-HFS`
- Populate the following structure:
  - `/readme.txt` (11 bytes, data fork only)
  - `/forky.txt` (14 bytes data fork + 9 bytes resource fork)
  - `/docs/nested/buried.txt` (13 bytes, three levels deep)
- Surface real catalog records via `HfsPlusFilesystem::read_catalog`
  (no stub placeholder — see Session D Phase B Part 1 for the
  implementation)
