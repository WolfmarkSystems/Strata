# ext4 test fixture

This directory holds the binary fixture consumed by `strata-fs`'s
`Ext4Walker` integration test.

## Files

| File | Committed? | Purpose |
|---|:---:|---|
| `mkext4.sh` | yes | Reproducible generation script for `ext4_small.img` |
| `ext4_small.expected.json` | yes | Expected enumeration / metadata manifest |
| `ext4_small.img` | **no** (see below) | 2 MB ext4 filesystem image |

## Why `ext4_small.img` is not committed yet

`ext4_small.img` must be generated from a Linux host with `e2fsprogs`
installed (`mkfs.ext4`) and loopback-mount privileges. The v15
Session B run happened on a macOS developer machine where
`mkfs.ext4`, Docker, and QEMU were all unavailable, so the binary
fixture generation is deferred to a Linux CI runner or a Linux
developer machine in Session C.

Integration tests that consume the fixture
(`ext4_walker::tests::walker_on_committed_fixture_enumerates_expected_paths`)
skip-guard on `ext4_small.img` presence: when absent, the test prints
`SKIP` and exits 0; when present, it validates enumeration against
`ext4_small.expected.json` exactly.

This follows the same discipline as the NTFS walker's
`tests/ground_truth_ntfs.rs`, which skip-guards on the non-distributed
Test Material corpus.

## Regenerating the fixture

On any Linux host with `e2fsprogs`:

```bash
cd crates/strata-fs/tests/fixtures
./mkext4.sh
# produces ext4_small.img
```

The script is deterministic: given the same inputs it produces the
same `.img` byte-for-byte. If `ext4_small.img` already exists and
differs from what the script would produce, the script will error
rather than silently overwrite — this prevents accidental drift
between the committed fixture and the committed expected-json.

## Acceptance contract

A committed `ext4_small.img` SHALL:

- Be exactly 2 MiB (2,097,152 bytes).
- Contain a valid ext4 filesystem (`mkfs.ext4 -L strata-ext4`).
- Populate the root directory and nested directories per
  `ext4_small.expected.json`.
- Reproduce bit-for-bit given the script + its environment.

`ext4_walker::tests::walker_on_committed_fixture_enumerates_expected_paths`
validates the first three points by walking the committed image and
cross-referencing the manifest.
