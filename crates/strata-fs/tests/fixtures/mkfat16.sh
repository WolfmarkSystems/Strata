#!/usr/bin/env bash
#
# mkfat16.sh — macOS-native FAT16 fixture generator for the
# FatWalker integration tests.
#
# Chose FAT16 over FAT32 for committable size: FAT32 requires
# ≥65525 clusters which at 512-byte sectors forces ≥33 MiB image
# size. A 16 MiB FAT16 volume still exercises every walker code
# path except the FAT32 root-cluster-is-a-chain case, which is
# covered by synth unit tests inside fat_walker/mod.rs.
#
# Non-determinism note — same caveat as mkhfsplus.sh: newfs_msdos
# does not offer deterministic UUID/timestamp options. Regenerating
# produces a valid FAT16 volume with the same content tree but a
# different volume ID and FAT-entry allocation. Tests match on
# structural invariants + file content, not byte hashes.
#
# Expected contents (matches fat16_small.expected.json):
#   /readme.txt                     (12 bytes, single cluster)
#   /big.bin                        (5000 bytes, spans 3 clusters)
#   /Long Filename Example.txt      (20 bytes, LFN chain)
#   /dir1/dir2/dir3/deep.txt        (7 bytes, 3-level nesting)
#
# Linux hosts: substitute `mkfs.fat -F 16` from dosfstools and
# loopback mount.
#
# Usage:
#   cd crates/strata-fs/tests/fixtures
#   ./mkfat16.sh

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

IMG="fat16_small.img"
LABEL="STRATAFAT"
SIZE_MIB=16

if [[ "$(uname)" != "Darwin" ]]; then
  echo "mkfat16.sh requires macOS (uses hdiutil + newfs_msdos)." >&2
  exit 2
fi
command -v hdiutil >/dev/null || { echo "hdiutil missing" >&2; exit 2; }
command -v /sbin/newfs_msdos >/dev/null || {
  echo "/sbin/newfs_msdos missing" >&2; exit 2;
}

if [[ -f "$IMG" ]]; then
  echo "refusing to overwrite existing $IMG" >&2
  exit 3
fi

dd if=/dev/zero of="$IMG" bs=1048576 count="$SIZE_MIB" status=none

DEV=$(hdiutil attach -nomount -nobrowse "$IMG" | head -1 | awk '{print $1}')
trap 'hdiutil detach "$DEV" 2>/dev/null || true' EXIT

/sbin/newfs_msdos -F 16 -v "$LABEL" "$DEV" >/dev/null
hdiutil detach "$DEV" >/dev/null
trap - EXIT

MNT=$(hdiutil attach -nobrowse "$IMG" | tail -1 | awk '{print $3}')
if [[ -z "$MNT" ]]; then
  MNT="/Volumes/$LABEL"
fi
trap 'diskutil unmount "$MNT" 2>/dev/null || true' EXIT

printf 'hello fat16\n' > "$MNT/readme.txt"
mkdir -p "$MNT/dir1/dir2/dir3"
printf 'buried\n' > "$MNT/dir1/dir2/dir3/deep.txt"
printf 'needs long filename\n' > "$MNT/Long Filename Example.txt"
python3 -c "import sys; sys.stdout.buffer.write(b'X' * 5000)" > "$MNT/big.bin"

# Strip macOS AppleDouble sidecar files — they'd pollute the
# enumeration manifest otherwise.
dot_clean -m "$MNT" >/dev/null 2>&1 || true
sync
diskutil unmount "$MNT" >/dev/null
trap - EXIT

actual=$(stat -f %z "$IMG")
expected=$((SIZE_MIB * 1024 * 1024))
if [[ "$actual" != "$expected" ]]; then
  echo "size mismatch: got $actual, expected $expected" >&2
  exit 6
fi

echo "OK: $IMG ($actual bytes, label=$LABEL, fs=FAT16)"
