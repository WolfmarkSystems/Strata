#!/usr/bin/env bash
#
# mkhfsplus.sh — reproducible HFS+ fixture generator for the
# HfsPlusWalker integration test. Unlike the ext4 fixture (which
# requires a Linux host because macOS lacks mkfs.ext4), HFS+
# generation runs natively on macOS via the base-system tools
# `hdiutil` and `newfs_hfs` — no Homebrew, no Docker, no Linux VM.
#
# Linux hosts: HFS+ userspace tooling exists (`hfsprogs` package)
# but is heavier; prefer running this script on macOS where the
# base system provides everything.
#
# Determinism notes:
#   - newfs_hfs does NOT accept deterministic-UUID or timestamp
#     overrides. Running this script twice on the same macOS
#     version produces IMG files that DIFFER in their volume UUID
#     and creation timestamps. A committed fixture is therefore
#     a one-time snapshot, not a byte-stable regeneration target.
#   - For full byte-stability, a future revision could hex-patch
#     the known UUID/date offsets — out of scope here.
#   - The walker tests match against file/folder names + structural
#     invariants (is_directory, parent relationships), not raw bytes,
#     which tolerates the non-deterministic metadata.
#
# Expected contents (matches hfsplus_small.expected.json):
#   /readme.txt                          (11 bytes)
#   /forky.txt                           (15 bytes data fork, 9 bytes rsrc)
#   /docs                                (directory)
#   /docs/nested                         (directory)
#   /docs/nested/buried.txt              (13 bytes)
#
# Usage:
#   cd crates/strata-fs/tests/fixtures
#   ./mkhfsplus.sh
# Output: hfsplus_small.img (2 MiB)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

IMG="hfsplus_small.img"
LABEL="STRATA-HFS"
SIZE_MIB=2

if [[ "$(uname)" != "Darwin" ]]; then
  echo "mkhfsplus.sh requires macOS (uses hdiutil + newfs_hfs)." >&2
  echo "On Linux, install hfsprogs and adapt the commands below." >&2
  exit 2
fi

command -v hdiutil >/dev/null || {
  echo "hdiutil not found — macOS base tool missing?" >&2
  exit 2
}
command -v /sbin/newfs_hfs >/dev/null || {
  echo "/sbin/newfs_hfs not found" >&2
  exit 2
}

if [[ -f "$IMG" ]]; then
  echo "refusing to overwrite existing $IMG" >&2
  echo "delete it manually if you intend to regenerate" >&2
  exit 3
fi

# 1. Allocate the raw image.
dd if=/dev/zero of="$IMG" bs=1048576 count="$SIZE_MIB" status=none

# 2. Attach (no mount) so we can format the raw device.
DEV=$(hdiutil attach -nomount -nobrowse "$IMG" | head -1 | awk '{print $1}')
if [[ -z "$DEV" ]]; then
  echo "hdiutil attach failed" >&2
  exit 4
fi
trap 'hdiutil detach "$DEV" 2>/dev/null || true' EXIT

# 3. Create the HFS+ filesystem.
/sbin/newfs_hfs -v "$LABEL" "$DEV" >/dev/null

# 4. Detach to remount with read-write mount-point.
hdiutil detach "$DEV" >/dev/null
trap - EXIT

# 5. Re-attach for mount.
MNT=$(hdiutil attach -nobrowse "$IMG" | tail -1 | awk '{print $3}')
if [[ -z "$MNT" ]]; then
  MNT="/Volumes/$LABEL"
fi
if [[ ! -d "$MNT" ]]; then
  echo "expected mount point $MNT not present" >&2
  exit 5
fi
trap 'diskutil unmount "$MNT" 2>/dev/null || true' EXIT

# 6. Populate.
printf 'hello hfs+\n' > "$MNT/readme.txt"
mkdir -p "$MNT/docs/nested"
printf 'deep content\n' > "$MNT/docs/nested/buried.txt"

printf 'file with fork' > "$MNT/forky.txt"
printf 'RSRC_DATA' > "$MNT/forky.txt/..namedfork/rsrc"

sync

# 7. Unmount.
diskutil unmount "$MNT" >/dev/null
trap - EXIT

# 8. Final size check.
actual=$(stat -f %z "$IMG")
expected=$((SIZE_MIB * 1024 * 1024))
if [[ "$actual" != "$expected" ]]; then
  echo "size mismatch: got $actual, expected $expected" >&2
  exit 6
fi

echo "OK: $IMG ($actual bytes, label=$LABEL, fs=HFS+)"
echo "Non-deterministic UUID/timestamps — commit as a one-time snapshot."
