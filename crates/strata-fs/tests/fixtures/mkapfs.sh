#!/bin/bash
# mkapfs.sh — regenerate apfs_small.img via hdiutil.
#
# Produces a 10 MB flat APFS container with reproducible content
# for the APFS walker's real-fixture integration tests. Matches
# the fixture originally generated in v16 Session 1.5's
# `/tmp/apfs_probe_fixture.img` that validated the external
# `apfs` crate against real hdiutil bytes (7/7 core checks
# passed).
#
# Requires macOS (hdiutil + xattr). Linux / CI hosts should use
# the committed `apfs_small.img` rather than regenerate.
#
# Usage:
#   cd crates/strata-fs/tests/fixtures
#   ./mkapfs.sh

set -euo pipefail

OUT_DIR="$(cd "$(dirname "$0")" && pwd)"
SPARSE="$OUT_DIR/apfs_small.sparseimage"
FLAT="$OUT_DIR/apfs_small.img"

command -v hdiutil >/dev/null || {
    echo "error: hdiutil not found (requires macOS)" >&2
    exit 1
}

if [[ -f "$SPARSE" ]]; then
    echo "error: $SPARSE already exists — delete before regenerating" >&2
    exit 2
fi
if [[ -f "$FLAT" ]]; then
    echo "error: $FLAT already exists — delete before regenerating" >&2
    exit 2
fi

# 1. Create sparse APFS container.
hdiutil create -size 10m -fs APFS -volname "STRATA-APFS" \
    -type SPARSE "$OUT_DIR/apfs_small"

# 2. Attach + populate.
ATTACH_OUT=$(hdiutil attach "$SPARSE")
MNT="/Volumes/STRATA-APFS"
trap 'hdiutil detach "$MNT" 2>/dev/null || true; rm -f "$SPARSE"' EXIT

printf 'alpha\n'   > "$MNT/alpha.txt"
printf 'beta\n'    > "$MNT/beta.txt"
printf 'gamma\n'   > "$MNT/gamma.txt"
mkdir -p "$MNT/dir1/dir2/dir3"
printf 'deep\n' > "$MNT/dir1/dir2/dir3/deep.txt"
python3 -c "import sys; sys.stdout.buffer.write(b'Z' * 12000)" > "$MNT/multi.bin"
printf 'fork\n' > "$MNT/forky.txt"
xattr -w com.strata.test "probe_value" "$MNT/forky.txt"

sync
diskutil unmount "$MNT"
DEV=$(echo "$ATTACH_OUT" | head -1 | awk '{print $1}')
hdiutil detach "$DEV"

# 3. Re-attach raw device and dd to flat container. The hdiutil
#    convert UDRO path produces a DMG wrapper; we want raw bytes
#    so that File::open(apfs_small.img) → ApfsVolume::open reads
#    byte 0 = container superblock directly.
DEV=$(hdiutil attach -nomount "$SPARSE" | head -1 | awk '{print $1}')
dd if="$DEV" of="$FLAT" bs=1m
hdiutil detach "$DEV"
rm -f "$SPARSE"
trap - EXIT

# 4. Sanity check: NXSB magic at offset 32.
if ! python3 -c "
import sys
with open('$FLAT', 'rb') as f:
    f.seek(32)
    magic = f.read(4)
    if magic != b'NXSB':
        sys.stderr.write(f'expected NXSB magic at offset 32, got {magic!r}\n')
        sys.exit(1)
"; then
    echo "error: fixture regeneration produced bytes that don't start with a valid APFS container" >&2
    exit 3
fi

echo "OK: $FLAT ($(stat -f %z "$FLAT") bytes)"
echo "Contains: alpha.txt beta.txt gamma.txt forky.txt multi.bin"
echo "          dir1/dir2/dir3/deep.txt"
echo "          + macOS .fseventsd metadata (automatic)"
