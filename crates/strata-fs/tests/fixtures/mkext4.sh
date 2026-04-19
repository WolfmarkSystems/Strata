#!/usr/bin/env bash
#
# mkext4.sh — reproducible ext4 fixture generator for the Ext4Walker
# integration test.
#
# Runs on Linux (requires e2fsprogs, root or sudo for loopback mount).
# macOS dev boxes should run this on a Linux CI host and commit the
# resulting ext4_small.img — the fixture is binary and must be
# generated once on a platform with mkfs.ext4.
#
# Determinism:
#   - Fixed file contents (literal strings; no random bytes).
#   - Fixed timestamps (SOURCE_DATE_EPOCH=0 → 1970-01-01 epoch).
#   - Fixed UUID via -U fixed-uuid option to mkfs.ext4.
#   - Fixed volume label "strata-ext4".
# Running this script twice on the same platform must yield
# byte-identical output.
#
# Acceptance manifest: ext4_small.expected.json
#
# Usage:
#   cd crates/strata-fs/tests/fixtures
#   ./mkext4.sh

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

IMG="ext4_small.img"
MNT="$(mktemp -d)"
SIZE_BYTES=$((2 * 1024 * 1024))  # 2 MiB
LABEL="strata-ext4"
UUID="00000000-0000-0000-0000-000000000001"

command -v mkfs.ext4 >/dev/null || {
  echo "mkfs.ext4 not found — install e2fsprogs" >&2
  exit 2
}
command -v sudo >/dev/null || {
  echo "sudo required to loopback-mount the image" >&2
  exit 2
}

if [[ -f "$IMG" ]]; then
  echo "refusing to overwrite existing $IMG" >&2
  echo "delete it manually if you intend to regenerate" >&2
  exit 3
fi

# 1. Pre-size the image.
dd if=/dev/zero of="$IMG" bs=1M count=2 status=none

# 2. mkfs.ext4 with deterministic options.
mkfs.ext4 -q \
  -L "$LABEL" \
  -U "$UUID" \
  -E nodiscard,no_copy_xattrs \
  -O ^has_journal,^uninit_bg,^dir_index \
  -I 128 \
  -N 64 \
  -F "$IMG"

# 3. Mount read-write to populate.
sudo mount -o loop,nosuid,noexec,nodev "$IMG" "$MNT"
trap 'sudo umount "$MNT" 2>/dev/null || true; rmdir "$MNT" 2>/dev/null || true' EXIT

# Force deterministic timestamps everywhere.
export SOURCE_DATE_EPOCH=0

# 4. Populate per the expected manifest.
echo -n "hello ext4 walker" | sudo tee "$MNT/readme.txt" >/dev/null
sudo mkdir -p "$MNT/dir1/dir2/dir3"
echo -n "deep content" | sudo tee "$MNT/dir1/dir2/dir3/deep.txt" >/dev/null
echo -n "one two three four" | sudo tee "$MNT/multi.txt" >/dev/null

# 5. Force every timestamp to epoch.
sudo find "$MNT" -exec touch -a -m -d "@0" {} +

# 6. Flush + unmount.
sudo sync
sudo umount "$MNT"
rmdir "$MNT" 2>/dev/null || true
trap - EXIT

# 7. Final size check.
actual_size=$(stat -c %s "$IMG" 2>/dev/null || stat -f %z "$IMG")
if [[ "$actual_size" != "$SIZE_BYTES" ]]; then
  echo "size mismatch: got $actual_size, expected $SIZE_BYTES" >&2
  exit 4
fi

echo "OK: $IMG ($actual_size bytes, label=$LABEL, uuid=$UUID)"
