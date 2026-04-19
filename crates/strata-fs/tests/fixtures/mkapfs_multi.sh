#!/bin/bash
# mkapfs_multi.sh — regenerate apfs_multi.img for the APFS-multi
# (CompositeVfs) walker integration tests.
#
# ⚠️  DMG LIMITATION — READ BEFORE RUNNING
#
# macOS's hdiutil and newfs_apfs produce DMG/sparseimage-backed
# APFS containers with NxSuperblock.max_file_systems = 1, meaning
# `diskutil apfs addVolume` fails with error -69493 ("can't add
# any more APFS Volumes to its APFS Container") on any second
# attempt, regardless of container size (verified at 20 MB, 60 MB,
# 100 MB, 200 MB, and on UDIF DMG / sparseimage / RAM disk
# backing). Physical APFS drives (built-in SSD, external USB/TB)
# ship with max_file_systems ~100 and support addVolume cleanly.
#
# This is a macOS disk-image infrastructure limitation, not a
# Strata or apfs-crate bug.
#
# CONSEQUENCES FOR STRATA:
#
# - The multi-volume APFS fixture `apfs_multi.img` canNOT be
#   generated on a developer workstation using only built-in tools
#   + disk images. A real two-volume container requires either:
#     (a) a physical APFS disk (external USB stick reformatted),
#     (b) an APFS image produced on macOS where a Mac has been
#         booted with the target container attached, or
#     (c) a sample image from an examiner's case archive.
#
# - `crates/strata-fs/src/apfs_walker/multi.rs` integration tests
#   gracefully skip when `apfs_multi.img` is absent. The walker's
#   logic is validated via:
#     * `parse_volume_scope` unit tests (8 exhaustive cases)
#     * Send+Sync probe
#     * The shared catalog/omap/extents helpers from the apfs crate
#       (real-fixture-validated against apfs_small.img in
#       Session 1.5 — the multi walker delegates to the same
#       helpers with per-volume state)
#     * Integration tests against real multi-volume containers as
#       they become available (examiner-provided evidence,
#       physical-disk forensic images)
#
# USAGE (physical drive — destroys data on target device):
#
#   # 1. Plug in an empty external drive. Identify via `diskutil list`.
#   DEV=/dev/diskN                     # e.g. /dev/disk8
#
#   # 2. Erase as APFS (creates container with max_file_systems=100).
#   diskutil eraseDisk APFS STRATA-MAIN $DEV
#
#   # 3. Identify the synthesized container.
#   CONTAINER=$(diskutil list $DEV \
#       | awk '/Apple_APFS[[:space:]]+Container[[:space:]]+disk/ {
#               for(i=1;i<=NF;i++) if ($i ~ /^disk[0-9]+$/) { print $i; exit }
#             }')
#
#   # 4. Add second volume.
#   diskutil apfs addVolume $CONTAINER APFS STRATA-DATA
#
#   # 5. Populate.
#   printf 'vol0-marker\n' > /Volumes/STRATA-MAIN/marker.txt
#   mkdir -p /Volumes/STRATA-MAIN/dir_a
#   printf 'inner-a\n' > /Volumes/STRATA-MAIN/dir_a/inner.txt
#   printf 'vol1-marker\n' > /Volumes/STRATA-DATA/marker.txt
#   python3 -c "import sys; sys.stdout.buffer.write(b'D' * 8192)" \
#       > /Volumes/STRATA-DATA/multi.bin
#
#   # 6. Unmount + dd to flat image.
#   diskutil unmountDisk $DEV
#   dd if=$DEV of=crates/strata-fs/tests/fixtures/apfs_multi.img bs=1m
#
#   # 7. Verify: multi walker integration tests pass.
#   cargo test -p strata-fs apfs_walker::multi
#
# If you ship a fixture via this recipe, please commit with it the
# expected manifest at `apfs_multi.expected.json` — same pattern as
# apfs_small, hfsplus_small, etc.

set -euo pipefail

echo "This script documents the regeneration recipe for apfs_multi.img." >&2
echo "Automatic generation via hdiutil/newfs_apfs is not possible on macOS" >&2
echo "due to the DMG-backed max_file_systems=1 limitation." >&2
echo "" >&2
echo "See the comment block at the top of this file for the manual recipe" >&2
echo "using a physical APFS drive." >&2
exit 0
