# Post-v16 Session C — Low-hanging fixes batch — COMPLETE

**Date:** 2026-04-20
**Trigger:** v0.16.0 real-image validation report
(`docs/FIELD_VALIDATION_REAL_IMAGES_v0.16.0.md`) — three gaps
tagged for Session C: FileVault detection (G3), Chromebook
misclassification (G7), and materialize filter scope for
Mac/iOS content (G10).
**Outcome:** three surgical commits, each with tripwire
tests. No code outside the three fix targets was modified.

## What shipped

### Fix 1 — `b28b64e`: FileVault `encrcdsa` detection

**Target:** `crates/strata-fs/src/fs_dispatch.rs`.
**Closes:** validation gap G3 (FileVault-wrapped DMGs silently
classified as "unknown filesystem").

Added `FsType::EncryptedDmgFileVault` variant with
as_str() == "FileVault-encrypted DMG". Detection fires on the
8-byte `encrcdsa` literal at byte 0, ahead of every
filesystem-magic check — confirmed against the v0.16.0 field
image `ENCRYPTED.dmg` whose first 16 bytes are
`encrcdsa\x00\x00\x00\x02\x00\x00\x00\x10`.

Dispatcher arm returns:

> "FileVault-encrypted DMG detected. Decryption is out of scope
> for Strata. Recommend offline key recovery via macOS keychain,
> institutional recovery key, or forensic decryption tooling."

Four tripwire tests:
- `detects_filevault_encrcdsa_at_byte_zero` — pins detection
- `filevault_detection_takes_precedence_over_inner_magic` —
  proves encrcdsa short-circuits even when ciphertext produces
  a false APFS match further into the first 1024 bytes
- `filevault_fs_type_str_is_stable`
- `dispatch_filevault_returns_structured_pickup_signal` —
  asserts the error names the wrapper, states decryption is
  out of scope, and names offline key recovery as remediation

### Fix 2 — `641e239`: DETECT-1 scan-root stripping + ChromeOS recovery markers

**Target:** `crates/strata-core/src/detect/mod.rs`.
**Closes:** validation gap G7 (Chromebook CTF tar
misclassified as Windows Workstation at 0.91 confidence).

Root-cause audit found **two** defects compounding into the
false positive:

1. **Examiner-workstation path pollution.** `tally_markers_for`
   lowercased the absolute path, so running Strata on macOS
   from `/Users/<name>/...` made every evidence path contain
   the substring `/users/` — tripping the Windows "Users dir"
   marker at weight 0.5 on every path. The probe showed 16+
   false "Users dir" firings on a pure-ChromeOS tree.
2. **ChromeOS markers required inputs the recovery image
   didn't have.** `/home/chronos/` (trailing slash) needs
   children to fire via substring match; on recovery images
   post-logout chronos is empty. `/etc/cros-machine-id` also
   absent.

Fixes:
- Added `scan_root` to `ScanCtx`; introduced
  `evidence_relative_path(path, scan_root)` that strips the
  root prefix before substring matching.
- Single-file inputs strip the file's PARENT instead of the
  file itself so `.mem` / `.pcap` / `.dmp` markers still fire.
- Added two ChromeOS markers tolerant of recovery shape:
  `/home/chronos` (bare dir, weight 0.9) and `/home/.shadow`
  (cryptohome, weight 0.8).

Two tripwire tests:
- `chromebook_recovery_tree_is_classified_as_chromeos` —
  exercises the minimal Chromebook-shape fixture (empty chronos
  + `.shadow` + user/root hash dirs) and asserts ChromeOS.
- `examiner_home_on_macos_does_not_trip_windows_users_marker` —
  pure-Linux tree in a tempdir (whose absolute path includes
  `/var/folders/...` or `/Users/...`) must not classify as
  Windows. Regression-pins the scan-root-stripping fix.

### Fix 3 — `5c63c57`: TARGET_PATTERNS extension for Mac/iOS examiner content

**Target:** `crates/strata-engine-adapter/src/vfs_materialize.rs`.
**Closes:** validation gap G10 (UNENCRYPTED.dmg APFS fixture
materialized zero files — contained three `.txt` files that no
existing TARGET_PATTERNS entry matched).

Added 12 extension suffixes covering plain-file content
examiners expect on Mac/iOS/mobile casework:

  `.txt`, `.pdf`, `.jpg`, `.jpeg`, `.png`, `.heic`, `.mov`,
  `.mp4`, `.eml`, `.mbox`, `.ipa`, `.apk`

Every pre-v16 pattern preserved. The 512 MB per-file cap
(MAX_MATERIALIZE_BYTES) and 16 GB total cap
(MAX_TOTAL_BYTES) still protect against runaway
materialization — an APFS volume full of `.mov` stops at the
cap and surfaces `hit_cap = true` in the report.

Three tripwire tests:
- `target_patterns_match_apfs_examiner_content_gap_g10` —
  pins each new extension against a representative Mac/iOS
  path, with commentary linking back to the G10 validation
  finding.
- `target_patterns_preserve_pre_v16_matches` — regression
  guard on every pre-v16 pattern so future cleanups can't
  silently drop Windows/Linux/Android targets.
- `target_patterns_ignore_irrelevant_files` — updated to use
  examples (`.bin`, `.gif`, `.ttf`, `.so`) that don't overlap
  the intentionally-broad substring patterns.

## Gate status

- **Clippy `-D warnings`:** clean workspace.
- **AST quality gate:** **PASS** — library baseline **424 / 5 / 5**
  preserved across all three commits.
- **Workspace tests:** passing (see `/tmp/strata_test_C.txt`
  monitor result for exact count; session-start baseline was
  3,836, and three commits added 9 net-new tripwire tests).
- **Dispatcher arms:** all 6 routes still live (NTFS, ext,
  HFS+, FAT, APFS-single, APFS-multi) + new FileVault
  short-circuit.
- **Charlie/Jo regression guards:** unchanged.
- **v15 Session 2 advisory tripwires:** unchanged.
- **9 load-bearing tests:** preserved.

## Commits

- `b28b64e` feat: FS-DISPATCH-FILEVAULT detect encrcdsa wrapper
- `641e239` fix: DETECT-1 strip scan-root prefix + add ChromeOS
  recovery markers
- `5c63c57` fix: materialize add Mac/iOS examiner content to
  TARGET_PATTERNS

## Tripwire inventory added in this session

### In `crates/strata-fs/src/fs_dispatch.rs`

1. `detects_filevault_encrcdsa_at_byte_zero`
2. `filevault_detection_takes_precedence_over_inner_magic`
3. `filevault_fs_type_str_is_stable`
4. `dispatch_filevault_returns_structured_pickup_signal`

### In `crates/strata-core/src/detect/mod.rs`

5. `chromebook_recovery_tree_is_classified_as_chromeos`
6. `examiner_home_on_macos_does_not_trip_windows_users_marker`

### In `crates/strata-engine-adapter/src/vfs_materialize.rs`

7. `target_patterns_match_apfs_examiner_content_gap_g10`
8. `target_patterns_preserve_pre_v16_matches`

Plus one existing test updated
(`target_patterns_ignore_irrelevant_files` — irrelevant examples
adjusted to avoid false-positive overlap with the new patterns).

## What's next

Per the session prompt: CLAUDE.md and website updates are
**deferred** to Session D-or-later once the APFS end-to-end
re-run validates these three fixes on real images (G10's
TARGET_PATTERNS extension is specifically the prerequisite for
that validation to land usefully).

Suggested Session D scope:
1. Re-run the v0.16.0 validation corpus subset that exercised
   the three fixed paths (UNENCRYPTED.dmg, ENCRYPTED.dmg,
   Chromebook tar, a realistic macOS evidence dir).
2. Verify the three tripwires hold under real-image load and
   produce the intended examiner-visible behaviour shift.
3. On success: update CLAUDE.md key numbers (gap list +
   tripwire count), restore website "Detection & Dispatch"
   subsection, publish the follow-up validation note.

## Discipline held

- Every fix surgical — three isolated files, each ~100 LOC
  diff.
- Every fix carried tripwires that fail loudly on regression
  with pickup-signal commentary in the assertion messages.
- v15 Lesson 1 applied to Fix 2 — the real root cause
  (examiner-home pollution) wasn't visible without running
  `classify()` against the actual Chromebook evidence and
  printing the fired evidence paths. The "ChromeOS markers
  needed tightening" diagnosis alone would have been a partial
  fix that still left Windows winning on every macOS
  examiner's workstation.

---

*No CLAUDE.md or website changes this session, per prompt.
Those land after Session D's re-run confirms the fixes landed
correctly.*

*Wolfmark Systems — post-v0.16 Session C, 2026-04-20.*
