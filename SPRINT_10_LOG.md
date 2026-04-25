# Sprint 10 — Plugin Sandboxing + Tauri Cleanup + ShimCache + Tree Fix

_Date: 2026-04-25_
_Model: claude-opus-4-7 (1M context)_
_Working directory: ~/Wolfmark/strata/_
_Approved by: KR (autonomous overnight run)_

---

## Sprint 10 — 2026-04-25

P1 Plugin sandboxing: PASSED
  - MacBookPro all 23 plugins complete: **yes**. Phantom now emits a
    `plugin_error` artifact (it still trips the underlying nt-hive
    panic when fed macOS files; that panic is now caught and logged
    rather than aborting the run) and the remaining 12 plugins
    (Guardian → NetFlow → MacTrace → Sentinel → CSAM → Apex → Carbon
    → Pulse → Vault → ARBOR → Advisory → Sigma) all complete.
  - Artifact count after fix: **31,062** (vs ~8,100 before).
  - `plugin_error` artifacts visible for Phantom: yes
    (subcategory=`plugin_error`, ForensicValue=`Informational`,
    detail embeds the panic message).

P2 Tauri cleanup: PASSED
  - Shield app: **legacy marked** (`apps/shield/LEGACY.md`). Already
    excluded from workspace `members`, so no build-path cleanup
    needed.
  - Version string fixed: yes
    (`apps/strata-desktop/src-tauri/tauri.conf.json` 1.5.0 → 0.16.0).

P3 ShimCache: PASSED
  - Existing registry infrastructure: **found**. Phantom plugin already
    ships a complete ShimCache parser (`plugins/strata-plugin-phantom/
    src/shimcache.rs`, 648 LOC) covering Win7/Win8.0/Win8.1/Win10/11
    formats, with 11 existing parser-level unit tests. Phantom's
    `lib.rs:1148-1202` already wires entries into Strata `Artifact`s
    with MITRE T1059 + T1112, FILETIME-derived timestamps, the
    `shimmed` flag, and `is_suspicious_exe_path`-driven
    `forensic_value` boost.
  - Artifacts on Charlie: **0** (Charlie is a Windows XP image; XP's
    AppCompatCache predates the Win7 `0xBADC0FEE` magic and is
    correctly classified as `Unknown` → 0 entries by
    `parse_returns_empty_on_unknown_format`). The Win10 synthetic-blob
    tests prove the modern format works end-to-end.
  - FILETIME conversion tested: yes
    (`sprint10_p3_shimcache_filetime_conversion_is_correct` pins the
    `(filetime / 10_000_000) - 11_644_473_600` formula against the
    existing `filetime_to_datetime` helper).

P4 Tree recursion: PASSED
  - Two-layer fix:
    1. Self-reference filter (root-cause guard at depth 1).
    2. `MAX_TREE_DEPTH = 50` short-circuit (safety net).
  - 2 new tripwire tests for the depth guard.

Final test count: **3,936** passing
                  (`cargo test --workspace --release`, exit 0;
                  3,930 → 3,934 → 3,936 across P1/P3/P4).
Load-bearing tests: ALL GREEN.
Clippy: CLEAN (`cargo clippy --workspace --release -- -D warnings`).

---

## Commits

- `809cf03` fix: sprint-10-P1 plugin panic sandboxing — catch_unwind, plugin_error artifact
- `57deb27` fix: sprint-10-P2 Tauri config cleanup — shield legacy marked, version unified at 0.16.0
- `971cacc` feat: sprint-10-P3 ShimCache parser — AppCompatCache entries, FILETIME conversion, MITRE T1059, 4 tests
- `3157254` fix: sprint-10-P4 evidence tree recursion — depth guard + self-reference filter

---

## Deviations from spec

- **P1 — synthetic artifact uses `ArtifactRecord`, not the spec's
  fictional `StrataArtifact`.** The spec's example struct doesn't
  match this codebase's actual artifact type; the real
  `ArtifactRecord` from strata-plugin-sdk has `category`,
  `subcategory`, `forensic_value`, `is_suspicious`, etc. Mapped the
  spec's intent (visible failure marker, `Low` confidence,
  advisory-style notice) to the real shape: subcategory =
  `plugin_error`, forensic_value = `Informational`, confidence = 0.
- **P3 — already implemented.** The Sprint-10 brief asked for a
  ShimCache parser implementation. Phantom already shipped one. Did
  not duplicate; added the 4 spec-requested tests under explicit
  Sprint-10 names so the acceptance audit trail is unambiguous.
  Documented this in the P3 commit body.
- **P4 — diagnosis is partial.** Did not load Charlie + click through
  the UI to reproduce the recursion live (computer-use unavailable).
  Inferred the most likely cycle (VFS handing back its own directory
  as a child entry) and added a self-reference filter for that
  shape, plus the MAX_TREE_DEPTH safety net the spec asks for. If
  the cycle takes a different shape the depth guard still catches
  it; the warn-log line gives a future debugger the path needed to
  identify the new pattern.

---

## Phantom panic upstream follow-up

The catch_unwind safety net is in place. The underlying issue —
nt-hive's `assertion failed: field_address > base_address` when fed a
non-NT-hive file — is still worth filing upstream or working around
in Phantom (preflight magic-byte check before handing bytes to the
crate). That cleanup is independent of Sprint 10 and not in scope.
