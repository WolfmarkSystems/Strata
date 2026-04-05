# Week 2 Close-Out (Registry Core I)

Date: 2026-03-10  
Primary baseline run: `_run/windows_roadmap/2026-03-10_211945`  
Primary gate run: `_run/windows_roadmap/2026-03-10_212019`

## Outcome

1. Hard goal status: complete.
2. Build: pass.
3. Tests: pass (`303` engine tests + workspace suite).
4. Clippy: pass (no active warnings in current run).
5. Fixture harness: pass (including corpus harness opt-in path).

## Completed Scope

1. UserAssist + Run/MRU normalization:
   - `MRUListEx` ordering support.
   - UserAssist binary count/timestamp parsing hardening.
2. USB/STOR normalization:
   - Correct VID/PID extraction from hardware IDs.
   - Normalized INF-style device descriptions.
3. Uninstall/services normalization:
   - Install date normalization (`YYYYMMDD` -> unix).
   - Service root-key filtering (ignore nested subkeys).
4. SAM/SECURITY metadata pass:
   - normalized user-right principal parsing (quoted + `hex(7)` multistring).
   - audit/security alias handling.
   - optional SAM account metadata fields.
5. Timestamp consistency pass:
   - shared registry helpers for unix + UTC formatting.
   - normalized UTC companion fields in registry update/uninstall/userassist outputs.

## Evidence Artifacts

1. Baseline summary JSON: `_run/windows_roadmap/2026-03-10_211945/baseline_summary.json`
2. Daily gate result JSON: `_run/windows_roadmap/2026-03-10_212019/daily_gate_result.json`
3. CLI snapshot summary JSON: `_run/windows_roadmap/snapshots/2026-03-10_212040/cli_snapshot_summary.json`

## Remaining Gaps (explicit)

1. Registry Core II (Amcache/ShimCache/BAM correlation) remains Week 3 scope.
2. No schema-level changes were introduced; this remains parser/output normalization only.
3. Any deeper timeline/event fusion remains in downstream EVTX/NTFS roadmap phases.
