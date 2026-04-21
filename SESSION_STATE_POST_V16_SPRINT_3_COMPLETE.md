# Post-v16 Sprint 3 — Trace + Chronicle plugin wiring — COMPLETE

**Date:** 2026-04-20
**Inputs:** `RESEARCH_POST_V16_PLUGIN_AUDIT.md`,
`RESEARCH_POST_V16_SIGMA_INVENTORY.md`,
`SESSION_STATE_POST_V16_SIGMA_ALIGNMENT_COMPLETE.md`.
**Scope:** Wire previously-unreached submodules in Trace and
Chronicle. No new parser code; parsers pre-existed. One
scope-limited third commit extended TARGET_PATTERNS to close
the loop on real Charlie evidence.

## Commits

| Commit | Fix | LOC |
|---|---|---:|
| `eb9d76b` | **Fix 1** — Trace wires `bits::parse_qmgr_binary` + `pca::parse_launch_dic` / `parse_general_db` | ~150 + ~80 tests |
| `ee0b2f4` | **Fix 2** — Chronicle wires `winxp::parse_info2` + `cam_database::parse` | ~100 + ~120 tests |
| `93014eb` | **Scope-limited** — TARGET_PATTERNS extended with INFO2, qmgr{0,1}.dat, qmgr.db, PcaApp*/Pca*, CAM db, /recycler/ (closes the loop on real Charlie) | ~20 + 1 test |

## Per-plugin submodule status

### Trace — `plugins/strata-plugin-trace/src/`

| Submodule | LOC | Status | Evidence in run() |
|---|---:|---|---|
| `bits.rs` | 156 | **wired (Sprint 3)** | `crate::bits::is_bits_path` + `parse_qmgr_binary` + `check_suspicion` |
| `pca.rs` | 197 | **wired (Sprint 3)** | `crate::pca::is_pca_path` + `parse_launch_dic` / `parse_general_db` + `check_suspicion` |
| `srum.rs` | 573 | already wired (pre-v16) | via `detect_srum` |

All Trace submodules now reach the dispatch layer. New
subcategories emitted: **"BITS Transfer"** (deep-parse
records beyond the surface `"BITS Job"` status) and **"PCA
Execution"**. Charlie real-evidence re-run (see §Before/after
below) surfaces 2 "BITS Job" surface records when the
materialize pattern extension lands; deep-parse "BITS
Transfer" records require qmgr blobs with carveable URL/path
content (Charlie's qmgr files materialized empty —
non-regressive, parser correctly returns zero).

### Chronicle — `plugins/strata-plugin-chronicle/src/`

| Submodule | LOC | Status | Reason |
|---|---:|---|---|
| `winxp.rs` | 224 | **wired (Sprint 3)** | `crate::winxp::parse_info2` wired to INFO2 filename dispatch |
| `cam_database.rs` | 210 | **wired (Sprint 3)** | `crate::cam_database::{is_cam_db_path, parse, check_suspicion}` wired |
| `shellbags_win7.rs` | 210 | **deferred** — deep fix | `reconstruct()` takes `Vec<RegistryBagNode>` from a USRCLASS.DAT hive walk. Chronicle has no registry-reader layer today; wiring requires extracting the hive-walking primitive from Phantom or building fresh. Dedicated sprint. |
| `ai_actions.rs` | 156 | **deferred** — deep fix | Same dependency on a registry reader. Deferred alongside shellbags_win7. |
| `click_to_do.rs` | 158 | **deferred** — scope decision | Takes a single JSONL line; needs a helper to identify Copilot+ log file paths under `%LOCALAPPDATA%`. Trivial to build, but Win11 25H2 Copilot+ evidence isn't in any realistic test corpus today. No Charlie/Jo impact. |
| `userassist_versions.rs` | 139 | **intentional helper utility** | Version-detection helpers for ShimCache / Prefetch / Transaction log kinds / UserAssist GUID buckets. Not a direct emitter; consumed by other Chronicle code that doesn't yet import it. Refactor target, not Scenario B dead code. |

Two new subcategories: **"XP Recycler Entry"** (T1070.004
Indicator Removal) and **"CAM Capability Access"** (MITRE
mapped per capability string — T1123 audio / T1125 video /
T1430 location / T1005 other).

## Tripwire tests added (7)

In `plugins/strata-plugin-trace/src/lib.rs::sprint3_wiring_tests`:

- `trace_wires_bits_deep_parse_via_bits_submodule` —
  synthetic qmgr0.dat blob with URL + path + GUID;
  verifies ≥1 "BITS Transfer" record and suspicion
  flagging on non-MS URLs.
- `trace_wires_pca_launch_dic_parse` — synthetic
  PcaAppLaunchDic.txt; verifies exactly 2 PCA Execution
  records and suspicious flag on AppData\Local\Temp path.
- `trace_pca_produces_zero_on_xp_or_win7_evidence_pending_win11_fixture`
  — Scenario A pinning: PCA is Win11 22H2+; on XP/Win7
  evidence no PCA files exist, so zero records is correct.

In `plugins/strata-plugin-chronicle/src/lib.rs::sprint3_wiring_tests`:

- `chronicle_wires_winxp_info2_recycler_parser` — synthetic
  820-byte INFO2 record; verifies ≥1 "XP Recycler Entry"
  and the deleted filename in the title.
- `chronicle_cam_database_pending_win11_23h2_fixture` —
  Scenario A pinning: CAM is Win11 23H2+; on pre-Win11
  evidence zero CAM records is correct.
- `chronicle_wires_cam_database_path_detection` —
  anti-regression smoke test for the dispatch path and
  the `is_cam_db_path` predicate.

In `crates/strata-engine-adapter/src/vfs_materialize.rs::tests`:

- `target_patterns_match_sprint3_wire_targets` — pins each
  new TARGET_PATTERNS entry against a realistic path.

## Before/after on Charlie (real E01 evidence)

End-to-end re-run: `strata ingest run --source charlie-2009-11-12.E01`
with the Sprint 3 post-materialize release binary.
Case output:
`test-output/validation-v0.16.0-post-fix-sprint3b/charlie_11_12/`.

| Plugin | Sprint 2 post | Sprint 3 post | Δ |
|---|---:|---:|---:|
| Strata Trace | 134 | **136** | +2 (new "BITS Job" surface records) |
| Strata Chronicle | 197 | 197 | 0 (XP recycler materialized empty — no INFO2 in Charlie's recycle bin) |
| Strata Vector | 2,465 | 2,465 | 0 |
| Strata Phantom | 535 | 535 | 0 |
| Strata Recon | 212 | 215 | +3 (more text scanned after new materialize targets) |
| Strata Vault | 180 | 180 | 0 |
| Strata Cipher | 12 | 12 | 0 |
| Strata Sigma | 8 | **8** | 0 (six persistence rules still firing, zero false positives preserved) |
| Other | — | — | unchanged |
| **Total** | 3,753 | **3,755** | +2 |

Interpretation:

- **Trace surface-level BITS Job detection fires (+2).** The
  materialize extension passed qmgr files through the filter.
  Deep-parse "BITS Transfer" records are zero because
  Charlie's qmgr files materialized empty (Charlie's XP
  variant didn't have BITS job content at capture time).
  Non-regressive; `bits::parse_qmgr_binary` correctly
  returns empty on empty input.
- **Chronicle XP Recycler is zero on Charlie.** The
  materialize pattern extension includes /recycler/ and
  info2, but Charlie's XP recycler tree was empty at
  capture time (standard — Windows XP's RECYCLER dir gets
  emptied on logoff in many configurations). The wire is
  verified via unit tests; real-evidence validation waits
  for an XP image with non-empty INFO2 content.
- **Sigma unchanged at 8 firings.** The Sprint 2 six
  persistence rules still fire on Charlie; no new or
  regressed rule hits. The rule 7 false positive stays
  closed.
- **Charlie regression non-regressive.** Every pre-Sprint-3
  plugin count holds.

## Tier 4 candidate subcategories surfaced

Per the Sprint 1 inventory discipline ("every new artifact
category wired must either align with an existing Sigma
rule predicate or be explicitly flagged as Tier 4 future
rule work"), Sprint 3 adds four new subcategories with no
current Sigma rule coverage:

| Plugin | Subcategory | Suggested Sigma rule |
|---|---|---|
| Trace | BITS Transfer | Non-Microsoft source URL correlated with recent file execution — Charlie had 0 qmgr content, Jo likewise. Win7+ evidence with real BITS history would trigger. |
| Trace | PCA Execution | LOLBin execution from user-writable path — overlaps existing rule logic but keyed on the Win11-specific PCA source. |
| Chronicle | XP Recycler Entry | Deletion activity co-occurrence with Defender/log-clear events. Feeds future "anti-forensic deletion chain" rule. |
| Chronicle | CAM Capability Access | Non-browser app granted microphone/camera/location access — stalkerware / SAPR signal. |

These are deferred to a later SIGMA-RULE-ALIGNMENT-2 sprint
alongside the Tier 4 work already queued (LSASS Dump, Vault,
Cipher, Browser History TOR, ARBOR Linux persistence).

## Quality gates

- **Library tests:** 3,852 (Sprint 2 baseline) → **3,858**
  (+6 net). Trace 26 pass (+3); Chronicle 32 pass (+3);
  vfs_materialize 8 pass (+1); one pre-existing test
  retargeted / consolidated during Chronicle wiring so the
  net delta is +6 not +7. No regressions anywhere in the
  workspace.
- **Clippy:** clean workspace (`-D warnings`).
- **AST quality gate:** **PASS** — library baseline
  **424 / 5 / 5** preserved across all three Sprint 3
  commits.
- **Dispatcher arms:** all 6 + FileVault short-circuit still
  live.
- **DETECT-1:** Chromebook classification still correct
  (verified via preserved `chromebook_recovery_tree_is_classified_as_chromeos`
  tripwire).
- **v15 Session 2 advisory tripwires:** unchanged.
- **Session A–D + Sprint 1–2 tripwires:** all green.
- **9 load-bearing tests:** preserved.

## Sprint 4 scope assessment (Guardian + Cipher + Vault)

Honest read based on what Sprint 3 discovered about
submodule compilation health:

- **Guardian** — single-file plugin (`lib.rs` 306 LOC, no
  submodules). Scenario A-with-latent-bug per
  RESEARCH_POST_V16_PLUGIN_AUDIT.md §4 — path literals use
  Windows `\\` and never match macOS-extracted paths. Fix
  scope: ~30 LOC path-normalization helper. Not a
  submodule-wiring problem; different flavor. Sprint 4
  should handle as a path-sep audit.
- **Cipher** — per inventory §1, Cipher emits exactly one
  subcategory (`Encrypted Container`, 12 records per image).
  The audit didn't flag Cipher as Scenario B; submodule
  structure likely minimal. Sprint 4 may find it's largely
  complete, with the real work being new Sigma rules
  keying on its output. Tier 4 rule-side.
- **Vault** — 1 subcategory (`Hidden Storage Indicator`,
  36 → 180 post-Session-C). Similar to Cipher. The
  identical-count-across-images finding from R8 was
  dissolved by Session C's materialize extension. No
  Scenario B red flag.

**Recommendation for Sprint 4:** pivot from "wire
submodules" to "rule alignment + path-sep normalization."
The low-hanging plugin-wiring work ARBOR + Nimbus + Carbon
+ Apex flagged by Session B's Scenario-B category remains
the higher-value next target; if Sprint 4 is strictly the
G+C+V trio as planned, scope it as a cleanup sprint
(Guardian path sep + Cipher/Vault confirmation that no
submodule wiring is owed).

Alternative: **Sprint 4 does ARBOR + Nimbus instead of
G+C+V**, saving the G+C+V cleanup for a later sprint.
ARBOR in particular has 5 unreached submodules
(`system_artifacts`, `chromeos`, `containers`, `logs`,
`persistence`) — a ~30 LOC dispatch change per Session B's
research doc, and ChromeOS evidence materialization is now
working after Session C's DETECT-1 fix.

## Deferrals (ship unfixed with tripwires / session-state
   notes)

- **Chronicle `shellbags_win7` + `ai_actions`**: require
  registry reader. Dedicated sprint — call it
  POST-V16-CHRONICLE-REGISTRY — that extracts or builds
  the hive-walking primitive.
- **Chronicle `click_to_do`**: no test corpus; trivial wire
  when Win11 25H2+ evidence arrives.
- **Chronicle `userassist_versions`**: utility module;
  consumed by refactor not wiring. Not a Scenario B gap.
- **Trace BITS deep-parse on real Charlie**: qmgr files
  materialized but empty content. Waits for richer
  Windows 7/10/11 evidence with real BITS transfer
  history.
- **Chronicle INFO2 on real Charlie**: Charlie's XP
  recycler was empty at capture time. Waits for XP
  evidence with non-empty recycler.

## Artefacts

- `plugins/strata-plugin-trace/` — Fix 1.
- `plugins/strata-plugin-chronicle/src/lib.rs` — Fix 2.
- `crates/strata-engine-adapter/src/vfs_materialize.rs` —
  scope-limited Fix 3.
- `test-output/validation-v0.16.0-post-fix-sprint3b/` —
  Charlie end-to-end re-run audit trail (gitignored).
- No CLAUDE.md or website update per prompt.

---

*Wolfmark Systems — Sprint 3 closeout, 2026-04-20.
Two plugins wired, four submodules deferred with pickup
signals. Charlie Sigma firings hold at 8; no regressions.*
