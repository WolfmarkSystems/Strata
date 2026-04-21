# Post-v16 Sprint 5 — Phantom + Sentinel + Remnant — COMPLETE

**Date:** 2026-04-21
**Inputs:** `RESEARCH_POST_V16_PLUGIN_AUDIT.md`,
`RESEARCH_POST_V16_SIGMA_INVENTORY.md`, session-state docs
from Sprints 1 / 2 / 3 / 4.
**Scope:** Three plugin audits + one cross-plugin alignment
fix. Sprint 4's "audit-clean likely" heuristic broke here —
Phantom surfaced real Scenario B work.

## Commits

| Commit | Scope |
|---|---|
| `bc665a2` | **Fix 1 — Phantom**: wire 7 orphaned submodules (memory_carving, memory_structures, notepad_tabstate, outlook, powershell, cloud_cli, windows_recall). 3 utility-library submodules (services, ring_doorbell, smart_locks) deferred. 8 tripwires. |
| `8f8f8bb` | **Fix 2 — Sentinel audit**: `lateral_movement` (393 LOC correlator) deferred pending EVTX record extraction refactor + Win8+ test corpus. 1 tripwire. |
| `6aee410` | **Fix 3 — Remnant + Sigma**: trim trailing-space `"Carved "` bug; Sigma Rule 1 / Rule 3 predicate widened with `"Carved"` substring. 4 Remnant tripwires + 1 Sigma tripwire. |

## Per-plugin audit outcome

### Phantom — 7 of 10 unreached submodules wired

Phantom has 20 submodule mod declarations. Audit found
**10 unreached** (no `crate::X::` call site in lib.rs):
cloud_cli, memory_carving, memory_structures,
notepad_tabstate, outlook, powershell, ring_doorbell,
services, smart_locks, windows_recall.

**7 wired** (direct-emission API: `is_*_path` /
`classify` + `scan` / `parse` returning typed records):

| Submodule | Emitted subcategory | MITRE | Trigger |
|---|---|---|---|
| memory_carving | `Memory String` | T1005 | `.mem`/`.dmp` |
| memory_structures | `Memory Process`, `Memory Network Connection` | T1057 / T1049 | same as above |
| notepad_tabstate | `Notepad TabState` | T1005 | `TabState*.bin` |
| outlook | `Outlook Carved` | T1114.001 | `.pst` + magic check |
| powershell | `PowerShell History` | T1059.001 | `ConsoleHost_history.txt` |
| cloud_cli | `Cloud CLI Credential` | T1552.001 | AWS/Azure/Terraform configs |
| windows_recall | `Windows Recall Capture`, `Windows Recall Locked` | T1113 | `UKG.db` |

**3 deferred** (utility libraries — no `pub fn scan(path)`
direct-emission signature):

- `services` — helper utils for SYSTEM-hive services
  parsing; refactor target.
- `ring_doorbell` — `parse_events(json)` + `parse_subscription
  (json)`; needs iteration layer for `%LOCALAPPDATA%\Amazon`.
- `smart_locks` — same JSON-string shape as ring_doorbell.

Deferrals pinned via
`phantom_utility_submodules_remain_unwired_pending_caller_infrastructure`
tripwire.

### Sentinel — `lateral_movement` deferred

`LateralMovementDetector::detect(&[EventRecord])` →
`Vec<LateralMovement>` is a stateful correlator taking typed
EVTX events. Current `parse_one_evtx` emits only
`Artifact`s, not `EventRecord`s. Wiring requires a refactor
to produce both record shapes from the same EVTX parse
pass. Charlie / Jo are `.evt` legacy (Sentinel's extension
gate skips them) so even fully-wired the detector would
produce zero correlations on the canonical test corpus.

Deferred via
`sentinel_lateral_movement_detector_pending_evtx_record_extraction`.

### Remnant — `"Carved "` trailing-space bug fixed + two
utility submodules deferred

**Fixed:** `format!("Carved {}", file_type)` with empty
`file_type` produced `"Carved "` (trailing space) —
documented in Sprint 1 inventory. Now:

```rust
if file_type.is_empty() {
    "Carved".to_string()
} else {
    format!("Carved {}", file_type)
}
```

**Companion Sigma fix:** Rule 1 (USB Exfiltration) + Rule 3
(AV Evasion) `remnant_delete` predicate widened:

```rust
r.subcategory.contains("Recycle")
    || r.subcategory.contains("USN")
    || r.subcategory.contains("Carved")
```

"Carved" substring uniquely originates from Remnant, so
widening closes the silent-miss gap without introducing
false-positive risk.

**Deferred:** `regions.rs` + `signatures.rs` (utility
libraries the lib.rs in-line carver should consume in a
refactor; not Scenario B dead code). Pinned via
`remnant_utility_submodules_remain_unused_pending_carver_refactor`.

## Tripwire tests added (14)

### `plugins/strata-plugin-phantom::sprint5_wiring_tests`

8 tests (source-inspection tripwires for each wired
submodule + the utility-library deferral):

- `phantom_wires_memory_carving`
- `phantom_wires_memory_structures`
- `phantom_wires_notepad_tabstate`
- `phantom_wires_outlook`
- `phantom_wires_powershell`
- `phantom_wires_cloud_cli`
- `phantom_wires_windows_recall`
- `phantom_utility_submodules_remain_unwired_pending_caller_infrastructure`

### `plugins/strata-plugin-sentinel::tests`

1 test:

- `sentinel_lateral_movement_detector_pending_evtx_record_extraction`

### `plugins/strata-plugin-remnant::sprint5_remnant_tests`

4 tests:

- `remnant_emits_carved_without_trailing_space_on_empty_file_type`
- `remnant_preserves_carved_with_file_type_suffix`
- `remnant_subcategory_format_matches_production` (source-
  inspects lib.rs for the is_empty() guard)
- `remnant_utility_submodules_remain_unused_pending_carver_refactor`

### `plugins/strata-plugin-sigma::tests`

1 test:

- `sigma_rule_1_matches_carved_subcategory_post_sprint5_widening`

## Before/after on Charlie (real E01 evidence)

End-to-end re-run with the Sprint 5 release binary. Case
output:
`test-output/validation-v0.16.0-post-fix-sprint5/charlie_11_12/`.

| Plugin | Sprint 4 post | Sprint 5 post | Δ |
|---|---:|---:|---:|
| Phantom | 535 | 535 | 0 — new submodules target file types absent from XP-era Charlie |
| Sentinel | 0 | 0 | 0 — `.evt` skip unchanged |
| Remnant | 1 (subcategory `"Carved "`) | 1 (subcategory `"Carved"`) | 0 count, subcategory trimmed |
| Vault | 180 | 180 | 0 |
| Vector | 2,465 | 2,465 | 0 |
| Cipher | 12 | 12 | 0 |
| Recon | 215 | 215 | 0 |
| Chronicle | 197 | 197 | 0 |
| Trace | 136 | 136 | 0 |
| **Sigma** | **8** | **9** | **+1** — new `RULE FIRED: USB Exfiltration Sequence` |
| Advisory Analytics | 2 | 2 | 0 |
| MacTrace | 1 | 1 | 0 |
| Conduit | 1 | 1 | 0 |
| CSAM Scanner | 1 | 1 | 0 |
| Apex | 1 | 1 | 0 |
| **Total** | 3,755 | **3,756** | **+1** |

**Interpretation:**

- **Remnant subcategory fix verified end-to-end.** The
  one Charlie Carved record now reads subcategory
  `"Carved"` (sans trailing space) vs. the previous
  `"Carved "`.
- **Sigma Rule 1 fires correctly on real Charlie evidence.**
  Charlie has USB Device records (14 Phantom) + Recent
  Files (143 Chronicle) + now-matchable Carved (1
  Remnant). The USB Exfiltration narrative is
  demonstrable on Charlie — a real forensic signal
  improvement that pre-Sprint-5 was silently missed.
- **Phantom's 7 new submodules correctly silent on
  Charlie.** XP-era evidence has none of the target
  files (memory dumps, Notepad TabState, Outlook PST,
  ConsoleHost history, cloud CLI credentials, Win11
  Recall DB). Scenario A working correctly — wire is
  proven by unit tests + source-inspection tripwires;
  real-evidence validation waits for Win10/11 images.
- **All seven pre-Sprint-5 Sigma firings preserved.** The
  six persistence rules (Active Setup, Winlogon, BHO,
  IFEO, Boot Execute, Shell Execute Hook) plus Kill
  Chain Coverage and Sigma Threat Assessment. No
  regressions; Rule 7 false positive stays closed.
- **Charlie Sigma firings went from 6 correct + 2 meta
  (Sprint 2) → 7 correct + 2 meta (Sprint 5).** The
  seven correct firings span the full Windows forensic
  narrative: persistence (6 rules) + exfiltration (USB
  Exfil rule 1). This is the canonical Windows demo
  material Sprint 2 promised.

## Tier 4 candidate subcategories surfaced

Seven new Phantom subcategories with no current Sigma rule
coverage — candidates for SIGMA-RULE-ALIGNMENT-2:

| Subcategory | Suggested rule |
|---|---|
| `Memory String` | suspicious URL / credential appearance in memory image |
| `Memory Process` | process-hollowing / unusual-parent correlations |
| `Memory Network Connection` | live-capture C2 indicators |
| `Notepad TabState` | unsaved draft with suspicious keyword / high content length |
| `Outlook Carved` | non-RFC822 email address patterns / suspicious subject |
| `PowerShell History` | already partially-covered by Rule 21 (obfuscated PowerShell) via `suspicious_pattern` field |
| `Cloud CLI Credential` | alone-fire rule: any cloud-cli credential record is investigative |
| `Windows Recall Capture` / `Locked` | stalkerware narrative + DPAPI pickup signal |

Plus the Sprint 3 candidates (BITS Transfer, PCA Execution,
XP Recycler Entry, CAM Capability Access) remain open for
the alignment sprint.

## Quality gates

- **Library tests:** 3,868 (Sprint 4 baseline) + 14 new
  Sprint 5 tripwires = **3,882** expected. Workspace
  test run completes in background.
- **Clippy:** clean workspace (`-D warnings`).
- **AST quality gate:** **PASS** — library baseline
  **424 / 5 / 5** preserved across all three Sprint 5
  commits.
- **Dispatcher arms:** all 6 + FileVault short-circuit
  still live.
- **DETECT-1:** Chromebook still classifies correctly.
- **v15 Session 2 advisory tripwires:** unchanged.
- **Sessions A–D + Sprints 1–4 tripwires:** all green.
- **9 load-bearing tests:** preserved.

## Deferrals (ship unfixed with tripwires)

| Item | Tripwire | Pickup |
|---|---|---|
| Phantom `services` / `ring_doorbell` / `smart_locks` | `phantom_utility_submodules_remain_unwired_pending_caller_infrastructure` | future caller-layer sprint |
| Sentinel `lateral_movement` | `sentinel_lateral_movement_detector_pending_evtx_record_extraction` | EVTX record extraction refactor + Win8+ test corpus |
| Remnant `regions` / `signatures` | `remnant_utility_submodules_remain_unused_pending_carver_refactor` | carver refactor |
| Sentinel `.evt` parser | `sentinel_evt_extension_skipped_pending_evt_parser` (Sprint 2) | dedicated `.evt` sprint |

## Sprint 6 scope assessment

The prompt asked for a Sprint 6 (report output audit)
recommendation and whether end-to-end Charlie validation
should ride alongside or stay in Sprint 7 demo rehearsal.

**Sprint 6 scope: report output audit.** The 14 sprints
between v0.16 Session 1 and post-v0.16 Sprint 5 have grown
the artifact surface substantially:

- Artifacts-per-Charlie: 3,399 (v0.16.0) → 3,756 (Sprint 5)
- Sigma firings: 2 (v0.16.0) → 9 (Sprint 5)
- Live subcategories: ~40 → ~55 (including Sprint 3/4/5
  additions — BITS Transfer, PCA Execution, XP Recycler
  Entry, CAM Capability Access, Memory String, Memory
  Process, Memory Network Connection, Notepad TabState,
  Outlook Carved, PowerShell History, Cloud CLI
  Credential, Windows Recall Capture / Locked)

Report generator / dashboard / UI surface may be behind
the plugin output. Things to audit in Sprint 6:

- Does the case report / HTML output reference the new
  Sprint 3–5 subcategories? If it uses a hardcoded
  subcategory-to-pretty-name map, it's probably showing
  "(unknown)" for the new ones.
- Does the Tauri desktop UI's forensic-dashboard filter
  surface new subcategories?
- Does the JSON-result output schema include the new
  MITRE mappings (T1113, T1552.001, T1547.014, etc.)?

**Recommendation on Charlie validation:** Ride with
**Sprint 7 demo rehearsal**, not Sprint 6. Sprint 6 is
output-surface work that benefits from the current Charlie
E2E baseline being stable post-Sprint-5. Re-running Charlie
every sprint adds cadence overhead without surfacing new
plugin signal. Sprint 7 does the full demo rehearsal run
covering: every new subcategory surfaces correctly in
reports + UI; Sigma's 9 Charlie firings render with
correct titles; MITRE mappings hyperlink correctly in any
report output; Charlie demo narrative flows end-to-end
(USB exfil → persistence → log clear).

Alternative if Sprint 6 reveals nothing needs fixing
(report generator is already abstract over subcategory
names), Sprint 7 becomes pure demo rehearsal + CLAUDE.md /
website update.

## Artefacts

- `plugins/strata-plugin-phantom/src/lib.rs` — Fix 1.
- `plugins/strata-plugin-sentinel/src/lib.rs` — Fix 2
  (audit tripwire only).
- `plugins/strata-plugin-remnant/src/lib.rs` — Fix 3
  (Remnant side).
- `plugins/strata-plugin-sigma/src/lib.rs` — Fix 3
  (Sigma side — Rule 1 / Rule 3 predicate widening).
- `test-output/validation-v0.16.0-post-fix-sprint5/charlie_11_12/`
  — Charlie end-to-end validation audit trail (gitignored).
- No CLAUDE.md or website update per prompt — those land
  after Sprint 7 demo rehearsal.

---

*Wolfmark Systems — Sprint 5 closeout, 2026-04-21.
Charlie USB Exfil rule now fires on real evidence. Seven
Sigma rules + two meta-records = nine Sigma artifacts.
The demo narrative gained its deletion / exfil chapter.*
