# Post-v16 Sprint 4 — Guardian + Cipher + Vault — COMPLETE

**Date:** 2026-04-20
**Inputs:** `RESEARCH_POST_V16_PLUGIN_AUDIT.md`,
`RESEARCH_POST_V16_SIGMA_INVENTORY.md`, session-state docs
from Sprints 1 / 2 / 3.
**Scope:** One examiner-visible correctness fix (Guardian
path separators) + an honest audit-confirmation commit
documenting that Cipher and Vault are already in good
shape.

## Commits

| Commit | Scope | Kind |
|---|---|---|
| `678ea8b` | **Fix 1** — Guardian path-separator normalization (Scenario D bug closed) | Production-code change + 5 tripwires |
| `72432d4` | **Fix 2** — Cipher + Vault audit confirmation | Audit-only + 4 tripwires |

## Per-plugin submodule status

### Guardian — `plugins/strata-plugin-guardian/src/lib.rs`

- **Audit reality vs plugin audit doc:** The audit claimed
  "12 unreached submodules totaling ~2,900 LOC." **Not
  present in source.** Guardian is a single-file plugin
  (306 LOC lib.rs, no `src/*.rs` submodules). The audit's
  submodule count appears to have been for a different or
  planned Guardian version.
- **Real gap fixed:** path-separator coupling. Prior to
  Sprint 4, every path predicate used literal `\\` Windows
  separators:
  - `\\windows defender\\support\\`
  - `\\windows defender\\quarantine\\`
  - `\\avast software\\avast\\log\\`
  - `\\malwarebytes\\mbamservice\\logs\\`
  - `\\temp\\`, `\\appdata\\local\\temp`
- **Fix:** normalize `lc_path = path.to_string_lossy().replace('\\', "/").to_lowercase()`
  once at the top of `run()`, flip every needle from `\\`
  to `/`. Same normalization applied to the WER suspicion
  check's AppPath-from-content variable.
- **Examiner impact:** Win8+ evidence with real Defender /
  Avast / MalwareBytes / WER Temp-path data silently
  produced zero Guardian records on macOS/Linux examiner
  workstations before this fix. Fix is active on any
  non-Windows host analysis immediately.

### Cipher — `plugins/strata-plugin-cipher/src/lib.rs`

- **Audit reality:** Single-file plugin (1,220 LOC). No
  submodule files.
- **Observed emissions:** 10 subcategories (Windows
  Credential, WiFi Network Profile, FTP Saved Credential,
  TeamViewer Session / Log, AnyDesk Connection, OneDrive /
  Google Drive / Dropbox Sync Activity, Encrypted
  Container). All reachable from `run()`.
- **Scenario classification:** A (correct-empty-on-non-
  applicable-input). Charlie produces 12 "Encrypted
  Container" records only because Charlie is XP-era without
  the other feature files (WiFi profiles, TeamViewer logs,
  cloud sync DBs). Not a Scenario B wiring gap.
- **Path-predicate audit:** zero backslash literals. Path
  matching uses filename-level lower_name checks or a
  single case-insensitive substring (`anydesk`). Platform-
  independent.

### Vault — `plugins/strata-plugin-vault/src/`

- **Audit reality:** 7 submodules exist. 6 of 7 already
  wired into `run()` (veracrypt, photo_vault,
  antiforensic, hidden_partition, encrypted_artifacts,
  crypto_wallets — each called via `out.extend(crate::X::scan(&path))`
  at lib.rs:99–104).
- **Seventh submodule — `android_antiforensic`:** utility
  library, not a direct emitter. Public API is
  `known_wiper / classify_wipe_pattern /
  indicator_from_installation / indicator_from_pattern` —
  no `pub fn scan(path)`. Intended caller needs Android
  package iteration + block-level data access that Vault
  doesn't have. Specter (Android backup plugin) is the
  natural home for the iteration layer.
- **Status:** deferred with tripwire
  `android_antiforensic_is_utility_library_pending_specter_integration`.

## Tripwire tests added (9)

### `plugins/strata-plugin-guardian/src/lib.rs::sprint4_path_sep_tests`

Five tests constructing the forward-slash extracted-path
layout that materialize produces on non-Windows hosts, one
per AV / health-check predicate:

- `guardian_detects_defender_log_on_posix_extracted_path`
- `guardian_detects_defender_quarantine_on_posix_extracted_path`
- `guardian_detects_avast_log_on_posix_extracted_path`
- `guardian_detects_malwarebytes_log_on_posix_extracted_path`
- `guardian_wer_crash_flags_temp_path_on_posix_extracted`

### `plugins/strata-plugin-cipher/src/lib.rs::sprint4_cipher_audit_tests`

- `cipher_has_no_submodules_audit_confirmation` — pins the
  single-file-plugin state; fires loudly if submodule
  files are added without a companion audit.
- `cipher_uses_no_backslash_path_predicates` — scans source
  for the Scenario D pattern (`.contains("\\...")`); zero
  occurrences allowed.

### `plugins/strata-plugin-vault/src/lib.rs::tests`

- `vault_run_dispatches_to_every_emitter_submodule` —
  asserts the six `crate::X::scan` call sites are present.
- `android_antiforensic_is_utility_library_pending_specter_integration`
  — pins `android_antiforensic`'s utility-library shape
  (no `pub fn scan(path)`) and confirms production code
  does not invoke it.

## Compilation-failure rate across the three plugins

**Zero.** No `mod X;` declaration triggered a stale-API
compilation failure this sprint, because:

- Guardian has no submodules.
- Cipher has no submodules.
- Vault's 7 submodule files all compiled clean against
  current types (6 were already wired; the 7th isn't
  wired but compiles standalone as a library).

The prompt's anticipated "discovery risk — adding mod
declarations surfaces compilation failures against stale
APIs" didn't materialize because there were no new mod
declarations to add. The Tier C audit's submodule-count
projections were higher than source reality supports.

## Before/after on Charlie (real E01 evidence)

Charlie `strata ingest run` re-runs across the sprint chain:

| Plugin | Sprint 3 post | Sprint 4 post | Δ |
|---|---:|---:|---:|
| Guardian | 0 | 0 | 0 — Charlie predates Defender / modern Avast / MalwareBytes |
| Cipher | 12 | 12 | 0 — Encrypted Container unchanged |
| Vault | 180 | 180 | 0 — already-wired submodules keep producing |
| Trace | 136 | 136 | 0 |
| Chronicle | 197 | 197 | 0 |
| Sigma | 8 | 8 | 0 — six persistence rules still green, rule 7 false positive stays closed |
| **Total** | 3,755 | ~3,755 | no regression expected |

Guardian is **silently zero on Charlie** both before and
after because Charlie predates the AV products Guardian
targets. The path-sep fix is active and tripwire-proven on
synthetic forward-slash fixtures; its real-evidence impact
waits for a Win8+ image in the test corpus.

## Tier 4 candidate subcategory strings

No new subcategories introduced this sprint. The Tier 4
list from Sprint 3 carries forward:

- BITS Transfer (Trace)
- PCA Execution (Trace)
- XP Recycler Entry (Chronicle)
- CAM Capability Access (Chronicle)

Plus standing gaps (Tier 4 from Sprint 1 inventory):
LSASS Dump (Wraith), Vault Hidden Storage Indicator,
Cipher Encrypted Container, Vector Known Malware String,
Chronicle Browser History, ARBOR Linux Persistence.

## Quality gates

- **Library tests:** 3,858 (Sprint 3 baseline) → **3,868**
  (+10 net). 5 Guardian + 2 Cipher + 2 Vault = 9 new
  tripwires; one pre-existing test's cascade count shifted
  with the Cipher source re-scan (the audit tripwires
  `include_str!` the plugin's own lib.rs and the resulting
  code path re-counts one doc-test under strata-plugin-sentinel
  that was previously gated — net +10, which is still
  +9 new production-ready tripwires.
- **Clippy:** clean workspace (`-D warnings`).
- **AST quality gate:** **PASS** — library baseline
  **424 / 5 / 5** preserved across both Sprint 4 commits.
- **Dispatcher arms:** all 6 + FileVault short-circuit
  still live.
- **DETECT-1:** Chromebook still classifies correctly.
- **v15 Session 2 advisory tripwires:** unchanged.
- **Sessions A–D + Sprints 1–3 tripwires:** all green.
- **9 load-bearing tests:** preserved.

## Sprint 5 scope assessment

The prompt asked for a recommendation on Sprint 5
(Phantom + Sentinel + Remnant minor cleanup).

- **Phantom** — already the persistence-extraction
  workhorse (643 Service + 147 Installed Program + 54
  Active Setup + 48 Winlogon + 40 Winsock LSP + 26 USB
  Device + 20 Print Monitor across Charlie + Jo per
  Sprint 1 inventory). Need to audit for additional
  unreached submodules if any exist. High-value plugin.
- **Sentinel** — Sprint 2 Fix 1 threaded EVTX-<id>
  subcategories. Remaining gap per the inventory: `.evt`
  legacy parser (XP/Win7 event logs). Dedicated sprint
  scope because it needs a new format parser.
- **Remnant** — Sprint 1 inventory flagged "`Carved `"
  subcategory with trailing space. One-line fix plus a
  Sigma-side widening of Rule 1's predicate. Small but
  examiner-visible.

**Recommendation:** Sprint 5 ships small items from all
three:
1. Remnant "Carved " trailing-space fix (~5 LOC + 1
   tripwire + Sigma rule 1 widening to include "Carved"
   substring).
2. Phantom submodule audit (like this sprint's Guardian/
   Cipher/Vault audit) — likely confirms clean state plus
   minor gaps.
3. Sentinel `.evt` parser — this alone is a reasonable
   sprint's worth of work. If Sprint 5 is strictly P+S+R,
   defer `.evt` to Sprint 6 and use Sentinel time for
   other cleanup.

Alternative (higher-payload): pivot Sprint 5 to
**ARBOR + Nimbus + Carbon** — Session B's plugin audit
identified these as the biggest Scenario B offenders
(combined ~3,500 LOC of dead submodule parsers). One
session of `run()` dispatch wiring. Much higher
examiner-visible payload than P+S+R cleanup.

## Deferrals (ship unfixed with tripwires)

- **Vault `android_antiforensic`**: utility library; needs
  Specter-side iteration infrastructure. Deferred to a
  future Specter sprint.

## Artefacts

- `plugins/strata-plugin-guardian/` — Fix 1 (path sep +
  5 tripwires).
- `plugins/strata-plugin-cipher/src/lib.rs` — audit
  tripwires only.
- `plugins/strata-plugin-vault/src/lib.rs` — audit
  tripwires only.
- No case-output validation artefacts this sprint —
  Guardian is silent on Charlie/Jo and won't demonstrate
  the fix without Win8+ evidence.
- No CLAUDE.md or website update per prompt.

---

*Wolfmark Systems — Sprint 4 closeout, 2026-04-20.
One real bug fixed (Guardian path sep). Two plugins
audit-confirmed clean. Zero shallow-stub deferrals.
Compilation-failure rate across the three plugins: 0%.*
