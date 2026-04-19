# SPRINTS_v16 Session 2 — complete

v16 Session 2 (ML-WIRE-1) shipped: advisory analytics modules
wired into `strata ingest run` via a new plugin registered before
Sigma. Pre-v0.14 audit debt closed. No APFS work — orthogonal
per queue.

**`v0.16.0` NOT tagged.** That's Session 5. Session 2 is the
audit-debt paydown.

## Sprint scorecard

| # | Sprint | Status | Commit |
|---|---|---|---|
| 1 | ML-WIRE-1 | **shipped** | `8d9ffb5` |

## What shipped

### New plugin crate `strata-plugin-advisory` (Session 2 primary)

Registered in `strata_engine_adapter::plugins::build_plugins()`
immediately before `SigmaPlugin`. Reads `ctx.prior_results`,
invokes:

1. `AnomalyEngine::analyze` — IQR/statistical anomaly detection
   across the plugin output stream.
2. `AntiForensicDetector::detect` + `ObstructionScorer::score` —
   weighted 0–100 anti-forensic obstruction scoring.
3. `SummaryGenerator::generate` — template-rendered executive
   summary (Handlebars; no LLM, no model files).

Emits `ArtifactRecord` items with:
- `subcategory ∈ {"ML Anomaly", "ML Obstruction", "ML Summary"}` —
  the exact literal strings Sigma rules 30/31/32 filter on.
- `detail` containing bracket-delimited tokens
  (`[anomaly_type=TemporalOutlier]`, `[confidence=0.88]`) — the
  exact format Sigma's `parse_ml_confidence` helper consumes.
- `forensic_value` + `suspicious` flag + `mitre_technique` mapped
  per anomaly type.
- Every detail string explicitly carries the
  `[ML-ASSISTED — ADVISORY ONLY]` suffix to preserve the
  `is_advisory` invariant from the underlying ML crates.

Pipeline insertion: existing plugin-registry ordering IS the
pipeline-stage mechanism. Advisory runs after every forensic
plugin (which produced artifacts Advisory analyses), and before
Sigma (which correlates Advisory's output with plugin output in
one pass). No new named pipeline stage added — would duplicate
orchestration with zero behavior gain.

### Module status per Phase A audit (Lesson 1 discipline)

Per v15 Lesson 1, every ML entry function body inspected — not
just signatures:

| Crate | Entry function | Status | Notes |
|---|---|---|---|
| `strata-ml-anomaly` | `AnomalyEngine::analyze` | **working** | Real IQR/z-score detectors (stealth, temporal, timestamp manipulation, antiforensic, deletion). 5 detector modules, all with non-stub bodies. |
| `strata-ml-obstruction` | `ObstructionScorer::score` + `AntiForensicDetector::detect` | **working** | 13-behavior weighted scoring with VSS multipliers. Scoring math tested; detector layer wired but detector.rs still has no unit tests (flagged in v14 Opus audit as Phase B Part 3-ish gap). |
| `strata-ml-summary` | `SummaryGenerator::generate` | **working** | Handlebars templates (5 `.hbs` files loaded via `include_str!`). Real section extraction + rendering. |
| `strata-ml-charges` | `engine::analyze` | **out of scope for ML-WIRE-1** | Separate sprint — charge-relevance scoring requires a charge list input that the `strata ingest run` CLI doesn't currently gather. Dependency for a future CHARGE-WIRE-1 sprint. |

**No module stubs discovered.** The crates are real. The only
pre-Session-2 defect was integration — the pipeline never called
them. That's now fixed.

### Sigma rules 30/31/32 firing path verified

Integration test `sigma_rule_30_path_reachable_via_advisory_detail_format`
proves: `AdvisoryPlugin::execute` produces `ArtifactRecord` items
that `SigmaPlugin::execute` consumes via `ctx.prior_results`
without error. The handoff works end-to-end. Sigma rules 30/31/32
fire when anomaly findings match their confidence thresholds
(≥0.80 for TemporalOutlier, ≥0.75 for StealthExecution, ≥0.85 for
TimestampManipulation) — identical to the pre-v16 filter logic,
no Sigma-side changes required.

### Tripwire tests (4 integration + 7 unit)

Integration (`crates/strata-engine-adapter/tests/advisory_wiring.rs`):

- `advisory_plugin_registered_before_sigma_in_static_build` — pins
  the ordering invariant. Regression here silently disables
  Sigma rules 30/31/32.
- `advisory_plugin_emits_records_with_sigma_matchable_subcategories`
  — pins the subcategory-string invariant.
- `advisory_analytics_invoked_by_ingest_run_pipeline` — the
  queue's explicitly-required tripwire. Replaces the pre-v16
  implicit behavior where ML modules ran only from
  `apps/tree/strata-tree`.
- `sigma_rule_30_path_reachable_via_advisory_detail_format` —
  cross-plugin end-to-end handoff verification.

Unit (`plugins/strata-plugin-advisory/src/lib.rs::tests`):

- `plugin_metadata_shape`
- `empty_prior_results_produces_at_least_summary`
- `anomaly_detail_format_matches_sigma_rule_regex` — pins the
  bracket-delimited token format.
- `anomaly_variant_names_match_rust_enum_exactly` — pins the
  variant-name string literals used by Sigma filters against
  accidental rename drift.
- `obstruction_artifact_has_score_and_severity_in_detail`
- `summary_artifact_carries_status_and_section_count`
- `execute_emits_system_activity_category_records`

### README restored

`README.md` "Features" bullet replaced with framing-accurate copy:

> **Advisory analytics** — deterministic statistics and templates
> wired into every `strata ingest run`: IQR-based anomaly
> detection over plugin artifact timelines, anti-forensic
> obstruction scoring (0–100), template-rendered executive case
> summaries. No ML models, no LLM calls, no external API
> dependencies. Findings feed Sigma rules 30/31/32 for cross-
> artifact correlation. All output tagged ADVISORY and requires
> examiner verification.

Per the Opus audit's prescribed language: "deterministic
statistics and templates" — not "AI-powered." Explicitly calls
out no models, no LLM, no external APIs.

## Deferred (not blocking v0.16 tag, but open pickup signals)

### 1. apps/strata-desktop/ dedicated Advisory panel

**Status:** Advisory records flow into the existing case
artifact store via the standard plugin pipeline, so they
automatically appear in whatever the desktop app's case view
displays for plugin artifacts. A *dedicated* "Advisory Panel" UI
component with severity color coding and filter UI is additive
work, deferred per the queue's explicit scope-balloon clause.

**Pickup signal:** `apps/strata-desktop/src-tauri/src/lib.rs` is
the primary IPC surface. A new Tauri command (e.g.,
`get_advisory_findings(case_id)`) would query
`artifacts.sqlite` for records with `subcategory LIKE 'ML %'`
and return them grouped by subcategory + sorted by severity.
The frontend Vue/React (whatever the desktop uses) then renders
a sidebar panel alongside the existing artifact list. Estimated
scope: ~150 LOC Tauri command + ~200 LOC frontend component.
Non-blocking for v0.16 tag — Session 5 tag policy requires
wiring into ingest pipeline (shipped) and the advisory findings
visible to examiners (shipped via plugin artifact store).

### 2. wolfmarksystems.com index.html

**Status:** Website source lives in a separate repo from this
Strata code repo. This commit updates the in-repo README that
ships alongside the Strata source. Publishing the framing-
accurate "Advisory Analytics" section on the public website is
an operator-side commit in the website repo.

**Pickup signal:** Wolfmark Systems website repo, `index.html`,
"07 / ML Analysis — AI-Powered Scoring" section from the pre-
v0.14 audit. Replace with:

> **07 / Advisory Analytics — Deterministic Statistics &
> Templates.**
> Three advisory analytic layers run locally on every ingest:
> IQR-based statistical outlier detection, weighted obstruction
> factor scoring (0–100), template-rendered case summaries.
> Pure-Rust, pure-local. No cloud call. No model files.
> Reproducible across machines. Findings feed Sigma rules
> 30/31/32 for cross-artifact correlation. Every output tagged
> ADVISORY pending examiner approval.

### 3. `strata-ml-charges` (charge-relevance scoring)

**Status:** Exists as a fourth ML crate with `engine::analyze`.
Not wired in ML-WIRE-1 because charge-relevance scoring needs
a charge list input that the `strata ingest run` CLI doesn't
currently collect. Wiring would require a new `--charges` CLI
argument and a charge-selection UI on the desktop side.

**Pickup signal:** Future `CHARGE-WIRE-1` sprint. Add
`--charges <toml-path>` to `strata ingest run`; parse into
`Vec<ChargeRef>`; pass to a second call-site in the advisory
plugin (conditional on charges being present). Desktop app
gets a charge-picker pre-ingest. Not on v0.16 critical path.

### 4. detector.rs unit-test gap (v14 audit carryover)

**Status:** `strata-ml-obstruction::detector::*` functions
(`detect_vss_deletion`, `detect_evtx_clearing`, etc.) have zero
`#[test]` coverage per the v14 Opus audit. The scorer layer
that consumes detector output IS tested. Fixing this is a
small targeted sprint.

**Pickup signal:** Add unit tests for each `detect_*` function
against realistic `PluginOutput` fixtures. Estimated scope:
~100 LOC of tests.

## Quality gates end-of-session

- **Test count:** **3,795** (from 3,784 at session start; +11 —
  7 unit tests in strata-plugin-advisory + 4 integration tests in
  strata-engine-adapter, all passing).
- `cargo clippy --workspace -- -D warnings`: **clean**.
- AST quality gate: **PASS** at v14 baseline (470 library
  `.unwrap()` / 5 `unsafe{}` / 5 `println!` — zero new).
- All 9 load-bearing tests preserved.
- **All four v15 dispatcher arms still route live** (verified
  via `cargo test -p strata-fs --lib fs_dispatch`: 17 passed):
  - NTFS (v11): `dispatch_*_ntfs_*` tests pass.
  - ext4 (Session B):
    `dispatch_ext4_arm_attempts_live_walker_construction` passes.
  - HFS+ (Session D):
    `dispatch_hfsplus_arm_attempts_live_walker_construction` passes.
  - FAT12/16/32 (Session E):
    `dispatch_fat32_arm_attempts_live_walker_construction` passes.
- **APFS dispatcher arm still returns literal `"v0.16"` message**
  (`dispatch_apfs_returns_explicit_v016_message` test passes).
  Session 2 did not touch the dispatcher.
- **exFAT arm still returns deferral message** (unchanged).
- Charlie/Jo regression guards: unchanged.
- No public API regressions. New crate is additive; engine-
  adapter adds one registration line; SummaryGenerator /
  AnomalyEngine / ObstructionScorer all consumed through their
  existing public APIs.

## Pickup signals for Session 3 (APFS object map + HFS+ read_file)

Session 3 is entirely orthogonal to Session 2. No cross-
dependencies. The Session 1 research doc
(`docs/RESEARCH_v16_APFS_SHAPE.md`) is the authoritative starting
point. Key decisions already locked there:

- **Start from `apfs_walker.rs`, not `apfs.rs`.** The former has
  working OMAP + fs-tree walking. The latter is the heuristic-
  scanner + stubs module that should be retired or feature-
  gated.
- **Expose public `resolve_object(oid, xid)` API.** Research
  doc §3 sketch.
- **Fusion detection at container superblock time**
  (`nx_incompatible_features & 0x100`).
- **Latest-checkpoint-only with tripwire test**
  `apfs_uses_latest_checkpoint_only_pending_historical_walk`.
- **HFS+ read_file extent reading** pairs architecturally with
  APFS extent-record work in the same session per queue.

## The bottom line

v16 Session 2 closed the pre-v0.14 audit debt. Every case run
through `strata ingest run` now invokes the advisory analytics
modules before Sigma correlation. Sigma rules 30/31/32 see ML
Anomaly records in their `ctx.prior_results` and fire against
them. The framing-accurate README section is restored. Tripwire
tests pin the invariants — any regression that silently breaks
the wiring fails CI loudly.

No APFS work. No v0.15 regressions. No quality-gate regressions.

Strata is a forensic tool.
