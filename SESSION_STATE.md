# Strata — Session State

_Last updated: 2026-04-24_
_Executor: claude-opus-4-7 (MARCUS)_
_Approved by: ETHAN + KR_

---

## Sprint 8 — 2026-04-24

**P1 UI IPC Fix: PASSED**
  - Root cause identified: yes — five layered bugs documented in
    [Step 1 IPC architecture diagnosis](#sprint-8-p1-step-1-findings).
    Static-analysis fixes shipped as F1–F4; dynamic GUI test then
    surfaced a deeper VFS-bridge gap (per KR diagnosis 2026-04-24
    after the FILES counter showed 0 + ARTIFACTS showed 6).
  - Charlie artifacts in GUI: **3,756** (matches CLI exactly)
  - FILES counter in GUI: **10,183** (matches CLI materialize report)
  - Report generated via GUI: not re-tested this session — implied
    working since report generation was unchanged and the artifact
    pipeline now feeds it the same data the CLI does. Flag for
    confirmation if needed.
  - Second image tested: not this session — KR confirmed P1 PASSED on
    Charlie + greenlit move to weekend break before re-testing on Jo
    or NPS Jean. Re-verify post-weekend if KR wants it.

  ### Fixes shipped (in order)

  - **F3** — `engine::run_all_on_evidence` now threads `prior_results`
    between plugin stages so Sigma/Advisory see the same correlation
    inputs the CLI's `run_all_on_path` feeds them. `lib.rs::run_all_plugins`
    collapsed onto a single threaded call (no more N independent
    `run_plugin` invocations from the loop). Strips the `"Strata "`
    prefix when emitting `plugin-progress` events so frontend keys
    match `PLUGIN_DATA` short names.
  - **F2** — `PLUGIN_NAMES` in `apps/strata-desktop/src-tauri/src/lib.rs`
    expanded from 15 to 23 entries (added Sentinel, CSAM Scanner,
    Apex, Carbon, Pulse, Vault, ARBOR, Advisory Analytics — the 8
    plugins that ship in `build_plugins()` but were silently dropped
    from the UI's Run All loop). `PLUGIN_DATA` in
    `apps/strata-ui/src/types/index.ts` extended with the 8 missing
    cards. `PluginsView.tsx:104` hard-coded `"11 plugins"` →
    `{PLUGIN_DATA.length} plugins`.
  - **F4** — `is_plugin_complete()` helper accepts `"complete" |
    "completed" | "success"`. Fixes the long-standing
    `plugins_not_run` flag in `get_artifacts` that was checking only
    `"completed"/"success"` while `run_plugin` actually emits
    `"complete"`. 2 unit tests pin the canonical strings; a third
    test (`plugin_names_covers_the_full_backend_registry`) round-trips
    `PLUGIN_NAMES` against `engine::list_plugins()`.
  - **F1** — `TopBar.handleOpenEvidence` and `App.tsx` ⌘E handler
    auto-trigger `runAllPlugins` after `loadEvidence`+`getStats`
    completes, then re-fetch stats. Shared `pluginsRunning` flag
    in the Zustand store; `IndexingBadge` component renders a
    pulsed amber tag next to the ARTIFACTS counter while the run
    is in flight.
  - **VFS-bridge** (post-F1–F4 diagnosis) — `run_all_on_evidence`
    now mounts the lowercase `VirtualFilesystem` composite the
    same way the CLI's `mount_partitions_composite` does, calls
    `materialize_targets` to extract forensic-target files to a
    per-evidence host scratch dir (`/tmp/strata-ui/<eid>/extracted`),
    populates `OpenEvidence.files` with stub `CachedFile` entries
    so `stats.files` reflects the extracted count, and runs plugins
    with `root_path = scratch` AND `vfs = Some(vfs.clone())` —
    both surfaces, mirroring `run_all_on_vfs`. New sentinel
    `MATERIALIZE_EVENT_NAME = "__materialize__"` lets the Tauri
    layer surface materialize-stage progress separately from
    per-plugin events. Unit test
    `run_all_on_evidence_populates_artifact_cache_and_uses_host_root_path`
    pins the cache write path and the file-vs-dir branching.

  ### Sprint 8 P1 Step 1 findings

  Five issues identified in the static-analysis pass before any code
  changes; all five are now resolved:
  - F1 — Open-evidence flow never auto-triggered Run All (UX gap).
  - F2 — Desktop `PLUGIN_NAMES` shipped 15 of 23 plugins.
  - F3 — `engine::run_plugin` threaded an empty `prior_results`,
    starving Sigma/Advisory.
  - F4 — Status-string mismatch (`"complete"` vs `"completed"/"success"`).
  - **VFS-bridge** (the showstopper) — Even after F1–F4, GUI ran
    plugins against `vfs.root()` virtual path with `vfs: None` in
    `PluginContext`. Plugins' `walk_dir` returned 0 entries.
    Materialize step from CLI was not invoked. KR caught this on
    the first GUI dynamic test (FILES=0, ARTIFACTS=6) and
    diagnosed the gap precisely.

**P2 Tauri Configuration Cleanup: NOT STARTED**
  - Stale configs resolved: no
  - Version string fixed: no — `tauri.conf.json` still at `"1.5.0"`
    while Cargo.tomls are at `0.16.0` (drift carried from
    Sprint 7.5 P4)
  - Reasoning: P1 took the full session per the sprint's "frontend
    focus, P1 not done until GUI works" mandate. P2 deferred to a
    later session.

**P3 ShimCache / AppCompatCache Parser: SKIPPED**
  - Artifacts on Charlie: N/A
  - Tests added: 0
  - Reasoning: P3 was gated on P2 being complete per sprint rules.
    Will pick up after P2.

  ### Verification snapshot (Sprint 8 close)

  - `cargo build --workspace`: clean, 1m 24s on a fresh wipe
  - `cargo tauri build` from `apps/strata-desktop`: clean, 2m 36s,
    both `Strata.app` and `Strata_1.5.0_aarch64.dmg` bundled
  - `cargo test --workspace`: **3,923 passed, 0 failed**
  - `cargo test -p strata-engine-adapter --lib`: **18 passed, 0 failed**
    (includes new `run_all_on_evidence_populates_artifact_cache_and_uses_host_root_path`)
  - `cargo test` from `apps/strata-desktop/src-tauri`: **3 passed, 0 failed**
    (Sprint 8 P1 unit tests for `is_plugin_complete` + `PLUGIN_NAMES` registry round-trip)
  - `cargo clippy --workspace -- -D warnings`: **clean** (0 warnings, 0 errors)
  - All 9 load-bearing tests green

  ### Hard-rules check

  - New `.unwrap()` in production: 0
  - New `unsafe{}`: 0
  - New `println!`: 0 (only `tracing::warn!` already used by upstream `materialize_targets`)
  - New TODO/FIXME: 0

  ### Commits this sprint

  - `a4027af` — `feat: sprint-8-P1 UI VFS materialize bridge — GUI
    shows 3,756 artifacts on Charlie, FILES 10,183, matches CLI exactly`

  ### New tracked issues (deferred to Sprint 9)

  1. **Evidence tree infinite recursion** — TopBar's left-side
     evidence tree displays `"Volume 0 (10223990784 bytes)"` nested
     20+ levels deep. Pure rendering bug; data model is correct.
     Likely a parent-pointer or memoization issue in `EvidenceTree.tsx`
     / `get_tree_children`. Tracked for Sprint 9.
  2. **Vector category mapping over-counts Execution History** —
     Vector emits 3,018 PE analysis entries categorised as
     Execution History, including 2,990+ records titled
     `"Suspicious PE Analysis: Valid PE file — no threat"`. Behavior
     is correct (Vector did parse those PEs) but the Execution
     History category should not surface negative-result records.
     Either filter at category-mapping time in
     `engine-adapter::get_artifact_categories` / Vector, or move
     the negative-result records to a separate "Static Analysis"
     category. Tracked for Sprint 9.

---

## Sprint 7.5 — 2026-04-23 / 2026-04-24

---

## Sprint 7.5 — 2026-04-23 / 2026-04-24

**P1 Desktop Rehearsal: PASSED (via CLI verification after UI path divergence)**
  - Test count before: 3,699 (actual measured; CLAUDE.md baseline claim of 3,896 was stale — see commit `072decf`)
  - Tauri build: success (`cargo tauri build` from `apps/strata-desktop`, 2m 06s, both `.app` and `.dmg` bundles produced)
  - Launch: Strata.app opened cleanly (PID 43680 on first run), license → examiner-profile flow reached
  - Charlie artifact count in UI: **3,756 via CLI** (UI-driven plugin run gated on computer-use approval timing; KR approved substituting CLI verification since the CLI exercises the same `strata-engine-adapter` + plugin pipeline that the UI consumes via Tauri IPC)
  - CLI command: `cargo run -p strata-shield-cli --bin strata -- ingest run --source "/Users/randolph/Wolfmark/Test Material/charlie-2009-11-12.E01" --case-dir /tmp/sprint75_case`
  - Elapsed: 528,209 ms (~8m 48s); 10,183 files materialized from 10.2 GB E01
  - Zero ERROR / WARN / panic / failed lines across 23/23 plugins
  - Per-plugin counts (top): Vector 2,465 · Phantom 535 · Recon 215 · Chronicle 197 · Vault 180 · Trace 136 · Sigma 9 · Cipher 12 · others 0–12
  - Initial blocker (`cargo tauri build` from workspace root picking up `apps/shield/desktop/tauri.conf.json` v1-format config): resolved by running build from the app directory. See `SPRINT_7_5_BLOCKER.md` for the full diagnosis. Stale v1 configs in the tree (`apps/shield/desktop/`) flagged for future cleanup — not touched this sprint.

**P2 Plugin Tests: PASSED**
  - New tests written: 27 (3 per plugin × 9 plugins)
  - Test count after: 3,699 (delta +27 from pre-P2 actual of 3,672)
  - Plugins backfilled: conduit, index, mactrace, netflow, nimbus, recon, specter, vector, wraith
  - Pattern per plugin (module `sprint75_backfill_tests`):
    1. `plugin_has_valid_metadata` — asserts name/version/description non-empty via `StrataPlugin` trait
    2. `plugin_returns_ok_on_empty_input` — runs against a nonexistent `root_path`; lenient assertion `is_ok() || empty` matching sprint spec
    3. `plugin_does_not_panic_on_malformed_input` — creates a temp dir containing a 6-byte garbage file (`0xFF 0x00 0xDE 0xAD 0xBE 0xEF`), runs plugin against it; no panic assertion only
  - API adapted from sprint pseudocode: real signature is `StrataPlugin::run(PluginContext) -> PluginResult` (not `plugin.run(&[])`)
  - All `.expect()` usage scoped to `#[cfg(test)]` blocks per sprint hard rules
  - Zero new `.unwrap()` / `unsafe{}` / `println!` / TODO / FIXME in production code
  - Baseline drift surfaced and corrected: CLAUDE.md previously claimed "3,896 passing"; actual workspace run measures 3,699 post-P2 (3,672 pre-P2). Updated in commit `072decf` (`fix: update test baseline in CLAUDE.md — actual count 3,699 not 3,896`).

**P3 exFAT: DEFERRED (sprint premise incorrect)**
  - Walker wired: no
  - Integration test: no
  - Reason: sprint plan described P3 as "wiring" and claimed "Pattern is identical to the FAT32 wiring." Investigation showed `crates/strata-fs/src/exfat.rs` (169 lines) exposes only `exfat_fast_scan()` returning an `ExFatBootSector` — it does NOT implement `VirtualFilesystem`. There is no `ExFatWalker`. By contrast, `fat_walker/mod.rs` is 1,063 lines of real VFS work. Building a real exFAT walker requires a directory-entry parser (0x85 / 0xC0 / 0xC1 entry types), FAT chain walking, UTF-16 filename decoding, and upcase table handling — realistically ~800–1,200 lines, not a sprint step.
  - Decision (KR): defer. The existing `"exFAT walker deferred — see roadmap"` pickup signal stays. Tripwire test `dispatch_exfat_returns_explicit_deferral_message` in `fs_dispatch.rs:580` continues to pin the deferral.
  - Roadmap entry added: `ROADMAP.md` near-term section.

**P4 Version drift: FIXED**
  - Decision: unified at workspace ground-truth 0.16.0 per KR direction
  - `apps/strata-desktop/src-tauri/Cargo.toml`: 1.5.0 → 0.16.0
  - `crates/strata-shield-cli/Cargo.toml`: 0.1.0 → 0.16.0
  - Workspace root `Cargo.toml`: no top-level `version` field — the 0.16.0 figure referenced in the sprint audit appears to be a project-semver label, not a Cargo.toml value. Both package-level Cargo.tomls now explicitly declare 0.16.0.
  - `cargo build --workspace` clean, 1m 51s
  - Not touched: `tauri.conf.json` version (`1.5.0`) — distinct from Cargo.toml package version and was outside P4 scope. Flag for future alignment if the release pipeline treats them as coupled.

---

## Verification snapshot (end of sprint)

- `cargo test --workspace`: 3,699 passed, 0 failed across 51 test binaries
- `cargo clippy --workspace -- -D warnings`: clean (0 warnings, 0 errors)
- Load-bearing tests (all 9 from CLAUDE.md): all green
  - `build_lines_includes_no_image_payload` ✓
  - `hash_recipe_byte_compat_with_strata_tree` ✓
  - `rule_28_does_not_fire_with_no_csam_hits` ✓
  - `advisory_notice_present_in_all_findings` ✓
  - `is_advisory_always_true` (strata-ml-anomaly) ✓
  - `advisory_notice_always_present_in_output` ✓
  - `examiner_approved_defaults_to_false` ✓
  - `summary_status_defaults_to_draft` ✓
  - `is_advisory_always_true` (strata-ml-charges) ✓

---

## Commits this sprint

- `072decf` — `fix: update test baseline in CLAUDE.md — actual count 3,699 not 3,896`
- `f50ed4a` — `fix: sprint-7.5-P4 version drift — unified at 0.16.0` (also captures P3 deferral note in new `ROADMAP.md`)

**Uncommitted at session end:** the 9 plugin-test-backfill edits (P2) remain as working-tree modifications (unstaged) — no explicit P2 commit instruction was given this sprint. Diff scope: `plugins/strata-plugin-{conduit,index,mactrace,netflow,nimbus,recon,specter,vector,wraith}/src/lib.rs` (append-only `sprint75_backfill_tests` modules).

---

## Flags for KR / ETHAN

1. **Stale Tauri v1 configs in tree** — `apps/shield/desktop/tauri.conf.json` uses v1-format `devPath`/`distDir`/`package`/`tauri` keys; was picked up by `cargo tauri build` when run from workspace root. Running from the app directory avoids it, but the stale configs are a footgun for anyone following the sprint's workspace-root build command verbatim. Candidates for removal or migration: `apps/shield/desktop/`, `apps/tree/forensicview-pro/src-tauri/` (missing `$schema`).
2. **CLAUDE.md "Key numbers" drift** — the sprint-7.5 work corrected the test-count line (3,896 → 3,699). The parenthetical "3,836 v0.16.0 baseline + 60 tripwires" math no longer reconciles and was preserved pending a broader refresh rather than silently rewritten. Worth a pass.
3. **CLAUDE.md Sigma finding count** — CLAUDE.md claims "7 Sigma findings fire" on Charlie; current CLI output shows Sigma emitting 9 artifacts. Not necessarily a regression (findings vs. total-artifact distinction), but worth confirming.
4. **UI IPC path** — P1 acceptance "Charlie loads and produces >= 3,756 artifacts in the UI" was verified via CLI proxy. The earlier reported "UI indexing failure" (cited in KR's pivot to CLI) is separately tracked and not a P1 blocker per KR direction.
5. **tauri.conf.json version drift (P4 follow-up)** — desktop package Cargo.toml is now 0.16.0, but `apps/strata-desktop/src-tauri/tauri.conf.json` still declares `"version": "1.5.0"`. If the release pipeline expects alignment, flag it.

---

_Sprint 7.5 executed per SPRINT_7_5.md. Stopping here per KR instruction._
