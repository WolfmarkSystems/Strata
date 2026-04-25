# LEGACY — `apps/shield/`

This directory holds the original "Forensic Suite" / "Strata Shield"
exploration. **It is no longer part of the active build.** The Strata
desktop app under `apps/strata-desktop/` and the headless engine /
CLI under `crates/strata-shield-engine` + `crates/strata-shield-cli`
are the canonical surfaces going forward.

## Status

- Not a member of the workspace (`Cargo.toml` `members` array does not
  include any path under `apps/shield/`).
- The `forensic_desktop` crate at `apps/shield/desktop/Cargo.toml` is
  unmaintained — last touched in the initial v0.3.0 import (`19f56b9`).
- The various `tauri.conf.json` files under `apps/shield/desktop/`,
  `apps/shield/gui-tauri/`, and `apps/shield/gui/` are reference-only.
  Do not run `cargo tauri build` against any of them.
- Build artifacts (logs, audit dumps, conversion scripts) accumulated
  here during early experimentation. They are kept for historical
  reference; they are not load-bearing.

## Why it stays

Several of the early forensic notes (`EVIDENCE_INGESTION_REVIEW.md`,
`FEATURES.md`, `SUITE_REALITY_REPORT.md`) capture context for how
Strata's plugin set evolved. Removing the directory would lose that
record. Treating it as legacy is the cheapest accurate option.

## What the active app is

- **GUI**: `apps/strata-desktop/` (Tauri 2 desktop app).
- **CLI / engine**: `crates/strata-shield-cli/` (binary), backed by
  `crates/strata-shield-engine/`.
- **UI**: `apps/strata-ui/` (React/Vite, statically packaged into
  the Tauri bundle).
- **Plugins**: 24 crates under `plugins/`, statically linked through
  `crates/strata-engine-adapter/`.

If you need to ship a fix or a new feature, work in those paths — not
here.
