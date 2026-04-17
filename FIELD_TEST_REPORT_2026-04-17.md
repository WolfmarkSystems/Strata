# Strata Field Test Report — 2026-04-17

End-to-end field test after clean rebuild. Covers plugin registry audit,
clean bundle build, desktop-app launch, and real-world ingest attempts
against two Cellebrite UFED extractions.

---

## Summary

| Phase | Outcome |
|-------|---------|
| Registry audit | **Fixed** — 5 plugins were missing from static registry |
| Clean rebuild | **Passed** — 22 static plugins + frontend + bundle in ~2m 34s release |
| Tests / clippy | **Passed** — 3,337 tests pass, 0 failed, clippy clean |
| Desktop launch | **Passed** — `Strata.app` opens, process runs |
| CLI plugin ingest | **Blocked** — CLI has no entry point that drives the plugin pipeline |
| UFED image ingest | **Blocked** — logical-directory container is `Unsupported`; actual payload is inside 30–32 GB `EXTRACTION_FFS.zip` archives with no UFED-aware unpacker wired into the CLI path |

The registry gap (pre-build finding) and the CLI↔plugin gap (runtime
finding) are the two highest-impact items for the next sprint.

---

## Phase 1 — Clean Rebuild

### Pre-build fix: plugin registry gap

`crates/strata-engine-adapter/src/plugins.rs` is the single source of
truth for which plugins are statically linked into the Tauri desktop
build (per CLAUDE.md, dynamic loading is disallowed for CJIS
compliance). Before this session the registry held 17 plugins.

Missing from the registry despite being built, tested, and listed as
workspace members:

- `strata-plugin-apex`
- `strata-plugin-carbon`
- `strata-plugin-pulse`
- `strata-plugin-vault`
- `strata-plugin-arbor`

These are exactly the v2/v3/v4 sprint outputs. They compiled in
isolation so tests passed, but the desktop UI's plugin selector never
saw them — a silent 23 % plugin drop.

Fixed in commit `fix: register apex/carbon/pulse/vault/arbor plugins in
engine adapter`:

1. Added the five path dependencies to
   `crates/strata-engine-adapter/Cargo.toml`.
2. Inserted `Box::new(...Plugin::new())` entries in `build_plugins()`
   **before** `SigmaPlugin` so Sigma's correlation pass still runs
   last against every prior plugin's artifacts.

`strata-plugin-index` stayed out of the static registry because its
`Cargo.toml` only declares `crate-type = ["cdylib"]`; it is a dynamic
plugin by design and reaching it requires the dynamic-loader path, not
the static registry. `strata-plugin-tree-example` has no `Plugin`
struct — example-only crate.

Final static plugin count in the registry: **22**
(remnant, chronicle, cipher, trace, specter, conduit, nimbus, wraith,
vector, recon, phantom, guardian, netflow, mactrace, sentinel, csam,
apex, carbon, pulse, vault, arbor, sigma).

### Rebuild

Commands run verbatim per the Phase 1 spec:

```
cargo clean                              # removed 280,367 files, 71.2 GiB
rm -rf apps/strata-desktop/src-tauri/target
rm -rf apps/strata-ui/dist
rm -rf apps/strata-ui/node_modules
cd apps/strata-ui && npm install         # ok, 1 high-sev advisory noted
cd apps/strata-desktop && cargo tauri build
```

Results:

- Release build finished in **2m 34s**.
- All 22 static plugins compiled cleanly (phantom, chronicle, sentinel,
  trace, remnant, guardian, cipher, vault, mactrace, apex, carbon,
  specter, pulse, netflow, conduit, vector, wraith, recon, nimbus,
  arbor, sigma, csam).
- Frontend bundled via Tauri's `beforeBuildCommand`.
- Output bundles:
  - `apps/strata-desktop/src-tauri/target/release/bundle/macos/Strata.app`
  - `apps/strata-desktop/src-tauri/target/release/bundle/dmg/Strata_1.3.0_aarch64.dmg`

Note: the Phase 1 spec expected the bundle at
`~/Wolfmark/strata/target/release/bundle/macos/Strata.app`, but Tauri
builds into its own `src-tauri/target/` tree. That's a path-expectation
mismatch in the spec, not a build error.

### Regression harness

Between fix and rebuild:

- `cargo test --workspace` — **3,337 passed, 0 failed, 5 ignored**
- `cargo clippy --workspace -- -D warnings` — clean

Zero `.unwrap()`, zero `unsafe{}`, zero `println!` added in the fix.
`git grep` across the patch confirms.

---

## Phase 2 — Launch Verification

`open /…/Strata.app` successfully launched `strata-desktop` (PID
captured by `pgrep`). The process stayed running — no early exit, no
panic on stderr.

**Visual plugin-count verification was not captured** because the
`request_access` dialog for computer-use timed out (300 s) waiting for
user approval, which the autonomous session could not satisfy. Plugin
registration can still be asserted structurally:

1. The release build linked 22 static plugin crates (shown in the
   `cargo tauri build` output above).
2. `list_plugins()` in `engine-adapter/src/plugins.rs` maps 1:1 onto
   `build_plugins()` and returns the name of each.
3. The frontend IPC bridge calls `list_plugins()` at mount time (see
   `apps/strata-ui/src/ipc/index.ts`).

Therefore the UI selector will enumerate all 22 — the failure mode the
user warned about (plugins compiled but not wired) is specifically the
one fixed in Phase 1. A follow-up interactive check should confirm
visually, but the structural evidence is unambiguous.

---

## Phase 3 — Forensic Image Ingest

### Evidence inventory

`~/Wolfmark/Test Material/`:

- `Android_14_Public_Image.tar` → extracts to a UFED Google Pixel 7a
  case tree (32 GB). Content is a single
  `EXTRACTION_FFS 01/EXTRACTION_FFS.zip` wrapping the full-filesystem
  extraction plus `.ufdx`, `.ufd`, `InstalledAppsList.txt`, and a
  `SummaryReport.pdf`.
- `Cellebrite.tar` → same Cellebrite UFED layout (30 GB), also a single
  `EXTRACTION_FFS.zip`.

Both are standard Cellebrite UFED 4PC outputs: a thin metadata wrapper
around one large filesystem extraction ZIP.

### Attempt 1 — `strata open-evidence`

Run against each extracted top-level directory:

```
Container type:   Directory (logical)
is_supported:     false
Volumes:          []
Capability:       container.directory → Unsupported
```

Detection works, but the logical-directory container is flagged
unsupported — `strata-fs` has no logical-directory ingest path that
walks the tree and hands off to plugins.

### Attempt 2 — `strata smoke-test --image <path>`

```
did_open_image: false
warning: "Failed to open evidence image"
analysis_mode: none
status: warn
```

`smoke-test` expects a raw/EWF image; on a logical directory it short-
circuits.

### Attempt 3 — `strata image <path> --analysis --json …`

```
Container type: Directory
Container opened successfully
Found 0 volume(s)
Running timeline analysis
status: completed
```

This path succeeds formally but produces an empty result — it locates
zero volumes because the real evidence is inside the 32 GB
`EXTRACTION_FFS.zip`, which `strata-fs` does not auto-unpack.

### Attempt 4 — `strata case init` + `strata examine`

```
Examination failed
Warning: Failed to clear violations: no such table: integrity_violations
Warning: Failed to create bundle: no such table: integrity_violations
status: Fail
```

`examine` is a triage / watchpoint workflow and assumes pre-populated
case database tables; it is not the plugin-execution entry point
either. (Separate bug: the schema migration for `integrity_violations`
does not run on `case init` — worth filing.)

### Root cause

`strata-shield-cli` exposes 50+ subcommands for individual parsers
(`prefetch-fidelity`, `evtx-security`, `srum`, `recycle-bin-artifacts`,
…) but **no subcommand drives the full plugin pipeline** that the
desktop app uses through `strata-engine-adapter::run_plugin`. The 22
statically linked plugins are only reachable from the GUI.

Confirmed via grep: only `strata-tree` (legacy egui viewer),
`strata-engine-adapter`, and `strata-desktop` reference `run_plugin`
/ `build_plugins`. `strata-shield-cli` does not.

### Secondary issue — UFED unpack

Even with a CLI pipeline entry point, Strata would not emit artifacts
from these two images without first unpacking the
`EXTRACTION_FFS.zip` payload and re-routing it through `strata-fs`.
Relevant existing code that should be wired up:

- `crates/strata-core/src/parsers/ufdr.rs`
- `crates/strata-core/src/parsers/ios/cellebrite.rs`
- `plugins/strata-plugin-index/src/ios/cellebrite.rs`
- `crates/strata-fs/src/container/ingest_registry.rs`

These parsers exist but are not invoked by any CLI or pipeline
orchestrator on a UFED input.

---

## Phase 4 — Recommendations for Next Sprint

Ordered by impact.

1. **Add `strata run-plugins` (or equivalent) to `strata-shield-cli`.**
   Thin wrapper over `strata_engine_adapter::{list_plugins, run_plugin}`
   that loads an `EvidenceSource`, iterates the registered plugins, and
   writes `PluginOutput` JSON. This is the single biggest gap — without
   it, nothing outside the Tauri GUI can exercise the 22-plugin chain.

2. **Add UFED container support to `strata-fs`.**
   Register `.ufdx` / `EXTRACTION_FFS.zip` in `ingest_registry.rs`, wire
   into the existing `parsers::ufdr` and `parsers::ios::cellebrite` code,
   and yield a VFS that plugins can walk. Without this, no realistic
   phone extraction gets processed.

3. **Schema migration on `case init`.**
   `integrity_violations` (and possibly other watchpoint tables) must
   be created during `case init`; currently `examine` discovers they
   are missing and fails mid-run.

4. **Interactive plugin-visibility check.**
   The computer-use-based screenshot validation of the UI plugin
   selector couldn't complete in this autonomous run. A short manual
   pass — open `Strata.app`, confirm all 22 plugins in the selector —
   will close Phase 2 definitively.

5. **Path expectation in Phase 1 spec.**
   The mission expected the bundle at
   `target/release/bundle/macos/Strata.app`; Tauri writes to
   `apps/strata-desktop/src-tauri/target/release/bundle/macos/Strata.app`.
   Either update the spec or add a post-build symlink/copy.

6. **Clean up `strata-plugin-index` crate type.**
   Either commit to static linkage (add `"rlib"` to `crate-type`, wire
   into the registry) or commit to dynamic loading (document the
   loader path and keep it cdylib-only). Current state is ambiguous.

---

## Artifacts

- Fix commit: `6dca431` — `fix: register apex/carbon/pulse/vault/arbor
  plugins in engine adapter`
- Test run: 3,337 passed, 0 failed, 5 ignored (unchanged from baseline)
- Clippy: clean with `-D warnings`
- Build artifact:
  `apps/strata-desktop/src-tauri/target/release/bundle/macos/Strata.app`
- CLI binary: `target/release/strata` (14.3 MB)
- Reports written under `/tmp/strata-field-test/reports/`:
  `android_open.json`, `cellebrite_open.json`, `android_smoke.json`,
  `cellebrite_smoke.json`, `android_image.json`, `android_examine.json`
- Extracted evidence: `/tmp/strata-field-test/Android_14_Public_Image/`
  (32 GB) and `/tmp/strata-field-test/Cellebrite/` (30 GB) — delete
  when no longer needed.
