# Strata Development Workflow

This workflow standardizes local development and CI expectations across Rust and Node/Tauri projects.

## Prerequisites

- Rust stable toolchain with `rustfmt` and `clippy`
- Node.js 20+
- Python 3.11+

## Daily Workflow

1. Pull latest changes.
2. Build only what you touched first.
3. Run workspace checks before opening a PR.

## Canonical Commands

- Full quality suite:
  - `bash scripts/run_workspace_checks.sh`
  - `powershell -ExecutionPolicy Bypass -File scripts/run_workspace_checks.ps1`
- Reliability gate only:
  - `bash scripts/check_reliability.sh`
  - `powershell -ExecutionPolicy Bypass -File scripts/check_reliability.ps1`
- Contract validation only:
  - `python3 scripts/validate_forensic_contracts.py`
  - `python scripts/validate_forensic_contracts.py`
- Benchmark smoke:
  - `bash scripts/benchmark_smoke.sh`

## Reliability Policy (Phase 1)

- New production `unwrap`/`expect` usage is blocked by baseline checks.
- `unsafe` usage is baseline-locked and restricted to approved files.
- Any intentional baseline change must be reviewed and justified in PR notes.

## Forensic Data Contract Policy (Phase 2)

- Evidence manifests must conform to `contracts/evidence.manifest.schema.json`.
- Artifact provenance records must conform to `contracts/artifact.provenance.schema.json`.
- Contract example files are validated in CI and serve as reference payloads.

## DX and Performance Policy (Phase 3)

- Rust quality and hygiene gates run on every push/PR.
- Node apps are auto-discovered and lint/build checked in CI.
- Benchmark smoke workflow ensures release/bench compilation stays healthy.

## Artifact Hygiene

Generated artifacts must never be committed:

- `node_modules`
- `target*`
- `dist`
- `build`
- `.vite`
