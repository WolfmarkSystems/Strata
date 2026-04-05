# Strata Forensic Correctness Invariants

This document defines non-negotiable correctness and integrity guarantees for the Strata ecosystem.

## 1) Evidence Ingestion Invariants

- Every evidence source must be assigned a stable `evidence_id`.
- Ingestion must record source metadata (path/device/container type, size, timestamps where available).
- Ingestion must compute and persist cryptographic hashes for source data when feasible.
- Unsupported or malformed evidence must return structured errors; ingestion must not panic.

## 2) Provenance Invariants

- Every derived artifact must retain provenance metadata:
  - source `evidence_id`
  - parser/module identifier and version
  - source record identifier or byte/offset reference when available
  - extraction timestamp in UTC
- Transformations must be traceable from report output back to source evidence and parser version.

## 3) Chain-of-Custody Invariants

- Case activity logs must be append-only at the semantic layer.
- Hash-chain verification for activity logs must be available and reproducible.
- Export workflows must support verification gating (block on failed verification when policy requires).

## 4) Determinism Invariants

- Given the same evidence input, configuration, and parser versions, core extraction output must be reproducible.
- Non-deterministic operations (parallel scheduling, unordered maps, clock-based behavior) must not alter semantic results.
- Any unavoidable non-determinism must be explicitly documented and isolated.

## 5) Error Handling Invariants

- Production paths must not use panic-driven control flow.
- Errors must include context (module, operation, relevant identifiers) without exposing secrets.
- Recoverable parser failures should degrade gracefully and continue processing where safe.

## 6) Security Invariants

- `unsafe` usage must be constrained to clearly defined modules with explicit justification.
- Dynamic plugin loading must enforce version compatibility and capability boundaries.
- Untrusted content parsing (files, memory dumps, plugin outputs) must be treated as hostile input.

## 7) Reporting Invariants

- Reports must include tool version/build metadata.
- Report summaries must be derivable from persisted evidence/artifact stores.
- Exported bundles must include a manifest with hashes for included files.

## 8) Operational Invariants

- CI must enforce formatting, linting, tests, and repository hygiene checks.
- Generated artifacts (`node_modules`, `target*`, `dist`, `build`, `.vite`) must not be committed.
- Dependency updates must preserve reproducibility and pass all quality gates.

## 9) Acceptance Checklist for New Features

A feature is not complete unless:

1. It preserves ingestion, provenance, and determinism invariants.
2. It includes tests covering malformed input behavior.
3. It avoids panics in production execution paths.
4. It updates case/report schema contracts if data shape changes.
5. It passes CI quality gates.
