# Windows Restore/Shadow Copies Coverage Limits

Status date: 2026-03-11

Current `restore-shadow-copies` support is intentionally conservative:

1. Supports JSON/CSV/text exports for restore-point and shadow-copy metadata.
2. Emits normalized rows with deterministic sort/dedupe and nullable identity fields.
3. Supports timeline mapping (`--source restore-shadow-copies`) and execution-correlation enrichment.

Known limits:

1. Coverage is export-driven; no full VSS block-level parsing is claimed.
2. File-level change details depend on source export completeness.
3. No inferred restoration outcomes are fabricated when fields are absent.
