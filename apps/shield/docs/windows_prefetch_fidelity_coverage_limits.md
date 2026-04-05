# Windows Prefetch Fidelity Coverage Limits

Status date: 2026-03-11

Current `prefetch-fidelity` support is intentionally conservative:

1. Supports directory, `.pf`, JSON, CSV, and line-text style prefetch exports.
2. Emits normalized rows with deterministic sort/dedupe and nullable execution/identity hints.
3. Supports timeline mapping (`--source prefetch`) and execution-correlation enrichment.

Known limits:

1. This is not a complete parser for every historical Prefetch format nuance.
2. Process identity fields are only surfaced when source references are present.
3. No inference is performed for absent run metadata.
