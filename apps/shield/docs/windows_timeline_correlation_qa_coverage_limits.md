# Windows Timeline Correlation QA Coverage Limits

Status date: 2026-03-11

Current `timeline-correlation-qa` support is intentionally conservative:

1. Supports JSON/CSV/text exports that already contain event/timestamp-style fields.
2. Emits normalized rows with deterministic sort/dedupe and nullable context fields.
3. Supports timeline mapping (`timeline --source timeline-correlation-qa`) and execution-correlation enrichment.

Known limits:

1. This command normalizes exported QA/performance rows only; it does not extract raw forensic artifacts itself.
2. Timestamp quality depends on source exports and can be sparse.
3. Severity is normalized conservatively (`info|warn|error`) without speculative escalation.
