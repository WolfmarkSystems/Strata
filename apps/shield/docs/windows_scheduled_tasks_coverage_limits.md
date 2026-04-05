# Windows Scheduled Tasks Coverage Limits

Status date: 2026-03-11

Current `scheduled-tasks-artifacts` support is intentionally conservative:

1. Parses task XML trees recursively and emits task/action-level records.
2. Normalizes `LastRunTime` / `NextRunTime` into unix+UTC fields where present.
3. Includes fallback text extraction for partially malformed or non-standard task exports.
4. Applies deterministic dedupe/sort and explicit null handling for optional fields.
5. Integrates with timeline (`--source scheduled-tasks`) and execution-correlation enrichment.

Known limits:

1. Trigger cadence detail is shallow; no full trigger semantic expansion yet.
2. COM-handler actions are surfaced but not deeply decoded.
3. Some environments expose binary task cache data not covered by XML/text export paths.
