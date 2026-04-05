# Windows WMI Persistence/Activity Coverage Limits

Status date: 2026-03-11

Current `wmi-persistence-activity` support is intentionally conservative:

1. Merges persistence bindings, trace records, and class instance rows from exported inputs.
2. Uses deterministic dedupe/sort with explicit null handling for missing timestamps.
3. Supports timeline source mapping (`--source wmi-persistence`) and execution-correlation enrichment.

Known limits:

1. Many persistence/instance rows are naturally untimestamped in exports.
2. No live WMI repository parsing path is included in this MVP.
3. Trace and instance formats vary heavily by export tooling; unknown formats degrade to warning-only behavior.

