# Windows User Activity/MRU Coverage Limits

Status date: 2026-03-11

Current `user-activity-mru` support is intentionally conservative:

1. Supports JSON/CSV/text exports for RunMRU/OpenSaveMRU/UserAssist/RecentDocs-like records.
2. Emits normalized rows with deterministic sort/dedupe and nullable identity fields.
3. Supports timeline mapping (`--source user-activity-mru`) and execution-correlation enrichment.

Known limits:

1. Coverage is export-driven and does not claim full per-hive binary replay.
2. Timestamp availability varies by source family (RunMRU may be timestampless).
3. No inferred user intent is fabricated when source metadata is sparse.
