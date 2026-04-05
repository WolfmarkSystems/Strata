# Windows Browser Forensics Coverage Limits

Status date: 2026-03-11

Current `browser-forensics` support is intentionally conservative:

1. Supports `sqlite`-identified input files, JSON arrays/objects, CSV exports, and line-text fallback.
2. Emits normalized rows with deterministic sort/dedupe and nullable identity/timestamp fields.
3. Supports timeline mapping (`--source browser-forensics`) and execution-correlation enrichment.

Known limits:

1. SQLite parsing is fallback-level and does not claim full browser database semantic coverage.
2. Browser profile/session attribution depends on source export quality.
3. No inferred visit metadata is fabricated when source fields are absent.
