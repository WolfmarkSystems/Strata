# Windows NTFS LogFile Signals Coverage Limits

Status date: 2026-03-11

Current `ntfs-logfile-signals` support is intentionally conservative:

1. Supports binary, JSON, and line-text style LogFile exports.
2. Emits normalized signal rows with deterministic sort/dedupe and nullable identity fields.
3. Supports timeline source mapping (`--source ntfs-logfile`) and execution-correlation enrichment.

Known limits:

1. This is not full `$LogFile` transaction replay.
2. Timestamp/identity fields are only populated when present in the source export.
3. Binary keyword scanning is signal-oriented and not a complete parser for every record type.
