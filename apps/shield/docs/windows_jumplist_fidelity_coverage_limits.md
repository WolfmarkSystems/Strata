# Windows JumpList Fidelity Coverage Limits

Status date: 2026-03-11

Current `jumplist-fidelity` support is intentionally conservative:

1. Supports automatic/custom destination files, directories, JSON, CSV, and line-text exports.
2. Emits normalized Jump List rows with deterministic sort/dedupe and nullable metadata fields.
3. Supports timeline mapping (`--source jumplist`) and execution-correlation enrichment.

Known limits:

1. Parsed entry metadata depends on available source structure and may be partial.
2. Binary fallback remains heuristic for malformed/truncated records.
3. No confidence scoring is inferred for missing provenance fields.
