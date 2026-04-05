# Windows USN Journal Fidelity Coverage Limits

Status date: 2026-03-11

Current `usn-journal-fidelity` support is intentionally conservative:

1. Supports exported JSON/CSV/text USN rows with normalized reason/timestamp fields.
2. Uses deterministic dedupe/sort and explicit null handling for missing timestamps.
3. Integrates with timeline source mapping (`--source usn-journal`) and execution-correlation enrichment.

Known limits:

1. Raw binary `$UsnJrnl` stream decoding is not included in this MVP command path.
2. Export shape variance can reduce field completeness (especially FRN/parent FRN and reason masks).
3. High-fidelity reason reconstruction depends on source export quality.

