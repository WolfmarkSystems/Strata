# Windows Amcache Coverage Limits

Status date: 2026-03-11

Current `amcache-deep` support is intentionally conservative:

1. Parses Amcache file-entry records from registry exports.
2. Supports fallback text parse mode when export parser yields no rows.
3. Normalizes timestamps and SHA1 values with explicit null handling.
4. Dedupe keeps deterministic newest rows by path/hash/timestamp key.
5. Integrates into timeline (`--source amcache`) and execution-correlation enrichment.

Known limits:

1. No full Amcache inventory model yet (focus is file-entry artifacts).
2. Some exports omit timestamps, limiting timeline usefulness.
3. Identity attribution is best-effort (`executable_name` only).
