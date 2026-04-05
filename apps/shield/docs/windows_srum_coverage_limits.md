# Windows SRUM Coverage Limits

Status date: 2026-03-10

Current SRUM support is intentionally conservative:

1. Accepts SRUM data exported as JSON or CSV.
2. Normalizes timestamps (`timestamp_unix`, `timestamp_utc`) and timestamp precision hints.
3. Normalizes identity/path fields (`user_sid`, `exe_path`) and dedupes exact duplicate rows.
4. Produces truthful warnings and quality flags for sparse or malformed input.
5. Supports timeline mapping via `timeline --source srum --srum-input <path>`.

Known limits:

1. Raw `SRUDB.dat` ESE direct decode is not implemented in this MVP.
2. Record-table-specific SRUM semantics are not fully modeled yet.
3. CSV parsing is intentionally simple and best-effort.
4. Correlation with execution/persistence clusters is currently indirect (timeline/summary level).
