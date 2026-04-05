# Windows LNK Shortcut Fidelity Coverage Limits

Status date: 2026-03-11

Current `lnk-shortcut-fidelity` support is intentionally conservative:

1. Supports `.lnk` files/directories, JSON, CSV, and line-text exports.
2. Emits normalized shortcut rows with deterministic sort/dedupe and nullable timestamp/path metadata.
3. Supports timeline mapping (`--source lnk-shortcuts`) and execution-correlation enrichment.

Known limits:

1. Parsed shell-link details depend on source completeness and may be partial.
2. Text/CSV fallback parsing is best-effort and does not replace binary decoding quality.
3. No inferred artifact confidence is emitted when source fields are absent.
