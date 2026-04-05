# Windows EVTX Sysmon Coverage Limits

Status date: 2026-03-11

Current EVTX Sysmon support is intentionally conservative:

1. Parses Sysmon EVTX/XML records via existing event XML extraction paths.
2. Normalizes core fields (`timestamp_unix`, `timestamp_utc`, `event_id`, `source`, `record_id`).
3. Preserves named `event_data` fields and semantic summary/category when available.
4. Emits quality metadata (`input_shape`, `parser_mode`, `fallback_used`, `deduped_count`, `quality_flags`).
5. Supports timeline (`--source evtx-sysmon`) and execution-correlation enrichment (`--evtx-sysmon-input`).

Known limits:

1. No provider message-DLL expansion for full rendered event text.
2. Raw EVTX chunk walking is still opportunistic via extracted XML fragments.
3. High-fidelity per-event schema typing is still minimal.
4. Correlation uses executable-name overlap and is not a full graph engine.
