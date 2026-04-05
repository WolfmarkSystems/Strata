# Windows EVTX Security Coverage Limits

Status date: 2026-03-10

Current EVTX security support is intentionally conservative:

1. Parses Security.evtx/XML records using existing event XML semantics.
2. Normalizes core fields (`timestamp_unix`, `timestamp_utc`, `event_id`, `source`, `record_id`).
3. Preserves named `event_data` fields when present.
4. Emits quality metadata (`input_shape`, `parser_mode`, `fallback_used`, `deduped_count`, `quality_flags`).
5. Exposes summary counters (`logon_events`, `failed_logons`, `privilege_escalation`, `account_changes`).

Known limits:

1. Raw EVTX chunk traversal is still opportunistic via XML extraction, not a full record-walk decoder.
2. Message-template expansion from provider DLLs is not implemented.
3. Some security event families have generic summaries when named fields are sparse.
4. Timeline fusion from this command is not yet directly wired as a dedicated source filter.
