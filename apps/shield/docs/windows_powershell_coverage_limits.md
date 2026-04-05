# Windows PowerShell Artifacts Coverage Limits

Status date: 2026-03-11

Current `powershell-artifacts` support is intentionally conservative:

1. Reads available PowerShell artifact sources without requiring backend/schema changes.
2. Supports mixed input shapes for events (`json array/object/records/events/items`) and text fallback.
3. Normalizes timestamps to `timestamp_unix` and `timestamp_utc` where source timestamps exist.
4. Adds deterministic sorting and dedupe (`source+timestamp+core_fields`).
5. Exposes quality metadata (`input_shapes`, `fallback_used`, `deduped_count`, warnings).
6. Enriches timeline (`--source powershell`) and execution correlation (`powershell_count`) using existing CLI pathways.

Known limits:

1. No direct EVTX 4103/4104 semantic decode in this command yet.
2. History and module rows usually lack authoritative execution timestamps.
3. No script-content deobfuscation or AMSI/ETW deep decoding in this MVP.
4. Identity fields are best-effort (`executable_name`) and not full user/session attribution.
