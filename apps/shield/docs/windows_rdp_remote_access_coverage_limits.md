# Windows RDP Remote Access Coverage Limits

Status date: 2026-03-11

Current `rdp-remote-access` support is intentionally conservative:

1. Supports JSON/CSV/text exports for RDP and remote-session metadata.
2. Emits normalized rows with deterministic sort/dedupe and nullable identity fields.
3. Supports timeline mapping (`--source rdp-remote-access`) and execution-correlation enrichment.

Known limits:

1. Coverage is export-driven and does not claim full event-log semantic reconstruction.
2. Session duration and timestamps depend on source completeness.
3. No inferred authentication context is fabricated when source fields are absent.
