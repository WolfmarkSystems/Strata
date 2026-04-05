# Windows USB Device History Coverage Limits

Status date: 2026-03-11

Current `usb-device-history` support is intentionally conservative:

1. Supports JSON/CSV/text exports for USB/device activity metadata.
2. Emits normalized rows with deterministic sort/dedupe and nullable identity fields.
3. Supports timeline mapping (`--source usb-device-history`) and execution-correlation enrichment.

Known limits:

1. Coverage is export-driven and does not claim full registry hive replay.
2. Timestamp quality depends on source completeness (`first_seen`/`last_seen` may be absent).
3. No inferred user attribution is fabricated when source fields are absent.
