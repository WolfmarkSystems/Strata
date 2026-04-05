# Windows Services/Drivers Coverage Limits

Status date: 2026-03-11

Current `services-drivers-artifacts` support is intentionally conservative:

1. Parses service config rows (`ImagePath`, `Start`, `DisplayName`) from registry exports.
2. Parses service failure-policy signals and delayed auto-start flags.
3. Parses `ServiceDll` parameter entries with suspiciousness flags and reason codes.
4. Uses deterministic dedupe/sort and explicit null handling for missing timestamp fields.
5. Integrates with timeline (`--source services-drivers`) and execution-correlation enrichment.

Known limits:

1. Registry exports often omit reliable per-row timestamps; timeline rows may be untimestamped.
2. No service state transition history (start/stop runtime events) is currently emitted.
3. No SCM binary-hive parser path yet; command targets text export workflows first.
