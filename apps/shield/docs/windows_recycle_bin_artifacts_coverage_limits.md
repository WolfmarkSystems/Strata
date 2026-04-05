# Windows Recycle Bin Artifacts Coverage Limits

Status date: 2026-03-11

Current `recycle-bin-artifacts` support is intentionally conservative:

1. Supports directory/file inputs in JSON, CSV, or line-text forms.
2. Emits normalized deletion rows with deterministic sort/dedupe and nullable owner SID fields.
3. Supports timeline source mapping (`--source recycle-bin`) and execution-correlation enrichment.

Known limits:

1. Legacy `INFO2` and modern `$I/$R` binary nuances are only partially represented via export-friendly paths.
2. Owner/user resolution is limited to source-provided SIDs.
3. Deleted-path fidelity depends on the export quality and field coverage.
