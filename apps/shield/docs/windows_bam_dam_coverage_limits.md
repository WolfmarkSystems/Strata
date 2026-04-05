# Windows BAM/DAM Coverage Limits

Status date: 2026-03-11

Current `bam-dam-activity` support is intentionally conservative:

1. Parses BAM and DAM user-settings execution traces from registry exports.
2. Normalizes execution timestamps and actor SID fields where present.
3. Applies deterministic ordering and per-key newest-row dedupe.
4. Emits quality metadata (`input_shape`, warning counts, dedupe metadata).
5. Integrates into timeline (`--source bam-dam`) and execution-correlation enrichment.

Known limits:

1. No direct user-profile resolution from SID in this command.
2. Missing timestamps reduce timeline event completeness.
3. No causal attribution beyond observed registry state entries.
