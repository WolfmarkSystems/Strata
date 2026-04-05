# Windows ShimCache Coverage Limits

Status date: 2026-03-11

Current `shimcache-deep` support is intentionally conservative:

1. Parses AppCompatCache/ShimCache entries from registry exports.
2. Normalizes timestamps into unix/UTC where available.
3. Dedupe keeps newest record per normalized path.
4. Emits quality metadata (`input_shape`, warning counts, dedupe metadata).
5. Integrates into timeline (`--source shimcache`) and execution-correlation enrichment.

Known limits:

1. No raw hive binary parser in this command; current scope is export-driven.
2. Rows without usable timestamp are not emitted into timeline views.
3. Confidence scoring remains minimal (`info` severity by default).
