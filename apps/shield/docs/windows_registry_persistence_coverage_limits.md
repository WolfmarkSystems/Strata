# Windows Registry Persistence Coverage Limits

Status date: 2026-03-11

Current `registry-persistence` support is intentionally conservative:

1. Correlates autorun, scheduled task, BAM/DAM, and Amcache indicators with stable fields.
2. Includes source confidence and reason-code metadata for transparency.
3. Uses deterministic sorting and tie-breaks for repeatable output.
4. Supports quality metadata including input shape and warning counts.
5. Integrates with timeline and execution-correlation source enrichment.

Known limits:

1. Correlation logic is heuristic and does not represent full causality.
2. Missing source exports reduce confidence and may produce sparse rows.
3. Scheduled-task detail is limited to currently parsed task metadata.
4. No schema/backend changes are performed; all output is derived from current parser inputs.
