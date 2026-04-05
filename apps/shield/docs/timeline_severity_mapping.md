# Timeline Severity Mapping (MVP)

This documents the current deterministic severity mapping used by `forensic_cli timeline`.

## Source-to-severity rules

1. `violations` source events map to `warn`.
2. `activity` source events map to `info`.
3. `evidence` source events map to `info`.
4. `execution` source events map to `info`.

## Scope notes

1. This is intentionally conservative for the current MVP.
2. No extra severity escalation is inferred unless source data explicitly supports it.
3. GUI badges should render these values as-is and not invent higher severity states.

## Validation

Severity mapping is covered by CLI smoke tests:

1. execution-source timeline rows assert `severity = info`.
2. violations-source timeline rows assert `severity = warn`.
