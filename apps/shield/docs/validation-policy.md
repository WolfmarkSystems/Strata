# Validation Policy

This policy defines release blocking checks for parser and ingest stability.

## Release blockers

- Parser output drift against snapshot fixtures.
- Missing provenance fields for canonical outputs.
- Ingest manifest regressions for supported formats.
- Performance regression beyond configured threshold.

## Required artifacts per release

- Compatibility matrix version stamp.
- Parser version manifest.
- Known limitations list.
- Reproducibility report with test summary.

## Test classes

- Unit tests for parser and correlation determinism.
- Fixture-driven regression tests.
- CLI smoke tests for ingest diagnostics.
- Performance checks for small/medium/large fixture sets.
