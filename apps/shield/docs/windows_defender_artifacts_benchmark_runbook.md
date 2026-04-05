# Windows Defender Artifacts Benchmark Runbook

Status date: 2026-03-11
Command: `forensic_cli defender-artifacts`

## Objective

Measure parse/runtime stability for Defender artifact ingestion under realistic small/medium/large export sets.

## Inputs

- `FORENSIC_DEFENDER_QUARANTINE`
- `FORENSIC_DEFENDER_SCAN_HISTORY`
- `FORENSIC_DEFENDER_ALERTS`
- `FORENSIC_DEFENDER_INDICATORS`
- `FORENSIC_DEFENDER_FILE_PROFILES`
- `FORENSIC_DEFENDER_MACHINE_ACTIONS`

## Baseline Command

```powershell
cargo run -p forensic_cli -- defender-artifacts --limit 5000 --json-result .\exports\defender_bench_result.json --quiet
```

## Suggested Dataset Tiers

- Small: <= 100 total records across all sources.
- Medium: ~10,000 total records across all sources.
- Large: >= 100,000 total records across all sources.

## Record Per Run

- Wall-clock runtime (`Measure-Command`).
- Result envelope `elapsed_ms`.
- Warning count and missing-source warnings.
- Output row counts per collection (`data.counts.*`).

## Pass Criteria

- Command exits `0` for valid input paths.
- Envelope shape remains stable.
- No panic/crash on malformed or missing optional source files.
- Deterministic counts/order for repeated runs on same dataset.
