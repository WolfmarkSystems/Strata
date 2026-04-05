# Windows USN Journal Fidelity Benchmark Runbook

Script: `scripts/windows_usn_journal_fidelity_benchmark.ps1`

## Input

1. `-UsnInput <path>`: USN export input (json/csv/text).

## Example

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_usn_journal_fidelity_benchmark.ps1 `
  -UsnInput .\fixtures\parsers\usn_journal_fidelity\win11\sample_win11_01.csv
```

## Output

Writes a timestamped benchmark summary JSON under `_run/windows_roadmap/benchmarks/<stamp>/`.

