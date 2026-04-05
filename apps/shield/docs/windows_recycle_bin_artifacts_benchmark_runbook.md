# Windows Recycle Bin Artifacts Benchmark Runbook

Script: `scripts/windows_recycle_bin_artifacts_benchmark.ps1`

## Input

1. `-Input <path>`: Recycle Bin export (json/csv/text).

## Example

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_recycle_bin_artifacts_benchmark.ps1 `
  -Input .\fixtures\parsers\recycle_bin_artifacts\win10\sample_win10_01.json
```

## Output

Writes a timestamped benchmark summary JSON under `_run/windows_roadmap/benchmarks/<stamp>/`.
