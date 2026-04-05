# Windows User Activity/MRU Benchmark Runbook

Script: `scripts/windows_user_activity_mru_benchmark.ps1`

## Input

1. `-Input <path>`: user activity / MRU source (JSON, CSV, or text export).

## Example

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_user_activity_mru_benchmark.ps1 `
  -Input .\fixtures\parsers\user_activity_mru\win10\user_activity_mru_win10_01.json
```

## Output

Writes a timestamped benchmark summary JSON under `_run/windows_roadmap/benchmarks/<stamp>/`.
