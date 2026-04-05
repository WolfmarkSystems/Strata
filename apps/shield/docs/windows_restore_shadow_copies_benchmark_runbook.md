# Windows Restore/Shadow Copies Benchmark Runbook

Script: `scripts/windows_restore_shadow_copies_benchmark.ps1`

## Input

1. `-Input <path>`: restore point / shadow copy source (JSON, CSV, or text export).

## Example

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_restore_shadow_copies_benchmark.ps1 `
  -Input .\fixtures\parsers\restore_shadow_copies\win10\restore_shadow_win10_01.json
```

## Output

Writes a timestamped benchmark summary JSON under `_run/windows_roadmap/benchmarks/<stamp>/`.
