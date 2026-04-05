# Windows Browser Forensics Benchmark Runbook

Script: `scripts/windows_browser_forensics_benchmark.ps1`

## Input

1. `-Input <path>`: Browser source (`sqlite`, JSON, CSV, or text export).

## Example

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_browser_forensics_benchmark.ps1 `
  -Input .\fixtures\parsers\browser_forensics\win10\sample_win10_01.json
```

## Output

Writes a timestamped benchmark summary JSON under `_run/windows_roadmap/benchmarks/<stamp>/`.
