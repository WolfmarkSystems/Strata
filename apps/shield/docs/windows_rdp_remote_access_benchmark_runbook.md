# Windows RDP Remote Access Benchmark Runbook

Script: `scripts/windows_rdp_remote_access_benchmark.ps1`

## Input

1. `-Input <path>`: RDP/remote access source (JSON, CSV, or text export).

## Example

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_rdp_remote_access_benchmark.ps1 `
  -Input .\fixtures\parsers\rdp_remote_access_artifacts\win10\sample_win10_01.json
```

## Output

Writes a timestamped benchmark summary JSON under `_run/windows_roadmap/benchmarks/<stamp>/`.
