# Windows JumpList Fidelity Benchmark Runbook

Script: `scripts/windows_jumplist_fidelity_benchmark.ps1`

## Input

1. `-Input <path>`: Jump List source (auto/custom destination file, directory, JSON, CSV, or text export).

## Example

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_jumplist_fidelity_benchmark.ps1 `
  -Input .\fixtures\parsers\jumplist_fidelity\win10\sample_win10_01.json
```

## Output

Writes a timestamped benchmark summary JSON under `_run/windows_roadmap/benchmarks/<stamp>/`.
