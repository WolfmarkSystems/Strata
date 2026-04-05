# Windows Timeline Correlation QA Benchmark Runbook

Script: `scripts/windows_timeline_correlation_qa_benchmark.ps1`

## Input

1. `-Input <path>`: timeline correlation QA source (JSON, CSV, or text export).

## Example

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_timeline_correlation_qa_benchmark.ps1 `
  -Input .\fixtures\parsers\timeline_correlation_qa_performance\win10\timeline_corr_win10_01.json
```

## Output

Writes a timestamped benchmark summary JSON under `_run/windows_roadmap/benchmarks/<stamp>/`.
