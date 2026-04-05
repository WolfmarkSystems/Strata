# Windows NTFS LogFile Signals Benchmark Runbook

Script: `scripts/windows_ntfs_logfile_signals_benchmark.ps1`

## Input

1. `-Input <path>`: NTFS LogFile export (binary/json/text).

## Example

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_ntfs_logfile_signals_benchmark.ps1 `
  -Input .\fixtures\parsers\ntfs_logfile_signals\win10\sample_win10_01.bin
```

## Output

Writes a timestamped benchmark summary JSON under `_run/windows_roadmap/benchmarks/<stamp>/`.
