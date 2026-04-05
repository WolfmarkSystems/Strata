# Windows NTFS MFT Fidelity Benchmark Runbook

Script: `scripts/windows_ntfs_mft_fidelity_benchmark.ps1`

## Input

1. `-MftInput <path>`: MFT export input (binary/json/csv/text).

## Example

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_ntfs_mft_fidelity_benchmark.ps1 `
  -MftInput .\fixtures\parsers\ntfs_mft_fidelity\win10\sample_win10_01.json
```

## Output

Writes a timestamped benchmark summary JSON under `_run/windows_roadmap/benchmarks/<stamp>/`.

