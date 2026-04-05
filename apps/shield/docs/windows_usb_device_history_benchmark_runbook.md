# Windows USB Device History Benchmark Runbook

Script: `scripts/windows_usb_device_history_benchmark.ps1`

## Input

1. `-Input <path>`: USB/device-history source (JSON, CSV, or text export).

## Example

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_usb_device_history_benchmark.ps1 `
  -Input .\fixtures\parsers\usb_device_history\win10\sample_win10_01.json
```

## Output

Writes a timestamped benchmark summary JSON under `_run/windows_roadmap/benchmarks/<stamp>/`.
