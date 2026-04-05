# Windows WMI Persistence Benchmark Runbook

Script: `scripts/windows_wmi_persistence_benchmark.ps1`

## Inputs

1. `-PersistInput <path>`: WMI persistence export file.
2. `-TracesInput <path>`: WMI traces export file.
3. `-InstancesInput <path>`: WMI instances export file.

## Example

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_wmi_persistence_benchmark.ps1 `
  -PersistInput .\fixtures\parsers\wmi_persistence_activity\win10\sample_win10_01_persistence.json `
  -TracesInput .\fixtures\parsers\wmi_persistence_activity\win10\sample_win10_01_traces.json `
  -InstancesInput .\fixtures\parsers\wmi_persistence_activity\win10\sample_win10_01_instances.json
```

## Output

Writes a timestamped benchmark summary JSON under `_run/windows_roadmap/benchmarks/<stamp>/`.

