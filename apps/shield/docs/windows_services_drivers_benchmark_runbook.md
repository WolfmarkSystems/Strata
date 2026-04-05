# Windows Services/Drivers Benchmark Runbook

Use this runbook to collect repeatable runtime metrics for `services-drivers-artifacts`.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_services_drivers_benchmark.ps1 -ServicesRegPath <services.reg>
```

## Output

Summary JSON is written under:

`_run/windows_roadmap/benchmarks/<utc_stamp>/services_drivers_benchmark_summary.json`

## Notes

- Use identical fixture input across runs.
- Benchmark is command-level (`forensic_cli services-drivers-artifacts`) and includes process memory peak.
