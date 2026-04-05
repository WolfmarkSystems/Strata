# Windows SRUM Benchmark Runbook

Use this runbook to collect repeatable SRUM command runtime metrics.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_srum_benchmark.ps1 -InputPath <path_to_srum_export>
```

## Output

Summary JSON is written under:

`_run/windows_roadmap/benchmarks/<utc_stamp>/srum_benchmark_summary.json`

## Notes

- Input should be a JSON or CSV SRUM export.
- Current command does not directly decode raw `SRUDB.dat` ESE databases.
- Use the same input file across runs when comparing parser changes.
