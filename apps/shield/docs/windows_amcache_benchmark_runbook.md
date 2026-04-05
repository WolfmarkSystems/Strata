# Windows Amcache Benchmark Runbook

Use this runbook to collect repeatable runtime metrics for `amcache-deep`.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_amcache_benchmark.ps1 -AmcacheRegPath <amcache.reg>
```

## Output

Summary JSON is written under:

`_run/windows_roadmap/benchmarks/<utc_stamp>/amcache_benchmark_summary.json`

## Notes

- Use identical fixture inputs across runs.
- Benchmark is command-level (`forensic_cli amcache-deep`) and includes process memory peak.
