# Windows ShimCache Benchmark Runbook

Use this runbook to collect repeatable runtime metrics for `shimcache-deep`.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_shimcache_benchmark.ps1 -AppCompatRegPath <appcompat.reg>
```

## Output

Summary JSON is written under:

`_run/windows_roadmap/benchmarks/<utc_stamp>/shimcache_benchmark_summary.json`

## Notes

- Use consistent fixture inputs between runs.
- Benchmark is command-level (`forensic_cli shimcache-deep`) and includes process memory peak.
