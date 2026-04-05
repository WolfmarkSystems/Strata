# Windows Registry Persistence Benchmark Runbook

Use this runbook to collect repeatable runtime metrics for `registry-persistence`.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_registry_persistence_benchmark.ps1 -AutorunRegPath <autorun.reg> -BamRegPath <bam.reg> -AmcacheRegPath <amcache.reg> -TasksRootPath <tasks_root>
```

## Output

Summary JSON is written under:

`_run/windows_roadmap/benchmarks/<utc_stamp>/registry_persistence_benchmark_summary.json`

## Notes

- Provide real inputs for at least one source (`autorun`, `bam`, `amcache`, `tasks`) for meaningful metrics.
- Use identical fixtures across runs to evaluate parser/correlation changes.
- Benchmark is command-level (`forensic_cli registry-persistence`) and includes process memory peak.
