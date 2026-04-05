# Windows Scheduled Tasks Benchmark Runbook

Use this runbook to collect repeatable runtime metrics for `scheduled-tasks-artifacts`.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_scheduled_tasks_benchmark.ps1 -TasksRoot <tasks_root>
```

## Output

Summary JSON is written under:

`_run/windows_roadmap/benchmarks/<utc_stamp>/scheduled_tasks_benchmark_summary.json`

## Notes

- Use identical fixture roots across runs.
- Benchmark is command-level (`forensic_cli scheduled-tasks-artifacts`) and includes process memory peak.
