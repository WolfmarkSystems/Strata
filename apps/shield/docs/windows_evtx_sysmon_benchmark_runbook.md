# Windows EVTX Sysmon Benchmark Runbook

Use this runbook to collect repeatable EVTX sysmon command runtime metrics.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_evtx_sysmon_benchmark.ps1 -InputPath <path_to_sysmon_evtx_or_xml_export>
```

## Output

Summary JSON is written under:

`_run/windows_roadmap/benchmarks/<utc_stamp>/evtx_sysmon_benchmark_summary.json`

## Notes

- Input can be `Sysmon.evtx` bytes or extracted XML event text.
- Use the same input file across runs when comparing parser changes.
- Benchmark output includes `elapsed_ms` and `peak_working_set_bytes`.
