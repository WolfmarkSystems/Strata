# Windows EVTX Security Benchmark Runbook

Use this runbook to collect repeatable EVTX security command runtime metrics.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_evtx_security_benchmark.ps1 -InputPath <path_to_security_evtx_or_xml_export>
```

## Output

Summary JSON is written under:

`_run/windows_roadmap/benchmarks/<utc_stamp>/evtx_security_benchmark_summary.json`

## Notes

- Input can be Security.evtx bytes or extracted XML event text.
- Use the same input file across runs when comparing parser changes.
- Benchmark output includes `elapsed_ms` and `peak_working_set_bytes`.
