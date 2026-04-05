# Windows Next-50 Execution Tracker

Status date: 2026-03-10

Legend:
- `DONE` completed and validated in current codebase.
- `PARTIAL` started but not complete to target scope.
- `PENDING` not started.

1. `DONE` Add `registry-persistence --json` fixture tests for mixed real-world hive exports.
2. `DONE` Normalize registry path casing/slash style with shared canonicalization helper.
3. `DONE` Add source confidence flags for `autorun/bam/dam/amcache/task` in registry persistence payload.
4. `DONE` Add correlation reason text/codes in registry persistence rows.
5. `DONE` Add parser + tests for RunOnceEx keys.
6. `DONE` Add parser + tests for IFEO debugger keys.
7. `DONE` Add parser + tests for AppInit_DLLs.
8. `DONE` Add parser + tests for Winlogon `Userinit/Shell` anomalies.
9. `DONE` Add parser + tests for service DLL hijack patterns.
10. `DONE` Add parser + tests for scheduled task COM handler actions.
11. `DONE` EVTX map: 4689 process termination enrichment.
12. `DONE` EVTX map: 4698 task create enrichment.
13. `DONE` EVTX map: 4702 task update enrichment.
14. `DONE` EVTX map: 4719 policy-change enrichment.
15. `DONE` EVTX map: 4728/4729 group membership normalization.
16. `DONE` EVTX map: 4732/4733 local group membership normalization.
17. `DONE` EVTX map: 4768/4769 Kerberos event summaries.
18. `DONE` EVTX map: 4776 auth pairing.
19. `DONE` EVTX map: 7045/7040 service persistence enrichment.
20. `DONE` EVTX map: 1102/104 tamper summaries.
21. `DONE` MFT path reconstruction with parent reference cache.
22. `DONE` Tests for orphaned MFT entries / parent-missing fallback.
23. `DONE` ADS extraction normalization.
24. `DONE` Deleted-file detection consistency pass.
25. `DONE` SI/FN timestamp conflict flags.
26. `DONE` Add short-name output when present.
27. `DONE` Malformed attribute chain hardening.
28. `DONE` `$UsnJrnl` parser + tests.
29. `DONE` Recycle Bin SID ownership correlation pass.
30. `DONE` `$LogFile` MVP signal extraction.
31. `DONE` Prefetch v17/v23/v26/v30 parity pass.
32. `DONE` Truncated Prefetch corpus tests.
33. `DONE` Prefetch reference path dedupe/ordering hardening.
34. `DONE` JumpList DestList tail/truncation resilience.
35. `DONE` Custom destinations parser integration.
36. `DONE` LNK enrichment (volume serial + MAC times).
37. `DONE` Unified recent-execution correlation payload.
38. `DONE` CLI `recent-execution` command.
39. `DONE` Timeline source option for execution correlations.
40. `DONE` Severity mapping rules doc + tests.
41. `DONE` Timeline dedup strategy implementation.
42. `DONE` Timeline pagination cursor contract.
43. `DONE` Timeline query benchmark script.
44. `DONE` Golden JSON contract tests for key commands.
45. `DONE` Malformed-input fuzz harness for registry/EVTX.
46. `DONE` Large-image stress gate with memory/runtime metrics.
47. `DONE` Deterministic sorting assertions for major CLI payloads.
48. `DONE` GUI Timeline support for expanded source categories.
49. `DONE` GUI Case Overview cards for persistence/execution rollups.
50. `DONE` Next-board/gap matrix tracker published in docs.

Current count:
- `DONE`: 50
- `PARTIAL`: 0
- `PENDING`: 0
