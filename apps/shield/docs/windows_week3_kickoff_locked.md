# Week 3 Kickoff Queue (Locked)

Window: 2026-03-23 to 2026-03-29  
Focus: Registry Core II (Windows)

## Hard Goal

Deliver stable, test-covered outputs for advanced Windows registry execution/persistence artifacts:

1. Amcache parsing quality pass.
2. ShimCache parsing quality pass.
3. BAM/DAM activity extraction quality pass.
4. Autoruns and scheduled-task registry correlation.
5. CLI output-contract cleanup for registry results.

## Day-by-Day Queue

## Monday

1. Amcache parser field normalization.
2. Add/extend fixture tests for common key/value variants.
3. Verify malformed/partial record resilience.

Acceptance:
1. outputs deterministic and truthful.
2. no regressions in existing tests.

## Tuesday

1. ShimCache parser normalization and timestamp consistency.
2. Validate parser behavior on truncated/partial records.
3. Add targeted regression tests.

Acceptance:
1. parser does not panic on malformed data.
2. normalized output field names are stable.

## Wednesday

1. BAM/DAM extraction normalization.
2. Ensure actor/path/time fields are consistent.
3. Add deterministic ordering tests.

Acceptance:
1. outputs stable across repeat runs.
2. no fabricated fields.

## Thursday

1. Correlate autoruns + scheduled-task registry signals.
2. Add low-risk helper for combined summary rows.
3. Add tests for missing-source scenarios.

Acceptance:
1. combined view stays truthful with partial sources.
2. no new backend/schema work.

## Friday

1. CLI output contract cleanup for registry-focused commands.
2. Ensure JSON/envelope field names remain backward-safe.
3. Add/refresh command snapshot baselines.

Acceptance:
1. snapshot diffs are intentional and documented.
2. GUI consumers remain compatible.

## Saturday

1. Week close-out gate run (`baseline + daily gate + fixture harness`).
2. Publish Week 3 summary with completed/remaining gaps.
3. Lock Week 4 kickoff queue.

## Pre-locked Follow-On (if ahead)

1. Additional registry parser perf micro-optimizations.
2. Expand malformed-input corpus for registry fixtures.
3. Tighten parser-specific clippy/doc lint cleanliness.

## Progress Notes (2026-03-10)

1. BAM parser now covers both `bam` and `dam` user settings paths with source attribution.
2. Persistence correlations now keep separate `bam_count` and `dam_count`.
3. Added `registry-persistence` CLI command with envelope/json support and stable payload fields.
4. Added smoke tests for registry persistence success and missing-source warning behavior.
5. Ahead-of-week EVTX semantic decode batch added mappings/tests for task-delete, service start-type change, system time change, and Sysmon process-access/remote-thread events.
6. Added cross-artifact execution correlation helper (`prefetch + jumplist + shortcuts`) with deterministic outputs and focused tests.
7. Added CLI command `execution-correlation` with envelope/json output and smoke coverage for success/missing-source scenarios.
8. Expanded EVTX semantic decode with account lifecycle (`4722/4725/4723/4724/4767`), logoff (`4634/4647`), and registry-change (`4657`) mappings plus regression tests.
9. Extended `registry-persistence` to ingest Amcache exports (`--amcache-reg`) and surface `amcache_count` in correlated rows with updated smoke coverage.
10. Added another EVTX semantic coverage batch (10 mappings) for privilege/object access, account-change/computer-account lifecycle, service lifecycle, shutdown initiation, and Sysmon timestamp tampering with dedicated tests.
11. Hardened registry persistence correlation contract with path canonicalization (device-prefix variants), deterministic `reason_codes`, `overall_confidence`, `source_confidence`, plus mixed-source/deterministic smoke tests.
12. Expanded registry parser coverage with RunOnceEx/IFEO/AppInit parsing, Winlogon anomaly detection, service DLL anomaly parsing, scheduled-task COM handler parsing, and MFT parent-chain path reconstruction tests.
13. Completed MFT hardening batch with ADS normalization, deleted-state consistency, short-name output, malformed attribute-chain tolerance, and SI/FN timestamp conflict flags plus focused parser tests.
14. Added a new `$UsnJrnl` parser (`json/csv` tolerant) with timestamp normalization, reason-mask expansion, deterministic newest-first sorting, and focused regression tests.
15. Recycle Bin parser now includes SID ownership correlation (`owner_sid`) extracted from recycle path components with deterministic unit tests.
16. Added an NTFS `$LogFile` MVP parser that surfaces deterministic textual signals from binary (`ascii/utf16`) or JSON inputs without claiming full transaction replay support.
17. Prefetch hardening batch completed: explicit version-offset parity for v17/v23/v26/v30, truncated-record safety tests, and case-insensitive path normalization/dedupe with deterministic ordering.
18. JumpList DestList structured parsing now tolerates truncated/corrupt tail records by advancing scan safely instead of aborting whole parse; regression test added.
19. Added `parsecustomdestinations` support for `.customdestinations-ms` files/directories with app-id hinting and explicit `Custom` entry typing, plus regression coverage.
20. Refactored LNK parsing to align with shell-link header offsets, improved LinkInfo volume-id extraction, and added regression coverage for MAC times plus drive serial/type extraction.
21. Expanded execution-correlation payload with unified timing fields (`first_seen`, per-source latest timestamps) and refreshed CLI smoke contract checks.
22. Added a new CLI command `evtx-security` with envelope/json support, quality metadata, and deterministic summary counters using existing eventlog parser paths.
23. Added EVTX security fixture pack (`30` samples + manifest) under `fixtures/parsers/evtx_security`.
24. Added EVTX security smoke/validation tests and golden JSON contract checks.
25. Added EVTX security benchmark script + runbook and explicit coverage-limit documentation.
26. Full gate re-run passed after EVTX additions: `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets --all-features`.
27. Timeline command now accepts `--source evtx-security` with `--evtx-security-input <path>` and emits normalized timeline rows.
28. Execution correlation now accepts `--evtx-security-input <path>` and enriches rows with `evtx_security_count` and latest EVTX timestamps.
29. Added new smoke tests for timeline EVTX source and execution-correlation EVTX enrichment.
30. EVTX identity normalization pass added for SID/user/computer/process-path fields with regression coverage.
31. Added `evtx-sysmon` CLI command with envelope/json support and Sysmon-focused summary counters.
32. Timeline now supports `--source evtx-sysmon` with `--evtx-sysmon-input <path>`.
33. Execution correlation now supports Sysmon enrichment (`evtx_sysmon_count`, latest Sysmon timestamps).
34. Added EVTX Sysmon fixture corpus (30 samples), benchmark script/runbook, and coverage-limits doc.
35. Added Sysmon smoke tests and golden contract checks; workspace gate remains green.
36. Completed PowerShell artifacts workstream MVP: added `powershell-artifacts` quality/dedupe metadata, timeline source integration tests, execution-correlation PowerShell enrichment tests, 30-sample fixture manifest, golden contract coverage, benchmark script/runbook, and coverage-limit documentation. Gate check passed on 2026-03-11 (`cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets --all-features`).
37. Completed Registry Core User Hives MVP: added `registry-core-user-hives` command contract tests, timeline integration (`--source registry-user-hives`), execution-correlation enrichment, 30-sample fixture manifest, benchmark script/runbook, and explicit coverage-limits documentation.
38. Completed next registry batch hardening: added `shimcache-deep` command smoke + golden contract coverage, fixed validation-envelope write behavior when `--json-result` appears after invalid `--limit`, and extended timeline/correlation coverage for registry user-hives + persistence sources.
39. Completed ShimCache timeline/correlation expansion: timeline now supports `--source shimcache` (`--shimcache-reg`), execution-correlation now emits `shimcache_count/latest_shimcache_*`, and added benchmark runbook + coverage-limits docs.
40. Completed Amcache Deep MVP: added `amcache-deep` command with deterministic sort/dedupe, fallback text parsing, timeline support (`--source amcache`), execution-correlation enrichment (`amcache_deep_count`), smoke/validation tests, golden contracts, fixture corpus (30), and benchmark/docs.
41. Completed BAM/DAM Activity MVP: added `bam-dam-activity` command with deterministic sort/dedupe and graceful warnings, timeline support (`--source bam-dam`), execution-correlation enrichment (`bam_dam_activity_count`), smoke/validation tests, golden contracts, fixture corpus (30), and benchmark/docs.
42. Added services/drivers kickoff artifacts for next board slice: 30-sample fixture manifest plus strict services/drivers input-shape detector with parser tests (`detect_services_drivers_input_shape`).
43. Completed Services/Drivers command slice: added `services-drivers-artifacts` CLI command with normalized records, fallback behavior, timeline source (`--source services-drivers`), execution-correlation enrichment (`services_drivers_count`), smoke/validation tests, golden contract coverage, and benchmark/coverage docs.
44. Completed Scheduled Tasks command slice: added input-shape detector + text fallback parser in `scheduledtasks`, added `scheduled-tasks-artifacts` CLI command, timeline source (`--source scheduled-tasks`), execution-correlation enrichment (`scheduled_tasks_count`), smoke/validation tests, golden contract coverage, fixture corpus (30), and benchmark/coverage docs.
45. Completed WMI persistence/activity command slice: added `wmi-persistence-activity` CLI command, strict WMI input-shape detector, tolerant path-based loaders for persistence/traces/instances, fallback text handling, smoke/validation tests, golden contract coverage, and fixture corpus (30).
46. Full gate remained green after registry/services/scheduled/WMI additions: `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets --all-features`.
47. Added WMI timeline/correlation integration: timeline now supports `--source wmi-persistence` with dedicated input flags; execution-correlation now emits `wmi_persistence_count/latest_wmi_persistence_*`.
48. Added `ntfs-mft-fidelity` command plus timeline source (`--source ntfs-mft`) and execution-correlation enrichment (`ntfs_mft_count/latest_ntfs_mft_*`) with conservative normalization and warnings.
49. Added `usn-journal-fidelity` command plus timeline source (`--source usn-journal`) and execution-correlation enrichment (`usn_journal_count/latest_usn_journal_*`) with deterministic dedupe/sort.
50. Added fixture packs/manifests for NTFS MFT Fidelity, USN Journal Fidelity, and NTFS LogFile Signals (30 samples each), plus benchmark scripts/runbooks/coverage-limit docs and updated contracts/smoke tests.
51. Completed batch `W7-0333..W7-0382`: added timeline source mapping for `prefetch|jumplist|lnk-shortcuts`, introduced `jumplist-fidelity` and `lnk-shortcut-fidelity` CLI commands with envelope/json contracts, expanded execution-correlation input aliases (`--prefetch-input|--jumplist-input|--lnk-input`), added fixture manifests/corpora for JumpList/LNK/Browser (30 each), and added coverage-limit + benchmark runbook/script docs for Prefetch/JumpList/LNK.
52. Completed batch `W7-0383..W7-0432`: added `browser-forensics`, `rdp-remote-access`, and `usb-device-history` CLI commands with normalized parser wrappers and envelope/json contracts; extended timeline with `--source browser-forensics|rdp-remote-access`; extended execution-correlation with `--browser-input|--rdp-input` enrichment; added smoke + validation + golden tests; added fixture manifests/corpora for RDP and USB (30 each); and added browser/RDP benchmark runbooks/scripts plus coverage-limit docs.
53. Completed batches `W7-0433..W7-0500`: finished timeline/correlation/summary/gating for `usb-device-history`, `restore-shadow-copies`, and `user-activity-mru`; added timeline correlation QA/performance parser + new `timeline-correlation-qa` CLI command with envelope/json contracts; extended timeline source filter (`--source timeline-correlation-qa` + `--timeline-correlation-input`) and execution-correlation enrichment (`timeline_correlation_qa_count/latest_timeline_correlation_qa_*`); added smoke + golden tests; and added timeline-correlation benchmark script/runbook + coverage-limits documentation.
54. Started `W8` backlog execution with defender batch `W8-0001..W8-0010`: added new `defender-artifacts` command (help + dispatch + envelope/json behavior), surfaced normalized Defender + Defender Endpoint summaries using existing engine modules only, added missing-source warning behavior, added smoke/validation tests, added golden contract coverage, and published `docs/windows_8of10_backlog_500.md` for next 500-task phase tracking.
55. Completed clap-args refactor batch 4 for NTFS/Prefetch/JumpList command wrappers: converted `ntfs-mft-fidelity`, `usn-journal-fidelity`, `ntfs-logfile-signals`, `prefetch-fidelity`, and `jumplist-fidelity` from manual `Vec<String>` parsing to typed clap structs, rewired `main.rs` dispatch to `parse_from`, preserved existing validation/envelope behavior, and re-ran `cargo test --workspace -q` successfully.
56. Completed clap-args refactor batch 5 for Windows source wrappers: converted `recycle-bin-artifacts`, `lnk-shortcut-fidelity`, `browser-forensics`, `rdp-remote-access`, and `usb-device-history` from manual `Vec<String>` parsing to typed clap structs, rewired `main.rs` dispatch to `parse_from`, preserved validation/envelope behavior, and re-ran `cargo test --workspace -q` successfully.
57. Completed clap-args refactor batch 6 (workflow/core commands): converted `verify-export`, `replay`, `replay-verify`, `artifacts`, and `hashset` to typed clap args, updated hashset subcommands to reuse common args, rewired `main.rs` dispatch, and re-ran `cargo test --workspace -q` successfully.
