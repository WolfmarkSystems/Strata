# Windows Capability Roadmap (90 Days)

Start date: 2026-03-10  
Target finish: 2026-06-07

## Operating Rules

1. Rust-first for production parsers and command paths.
2. Python only for corpus tooling, diffing, and validation helpers.
3. `cargo build --workspace` and `cargo test --workspace` must stay green every day.
4. Every parser change ships with fixture tests in the same PR.
5. No new feature starts when current week's hard goal is incomplete.

## Week-by-Week Plan With Daily Goals

## Week 1 (2026-03-10 to 2026-03-15) - Baseline Lock + Harness

- Tue: Freeze parser inventory and current failing test inventory.
- Wed: Add deterministic baseline snapshot script (build/test/clippy + fixture metadata).
- Thu: Add daily gate script and machine-readable summary artifacts.
- Fri: Capture first formal baseline and publish week report.
- Sat: Stabilize flaky tests and lock execution checklist.
- Sun: Buffer and backlog grooming.

Hard goal: reproducible Week 1 baseline runbook with stored metrics and repeatable scripts.

## Week 2 (2026-03-16 to 2026-03-22) - Registry Core I

- Mon: UserAssist + Run/MRU normalization pass.
- Tue: SYSTEM hive USB/STOR extraction hardening.
- Wed: SOFTWARE hive uninstall/services normalization.
- Thu: SAM/SECURITY metadata extraction pass.
- Fri: Registry timestamp consistency and UTC normalization.
- Sat: Fixture coverage and edge-case tests.
- Sun: Buffer and cleanup.

Hard goal: stable registry core outputs for user/system/software artifacts.

## Week 3 (2026-03-23 to 2026-03-29) - Registry Core II

- Mon: Amcache parser quality pass.
- Tue: ShimCache parser quality pass.
- Wed: BAM/DAM activity extraction quality pass.
- Thu: Autoruns and scheduled-task registry correlation.
- Fri: CLI output contract cleanup for registry results.
- Sat: Corpus regression on real hives.
- Sun: Buffer and cleanup.

Hard goal: reliable registry ecosystem outputs for Amcache/ShimCache/BAM workloads.

## Week 4 (2026-03-30 to 2026-04-05) - EVTX Semantics I

- Mon: Security event mappings set A.
- Tue: Security event mappings set B.
- Wed: System log semantic mapping pass.
- Thu: Application log semantic mapping pass.
- Fri: Severity/category mapping consistency pass.
- Sat: EVTX fixture tests and malformed input handling.
- Sun: Buffer and cleanup.

Hard goal: first practical EVTX semantic decode for high-value Windows events.

## Week 5 (2026-04-06 to 2026-04-12) - EVTX Semantics II

- Mon: Sysmon event mapping set A.
- Tue: Sysmon event mapping set B.
- Wed: PowerShell operational events.
- Thu: WMI/Task Scheduler/RDP event mapping.
- Fri: Actor/session/correlation ID normalization.
- Sat: EVTX performance + resilience sweep.
- Sun: Buffer and cleanup.

Hard goal: incident-response-useful EVTX semantic coverage.

## Week 6 (2026-04-13 to 2026-04-19) - NTFS Fidelity I

- Mon: MFT attribute parsing correctness pass.
- Tue: SI/FN timestamp normalization and tests.
- Wed: ADS detection and output hardening.
- Thu: Deleted-entry handling improvements.
- Fri: Path reconstruction quality pass.
- Sat: Corrupt/partial NTFS fixture validation.
- Sun: Buffer and cleanup.

Hard goal: reliable NTFS metadata extraction with correct timestamp semantics.

## Week 7 (2026-04-20 to 2026-04-26) - NTFS Fidelity II

- Mon: USN journal parsing quality pass.
- Tue: `$LogFile` signal extraction MVP.
- Wed: Recycle Bin correlation improvements.
- Thu: Short-name/long-name reconciliation.
- Fri: NTFS timeline event shape alignment.
- Sat: Large image stress tests.
- Sun: Buffer and cleanup.

Hard goal: stable NTFS timeline-grade event pipeline.

## Week 8 (2026-04-27 to 2026-05-03) - Prefetch + JumpList + LNK

- Mon: Prefetch parser correctness and guards.
- Tue: Prefetch execution metadata consistency.
- Wed: JumpList parser resilience pass.
- Thu: LNK metadata enrichment pass.
- Fri: Cross-artifact "recent execution/files" correlation.
- Sat: Fixtures + command output validation.
- Sun: Buffer and cleanup.

Hard goal: production-usable Prefetch/JumpList/LNK pipeline.

## Week 9 (2026-05-04 to 2026-05-10) - Execution/Persistence Signals

- Mon: SRUM extraction hardening.
- Tue: PowerShell traces and history normalization.
- Wed: Browser artifact path support refinement.
- Thu: Services/tasks persistence correlation.
- Fri: Unified execution timeline payload alignment.
- Sat: Regression sweep.
- Sun: Buffer and cleanup.

Hard goal: stronger execution and persistence visibility from Windows artifacts.

## Week 10 (2026-05-11 to 2026-05-17) - Correlation Contract

- Mon: Unified event schema review and cleanups.
- Tue: Provenance and confidence fields pass.
- Wed: Dedup/merge correctness tuning.
- Thu: Case-level summary metrics.
- Fri: Query performance tuning for timeline payloads.
- Sat: CLI/GUI contract validation.
- Sun: Buffer and cleanup.

Hard goal: stable, correlation-ready payloads for investigator workflows.

## Week 11 (2026-05-18 to 2026-05-24) - Throughput and Scale

- Mon: Profile parser hot paths.
- Tue: I/O batching improvements.
- Wed: Memory footprint reductions.
- Thu: Parallel worker tuning (deterministic outputs preserved).
- Fri: 256GB-class image soak test process and metrics.
- Sat: Performance regression gating.
- Sun: Buffer and cleanup.

Hard goal: measurable throughput and stability gains on large images.

## Week 12 (2026-05-25 to 2026-05-31) - Reliability and Noise Control

- Mon: Edge-case parser hardening.
- Tue: False-positive suppression improvements.
- Wed: Error-path and fallback quality pass.
- Thu: Corrupt/incomplete artifact resilience tests.
- Fri: Output stability and compatibility pass.
- Sat: Full matrix run and triage.
- Sun: Buffer and cleanup.

Hard goal: low-noise, resilient Windows pipeline ready for release candidate validation.

## Week 13 (2026-06-01 to 2026-06-07) - RC Readiness

- Mon: Coverage report and docs refresh.
- Tue: Remaining critical gaps triage.
- Wed: End-to-end case replay validation.
- Thu: Packaging and release checks.
- Fri: Final bugfix window.
- Sat: RC freeze.
- Sun: Post-freeze validation report.

Hard goal: shippable Windows-focused release candidate with explicit remaining gaps.

## Saturday Gate (Every Week)

1. Build and tests pass in workspace.
2. New parser changes include fixture tests.
3. Regression snapshot generated and stored.
4. Coverage status updated (`new checkmarks` and `remaining gaps`).
5. One performance snapshot captured.
