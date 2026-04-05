# Week 2 Backlog (Locked)

Window: 2026-03-16 to 2026-03-22  
Focus: Registry Core I (Windows)

## Execution Status (Updated 2026-03-10)

1. Completed: UserAssist + Run/MRU normalization + tests.
2. Completed: SYSTEM USB/STOR normalization + tests.
3. Completed: SOFTWARE uninstall/services normalization + malformed-value tests.
4. Completed: SAM/SECURITY metadata normalization + malformed/optional-value tests.
5. Completed: cross-registry timestamp normalization pass for registry update/uninstall/userassist outputs.
6. Completed: full regression gates (`build`, `test`, `clippy`, fixture harness, baseline snapshot, daily gate, CLI snapshot).
7. Completed: follow-on cleanup queue (`&PathBuf`/`find`/nested-if`) is green with current clippy run.

## Hard Goal

Deliver stable, test-covered registry outputs for core user/system/software artifacts:

1. UserAssist + Run/MRU normalization.
2. SYSTEM USB/STOR metadata extraction consistency.
3. SOFTWARE uninstall/services normalization.
4. SAM/SECURITY metadata extraction hygiene.
5. UTC/timestamp normalization pass across registry outputs.

## Day-by-Day Execution

## Monday

1. UserAssist decode and normalization pass.
2. Run/MRU output normalization pass.
3. Add/extend fixture tests for parsed field presence and timestamp shape.

Acceptance:
1. commands/tests pass.
2. normalized fields are consistent and deterministic.

## Tuesday

1. SYSTEM hive USB/STOR extraction review.
2. normalize device identifiers and key timestamps.
3. add regression tests for known USB key patterns.

Acceptance:
1. deterministic parsed rows from fixture exports.
2. no regressions in existing registry tests.

## Wednesday

1. SOFTWARE uninstall/services extraction review.
2. normalize publisher/version/install date field handling.
3. add tests for missing/partial value paths.

Acceptance:
1. parser tolerates incomplete records safely.
2. outputs remain truthful (no inferred fake fields).

## Thursday

1. SAM/SECURITY metadata extraction cleanup.
2. normalize account/security metadata field names.
3. add tests for absent optional values and malformed lines.

Acceptance:
1. no panic on malformed input.
2. command outputs remain stable and parseable.

## Friday

1. cross-registry timestamp normalization (utc/value formatting).
2. update summary helpers and any envelope data shaping impacted.
3. full workspace and fixture-harness regression run.

Acceptance:
1. build/test/clippy pass.
2. no output-shape break in CLI envelope consumers.

## Saturday

1. week close-out run: baseline + daily gate + fixture harness.
2. publish Week 2 summary (completed/remaining).
3. lock Week 3 kickoff queue.

## Pre-locked follow-on queue (if ahead of schedule)

1. `&PathBuf` to `&Path` warning cleanup in registry-adjacent modules.
2. `filter(...).next()` -> `.find(...)` cleanup in parser helpers.
3. nested `if` collapses in low-risk parsing blocks.
