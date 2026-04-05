# Week 1 Triage (2026-03-10)

Source run: `_run/windows_roadmap/2026-03-10_041545`

## Test/Flake Status

1. Workspace failed tests: `0`
2. Known flaky tests: none observed in current runs.
3. Immediate blocking failures: none.

## Top Warning Buckets

1. `this if statement can be collapsed` (25)
2. `reference immediately dereferenced` (12)
3. `filter(..).next() -> find(..)` (11)
4. `&PathBuf instead of &Path` (8)
5. `unnecessary cast u32->u32` (7)
6. `useless vec!` (5)
7. `field reassignment with default` (5)
8. `needlessly taken reference of left operand` (5)

## Fast-Fix Priorities (next batches)

1. `filter(...).next()` -> `.find(...)`.
2. collapse nested `if` blocks where behavior is unchanged.
3. remaining `&PathBuf` -> `&Path` conversions in parser modules.
4. remove redundant casts and needless borrows.
5. convert trivial `vec!` to arrays in tests/constant lists.

## Risk Notes

1. Most warnings are style and low semantic risk; good candidates for high-throughput cleanup.
2. `too_many_arguments` warnings are architectural and not targeted for Week 1/2 fast batches.
3. Keep parser behavior frozen while doing mechanical cleanup; run full workspace tests after each batch.
