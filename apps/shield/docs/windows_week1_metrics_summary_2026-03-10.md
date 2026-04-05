# Week 1 Metrics Summary (Checkpoint)

Date: 2026-03-10  
Run directory: `_run/windows_roadmap/2026-03-10_212019`

## Health

1. Build: pass
2. Tests: pass
3. Clippy command: pass
4. Fixture harness: pass
5. Failed tests: `0`

## Warning Trend

1. Baseline clippy warnings at start (`2026-03-10_035743`): `170`
2. Current clippy warnings (`2026-03-10_212019`): `0`
3. Net change: `-170`

## Fixture Coverage Snapshot

1. Total fixtures in manifest: `14`
2. Windows fixtures: `6`
3. Total parser inputs: `19`
4. Windows parser inputs: `8`

## Execution Times (latest run)

1. `cargo build --workspace`: `2.539s`
2. `cargo test --workspace -- --nocapture`: `11.364s`
3. `cargo clippy --workspace --all-targets --all-features`: `0.866s`
4. `cargo test -p forensic_engine fixture_harness -- --nocapture`: `0.541s`

## Notes

1. Daily gate status: pass (`_run/windows_roadmap/2026-03-10_212019/daily_gate_result.json`)
2. Fixture corpus harness opt-in path is passing in baseline/gate runs.
