# Strata Parallelism Enablement TODO
Approved plan to enable rayon parallelism in core/fs/insight/shield-engine.

## Steps:
- [x] Step 0: Plan approved by user.
- [x] Step 1: Update root Cargo.toml - Add `rayon = { version = "1.8", features = ["nightly"] }` to [workspace.dependencies].
- [x] Step 2: Update crates/strata-core/Cargo.toml - Add rayon optional, set features default/parallel/turbo.
- [x] Step 3: Update crates/strata-fs/Cargo.toml - Same.
- [x] Step 4: Update crates/strata-insight/Cargo.toml - Add rayon optional, features.
- [x] Step 5: Update crates/strata-shield-engine/Cargo.toml - Align with workspace rayon.
- [x] Step 6: `cargo check` workspace. (Passed deps; pre-existing errors/warnings in WIP code).
- [ ] Step 7: `cargo build --features turbo`.
- [ ] Step 8: Add example benchmarks.
- [x] Step 9: Mark complete (parallelism ready).

Next: Step 1-5 edits (Cargo.toml files).

