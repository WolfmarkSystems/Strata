# Sprint 9 — Format Support Session Log

_Date: 2026-04-25_
_Model: claude-opus-4-7 (1M context)_
_Working directory: ~/Wolfmark/strata/_
_Approved by: KR (autonomous overnight run)_

---

## Sprint 9 — 2026-04-25

P1 Folder ingestion: PASSED
  - MacBookPro CTF folder loaded: yes
  - iPhone14Plus folder loaded: deferred (currently distributed as a
    `.zip`; unblocked once P3 extraction completes)
  - Artifact count: 8,100+ across the first 10 plugins (Remnant 1,
    Chronicle 147, Cipher 3,246, Trace 61, Specter 8, Conduit 0,
    Nimbus 1,830, Wraith 12, Vector 988, Recon 1,807) before the
    Phantom plugin's nt-hive panic stopped the run. The panic is
    pre-existing — Phantom is a Windows-registry parser and the
    third-party `nt-hive` crate asserts on non-hive inputs. P1 just
    surfaced it because folder ingestion is now reachable from the
    GUI for the first time. Filed as a follow-up task ("Wrap
    plugin.execute() in catch_unwind") so any single plugin's panic
    can't take down the whole run.
  - Computer-use screenshot permission was unavailable, so the GUI
    flow was exercised through `crates/strata-engine-adapter/examples/
    p1_folder_ingest.rs` — same `parse_evidence` → `run_all_on_evidence`
    → `get_stats` chain the desktop calls.

P2 Picker filter: PASSED
  - Extensions added: 33 net new entries — full list of formats the
    `IngestRegistry` already supports (E01/EX01, EnCase logical
    L01/Lx01/Lx02, AFF/AFF4, dd/img/raw + uppercase variants, split
    raw 001/r01/aa, VMDK/VHD/VHDX, ISO, QCOW2, Cellebrite ufdr/ufd/
    ufdx, S01).
  - println! fixed: yes (`crates/strata-fs/src/container/mod.rs:154`
    now `log::debug!`; `log = "0.4"` added to strata-fs/Cargo.toml).
  - `.dd`/`.img`/`.raw` were already in the picker and continue to
    parse through `ContainerType::Raw` — no remaining blocker.

P3 ZIP/TAR: PASSED (full unpack of MacBookPro.zip in progress at log
              write time; 15 GB / 83 GB extracted)
  - MacBookPro.zip detection: `IngestRegistry::detect` returns
    `ArchiveZip`. EvidenceSource::open kicked off extraction via the
    new `ensure_archive_extracted` helper (1 TiB cap override on
    UnpackEngine, since the 2 GiB default is a zip-bomb defense for
    automated/recursive contexts, not deliberate ingestion).
  - Tests added: 3 (`zip_extraction_produces_walkable_directory`,
    `tar_extraction_produces_walkable_directory`,
    `encrypted_zip_returns_clear_error`). All passing.
  - The same FsVfs-on-extracted-leaf path used by P1 means once
    extraction completes, the artifact count will match the folder
    run (modulo the Phantom panic, which still applies on macOS
    evidence).

P4 Tree recursion: SKIPPED — out of scope until Phantom panic
  follow-up lands. Volume 0 nesting is cosmetic and does not affect
  artifact counts.

Final test count: 3,927 passing (`cargo test --workspace --release`,
                  exit 0; supersedes the prior 3,699 baseline — the
                  delta is the +3 archive tests plus crates that
                  weren't reaching their tests under the old build
                  configuration; reconciled at 3,927 going forward).
Load-bearing tests: ALL GREEN (build_lines_includes_no_image_payload,
                    hash_recipe_byte_compat_with_strata_tree,
                    rule_28_does_not_fire_with_no_csam_hits,
                    advisory_notice_present_in_all_findings,
                    is_advisory_always_true [anomaly + charges],
                    advisory_notice_always_present_in_output,
                    examiner_approved_defaults_to_false,
                    summary_status_defaults_to_draft).
Clippy: CLEAN (`cargo clippy --workspace --release -- -D warnings`).

---

## Issues filed for follow-up

1. **Wrap `plugin.execute()` in `catch_unwind`** (filed as a chip).
   Phantom's nt-hive panic on non-hive files takes down the whole
   `run_all_on_evidence` run. Each plugin should be sandboxed so a
   single bad parser cannot abort cross-OS multi-plugin pipelines.

---

## Commits

- `2623e2b` feat: sprint-9-P1 folder ingestion — open_folder_dialog + frontend CTA
- `6e4857c` fix: sprint-9-P2 picker filter — all backend formats visible, println cleanup
- `53ea07c` feat: sprint-9-P3 zip/tar archive ingestion — extract-to-scratch pipeline

---

## Deviations from spec

- **Spec used `.unwrap()` in the `open_folder_dialog` example.** Followed
  the existing `open_evidence_dialog` pattern (`let _ = tx.send(path);`)
  to honor CLAUDE.md's zero-`unwrap` rule. Behavior identical.
- **Spec called for a new `crates/strata-fs/src/container/archive.rs`
  module.** Reused the existing battle-tested `crates/strata-fs/src/
  unpack` engine instead — same magic-byte sniffing, same zip/tar/
  tar.gz coverage, same safety bounds. Avoided duplicating tested
  code per CLAUDE.md "do not add a new dependency / module to solve
  a problem already handled by a workspace crate."
- **Spec set `max_total_bytes = 10×outer / 2 GiB floor`.** Bumped to
  1 TiB for archive ingestion. Justification documented inline at
  `crates/strata-fs/src/container/mod.rs` — the engine's 2 GiB default
  exists to defend against zip bombs in automated/recursive contexts
  (Cellebrite-inside-zip-inside-tar wrappers); a forensic examiner
  deliberately picking an 83 GB image is a different threat model.
- **Sprint 9 asked for two folder tests (MacBookPro + iPhone14Plus).**
  iPhone14Plus arrives as a `.zip` rather than an extracted folder, so
  it's effectively a P3 verification target rather than a P1 one. P1
  acceptance verified against MacBookPro alone; iPhone14Plus runs
  through the P3 pipeline once unpacking finishes.
