# code-reviewer — Strata forensic parser code review

Loaded when reviewing Rust changes to Strata plugins, parsers, or the
engine. Review everything below on every changed file.

## Forensic parser review checklist

* **Timestamp epoch correctness**: FILETIME → `(filetime / 10_000_000) -
  11644473600`; CoreData / Apple epoch → `coreadata_secs + 978_307_200`;
  WebKit → `(webkit_us - 11_644_473_600_000_000) / 1_000_000`. All
  conversions must use `DateTime::<Utc>::from_timestamp` + checked
  arithmetic. `saturating_add` is mandatory on timestamp arithmetic —
  no silent overflow.
* **Binary reads are bounds-checked**: every slice index must either
  use `.get(range)` or be preceded by `if bytes.len() < N` guards.
  Reject `&bytes[a..b]` panics on attacker-controlled input.
* **Artifact category**: set correctly per plugin domain
  (`Communications`, `UserActivity`, `ExecutionHistory`, `SystemActivity`,
  `WebActivity`, `NetworkArtifacts`, `AccountsCredentials`). A wrong
  category breaks UI filters.
* **MITRE technique required**: every `Artifact` and every
  `ArtifactRecord` must carry a non-empty `mitre` / `mitre_technique`
  field. Unmapped artifacts are incomplete artifacts.
* **`forensic_value`** is set on every artifact (`High`, `Medium`, or
  `Low`). Missing is a blocker.
* **`source` traces back to evidence**: each artifact's `source` /
  `source_path` must be the original file path, not a working copy.
* **Field doc comments describe forensic significance**, not just the
  data shape. "Process ID" is insufficient; "Process that emitted the
  log; T1059 indicator when process is `cmd.exe`" is correct.

## Strata-specific anti-patterns — block merges on any of these

* `.unwrap()` on a `Result` or `Option`. Use `?`, `match`, or `let ...
  else`. Exceptions only for compile-time constants where failure is
  impossible.
* `unsafe {}` blocks. If a dependency requires unsafe, that dependency
  needs separate justification.
* `println!` / `eprintln!`. Use `log::debug!`, `log::info!`,
  `log::warn!`, or `log::error!`. Raw stdout breaks Tauri IPC.
* Adding a dependency not already in `Cargo.toml` without justification.
  Prefer workspace crates. Document why a new dep is needed.
* Touching files outside the sprint scope. Surgical edits only.
* Removing or modifying existing tests. If a test is in your way, fix
  the code, not the test.
* Plugin routing a file type already owned by another plugin
  (e.g. Windows registry parsing inside MacTrace).

## Load-bearing tests — never remove

The following tests encode court-review-critical invariants. Removal or
weakening of any requires an explicit comment explaining why and an
equivalent invariant added elsewhere.

* `build_lines_includes_no_image_payload` (strata-csam)
* `hash_recipe_byte_compat_with_strata_tree` (strata-core / strata-tree)
* `rule_28_does_not_fire_with_no_csam_hits` (strata-plugin-sigma)
* `advisory_notice_present_in_all_findings` (strata-csam)
* `is_advisory_always_true` (strata-ml-anomaly)
* `advisory_notice_always_present_in_output` (strata-ml-summary)
* `examiner_approved_defaults_to_false` (strata-ml-charges)
* `summary_status_defaults_to_draft` (strata-ml-summary)
* `is_advisory_always_true` (strata-ml-charges)

## Review output format

Produce a single bullet list under each of these headings, only
including headings with findings:

* **Blocker** — merge must not land. Cite file:line.
* **Should fix before merge** — style, missing doc, weak test.
* **Nits** — optional polish.

Cite file paths and line numbers; paste exact snippets only when the
diff is more than 20 lines away from context.
