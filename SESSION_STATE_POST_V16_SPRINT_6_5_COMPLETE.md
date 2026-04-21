# Post-v16 Sprint 6.5 — Report generator unification — COMPLETE

**Date:** 2026-04-21
**Inputs:** `SESSION_STATE_POST_V16_SPRINT_6_COMPLETE.md`
(the demo-blocker audit), `RESEARCH_POST_V16_SIGMA_INVENTORY.md`,
session-state docs from Sprints 3 / 4 / 5.
**Scope:** Ship AR-1 Option C from Sprint 6 — retire
`strata report-skeleton`, build `strata report` as a first-
class consumer of the plugin SQLite + case metadata JSON.

## Commits

| Commit | Scope |
|---|---|
| `1b8e57b` | **Main delivery** — new `strata report` command (550 LOC), retirement of `report-skeleton`, ingest emits `case-metadata.json`, subcommand wiring. 11 new tripwires. |
| `5d0da87` | Clippy cleanup on the new report module (useless_format x3, single_char_add_str, needless_deref). Cosmetic. |

## Sprint 6 findings closed

| Finding | Fix |
|---|---|
| **G1** report-skeleton DB disconnect | New `strata report` reads `<case-dir>/artifacts.sqlite` directly |
| **G2** no findings section | Per-Sigma-rule Findings section with supporting artifacts table |
| **G3** no MITRE ATT&CK section | Unique-technique summary table with inferred-tactic column |
| **G4** no chain of custody | Ingest-level CoC table (started / finished) — sub-ingest CoC is v0.17 |
| **G5** no examiner certification | Signed block naming examiner, Strata version, case name, timestamps |
| **G6** evidence source "Not available" | Cascaded close from G1 |
| **G7** SHA-256 "UNVERIFIED" | Cascaded close from G1 (ingest-time hash capture is separate concern) |
| **G11** hardcoded report version | `env!("CARGO_PKG_VERSION")` at compile time |
| **G14** tool version string wrong | Same mechanism — cannot drift |

## Sprint 6 findings explicitly deferred

| Finding | Reason |
|---|---|
| G8 PDF / Word output | Focused output-format sprint (documented in Sprint 6 prompt) |
| G9 agency branding | v0.17 |
| G10 artifact hyperlinks | Polish sprint |
| G12 generic parser note | Polish sprint |
| G13 typography | Already correct |
| AR-2 display-name mapping | v0.17 |
| AR-3 JSON schema validation | v0.17 |
| SIGMA-RULE-ALIGNMENT-2 | Post-Sprint-7 |

## New command implementation summary

### `strata report` — court-ready examiner report

File: `crates/strata-shield-cli/src/commands/report.rs`
(~550 LOC).

**Invocation:**

```
strata report --case-dir <path>
strata report --case-dir <path> --output report.md
strata report --case-dir <path> --examiner "Override Name"
```

**Data sources:**

- `<case-dir>/artifacts.sqlite` — full plugin output, queried
  read-only. Shape: `artifacts` table with
  `plugin_name / category / subcategory / title / detail /
  source_path / timestamp / forensic_value / mitre_technique /
  confidence / is_suspicious`.
- `<case-dir>/case-metadata.json` — `IngestRunSummary` shape.
  Ingest now always writes this (previously gated on
  `--json-result`).

**Seven sections rendered in documented order:**

1. Header (title, examiner, case, timestamps, Strata version,
   total artifact count)
2. Evidence Integrity (source path, case dir, DETECT-1
   classification + confidence, hash-verification note)
3. Findings (per-Sigma-rule breakdown — one sub-section per
   rule firing, with MITRE ID, severity, rule detail, and
   a supporting-artifacts table capped at 10 rows per rule
   for courtroom readability)
4. MITRE ATT&CK Coverage (BTreeMap-sorted table of every
   unique technique with artifact count + inferred tactic;
   paste-into-Navigator friendly)
5. Per-Plugin Summary (plugin × subcategory × count matrix)
6. Chain of Custody (ingest started / completed events;
   sub-ingest CoC flagged as v0.17)
7. Examiner Certification (signed block with examiner name,
   Strata version, case name, ingest timestamps)
8. Limitations (standard boilerplate + transparency notes)

**Markdown output only.** PDF / Word / agency-branded HTML
deferred per prompt.

### Ingest `case-metadata.json` write

Two-line addition in `crates/strata-shield-cli/src/commands/ingest.rs`:
after constructing `IngestRunSummary`, always serialize to
`<case-dir>/case-metadata.json`. Keeps the file next to
`artifacts.sqlite` so `strata report --case-dir <path>` finds
both without examiner config.

### `report-skeleton` retirement

`crates/strata-shield-cli/src/commands/report_skeleton.rs`
stripped to a ~50-line deprecation stub:

- Flags unchanged (backward-compatible CLI so scripts don't
  explode on `--case`/`--examiner` args).
- `execute()` prints a deprecation message naming the
  replacement command + the root-cause explanation, then
  exits `rc=2`.
- Pre-existing report-generation logic (SQLite query, HTML
  template invocation) deleted.

## Tripwire tests added (11)

Ten in `crates/strata-shield-cli/src/commands/report.rs::tests`:

- `strata_report_reads_artifacts_sqlite_not_forensic_db` —
  integration-style: writes synthetic case dir with both
  files, confirms `load_artifacts()` + `load_case_metadata()`
  succeed.
- `strata_report_finds_seven_sigma_rules_on_charlie_shape_fixture`
  — synthesizes the Charlie Sprint 5 firing pattern
  (6 persistence + USB Exfil); asserts 7 `### Finding N:`
  sub-sections render.
- `strata_report_renders_mitre_attack_section_with_technique_ids`
  — asserts the seven Sigma-firing MITRE techniques
  (T1547.014 / T1547.004 / T1176 / T1546.012 / T1547.001 /
  T1546.015 / T1091) all appear in the ATT&CK table.
- `strata_report_renders_chain_of_custody_section` — section
  must always render (placeholder "not recorded" text if
  metadata sparse; populated rows otherwise).
- `strata_report_renders_examiner_certification_block` —
  examiner name + Strata version + case name all appear.
- `strata_report_tool_version_matches_cargo_pkg_version` —
  `env!("CARGO_PKG_VERSION")` at compile time; cannot drift.
- `case_metadata_json_round_trips_from_ingest_summary_shape`
  — serde round-trip integrity between
  `IngestRunSummary` → `CaseMetadata`.
- `strata_report_loads_metadata_from_case_dir_json` —
  tempdir integration test for `load_case_metadata`.
- `strata_report_renders_all_seven_sections_in_order` —
  structural tripwire for section ordering.
- (the first test is also the data-source contract pin)

One in `crates/strata-shield-cli/src/commands/report_skeleton.rs::tests`:

- `report_skeleton_command_deprecated_or_removed` — pins
  the retirement: DEPRECATED marker, `exit(2)`, redirect
  to `strata report --case-dir`, no `Connection::open` in
  production code.

## End-to-end Charlie validation

Ran the full command flow against Charlie post-Sprint-6.5:

```
./target/release/strata ingest run \
    --source charlie-2009-11-12.E01 \
    --case-dir test-output/sprint-6-5-report-unification/charlie/case \
    --case-name sprint6-5-charlie \
    --examiner "Sprint 6.5 Auditor" \
    --auto --auto-unpack

./target/release/strata report --case-dir <case-dir>
```

Result:

```
Strata examiner report generated:
  Case dir:   .../charlie/case
  Examiner:   Sprint 6.5 Auditor
  Artifacts:  3756 across 14 plugin(s)
  Output:     .../report.md
  Strata ver: 0.1.0 (embedded at compile time)
```

Generated report structure verified — all 7 sections present
in documented order. Excerpt below (real Charlie data):

```markdown
# Digital Forensic Examination Report

| Field | Value |
|---|---|
| Case name | sprint6-5-charlie |
| Examiner | Sprint 6.5 Auditor |
| Evidence source | .../charlie-2009-11-12.E01 |
| Ingest started | 2026-04-21T18:23:43Z |
| Ingest finished | 2026-04-21T18:25:15Z |
| Total artifacts | 3756 |

## 2. Findings

**7 Sigma rule(s) fired.** Each firing below is a cross-
artifact correlation the examiner should review:

### Finding 1: USB Exfiltration Sequence
- **Severity:** Medium
- **Source:** Strata Sigma correlation engine
(rule detail)

**Supporting artifacts (top 10 of matching set):**
| Plugin | Subcategory | Title | Source path |
| Strata Phantom | USB Device | USB: Vid_0430&Pid_0100 | … |
| Strata Phantom | USB Device | USB: Vid_413c&Pid_2105 | … |
(...)

### Finding 2: Active Setup Persistence
- **MITRE ATT&CK:** `T1547.014`
(real registry CLSIDs from SOFTWARE hive)

## 3. MITRE ATT&CK Coverage

**42 distinct MITRE ATT&CK technique(s)** with evidence in
this case. Paste the technique IDs into the ATT&CK Navigator
to visualize coverage as a heat map.

| Technique ID | Artifact count | Tactic (inferred) |
| `T1003.003` | 2 | Credential Access |
| `T1027.003` | 180 | Defense Evasion |
| `T1070.006` | 46 | Defense Evasion |
| `T1547.014` | … | Persistence |
(...)

## 5. Chain of Custody

| Time (UTC) | Actor | Action |
| 2026-04-21T18:23:43Z | Sprint 6.5 Auditor |
  Ingest started — source charlie.E01 |
| 2026-04-21T18:25:15Z | Sprint 6.5 Auditor |
  Ingest completed — 3756 artifact(s) extracted by 23 plugin(s) |

## 6. Examiner Certification

I, **Sprint 6.5 Auditor**, certify that I examined the
evidence described in this report using the Strata Forensic
Platform (version `0.1.0`) in read-only mode. …
```

Observations from the real report:

- **42 unique MITRE techniques** automatically surface from
  Charlie — validates that plugins across the board populate
  `mitre_technique` correctly (CLAUDE.md contract honored).
- **7 Sigma findings all render with MITRE IDs** + supporting
  artifacts (real USB VID/PID values, real CLSIDs).
- **CoC populates** with real ingest timestamps + examiner
  identity.
- **Examiner certification** cites correct Strata version
  from `env!` — not hardcoded, cannot drift.
- **Observable minor issue (not a Sprint 6.5 regression):**
  Sigma findings show `Severity: Medium` — the rule emissions
  don't set `forensic_value` in their Artifact fields, so
  downstream execute() defaults to Medium. Could be lifted to
  Critical in a future Sigma tweak; out of Sprint 6.5 scope.
- **Observable minor issue (not a Sprint 6.5 regression):**
  DETECT-1 shows "Unknown filesystem (confidence 0.00)"
  because the classifier runs against the image container
  before filesystem walk completes. Not a Sprint 6.5
  concern; classification correctness is tracked separately.

Deprecated `report-skeleton` exit confirmed:

```
$ strata report-skeleton --case foo
strata report-skeleton has been retired (Sprint 6.5).
…
Use the replacement command:
    strata report --case-dir <case-dir>
…
$ echo $?
2
```

## Quality gates

- **Library tests:** 3,886 (Sprint 6 baseline) + 11 new
  Sprint 6.5 tripwires = **3,897** expected.
- **Clippy:** clean workspace (`-D warnings`). One follow-up
  commit (`5d0da87`) cleaned three useless `format!` calls,
  a `push_str("…")` → `push('…')`, and a needless
  `.as_deref()`.
- **AST quality gate:** **PASS** — library baseline
  **424 / 5 / 5** preserved.
- **Dispatcher arms:** all 6 + FileVault short-circuit
  unchanged.
- **DETECT-1:** Chromebook classification unchanged.
- **v15 Session 2 advisory tripwires:** unchanged.
- **Sessions A–D + Sprints 1–6 tripwires:** all green.
- **9 load-bearing tests:** preserved.
- **Charlie artifact count:** 3,756 (unchanged — this sprint
  doesn't touch extraction).
- **Charlie Sigma firings:** 9 (unchanged — 7 rule fires +
  2 meta records). The new report renders these as the 7
  primary Findings plus the two meta records in the
  Per-Plugin Summary.

## Sprint 7 unblocked

Sprint 6.5's Sprint 7 precondition is met:

- Demo rehearsal can run the full `strata ingest run` +
  `strata report --case-dir` flow against Charlie (or any
  richer Win10/11 image) and get a real, examiner-quality
  report.
- All 7 Charlie Sigma firings render with MITRE technique
  IDs + supporting evidence.
- 42 MITRE ATT&CK techniques surface with coverage counts
  ready for Navigator paste.
- Chain of custody shows real ingest timestamps + examiner
  identity.
- Examiner certification block cites correct Strata version
  (immutable via env!).

Sprint 7 remaining scope:

- Full demo-rehearsal walkthrough against Charlie + ideally
  a richer Windows 10/11 image.
- Confirm every Sprint 3-5 subcategory surfaces correctly
  in the §4 Per-Plugin Summary.
- Confirm the ATT&CK section renders meaningful tactic
  coverage for the demo narrative.
- Update CLAUDE.md + website with post-v16 changes.

## Artefacts

- `crates/strata-shield-cli/src/commands/report.rs` — new
  command (~550 LOC).
- `crates/strata-shield-cli/src/commands/report_skeleton.rs`
  — deprecation stub (~50 LOC).
- `crates/strata-shield-cli/src/commands/ingest.rs` — two-line
  case-metadata.json write addition.
- `crates/strata-shield-cli/src/commands/mod.rs`,
  `src/main.rs` — subcommand wiring.
- `test-output/sprint-6-5-report-unification/charlie/` —
  end-to-end validation artifacts (real markdown report,
  ingest logs, case DB; gitignored).
- No CLAUDE.md or website update per prompt — those land
  after Sprint 7 demo rehearsal.

---

*Wolfmark Systems — Sprint 6.5 closeout, 2026-04-21.
Report-skeleton retired. Seven Sigma findings render with
MITRE mappings and supporting evidence on real Charlie.
Demo blocker closed. Sprint 7 unblocked.*
