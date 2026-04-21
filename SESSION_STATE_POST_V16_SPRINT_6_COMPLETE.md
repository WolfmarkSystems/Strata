# Post-v16 Sprint 6 — Report output audit + consumer surface alignment — COMPLETE

**Date:** 2026-04-21
**Inputs:** `RESEARCH_POST_V16_SIGMA_INVENTORY.md`, session-
state docs from Sprints 1 / 2 / 3 / 4 / 5.
**Scope:** Audit three downstream subcategory consumers
(report generator, Tauri UI, JSON export) against the
Sprint 3-5 subcategory surface growth + generate a full
report from Charlie and audit it with examiner eyes. No
production code changes this sprint — the audit IS the
deliverable.

## Headline findings

1. **All three downstream consumers are audit-clean** —
   dynamic subcategory consumption confirmed via source-
   inspection tripwires. Sprint 3-5 subcategory expansion +
   Sprint 5 "Carved " trim landed without breaking any
   consumer.

2. **`strata report-skeleton` produces an empty report** on
   real case output. Demo-blocker architectural disconnect:
   report generator queries `./forensic.db` (strata-core
   case-store schema), `strata ingest run` writes
   `<case-dir>/artifacts.sqlite` (plugin schema). Same
   command sequence the user docs describe = empty report
   with all-zero counts. **This is a bigger finding than
   subcategory surface alignment, and it's deferred to a
   dedicated Sprint 6.5.**

3. **Report skeleton itself is a shell** — no findings
   section, no Sigma rule firings, no MITRE ATT&CK
   navigator, no chain of custody, no per-plugin breakdown,
   no per-subcategory detail, no PDF output, no embedded
   artifacts. Even if the DB disconnect were fixed today,
   the report would still be a summary-counts-only
   document with a signature line.

## Commits

| Commit | Scope |
|---|---|
| `c4a87bf` | **Fix 1 — Consumer audit tripwires.** Four anti-regression tests in `crates/strata-shield-cli/tests/sprint6_consumer_audit.rs` confirming the report generator, JSON export, and Tauri UI all consume subcategories dynamically. Zero hardcoded Sprint 3-5 literals found anywhere outside legitimate plugin/sigma source. |
| (this doc) | **Session-state** with examiner-quality audit findings ranked by severity and deferred Sprint 6.5 scope. |

Fixes 2, 3, 4 from the prompt collapsed into Fix 1's audit
because the subcategory-surface audit surfaced zero gaps.
Fix 4 (examiner-quality report audit) produced findings
too large for Sprint 6 — captured in § "Sprint 6.5 scope"
below.

## Per-consumer audit outcome

### Report generator — audit-clean

`crates/strata-shield-engine/src/report/` (HTML / JSON /
JSONL / CSV / PDF) + `crates/strata-core/src/report/`
(court-ready + UCMJ).

- `CourtReadyReportInput` carries typed fields (examiner,
  case_id, evidence_source_path, sha256_hash, counts of
  files / artifacts / timeline events / notable items).
  No subcategory strings.
- `JsonReport::Finding { category, severity, title,
  description, source, ... }` uses free-form strings.
  Loose schema; new subcategories pass through without
  validation.
- No hardcoded Sprint 3-5 subcategory literal found in
  any of the six report modules.

**Verdict:** already-correct dynamic consumption pinned by
`report_generators_consume_subcategories_dynamically` +
`json_export_consumes_subcategories_dynamically` tripwires.

### Tauri UI — audit-clean

`apps/strata-ui/src/`. React source consumes
`artifact.category` + `artifact.plugin` via `AppState` +
`ArtifactDetail.tsx`. No hardcoded subcategory enumeration
in any filter panel, dropdown, sort column, or detail
panel.

**Verdict:** dynamic consumption pinned by
`tauri_ui_consumes_subcategories_dynamically` tripwire.

### JSON export — audit-clean

`crates/strata-shield-engine/src/report/json.rs`. The
`Finding.category` + `Artifact.artifact_type` fields are
free-form `String` values — serde pass-through, no
validation, no enum gating. New subcategories serialize
without code changes.

**Verdict:** pinned by the `json_export` tripwire above.

### `"Carved "` trailing-space consumer audit — clean

Sprint 5 Fix 3 trimmed Remnant's emission from `"Carved "`
to `"Carved"`. Workspace-wide scan for the trailing-space
form returned zero hits outside Remnant's own source.
Nothing broke.

**Verdict:** pinned by
`remnant_trailing_space_carved_is_not_referenced_by_any_consumer`.

## Examiner-quality report audit findings (ranked by severity × demo-impact)

Ran `strata ingest run` on Charlie then `strata report-
skeleton --case sprint6-charlie` from the case dir.
Inspected the resulting `report.html`. Findings:

### S0 — CRITICAL demo-blockers (MUST fix for demo readiness)

| # | Finding | Evidence | Fix scope |
|---|---|---|---|
| G1 | **report-skeleton reads wrong database.** Queries `./forensic.db` for schema `evidence` / `ingest_manifests` / `file_table_rows` / `case_stats` / `evidence_timeline` / `bookmarks` / `notes` / `exhibits` / `artifact_summary`. `strata ingest run` writes `<case-dir>/artifacts.sqlite` with a single `artifacts` table. Complete disconnect. | Report on Charlie shows `Total files indexed: 0`, `Total artifacts extracted: 0`, `Timeline event count: 0`, `Notable items count: 0`, "Case database: not found, report generated with defaults." Charlie actually has 3,756 artifacts. | **Either** teach `report-skeleton` to read from `artifacts.sqlite` and synthesize the expected tables, **or** make `ingest run` also populate the case-store schema, **or** deprecate `report-skeleton` in favor of a new report command that consumes the plugin SQLite directly. |
| G2 | **No findings section.** Report has 4 sections (Evidence Integrity, Methodology, Findings Summary, Limitations, Signature Placeholder). "Findings Summary" is four summary count tiles. No list of actual findings. No Sigma rule firings. No per-plugin breakdown. | Charlie has 9 Sigma firings (6 persistence rules + USB Exfil + 2 meta). None appear in the report. | Report template expansion — dedicated "Findings" section rendering per-artifact / per-Sigma-rule details. |
| G3 | **No MITRE ATT&CK mapping visible.** Post-Sprint-2 every Phantom persistence rule carries a MITRE technique ID (T1547.014 / T1547.004 / T1176 / T1546.012 / T1547.001 / T1546.015). None surface in the report. | Grep of report HTML: zero MITRE strings. | ATT&CK navigator section in report template. |

### S1 — HIGH (professional-appearance blockers)

| # | Finding | Evidence | Fix scope |
|---|---|---|---|
| G4 | **No chain of custody section.** Professional forensic reports carry an explicit chain-of-custody table: who acquired / transferred / analyzed, when, hash verification at each step. | Report has "Evidence Integrity" with just source path + SHA-256. | Add CoC section. |
| G5 | **No examiner certification block.** Signature placeholder exists (`Examiner Signature: ___`) but no credential certification, no tool-version attestation block, no statement of methodology adherence. | Signature section is two blank lines. | Add professional certification template. |
| G6 | **Evidence source path shows "Not available".** `ingest run` records the source path; `report-skeleton` can't retrieve it because of G1. | See G1 evidence. | Closes with G1. |
| G7 | **SHA-256 hash shows "Not provided" / UNVERIFIED.** Same root cause as G6. | See G1 evidence. | Closes with G1. |
| G8 | **No PDF / Word output generation.** `report-skeleton` emits only HTML. Court-ready workflows typically require signed PDF. | `report-skeleton --help` has no format flag. | Add PDF / Word renderer (prompt mentioned Word/PDF both; neither exists). |

### S2 — MEDIUM (polish)

| # | Finding | Evidence | Fix scope |
|---|---|---|---|
| G9 | **No case header branding.** Report lacks agency logo, case photograph, exhibit list. | HTML header has only H1 + four meta cards (Examiner / Case ID / Generated / Report Version). | Optional — defendable to ship without per-case branding. |
| G10 | **No hyperlinks to extracted artifacts.** Report doesn't link from a finding to the extracted file in the case dir. Examiner reading the report can't one-click to the evidence. | HTML has zero `<a href>` tags to extracted paths. | File-reference hyperlinks. |
| G11 | **"Report Version 1.0" is a hardcoded string.** Should track Strata release version. | Report shows `Report Version: 1.0`; Strata is at v0.16.0. | One-line fix. |
| G12 | **"Parser maturity note" is generic boilerplate.** Reads "Results from Experimental parsers should be corroborated" — doesn't list which parsers ran as experimental. | HTML text. | Parser-status table. |

### S3 — LOW / cosmetic

| # | Finding | Evidence | Fix scope |
|---|---|---|---|
| G13 | **Typography is actually fine.** HTML uses Arial, reasonable margins, color-differentiated section cards. Not amateur. | Screenshot inspection. | No change needed. |
| G14 | **"Tool version: 0.1.0" hardcoded to strata-shield-cli's Cargo version.** Misleading if Strata is at v0.16.0. | HTML text. | Pull from workspace version. |

## Tripwires added (4)

All in `crates/strata-shield-cli/tests/sprint6_consumer_audit.rs`:

- `report_generators_consume_subcategories_dynamically`
- `json_export_consumes_subcategories_dynamically`
- `tauri_ui_consumes_subcategories_dynamically`
- `remnant_trailing_space_carved_is_not_referenced_by_any_consumer`

Each is a source-inspection test: walk the relevant subtree
for .rs / .ts / .tsx files, scan for Sprint 3-5 subcategory
string literals, filter out legitimate plugin/sigma/docs
sources, assert zero remaining hits.

## Architectural recommendations for v0.17

### AR-1 (high priority) — Report ↔ case-store schema unification

Either:

- **Option A**: Teach `ingest run` to populate the
  strata-core case-store schema (`evidence`,
  `ingest_manifests`, `file_table_rows`, `case_stats`,
  `artifact_summary`, `evidence_timeline`) alongside the
  plugin `artifacts.sqlite`. Report-skeleton works as
  designed.

- **Option B**: Rewrite `report-skeleton` to consume
  `artifacts.sqlite` directly + synthesize summary counts
  at report-gen time. Simpler.

- **Option C**: Retire `report-skeleton` entirely.
  Publish a new `strata report` command that's a
  first-class consumer of the plugin SQLite plus an
  embedded case-metadata JSON. Cleanest.

Recommendation: **Option C**. `report-skeleton`'s schema
expectation is artifact of a different case-store design
that's no longer the primary write path. Replace rather
than refactor.

### AR-2 (medium priority) — Display-name mapping infrastructure

13 new subcategory strings surfaced in Sprints 3-5. Raw
strings like `"BITS Transfer"` and `"PCA Execution"` render
in examiner reports. For casework output, prettier names
(`"Background Intelligent Transfer Service (BITS) Job"`,
`"Program Compatibility Assistant Execution Log"`) are
appropriate.

Shared table in `strata-plugin-sdk` keyed by subcategory
string; consumed by report generator's finding renderer.
**Do not invent per-consumer maps** — Session B's plugin
audit already cautions against this pattern. Single shared
pretty-name mapping.

### AR-3 (low priority) — JSON schema validation

Current JSON export is pass-through. For third-party
integrations (Autopsy import, Cellebrite export, custom
SOAR pipelines) a documented + validated schema is
appropriate. Not a blocker; nice-to-have.

## Sprint 6.5 scope (deferred focused sprint)

Items G1 + G2 + G3 are demo-blockers. **Sprint 6.5** ships
them as a focused sprint:

1. **G1 fix** — pick option from AR-1 (recommend C). ~250
   LOC new `strata report` command that consumes the
   plugin SQLite + produces reports with real data.
2. **G2 fix** — Findings section in report template.
   Render per-plugin groups + per-Sigma-rule firings +
   MITRE mapping hyperlinks.
3. **G3 fix** — ATT&CK navigator section. Render
   observed MITRE technique IDs as a link list; optionally
   embed the ATT&CK navigator JSON format for external tool
   import.
4. **G4 fix** — Chain of custody table (simple: read
   activity_log or equivalent, render chronological events).
5. **G5 fix** — Examiner certification block.
6. **G11 + G14** — Tool-version + report-version
   correctness. One-line fixes.

Estimated Sprint 6.5 scope: ~400 LOC report-side changes
+ ~100 LOC of tripwire tests.

Items G6, G7 close automatically when G1 closes. G8 (PDF
rendering) and G9, G10, G12, G13 ship in a later report-
polish sprint.

## Quality gates

- **Library tests:** 3,882 (Sprint 5 baseline) + 4 new
  Sprint 6 tripwires = **3,886** expected.
- **Clippy:** clean workspace (expected — no production
  code changed).
- **AST quality gate:** PASS — library baseline
  **424 / 5 / 5** preserved. Zero production code
  changes.
- **Dispatcher arms:** all 6 + FileVault short-circuit
  unchanged.
- **DETECT-1:** Chromebook still classifies correctly.
- **v15 Session 2 advisory tripwires:** unchanged.
- **Sessions A–D + Sprints 1–5 tripwires:** all green.
- **9 load-bearing tests:** preserved.

## Sprint 7 scope assessment

The prompt asked for Sprint 7 demo rehearsal scope
recommendation.

**Hard pre-requisite for Sprint 7:** Sprint 6.5 must land
G1 + G2 + G3 first. Running a demo rehearsal against the
current report-skeleton produces an empty report that
would tank the demo. The subcategory surface is ready,
the plugin outputs are ready, the Sigma firings are ready
— **the report generator is the bottleneck**.

Recommended sequencing:

- **Sprint 6.5** — report-skeleton disconnect fix + findings
  section + ATT&CK section (G1/G2/G3 above). ~400 LOC.
- **Sprint 7** — Demo rehearsal against a real case
  (Charlie, or ideally a richer Windows 10/11 image):
    - Run full `strata ingest run` with the new report
      command
    - Validate every Sprint 3-5 subcategory appears in
      the report
    - Validate all 9 Charlie Sigma firings render with
      MITRE mappings
    - Walk the report as an examiner — confirm findings
      flow from evidence integrity → findings → threat
      assessment → signatures
    - If polish issues surface (G9-G14), patch inline
- **CLAUDE.md + website update** — lands with Sprint 7
  close.

Alternative: **if Sprint 6.5 is deferred**, Sprint 7 becomes
"demo rehearsal without report output, using SQLite
inspection / JSON summary only" — workable for internal
technical reviews, inadequate for external demos.

## Deferrals with tripwires (carry-forward)

Inherited from prior sprints, all still valid:

- Phantom services / ring_doorbell / smart_locks
- Sentinel lateral_movement
- Sentinel `.evt` parser
- Remnant regions / signatures
- Vault android_antiforensic

No new deferrals from Sprint 6 — the big findings (G1-G3)
are Sprint 6.5 scope, not indefinite deferrals.

## Artefacts

- `crates/strata-shield-cli/tests/sprint6_consumer_audit.rs`
  — 4 anti-regression tripwires.
- `test-output/sprint-6-report-audit/charlie/` — ingest +
  empty-report audit trail (gitignored).
- No CLAUDE.md or website update per prompt — those land
  after Sprint 7 demo rehearsal confirms end-to-end
  readiness.

---

*Wolfmark Systems — Sprint 6 closeout, 2026-04-21.
Consumer alignment audit clean. Report-skeleton DB
disconnect surfaced as Sprint 6.5 demo-blocker. Subcategory
surface is ready; report output is the bottleneck.*
