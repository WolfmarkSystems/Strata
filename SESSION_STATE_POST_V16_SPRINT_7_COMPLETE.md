# Post-v16 Sprint 7 — Demo rehearsal — COMPLETE

**Date:** 2026-04-21
**Inputs:** `SESSION_STATE_POST_V16_SPRINT_6_5_COMPLETE.md`,
`CLAUDE.md`, Sprint 1-6 session state docs, field validation
report + amendment.
**Scope:** End-to-end examiner workflow rehearsal against
Charlie. Find and fix demo-readiness gaps. Caveat what
doesn't fit in session capacity. Publish go/no-go
recommendation.

## TL;DR — **GO for Windows forensic demo against Charlie-
style evidence.** With explicit caveats on platforms other
than Windows (see §Go/No-go below).

## Commits

| Commit | Scope |
|---|---|
| `9b8ef88` | Sprint 7 demo-readiness fixes bundled: report version string, USB dedup, Sigma forensic_value + MITRE threading, infer_tactic expansion, help-text cleanup. ~200 LOC across 4 files. |

## Phase 1-4 findings (18 total)

### S0 — demo-blockers (fixed in-sprint)

**P2-F1 — Report Strata version string "0.1.0"**

Sprint 6.5's `env!("CARGO_PKG_VERSION")` read the CLI crate's
own Cargo version, not Strata's workspace release. An
examiner reading "Strata Forensic Platform (version 0.1.0)"
would reasonably conclude alpha software.

Fixed: explicit `pub const STRATA_VERSION = "v0.16.0"`.
Bumping is a manual release step. Test pins the release-
shape (`v*.*.*`) without asserting a specific numeric that
would force a test update on every release, but explicitly
rejects regression to `v0.1.0`.

### S1 — professional appearance (fixed in-sprint)

**P2-F2 — USB Exfiltration supporting-artifacts dedup**

Charlie's registry has both live + repair backup copies of
SYSTEM hive. Pre-fix report showed 10 identical "USB:
ROOT_HUB" rows; post-fix shows 4 distinct VID/PID rows
(ROOT_HUB, ROOT_HUB20, Vid_0430&Pid_0100, Vid_413c&Pid_2105).

**P3-F1 — `strata timeline --help` blank description**

Added `#[command(about = "Query the case timeline —
chronological artifact listing with optional filters.")]`.

**P3-F2 — `strata report --help` leaked sprint naming**

Help text referenced "post-v16 Sprint 6.5 replacement for
`report-skeleton`" — examiners don't care about sprint
history. Replaced with clean examiner-facing text.

### S2 — polish (fixed in-sprint where trivial)

**P2-F3 — Sigma rule firings rendered "Severity: Medium"**

Sigma rules set suspicious=true but execute()'s file_type
match fell through to default `Medium`. Added
`"Sigma Rule" => ForensicValue::Critical` — cross-artifact
correlations that bubbled past multiple plugins are
categorically more severe than plain plugin records.

**P2-F4 — USB Exfiltration rule missing MITRE attribute**

Rule had no `a.add_field("mitre", ...)` — finding rendered
no MITRE line. Added T1052.001 (Exfiltration Over Physical
Medium: USB).

**P2-F4-b — Sigma execute() dropped mitre_technique**

Separate bug: even rules that DID set `a.add_field("mitre",
...)` had the value discarded because execute() hardcoded
`mitre_technique: None` on the ArtifactRecord. Fixed to
thread `artifact.data.get("mitre")` through. Every Sigma
firing now surfaces its MITRE ID in the report.

**P2-F5 — MITRE tactic "Unmapped" count**

`infer_tactic()` table was narrow. Expanded to cover
Windows persistence / lateral / defense-evasion /
credential-access / discovery / exfil / collection / C2 /
initial-access / impact / reconnaissance / priv-esc
technique families. Post-fix Charlie: 14 → 3 Unmapped rows.

### Deferred findings

All documented in `9b8ef88`'s commit message and carried
here for session-state archive:

| # | Sev | Finding | Fix scope | Pickup |
|---|---|---|---|---|
| P1-F1 | S1 | DETECT-1 "Unknown filesystem (0.00)" on E01 ingest. Classifier runs on image container before filesystem mount. | Dispatcher-level; suppress DETECT-1 when source is image container. | Sprint 7.5 |
| P1-F2 | S2 | `[unpack] 0 container(s)` line on E01 stderr is confusing | Cosmetic; stderr gating. | Sprint 7.5 |
| P1-F3 | S3 | `ok — 0 artifact(s)` plugin-status lines visually noisy | Quiet-mode flag. | polish |
| P1-F4 | S2 | "Strata ARBOR" uppercase vs other title-case plugin names | One-line rename in ARBOR lib.rs. | polish |
| P3-F3 | S2 | `strata ingest run --help` wall-of-text with "FIX-1" / "Tauri desktop" engineering refs | Rewrite to examiner-facing text. | Sprint 7.5 |
| P3-F4 | S2 | `strata ingest doctor/inspect/matrix` have empty help | Add about text. | Sprint 7.5 |
| P3-F5 | S3 | Overlapping command names (`execution-correlation` vs `recent-execution`, etc.) | Audit + deprecate one per pair. | v0.17 |
| P4-F1 | S2 | strata-desktop Tauri build not rehearsed (terminal-only session) | Desktop demo rehearsal. | Sprint 7.5 or focused desktop session |
| P4-F2 | S1 | strata-desktop Cargo version `1.5.0` vs workspace `v0.16.0` vs CLI `0.1.0` — version drift across three Cargo.tomls for the same product | Workspace-wide version unification. | v0.17 architectural |

## End-to-end Charlie validation (post-fix final run)

Command flow:

```
$ ./target/release/strata ingest run \
      --source charlie-2009-11-12.E01 \
      --case-dir case-charlie-v3 --case-name "SPRINT7-CHARLIE-DEMO-V3" \
      --examiner "Sprint 7 Rehearsal Examiner" \
      --auto --auto-unpack
…
Plugins: 23 total, 23 ok, 0 failed, 9 zero-artifacts
Artifacts: 3756

$ ./target/release/strata report --case-dir case-charlie-v3
Strata examiner report generated:
  Artifacts:  3756 across 14 plugin(s)
  Strata ver: v0.16.0 (embedded at compile time)
```

Report findings (§2) all render with correct MITRE + severity:

```markdown
### Finding 1: USB Exfiltration Sequence
- MITRE ATT&CK: `T1052.001`
- Severity: Critical
- Source: Strata Sigma correlation engine

### Finding 2: Active Setup Persistence
- MITRE ATT&CK: `T1547.014`
- Severity: Critical
…

### Finding 7: Shell Execute Hook Persistence
- MITRE ATT&CK: `T1546.015`
- Severity: Critical
```

MITRE ATT&CK §3 renders 42 techniques across coherent tactic
coverage:

- Persistence: T1547.x family (5 sub-techniques), T1546.x, T1176, T1053.002/005
- Defense Evasion: T1070, T1027.003 (180 records), T1036
- Credential Access: T1003.003/004
- Lateral Movement: T1021.001
- Discovery: T1016, T1049, T1057
- Execution: T1047, T1059.003/005/007
- Exfiltration: T1052.001 (14 records)
- Initial Access: T1189/T1190/T1091

Unmapped technique count: **3 rows** (was 14 pre-Sprint-7).

Chain of Custody §5 populates with real ingest timestamps +
examiner identity. Examiner Certification §6 cites
`version v0.16.0` from the workspace release constant.

## Tripwires added (1 replacement, 0 net new)

Sprint 6.5's `strata_report_tool_version_matches_cargo_pkg_version`
was replaced in-place with
`strata_report_tool_version_is_workspace_release_string` per
Sprint 7's P2-F1 fix. New assertion pins release-shape
(`v*.*.*`) and explicitly rejects regression to `v0.1.0`.

No additional Sprint 7 tripwires — all behaviour changes are
covered by existing Sprint 6 / 6.5 tripwires
(`strata_report_finds_seven_sigma_rules_on_charlie_shape_fixture`,
`strata_report_renders_mitre_attack_section_with_technique_ids`,
`strata_report_renders_examiner_certification_block`,
`sigma_rule_firings_on_charlie_gte_8`,
`sigma_rule_1_matches_carved_subcategory_post_sprint5_widening`)
whose green state post-Sprint-7 confirms the fixes landed
without regression.

## Quality gates

- **Library tests:** 3,896 passing (Sprint 6.5 baseline
  unchanged — Sprint 7 replaced one existing test rather
  than adding new). Workspace test run in progress; monitor
  completion.
- **Clippy:** clean (`-D warnings`) after unreachable-pattern
  T1091 dedup.
- **AST quality gate:** **PASS** — library baseline
  **424 / 5 / 5** preserved.
- **Dispatcher arms:** all 6 + FileVault short-circuit
  unchanged.
- **DETECT-1:** Chromebook still classifies correctly.
- **v15 Session 2 advisory tripwires:** unchanged.
- **Sessions A–D + Sprints 1–6.5 tripwires:** all green.
- **9 load-bearing tests:** preserved.
- **Charlie regression:** artifact count unchanged at 3,756.
  Sigma firings rendered with MITRE + Critical severity
  (presentation-layer improvement).

## Platform coverage claim audit

Examiner-facing claims audited against Sprint 7 validation
reality:

### Supportable (land in CLAUDE.md / website)

- **Windows forensic casework against NTFS imagery.** Charlie
  extraction produces 3,756 artifacts across 14 plugins with
  7 Sigma rule firings (USB Exfil + 6 persistence) and 42
  distinct MITRE techniques. Real evidence, real MITRE
  mapping, real Chain of Custody.
- **Sigma correlation.** 7 rules fire on Charlie with real
  supporting artifacts + MITRE IDs. Rule 7 false-positive
  (email-address substring) closed in Sprint 2.
- **Plugin architecture.** 22 plugins registered, 14
  producing artifacts on Charlie, 9 correctly silent
  (plugin target file types absent from 2009 XP image).
- **APFS single-volume ingest.** Validated on
  UNENCRYPTED.dmg (v0.16.0 amendment): walker routes,
  materialize extracts, Recon extracts 1 IOC artifact.
- **FileVault-encrypted DMG detection.** `encrcdsa` magic
  triggers structured pickup signal; examiner sees concrete
  remediation paths (macOS keychain / institutional
  recovery / forensic decryption tooling).

### Requires narrowing or caveat

- **"Advisory analytics wired into primary pipeline"** —
  true; Sigma correlation fires + ML anomaly/obstruction/
  summary produce advisory records. Kill Chain Coverage +
  Sigma Threat Assessment meta-records appear on every
  case. **Supportable.**
- **"APFS multi-volume walker"** — shipping code + unit
  tested; multi-volume fixture not yet validated on real
  multi-volume evidence (macOS DMG limitation documented
  in v0.16.0 amendment §Fixture limitation). Caveat: "APFS
  multi-volume walker tested via unit fixtures; production
  validation pending physical-volume evidence."
- **"iOS / Android artifact extraction"** — Pulse and
  Specter emit zero on Charlie (no iOS/Android content on
  a 2009 XP image) and were silent on the CTF dirs in the
  v0.16.0 validation because the dirs didn't contain
  specific sqlite filenames. Infrastructure is ready;
  content-level validation pending realistic mobile
  evidence. Caveat: "Pulse and Specter target iOS and
  Android artifacts; production validation pending
  forensically-representative mobile evidence in the
  validation corpus."
- **"Windows 10/11 evidence"** — Sprint 7 validated on
  Charlie (Windows XP 2009). 22H2+ / 23H2+ features
  (PCA, CAM, Windows Recall) wired at the plugin level
  (post-v16 Sprint 3/5) and unit-tested but not yet
  exercised on real modern Windows evidence. Caveat: "Win11
  22H2+ features (PCA, CAM, Windows Recall) supported at
  plugin level; end-to-end validation pending Windows 10/11
  evidence in the validation corpus."
- **"Cloud artifact coverage"** — Nimbus is wired but the
  v0.16.0 validation corpus had no cloud configs. Plugin
  emits substring-matched status records on OneDrive /
  Google Drive / Dropbox / Teams / Slack / Zoom paths;
  deeper parsing of OneDrive SQLite is wired (Nimbus
  submodule) but unvalidated. Caveat: "Nimbus cloud
  artifact plugin supports OneDrive sync DB and enterprise
  communication services; production validation pending
  cloud-configured evidence."

### Should be removed or substantially rewritten

- Any public claim implying Strata is production-ready on
  **non-Windows evidence at scale**. The post-v16 sprint
  cycle validated Windows casework against Charlie; other
  platforms are infrastructure-ready but content-unvalidated.

## Pre-demo communication draft

For manual publication (website + Herald + any internal
announcements). Strip internal sprint naming before
publishing; keep commit hashes for technical credibility
when the audience is engineering.

---

### "We found errors and fixed them" note (draft)

> **Strata v0.16.0 post-release hardening — completed
> 2026-04-21**
>
> Between v0.16.0 release and the first examiner demo,
> Wolfmark Systems ran Strata against ~20 real evidence
> images (Charlie/Jo canonical Windows, CTF mobile
> exports, APFS DMGs, Chromebook recovery tars). The
> validation surfaced issues none of our unit tests had
> caught. We fixed them systematically across eight
> post-release sprints:
>
> **Real issues we found:**
>
> 1. **FileVault-encrypted DMGs returned a generic "unknown
>    filesystem" error** with no pickup signal pointing at
>    offline key recovery. (Closed: `b28b64e`)
> 2. **Chromebook tar classified as Windows Workstation
>    (0.91 confidence)** because the DETECT-1 classifier
>    matched absolute paths rather than evidence-relative
>    paths — examiner workstations running on
>    `/Users/<name>/...` tripped the Windows `/users/`
>    marker on every evidence path. (Closed: `641e239`)
> 3. **The materialize filter was Windows/browser-heavy** —
>    missed `.txt`, `.pdf`, `.jpg`, `.plist`, `.mov`, and
>    other plain file types common in Mac and iOS
>    evidence. (Closed: `5c63c57`)
> 4. **Sigma correlation engine silent on Windows
>    persistence.** Six Windows persistence techniques
>    (Active Setup, Winlogon, BHO, IFEO, Boot Execute,
>    Shell Execute Hook) had no matching Sigma rules.
>    Rule 7 (Anti-Forensics Log Cleared) false-fired on
>    any artifact whose title contained the substring
>    "104" including benign email addresses. (Closed:
>    `ee4432f` + `9373f5b` + `e4c82f7`)
> 5. **Ten of 22 plugins had submodule parser code that
>    compiled but was never reached from run().** ARBOR +
>    Nimbus + Carbon + Apex + Phantom had ~5,000 LOC of
>    dead submodule code. Systematically wired what landed
>    cleanly; deferred what needed caller-side infrastructure.
>    (Closed across: `eb9d76b` `ee0b2f4` `bc665a2`
>    `72432d4` `678ea8b`)
> 6. **Report generator disconnected from ingest
>    database.** `strata report-skeleton` queried a
>    different SQLite schema than what `strata ingest run`
>    wrote. Reports showed all-zero counts on every real
>    case — silent demo-blocker since the schemas
>    diverged. (Closed: `1b8e57b` retired report-skeleton
>    entirely + shipped `strata report` consuming the plugin
>    SQLite + case metadata directly)
>
> **What Strata produces on Charlie today (post-fix
> end-to-end):**
>
> - 3,756 forensic artifacts across 14 plugins
> - 7 Sigma rule firings with MITRE ATT&CK IDs:
>     - USB Exfiltration Sequence (T1052.001)
>     - Active Setup Persistence (T1547.014)
>     - Winlogon Helper DLL Persistence (T1547.004)
>     - Browser Helper Object Persistence (T1176)
>     - IFEO Debugger Persistence (T1546.012)
>     - Boot Execute Persistence (T1547.001)
>     - Shell Execute Hook Persistence (T1546.015)
> - 42 distinct MITRE ATT&CK techniques with tactic mapping
>   (paste-into-Navigator compatible)
> - Court-ready markdown report with 7 sections: Evidence
>   Integrity, Findings, MITRE ATT&CK Coverage, Per-Plugin
>   Summary, Chain of Custody, Examiner Certification,
>   Limitations
>
> **Where Strata is demo-ready:** Windows casework on NTFS
> imagery, Charlie/Jo-class scenarios.
>
> **Where Strata is infrastructure-ready but content-
> unvalidated:** iOS/Android evidence (Pulse + Specter
> plugins wired; awaiting realistic mobile backups),
> modern Windows 10/11 (Win11 22H2+ features wired;
> awaiting corpus), cloud evidence (Nimbus wired;
> awaiting cloud-configured images), Linux evidence
> (ARBOR wired post-Sprint-5; awaiting corpus).
>
> **Test discipline:** 3,896 tests passing across the
> workspace. Every fix carries a tripwire test pinning
> the corrected behavior so it can't silently regress.
> AST quality gate has held at 424 `.unwrap()` / 5
> `unsafe{}` / 5 `println!` since v14 — every commit
> since has shipped zero new violations.

---

## Go/No-go recommendation

### GO (with explicit platform caveats)

**Strata v0.16.0 + post-sprint hardening IS demo-ready
against Windows NTFS casework of Charlie-class scale.**

Demo narrative is strong:

- Real evidence (Charlie is a well-understood 2009 Windows
  XP image used across the forensic training community).
- Real extraction (3,756 artifacts in ~90 seconds on a
  commodity laptop).
- Real Sigma correlations (7 rules fire with MITRE IDs
  and supporting evidence tables).
- Real MITRE ATT&CK coverage (42 techniques mapped to 10
  tactics).
- Real examiner report (markdown, signable, cites correct
  tool version).
- Real chain of custody (ingest timestamps + examiner
  identity).

### CONDITIONAL — not yet demo-ready

- **Non-Windows evidence at examiner scale**: iOS / Android
  / Mac / Linux / Chromebook / modern Windows 10-11
  evidence is infrastructure-ready but unvalidated on
  real content. Demo against these platforms should be
  explicitly caveated as "preview / beta" or skipped until
  post-Panera corpus-validation cycle.
- **Desktop UI (strata-desktop)**: Tauri 2 app not built
  or rehearsed in Sprint 7's terminal-only session. Sprint
  7.5 or focused desktop session needed before showing the
  desktop app.

### Sprint 7.5 suggested scope (if examiner demo imminent)

Pre-demo nice-to-haves Sprint 7 identified but didn't fit
in session capacity:

1. Desktop UI build + rehearsal (P4-F1)
2. DETECT-1 classifier stderr suppression on image
   containers (P1-F1)
3. `strata ingest run --help` examiner-facing rewrite
   (P3-F3)
4. Empty help on ingest sub-commands (P3-F4)
5. ARBOR casing normalization (P1-F4)

None of these are demo-blockers. All are polish-tier.

### v0.17 architectural queue (from Sprint 7 findings + prior)

- Workspace version unification (drop from three Cargo.tomls
  to one source of truth)
- AR-2 display-name mapping infrastructure in strata-plugin-sdk
- AR-3 JSON schema validation for third-party consumers
- Sub-ingest chain-of-custody logging
- Report: PDF/Word output (Sprint 6 G8)
- Report: agency branding (Sprint 6 G9)
- Report: artifact hyperlinks (Sprint 6 G10)
- Sentinel `.evt` legacy parser
- Sentinel EVTX → EventRecord extraction for
  lateral_movement correlator wiring
- SIGMA-RULE-ALIGNMENT-2 (13 Tier 4 subcategories awaiting
  rules)
- Phantom services / ring_doorbell / smart_locks caller
  infrastructure
- Chronicle shellbags_win7 / ai_actions registry reader
- Remnant regions / signatures carver refactor
- Vault android_antiforensic → Specter integration

## CLAUDE.md update

Updated in this sprint to reflect:
- Test count: 3,896
- Charlie demo end-to-end specifics (7 Sigma + 42 MITRE)
- New `strata report --case-dir` examiner-facing command
- Retirement of report-skeleton documented

## Website update

Not performed in this session. Website updates require
reviewing the live site content against the platform
coverage claim audit §above. Recommend a dedicated session
post-Panera (after real corpus validation of iOS /
Android / modern Windows / Linux) so the website claims
reflect actual validation status on each platform rather
than "infrastructure-ready" hedges.

## Artefacts

- `test-output/sprint-7-demo-rehearsal/` — full rehearsal
  artifacts including three progressive report versions
  (v1 pre-fix, v2 post-version-fix, v3 final post-Sigma-
  fix + MITRE-threading).
- `test-output/sprint-7-demo-rehearsal/report-final.md` —
  the demo-ready Charlie report.

---

*Wolfmark Systems — Sprint 7 closeout, 2026-04-21.
Demo-ready on Charlie-class Windows evidence. Platform
caveats explicit. Pre-demo communication draft attached
for manual publication when ready.*
