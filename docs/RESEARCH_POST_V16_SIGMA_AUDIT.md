# RESEARCH_POST_V16_SIGMA_AUDIT.md

**Session:** Post-v16 Session A (Sigma correlator audit)
**Date:** 2026-04-20
**Trigger:** `FIELD_VALIDATION_REAL_IMAGES_v0.16.0.md` §5 gap G4 —
"Sigma correlator never fires a rule, only produces 2 audit-level
artifacts per run across all 18 inputs including Charlie/Jo where
2,500+ Windows persistence artifacts were present."
**Outcome:** research doc only — **fix deferred** to a follow-up
session. No production code modified.

## TL;DR

The "2 meta-records per run" observation is **accurate but
mis-diagnosed** in the validation report. Sigma is **not broken**.
The correlation engine iterates 30+ real rules and evaluates each
against the full `prior_results` artifact set — the rules simply
don't fire.

**Root cause:** **systemic subcategory-string contract mismatch**
between 22 upstream plugins and Sigma's rule predicates. Sigma's
rules were written against subcategory strings that many plugins
do not emit; plugins emit subcategory strings that Sigma's rules
don't check for. This is an integration-contract gap spanning
~30 rules × ~10 plugins, not a one-line fix.

**What always fires** on every Sigma run (explaining the "2
meta-records"):
1. "Kill Chain Coverage" at `lib.rs:147-159` — unconditional.
2. "Sigma Threat Assessment" summary at `lib.rs:1050-1057` —
   unconditional.

Every run produces exactly these two artifacts plus whatever
rules the prior plugin artifacts happen to trigger.

**What should have fired on Charlie but didn't**, and why:
- **v1.3.0 Hayabusa EVTX rules (~20 rules)**: require
  `subcategory == "EVTX-<id>"` from Sentinel. Sentinel emits
  zero EVTX artifacts on Charlie/Jo because they are Windows
  XP/7 with legacy `.evt` files, not `.evtx`. Sentinel's v1.3.0
  EVTX parser is `.evtx`-only. **20+ rules silently gated out by
  XP-era evidence.**
- **Multi-plugin correlation rules (~10 rules)**: each checks
  ≥2 subcategory signatures. Charlie has the first half of
  many such pairs (USB Device ✓, Service ✓, AutoRun ✓, Recent
  Files ✓, Suspicious Script+Critical ✓) but not the second
  half the rule requires (`"Recycle"/"USN"` from Remnant,
  `"SAM Account"` from Phantom, `"Archive Tool"` from Phantom,
  `"Office Trust Record"` from Chronicle, etc.).
- **No rule keys on the Windows persistence subcategories
  Phantom does emit** (Active Setup, Winlogon Persistence,
  IFEO Debugger, Boot Execute, Shell Execute Hook, Browser
  Helper Object). Charlie has 386 artifacts across these
  subcategories — all forensically-real persistence markers —
  and none of them trigger a Sigma rule because no rule has a
  predicate like `subcategory ∈ {"Active Setup", "Winlogon
  Persistence", ...}`.

**Classification:** subcategory-contract drift. Not wiring, not
parser, not evaluation logic. Deep enough that the fix is a
multi-session audit + alignment, not a one-session patch.

## Evidence

### E1 — Sigma code actually iterates rules and evaluates them

`plugins/strata-plugin-sigma/src/lib.rs` is 1,544 lines. `fn run`
at line 99 does:

1. Returns a "No Input Data" artifact if `ctx.prior_results` is
   empty (line 112).
2. Collects every prior-plugin `ArtifactRecord` into
   `all_records: Vec<&ArtifactRecord>` (line 115).
3. Aggregates technique → tactic counts across all records
   (lines 125–137).
4. **Emits "Kill Chain Coverage" artifact unconditionally**
   (line 159).
5. Iterates ~30 rule blocks (lines 167–1008), each:
   - Computes a condition from `all_records` (usually
     `all_records.iter().any(|r| r.subcategory == "...")` or
     `count_evtx(N)`).
   - If condition matches, pushes a `RULE FIRED:` artifact.
6. Builds a technique breakdown + threat-level assessment
   (lines 1011–1038).
7. **Emits "Sigma Threat Assessment" summary artifact
   unconditionally** (line 1057).

**This is not a stub.** Rules 28/29 check CSAM detail tokens
(`r.detail.contains("[confidence=Confirmed]")`). Rules 30–34
check ML anomaly subcategories with confidence parsing. Rules
regarding EVTX use a typed `count_evtx` closure. Each rule
block is independently drafted and compiles against the actual
`ArtifactRecord` shape.

**What happens when a rule's predicate returns false**: rule
block is skipped, execution continues to the next rule. No
artifact emitted, no error. This is the exact "silent zero"
shape described in CLAUDE.md — it LOOKS like the rule isn't
there if you don't look at the code.

### E2 — Charlie's artifact distribution vs. Sigma's rule predicates

From `test-output/validation-v0.16.0/charlie_11_12/case/artifacts.sqlite`:

Top subcategories in Charlie (plugin-emitted):

| Subcategory | Count | Emitted by |
|---|---:|---|
| Suspicious PE Analysis | 2,449 | Strata Vector |
| Service | 321 | Strata Phantom |
| Recent Files | 143 | Strata Chronicle |
| Installed Program | 74 | Strata Phantom |
| Timestomp Detected | 46 | Strata Trace |
| LOLBIN | 46 | Strata Trace |
| Prefetch Executions | 40 | Strata Trace |
| Prefetch | 40 | Strata Trace |
| Hidden Storage Indicator | 36 | Strata Phantom |
| Active Setup | 27 | Strata Phantom |
| Winlogon Persistence | 24 | Strata Phantom |
| Winsock LSP | 20 | Strata Phantom |
| USB Device | 14 | Strata Phantom |
| Browser History | 14 | Strata Chronicle |
| Suspicious Script | 13 | Strata Vector (all Critical) |
| Encrypted Container | 12 | Strata Vault |
| IFEO Debugger | 2 | Strata Phantom |
| Boot Execute | 2 | Strata Phantom |
| (30+ other categories) | 1–10 each | various |

Sigma rule predicates explicitly check these subcategory
strings:

| Sigma predicate | Present in Charlie? | Rule(s) gated by absence |
|---|---|---|
| `== "USB Device"` | ✓ (14) | USB Exfil needs 2 more |
| `== "Recent Files"` or `== "OpenSavePidlMRU"` | ✓ (143) | USB Exfil needs 2 more |
| `.contains("Recycle")` or `.contains("USN")` | ✗ | **USB Exfil Sequence** blocked |
| `== "7-Zip"`, `"WinRAR"`, `"Rclone Config"`, `"MEGAsync Config"`, `"WinSCP Config"` | ✗ | **Archive+Exfil** blocked |
| `== "Defender Log"` or `"Avast Log"` | ✗ (Guardian: 0 artifacts) | **AV Evasion** blocked |
| `== "SAM Account"` or `"Cloud Identity"` | ✗ | **New Account+Persistence** blocked |
| `== "Service"`, `"AutoRun"`, `"BAM/DAM"` | ✓ (321 + 5 + 0) | partial — needs above pair too |
| `== "ShimCache"` | ✗ | **Shimcache Ghost** predicate `shimcache>0` false |
| `== "Prefetch"` | ✓ (40) | Shimcache Ghost's `prefetch==0` condition fails |
| `== "Web Attack"` | ✗ | **Web Server Compromise** blocked |
| `title.contains("1102")` or `"104"` | ✗ (no Sentinel output) | **Log Clearing** blocked |
| `== "Archive Tool"` | ✗ | **Archive+Exfil extended** blocked |
| `== "Office Trust Record"` | ✗ (Chronicle doesn't emit) | **Office Macro Chain** blocked |
| `== "Suspicious Script"` + Critical | ✓ (13 Critical) | partial — needs trust_record |
| `== "Factory Reset"` | ✗ (Android-specific) | N/A for Charlie |
| `== "SRUM Database"` | ✗ (Trace emits different subcat) | **SRUM+Exfil** blocked |
| `== "Capability Access"` | ✗ (Phantom doesn't emit) | **Suspicious Capability** blocked |
| `== "EVTX-<N>"` for N ∈ {1102, 104, 4625, 4740, 4698, 7045, 4697, 4720, 4732, 4769, 4104, 4624, 4648, 4672, 10 (Sysmon LSASS), 19 (Sysmon WMI), 22 (Sysmon DNS), plus Defender tamper, 4820…} | ✗ (Sentinel: 0) | **20+ Hayabusa rules** blocked |
| `== "CSAM Hit"` + confidence token | ✗ (CSAM Scanner emits status with subcat `"CSAM Scanner"`) | **Rules 28–29** correctly blocked (no hits) |
| `== "ML Anomaly"` + type tokens + confidence | unclear (ML Advisory emits 2 artifacts — need to parse detail) | **Rules 30–34** — see E3 |

### E3 — What ARE the two "Kill Chain Coverage" and "Sigma Threat Assessment" records

Confirmed via `sqlite3`:

```
$ sqlite3 artifacts.sqlite \
    "SELECT subcategory, title FROM artifacts
     WHERE plugin_name='Strata Sigma'"
Kill Chain Coverage       | Kill Chain Coverage
Sigma Threat Assessment   | Sigma Threat Assessment
```

Both records are metadata:
- Kill Chain Coverage lists 12 MITRE ATT&CK tactics and marks
  each `[X]` or `[ ]` based on technique mappings accumulated
  from prior artifacts' `mitre_technique` fields.
- Sigma Threat Assessment summarizes total artifacts, suspicious
  count, and tactic coverage in a single detail string.

These are **correct forensic outputs** — the kill-chain coverage
summary is exactly what an examiner reviewing a case wants at a
glance. They are NOT rule firings.

### E4 — Charlie DOES carry data that should trigger rules if predicates matched plugin output

Forensically, Charlie (2009 DEFCON CTF Windows workstation image)
has abundant correlation-worthy evidence that an examiner would
expect Sigma to flag:

- **Persistence toolkit**: 321 services + 27 Active Setup + 24
  Winlogon Persistence + 5 AutoRun + 3 BHO + 2 Shell Execute Hook
  + 2 IFEO Debugger + 2 Boot Execute = **386 persistence
  artifacts**. None of these subcategories has a dedicated Sigma
  rule; they only count inside multi-condition combinations that
  also require subcategories Phantom doesn't emit.
- **Anti-forensic activity**: 46 Timestomp Detected (Trace) — no
  Sigma rule uses this subcategory. 12 Encrypted Container
  (Vault) — no Sigma rule. 36 Hidden Storage Indicator (Phantom)
  — no Sigma rule.
- **Malware indicators**: 2,449 Suspicious PE Analysis (Vector) —
  no Sigma rule keys on this subcategory. 13 Critical Suspicious
  Script (Vector) — rule #13 checks this but pairs it with
  `"Office Trust Record"` which Charlie lacks.
- **Execution evidence**: 40 Prefetch + 40 Prefetch Executions —
  only used as a NEGATIVE predicate (Shimcache Ghost requires
  `prefetch == 0`).
- **User activity**: 143 Recent Files, 14 Browser History.

**An examiner working this image in Strata's UI sees the 3,399
raw artifacts. Sigma adds nothing about correlation because its
rules don't key on the subcategories that are actually present.**

### E5 — This is a 22-plugin × 30-rule alignment problem, not a bug

The ArtifactRecord schema is:

```rust
struct ArtifactRecord {
    plugin_name: String,
    category: String,            // stable, ~10 values
    subcategory: String,         // free-form per plugin
    title: String,
    detail: String,
    forensic_value: ForensicValue,
    mitre_technique: Option<String>,
    // ...
}
```

The `subcategory` field is **free-form per plugin**. No central
registry, no shared constants, no `#[derive(strum::EnumString)]`
discipline. Sigma's rule predicates compare against literal
strings — so if Phantom emits `"Active Setup"` and Sigma writes
`r.subcategory == "Persistence Registry Key"`, the string compare
returns false silently.

**Blast radius:**
- Sigma plugin has ~30 rules, each referencing 1–5 subcategory
  string literals → estimated 60–100 subcategory references in
  Sigma's code alone.
- 22 forensic plugins each emit 5–30 distinct subcategory
  strings → estimated 150–300 distinct emitted subcategory
  strings across the ecosystem.
- The intersection (plugin-emitted strings that Sigma actually
  checks) on the Charlie case is: `USB Device`, `Recent Files`,
  `Service`, `AutoRun`, `Prefetch`, `Suspicious Script`. **6
  strings.**

**This is the v15 Lesson 1 failure mode at the integration
layer**: each component's signatures are correct, each component
compiles, each component's unit tests pass — but the runtime
contract between them is mismatched, and the "evidence" of
correct operation is a pattern that exists in every test run
because the unconditional meta-records look like rule firings.

## Classification

| Dimension | Assessment |
|---|---|
| Wiring bug (plugin not registered, pipeline ordering, dispatch returning early) | **No.** Sigma is registered, runs last per the `prior_results` flow, receives all upstream artifacts correctly, iterates every rule. |
| Parser bug (plugin unable to parse its inputs) | **No.** Prior plugins (Phantom, Chronicle, etc.) do parse their inputs; the 2,500+ Charlie artifacts are real. |
| Evaluation-logic bug (broken rule engine) | **No.** Rule evaluation is straightforward boolean predicates over `all_records`. No short-circuit to hardcoded output. No rule engine state that could corrupt. |
| Subcategory-contract mismatch (data-shape drift between emitter and consumer) | **YES** — this is the root cause. |
| Missing rules (plugin outputs no rule keys on) | **Also yes** — persistence subcategories from Phantom have no single-predicate Sigma rule even when they're forensically real. |

## Scope estimate for the fix

Neither "one-line wiring fix" nor "rewrite the engine." It is a
**two-to-three session audit + alignment sprint**:

### Option A — Expand Sigma's rules to match emitted subcategories

1. **Session:** inventory plugin subcategory emissions. Build a
   spreadsheet / Cargo-test registry of "plugin → subcategory →
   example detail." ~300–500 entries. No code changes to
   plugins.
2. **Session:** update Sigma's rule predicates to reference the
   actual emitted strings; add 5–10 net-new rules keying on
   high-value single subcategories (persistence family,
   anti-forensic family, malware indicator family).
3. **Session:** add a Charlie/Jo regression tripwire asserting
   at least N ≥ 3 Sigma rule firings on Charlie and at least M
   ≥ 3 on Jo. Wire new rules' artifact emissions into the
   existing `artifacts.sqlite` schema (no migration needed).

**LOC estimate:** ~500 LOC Sigma changes, ~50 LOC tripwire, zero
plugin changes. Each new rule is ~15 LOC.

### Option B — Introduce a subcategory-alias registry

1. **Session:** define `SubcategoryAlias` in
   `strata-plugin-sdk::subcategory_alias` with an alias map from
   plugin-emitted strings to canonical Sigma-rule keys.
2. **Session:** Sigma rules consume aliases instead of raw
   strings. Plugin outputs unchanged.
3. **Session:** tripwire regression on Charlie/Jo.

**Pro:** plugins stay stable; the mapping is a single file.
**Con:** introduces a new abstraction that must be kept in sync;
runs the risk of hiding contract drift.

### Option C — Audit & realign plugin subcategories

Most invasive. Standardize subcategory enums across plugins per
MITRE tactic family. Requires updating every plugin's emission
code and its tests.

**Pro:** cleanest long-term.
**Con:** high-LOC, high-risk, touches 22 plugins, breaks
downstream consumers (case DB queries, report templates).

### Recommendation

**Option A.** Aligns with Strata's "Surgical Changes" principle
(touch only what must change — the consumer of subcategory
strings, not every emitter). Each new rule is independently
tripwire-testable per the v15 discipline. Blast radius limited
to Sigma's plugin crate.

## Same-session fix analysis

Per the session prompt's decision criteria:
- "If the cause is a one-line or few-line wiring fix, fix it in
  the same session."
- "If the cause requires rewriting the correlation engine's
  evaluation loop or the rule matching logic, ship the research
  doc and stop."

This is **neither extreme**. It is a 200–500 LOC alignment job
that warrants disciplined implementation with tripwires, not a
drive-by patch. A one-rule drive-by addition would:

- Make the validation report's G4 bullet look "fixed" without
  addressing the 20+ other rules that remain gated
- Risk shipping a single rule that matches too broadly
  (false positives) or too narrowly (still silent) without the
  subcategory inventory to validate against
- Not establish the tripwire regression that prevents the gap
  from re-emerging

**Decision: ship this research doc. Defer the alignment work to
a follow-up session**, ideally scheduled when the validation
corpus (Charlie/Jo + a realistic Mac image + an iOS fixture)
is fully curated so new rules can be tested end-to-end per
v15 Lesson 2.

## Recommended follow-up work

### Session-next (single sprint)

**Sprint ID:** SIGMA-SUBCATEGORY-INVENTORY
**Scope:** produce `docs/SIGMA_SUBCATEGORY_CONTRACT.md`
enumerating every plugin's emitted subcategories with example
detail strings, organized by plugin name × MITRE tactic family.
Source of truth: a diagnostic test that runs the full pipeline
against Charlie and dumps the distinct
`(plugin_name, subcategory)` tuples. ~250 LOC of test + ~3 KB
markdown doc. No production code changes.
**Acceptance:** doc committed; diagnostic test passes on Charlie
with a deterministic output snapshot.

### Session-after-next (single sprint)

**Sprint ID:** SIGMA-RULE-ALIGNMENT
**Scope:** per §Scope Option A — update Sigma rule predicates
to key on actual emitted subcategories, add 5–10 new rules
covering high-value single-subcategory categories (persistence
family, anti-forensic family, malware indicator family), and
commit a Charlie-regression tripwire asserting
`sigma_rule_firings_on_charlie >= 3`.
**Acceptance:** Charlie case produces ≥3 Sigma rule-fired
artifacts; all 18-image validation corpus re-run shows non-
trivial rule firings on evidence-rich inputs.

### Session-after-that (CLAUDE.md update)

**Sprint ID:** POST-V16-DOCUMENTATION-BATCH
**Scope:** CLAUDE.md key-numbers update + follow-up validation
report + website "Correlation Engine" section restoration per
the v16 Session 2 pattern (Opus audit debt closed with accurate
framing).

## Related v0.16.0 validation report gaps touched

- **G4** (Sigma never fires) — root-cause'd here. Recommendation
  R2 in the validation report aligns with Session-after-next
  sprint above.
- **G5** (10 plugins zero artifacts) — partially relevant.
  Sentinel's zero-on-Charlie directly gates 20+ Hayabusa rules.
  A separate Sentinel-audit session should determine whether
  adding `.evt` parsing is in scope for v17 (legacy Windows
  casework support).
- **G6** (Remnant always 1 artifact) — orthogonal, but informs
  the SIGMA-SUBCATEGORY-INVENTORY work: Remnant's single
  emission has subcategory `"Carved "` (literal, with trailing
  space) which no Sigma rule checks for. If that's intended as a
  status record, it should be emitted with a dedicated
  `subcategory = "Scan Status"` string that Sigma can skip
  explicitly.

## What this session verified (baselines, not changes)

- Strata library tests at session start: 3,836 passing.
- Strata library tests at session end: 3,836 passing (no code
  changed).
- `cargo clippy --workspace -- -D warnings`: clean.
- AST quality gate: PASS (424 / 5 / 5 library baseline
  preserved).
- Charlie/Jo regression pattern: unchanged from v0.16.0
  validation (3,399 / 3,542 total artifacts; per-plugin
  breakdowns identical).
- v15 Session 2 advisory tripwires: unchanged.
- All 4 v15 + 2 v16 APFS dispatcher arms: still route live.

---

*No code changes in this session. Fix deferred to the
SIGMA-SUBCATEGORY-INVENTORY + SIGMA-RULE-ALIGNMENT sprint pair
per §Scope estimate Option A.*

*Wolfmark Systems — post-v0.16 audit, 2026-04-20.*
