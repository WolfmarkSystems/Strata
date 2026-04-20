# Post-v16 Session A — Sigma correlator audit — COMPLETE

**Date:** 2026-04-20
**Trigger:** Validation report
`docs/FIELD_VALIDATION_REAL_IMAGES_v0.16.0.md` §5 gap G4
("Sigma correlator never fires a rule, only produces 2
audit-level artifacts per run").
**Outcome:** research doc shipped; **fix deferred** per the
session prompt's decision criteria.

## Summary

Investigated whether Sigma's failure to fire rules in the
v0.16.0 real-image validation run is a simple wiring fix or a
deeper issue. The answer is **deeper — but not rewrite-grade**.
Root cause is a systemic subcategory-string contract mismatch
between 22 plugins and ~30 Sigma rules, plus a 20+ rule
dependency on `.evtx` subcategories that Sentinel cannot emit
on Windows XP/7 (`.evt`) images like Charlie/Jo.

Sigma itself is **not broken**:
- The correlation engine iterates 30+ real rule blocks.
- Each block evaluates a boolean predicate over all
  `prior_results` artifacts.
- Failing predicates silently skip — the v15 Lesson 1
  failure mode at the integration layer.
- The "2 meta-records per run" are **two unconditional
  records** that always fire: `Kill Chain Coverage` (line 159)
  and `Sigma Threat Assessment` (line 1057).

The fix requires a 2–3 session audit + rule-alignment sprint
(inventory → realign predicates → Charlie-regression
tripwire). That is neither "one-line wiring" nor "rewrite
the engine" — it sits in the middle, and per the session
prompt's decision criteria the middle case ships research
and defers implementation.

## What was done this session

- **Grep and read** of `plugins/strata-plugin-sigma/src/lib.rs`
  (1,544 LOC) and `crates/strata-core/src/sigma/{correlation,
  rules,mod}.rs` (645 LOC) — function-body inspection per
  v15 Lesson 1, not signature-only.
- **SQL queries** against
  `test-output/validation-v0.16.0/charlie_11_12/case/artifacts.sqlite`
  to verify exactly which subcategories Charlie's prior plugins
  emitted and which Sigma rules' predicates those subcategories
  do/don't satisfy.
- **Cross-referenced every Sigma rule predicate** against
  Charlie's 3,399 artifact distribution. Found 6 plugin-emitted
  subcategories that Sigma checks (USB Device, Recent Files,
  Service, AutoRun, Prefetch, Suspicious Script+Critical) out
  of ~60 plugin-emitted subcategories present and ~60 Sigma
  predicates registered.
- **Classified** the gap:
  - Not wiring (plugin registered, runs last, receives all
    upstream artifacts correctly)
  - Not parser (upstream plugins do produce the 2,500+ Charlie
    artifacts)
  - Not evaluation logic (predicate eval is straightforward
    boolean checks)
  - **IS** subcategory-string contract drift across the
    emitter→consumer boundary
- **Wrote** `docs/RESEARCH_POST_V16_SIGMA_AUDIT.md` (detailed
  audit + scope estimate + 3 recommended follow-up sprints).
- **Committed** the research doc only.

## What was NOT done this session

- **No production code was modified.** Sigma's `lib.rs` is
  unchanged. No plugin subcategory emission was touched. No
  new rule was added.
- **No tripwire was added.** The `sigma_rule_firings_on_charlie
  >= 3` tripwire lands with the SIGMA-RULE-ALIGNMENT sprint,
  not before.
- **CLAUDE.md was not updated** — per the session prompt,
  CLAUDE.md updates land after Session C when fixes are
  consolidated.

## Gate status at session end

- **Library tests:** 3,836 passing (unchanged from v0.16.0
  baseline).
- **Clippy `-D warnings`:** clean (no code changes).
- **AST quality gate:** PASS (424 / 5 / 5 library baseline
  preserved).
- **Dispatcher arms:** all 6 (NTFS, ext, HFS+, FAT,
  APFS-single, APFS-multi) route live; verified via `cargo
  test -p strata-fs --lib fs_dispatch` as a sanity check.
- **v15 Session 2 advisory tripwires:** unchanged.
- **Charlie/Jo regression guard:** unchanged (still produces
  3,399 / 3,542 artifacts with identical per-plugin
  breakdowns).
- **9 load-bearing tests:** preserved.

## Recommended follow-up sprints

Per the research doc §Scope estimate Option A (Strata's
"Surgical Changes" principle — touch only the consumer of
subcategory strings):

1. **SIGMA-SUBCATEGORY-INVENTORY** (single session) — produce
   `docs/SIGMA_SUBCATEGORY_CONTRACT.md` enumerating every
   plugin's emitted subcategories + example detail strings;
   source of truth is a diagnostic test running the full
   pipeline against Charlie and snapshotting the distinct
   `(plugin_name, subcategory)` tuples.
2. **SIGMA-RULE-ALIGNMENT** (single session) — update Sigma
   rule predicates to key on actual emitted subcategories + add
   5–10 net-new rules covering high-value single-subcategory
   families (Windows persistence toolkit, anti-forensic
   family, malware indicators); commit a
   `sigma_rule_firings_on_charlie >= 3` tripwire.
3. **POST-V16-DOCUMENTATION-BATCH** (Session C per the
   post-v16 execution plan) — consolidated CLAUDE.md key-
   numbers update + follow-up validation report + website
   correlation-engine copy.

The SIGMA-RULE-ALIGNMENT sprint is the v17-eligible deliverable
that turns the validation report's G4 from "broken" to "shipped
with live tripwire."

## Commit

- `(this commit)` — `docs/RESEARCH_POST_V16_SIGMA_AUDIT.md` +
  `SESSION_STATE_POST_V16_SIGMA_COMPLETE.md`

No code commits this session. Per the session prompt: "If same-
session fix lands, add the commit hash to the research doc."
No fix landed → no hash to add.

---

*The correlator is not broken. It is correctly running rules
that have the wrong keys. The fix is disciplined alignment, not
a drive-by patch. Research doc + deferral is the right shape.*
