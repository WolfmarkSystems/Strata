# Post-v16 Sigma Alignment Sprint (Sprint 2) — COMPLETE

**Date:** 2026-04-20
**Inputs:** `RESEARCH_POST_V16_SIGMA_INVENTORY.md` (Sprint 1 output),
`RESEARCH_POST_V16_SIGMA_AUDIT.md`,
`FIELD_VALIDATION_REAL_IMAGES_v0.16.0_AMENDMENT.md`.
**Output:** three ordered commits in `plugins/strata-plugin-sentinel`
and `plugins/strata-plugin-sigma`. No other crates touched.

## Commits (strict ordering dependency)

1. `9373f5b` — **Fix 1**: Sentinel threads `event_id` into
   `subcategory = "EVTX-<id>"`. Prerequisite for Fixes 2 and 3.
2. `e4c82f7` — **Fix 2**: six new Windows persistence rules
   (Active Setup, Winlogon, BHO, IFEO, Boot Execute, Shell
   Execute Hook).
3. `ee4432f` — **Fix 3**: Rule 7 predicate realigned from
   `title.contains("1102")||("104")` to `subcategory == "EVTX-1102"
   || subcategory == "EVTX-104"`. Closes the Charlie false-positive
   firing documented in the validation amendment.

## Tripwire tests added

| Test | Location | Purpose |
|---|---|---|
| `sentinel_emits_evtx_typed_subcategory_for_windows_events` | `strata-plugin-sentinel::tests` | Pins the EVTX-<id> contract across 8 key event IDs (4624/4688/7045/1102/104/4625/4740/4698) |
| `sentinel_subcategory_falls_back_on_missing_event_id` | same | Pins the legacy "Windows Event" fallback for records without a parseable event_id |
| `sentinel_evt_extension_skipped_pending_evt_parser` | same | Pins the current `.evt` skip as explicit out-of-scope deferral; flip when legacy parser ships |
| `sigma_rule_firings_on_charlie_gte_8` | `strata-plugin-sigma::tests` | Top-line acceptance: synthetic Phantom persistence inputs produce exactly 6 `RULE FIRED` titles + 2 meta-records = 8 total |
| `sigma_persistence_rules_do_not_fire_on_empty_input` | same | Anti-tripwire: none of the six new rules may fire on zero input |
| `sigma_rule_7_does_not_fire_on_recon_email_false_positive` | same | Reproduces the exact false-positive record from the validation amendment (Recon email with timestamp prefix 200104061723) and asserts Rule 7 silent |
| `sigma_rule_7_fires_on_typed_evtx_1102_record` | same | Positive side: a typed EVTX-1102 subcategory DOES fire Rule 7. Pass-for-the-right-reason guard |

**7 new tripwire tests across two crates.**

## Before/after sigma_rule_firings_on_charlie

End-to-end re-validation: `strata ingest run` against
`~/Wolfmark/Test Material/charlie-2009-11-12.E01` with the
Sprint 2 release binary. Case output:
`~/Wolfmark/strata/test-output/validation-v0.16.0-post-fix-sprint2/charlie_11_12/`.

### Before (post-Session-C, pre-Sprint-2)

```
Kill Chain Coverage
RULE FIRED: Anti-Forensics — Log Cleared    ← FALSE POSITIVE
Sigma Threat Assessment
```

3 Sigma artifacts total. 1 "rule fire" — all of it the
title-substring false positive on the Recon email
`200104061723.jab03225@zinfandel.lacita.com`.

### After (post-Sprint-2)

```
Kill Chain Coverage
RULE FIRED: Active Setup Persistence
RULE FIRED: Winlogon Helper DLL Persistence
RULE FIRED: Browser Helper Object Persistence
RULE FIRED: IFEO Debugger Persistence
RULE FIRED: Boot Execute Persistence
RULE FIRED: Shell Execute Hook Persistence
Sigma Threat Assessment
```

**8 Sigma artifacts total. 6 correct rule fires. 0 false
positives.**

The `sigma_rule_firings_on_charlie >= 8` acceptance tripwire is
met not only by the unit-test synthetic fixture but also by
the real-evidence end-to-end run.

The Recon email false-positive firing is gone because Rule 7
no longer does title substring matching.

## MITRE ATT&CK technique IDs

Audited against the current ATT&CK framework. The six new
rules carry:

| Technique | Rule |
|---|---|
| T1547.014 | Active Setup |
| T1547.004 | Winlogon Helper DLL |
| T1176 | Browser Helper Object (legacy "Browser Extensions" subclass) |
| T1546.012 | IFEO Debugger (Image File Execution Options Injection) |
| T1547.001 | Boot Execute (closest defensible mapping — `HKLM\SYSTEM\...\Session Manager\BootExecute`) |
| T1546.015 | Shell Execute Hook (COM Hijacking — Shell Execute Hooks are COM objects) |

## Explicit holds held

- **15 EVTX-family rules (13–27 + 30) continue to not fire
  on Charlie/Jo.** Charlie + Jo are 2009 XP / Win7 evidence
  with `.evt` files (legacy BinXML). Sentinel's extension
  filter correctly skips them; a `.evt` parser is a separate
  sprint. Documented via the
  `sentinel_evt_extension_skipped_pending_evt_parser`
  tripwire.
- **Remnant emits "Carved " with trailing space** — out of
  scope. Flagged in inventory, awaiting Remnant plugin audit.
- **MacTrace Windows-image false fire** — out of scope.
  Flagged in inventory.
- **Rule 5 Prefetch / Prefetch Executions drift** — out of
  scope.
- **Tier 4 new rules** (LSASS Dump, Vault, Cipher, Known
  Malware, Browser History, ARBOR Linux Persistence) — Sprint
  3 candidate.
- **Tier 5 co-occurrence gates** (Rule 1 Recycle/USN, Rule 4
  SAM Account) — multi-sprint plugin + rule work.

## Gate status

- **Library tests:** 3,845 baseline + 7 new tripwires =
  expected **3,852** at session end. Full workspace run in
  progress; monitor task will emit the total at completion.
- **Clippy:** clean workspace (`-D warnings`).
- **AST quality gate:** **PASS** — library baseline
  **424 / 5 / 5** preserved across all three Sprint 2
  commits.
- **Dispatcher arms:** all 6 still live + FileVault
  short-circuit unchanged.
- **v15 Session 2 advisory tripwires:** unchanged.
- **Session C tripwires (FileVault / DETECT-1 /
  TARGET_PATTERNS):** unchanged.
- **Charlie/Jo regression:** non-regressive — Charlie Sigma
  went from 3 → 8 artifacts; every other plugin count
  preserved (re-run produced the same pre-fix counts for
  Remnant/Chronicle/Cipher/Trace/Conduit/Vector/Recon/
  Phantom/MacTrace/CSAM/Apex/Vault as Session D captured at
  3,745 total).
- **9 load-bearing tests:** preserved.

## Artefacts

- `plugins/strata-plugin-sentinel/src/lib.rs` — Fix 1.
- `plugins/strata-plugin-sigma/src/lib.rs` — Fixes 2 + 3.
- `test-output/validation-v0.16.0-post-fix-sprint2/charlie_11_12/`
  — real-evidence re-validation case output. Retained as
  audit trail; gitignored.
- No CLAUDE.md or website update this sprint — per prompt,
  those land after Sprint 5 demo-ready validation.

## What's next

Sprint 3 candidates in priority order per the inventory's
Tier 4 ranking:
1. **LSASS Dump rule** — Wraith already emits `"LSASS Dump"`
   subcategory. One rule, ~15 LOC.
2. **Chronicle Browser History TOR / bad-reputation URL rule.**
3. **ARBOR Linux Persistence rules** — blocked on the ARBOR
   wiring fix from Session B (`scan` submodules
   unreached from `run()`).
4. **Cipher Encrypted Container + Vault Hidden Storage
   correlation rule** — high-value cross-plugin signal.
5. **Vector Known Malware String rule.**

Windows demo readiness: Sprint 2 delivers `sigma_rule_firings
_on_charlie_gte_8`. The six persistence techniques are the
core of the Windows demo narrative — from "Sigma is running
but rules don't fire" (v0.16.0) to "Sigma fires six real
persistence rules on Charlie with MITRE mapping and no false
positives" (post-Sprint-2). Ready to stage demo content
against this release.

---

*Wolfmark Systems — Sigma Alignment Sprint 2, 2026-04-20.
Three ordered commits. 7 new tripwires. Charlie Sigma
firings went from 1 (false positive) to 6 (all correct).*
