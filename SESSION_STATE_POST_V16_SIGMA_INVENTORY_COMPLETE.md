# Post-v16 Sigma Inventory Sprint — COMPLETE

**Date:** 2026-04-20
**Output:** `docs/RESEARCH_POST_V16_SIGMA_INVENTORY.md`
**Scope:** Research-only. No Strata library or plugin code
modified. Plugin emission inventory queried from Charlie + Jo
SQLite cases; Sigma rule predicate inventory inspected per
v15 Lesson 1 (function bodies, not titles).

## Headline findings

Three structural defects dominate the gap analysis. All three
must be fixed together for Windows persistence-demo readiness.

### Defect 1 — Sentinel emits one flat subcategory

Every Sentinel record carries `subcategory = "Windows Event"`
(lib.rs:303), regardless of underlying EVTX event ID. Fifteen
Sigma rules (13–27 + 30) key on `subcategory == "EVTX-<id>"`.
**None can fire today.** The event ID is already parsed and
available in `a.data.get("mitre")`; it's just not threaded
through as the record's subcategory.

### Defect 2 — Six persistence categories have no rules

Phantom emits 120 records across Charlie + Jo for the exact
Sprint 2 target set — Active Setup (54), Winlogon (48), BHO
(6), IFEO (4), Boot Execute (4), Shell Execute Hook (4). Zero
Sigma rules key on any of these strings. Rule 4 is the only
persistence-aware rule, and its predicate covers only
Service/AutoRun/BAM-DAM. The six new rules the sprint
targets don't exist yet.

### Defect 3 — Rule 7 predicate drift

`r.title.contains("1102") || r.title.contains("104")` is the
predicate for "Anti-Forensics — Log Cleared." On Charlie
post-Session-C this fires on a Recon email-address artifact
whose source contained the timestamp `200104061723@...` —
confirmed false positive documented in the Session D
amendment. The one-line fix is to change the predicate to
`r.subcategory == "EVTX-1102" || r.subcategory == "EVTX-104"`
— but that fix is gated on Defect 1 being fixed first.

## Sprint 2 scope recommendation

Hard ship list:

1. **Sentinel EVTX-typed subcategory emission** — 20 LOC in
   `SentinelPlugin::execute`. Extract event ID from
   `a.data`, format `"EVTX-<id>"`, use as record subcategory.
   This single change lights up rules 13–27, 30, and makes
   Defect 3's predicate fix possible.
2. **Six new persistence rules** — ~15 LOC each, ~90 LOC
   total. Each keys on the corresponding Phantom subcategory
   and emits a `RULE FIRED: <Category> Persistence` record
   with the appropriate MITRE technique (T1547.x for
   Active Setup/Winlogon/IFEO/Boot Execute/Shell Execute
   Hook/BHO family).
3. **Rule 7 predicate fix** — 1-LOC change to use
   subcategory equality instead of title substring.

Target tripwire: `sigma_rule_firings_on_charlie >= 8`
(six new persistence rules + two pre-existing meta records
— Kill Chain Coverage and Sigma Threat Assessment). Also
`sigma_rule_7_does_not_fire_on_recon_email_false_positive`.

Total Sprint 2 LOC: ~110 across Sentinel + Sigma plugins.

## Gap tier summary (from the inventory doc)

| Tier | Gap | Records affected | Sprint |
|---|---|---:|---|
| 1 | Sentinel flat subcategory | 0 on C/J (.evt gate) but 100 % of EVTX evidence in future | **Sprint 2** |
| 2 | 6 missing persistence rules | 120 Charlie+Jo records (54+48+6+4+4+4) | **Sprint 2** |
| 3 | Rule 7 false-positive predicate | 1 Charlie false fire documented | **Sprint 2** |
| 4 | Missing rules for LSASS Dump / Vault / Cipher / Known Malware / Browser History / ARBOR Linux Persistence | 1,800+ records | Sprint 3 |
| 5 | Rule co-occurrence gates (SAM Account / Archive Tool / Remnant "Carved ") | Gates rules 1/4/8 | Multi-session, mixed plugin+rule work |
| 6 | Rule 5 `Prefetch` vs `Prefetch Executions` | Low-impact substring drift | Audit-only |

## Other observations worth surfacing

- **Remnant emits `"Carved "` with trailing space.** Rule 1
  (USB Exfiltration) keys on `contains("Recycle") ||
  contains("USN")` — neither matches. Remnant is silent-
  mismatched; a rule-side widening OR a Remnant subcategory
  audit fixes it. Not Sprint 2; flag for a Remnant plugin
  sprint.
- **MacTrace firing on Windows images** — 2 records of
  `"Firefox Places (macOS)"` on Charlie AND Jo. Suggests
  path-pattern matching that's OS-agnostic. Flag as plugin
  hardening, out of this sprint.
- **ML Anomaly asymmetry.** Jo has 6 ML Anomaly records,
  Charlie has 0. Rules 31–35 fire on Jo; silent on Charlie.
  Correct behaviour — ML modules found Jo's timestamp
  patterns interesting and Charlie's not.
- **Vault Hidden Storage Indicator was 36 per image pre-fix
  and 180 Charlie post-fix (Session C).** The "identical 36"
  that looked like an artifact cap in R8 is dissolved by the
  extended materialize patterns. R8 is effectively closed.

## Gate status at session end

- Library tests: 3,845 (unchanged — no code modified).
- Clippy: clean (no code modified).
- AST baseline: 424/5/5 preserved.
- All 6 dispatcher arms + FileVault short-circuit: still
  live (spot-verified via
  `cargo test -p strata-fs --lib fs_dispatch`).
- Session C tripwires (24 + 84 + 7 in fs_dispatch, detect,
  vfs_materialize): all green.
- v15 Session 2 advisory tripwires: unchanged.
- Charlie/Jo regression: unchanged.
- 9 load-bearing tests: preserved.

## Artefacts

- `docs/RESEARCH_POST_V16_SIGMA_INVENTORY.md` — the inventory
  doc.
- No CLAUDE.md or website update this session — CLAUDE.md
  was last refreshed at end of Session D (test count 3,845 +
  FileVault pickup signal). Leave it where it is.

## What's next

Sprint 2 (SIGMA-RULE-ALIGNMENT) consumes this inventory and
ships the three defect fixes described in §5. Criteria for
Sprint 2 acceptance:
- `sigma_rule_firings_on_charlie >= 8` tripwire green.
- `sigma_rule_7_no_recon_email_false_positive` tripwire
  green.
- 15 EVTX-family rules continue to silently match nothing
  on C/J (because Charlie/Jo have `.evt` not `.evtx` —
  Sentinel's extension gate still excludes them). This is
  correct behaviour and must not be asserted as "EVTX rules
  fire on Charlie" — that's a `.evt` parser sprint
  question, not Sprint 2's deliverable.
- All post-fix gates preserved.

---

*Wolfmark Systems — 2026-04-20. Inventory complete, Sprint 2
unblocked.*
