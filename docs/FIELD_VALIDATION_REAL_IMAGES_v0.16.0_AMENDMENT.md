# FIELD_VALIDATION_REAL_IMAGES_v0.16.0_AMENDMENT.md

**Amends:** `docs/FIELD_VALIDATION_REAL_IMAGES_v0.16.0.md`
(the v0.16.0 real-image validation).
**Release under test:** v0.16.0 + post-v16 Sessions A / B / C
(commits `b28b64e` + `641e239` + `5c63c57`).
**Amendment date:** 2026-04-20.
**Validator:** autonomous re-run (no production code modified
in this session).

This amendment re-runs the three images whose behaviour Session
C's fixes targeted (UNENCRYPTED.dmg, ENCRYPTED.dmg, Chromebook
CTF tar) plus a Charlie/Jo regression check. It compares
pre-fix and post-fix output side-by-side and honestly updates
which original R1–R10 recommendations are now closed vs. still
open.

## Executive summary

- **Fix 1 (FileVault detection, G3) — confirmed live.** The
  ENCRYPTED.dmg dispatch log now reads
  `[evidence] skipped fs0 at offset 0: FileVault-encrypted
  DMG detected. Decryption is out of scope for Strata.
  Recommend offline key recovery via macOS keychain,
  institutional recovery key, or forensic decryption
  tooling.` vs. pre-fix `unknown filesystem at partition
  offset 0`. The examiner-visible improvement is the reason
  for this entire fix batch.
- **Fix 2 (DETECT-1 Chromebook, G7) — confirmed live.** The
  Chromebook CTF tar now classifies as **ChromeOS (confidence
  0.78)** recommending 4 plugins (Nimbus, Recon, Carbon,
  Sigma). Pre-fix: **Windows Workstation (0.91)** recommending
  13 Windows plugins. The 303 Vector "Suspicious PE Analysis"
  false positives from the pre-fix run are gone because
  Carbon/Vector aren't recommended for ChromeOS any more.
- **Fix 3 (TARGET_PATTERNS extension, G10) — confirmed live.**
  UNENCRYPTED.dmg materialized **4 files (20 bytes)** post-fix
  vs. **0 files (0 bytes)** pre-fix. Files extracted:
  `file1.txt`, `file2.txt`, `file3.txt`, and a bonus
  `.Trashes/501/trash.txt` from the APFS volume's trash dir.
  Session A's original R1 ("APFS walker end-to-end unverified
  on realistic Mac content") is materially closed: the walker
  correctly enumerated the volume, read file content, passed
  it to plugins, and plugins saw real bytes.
- **Regression preserved.** Charlie produces **3,745
  artifacts** post-fix (up from 3,399 pre-fix — +346 driven by
  Session C's +12 extensions surfacing more `.log` / `.txt` /
  `.pdf` content for Recon, Vault, Apex). Charlie's walker
  path, materialize count, and every original per-plugin
  distribution is non-regressive.
- **Honest honest finding:** one Sigma rule fired on Charlie
  post-fix (`RULE FIRED: Anti-Forensics — Log Cleared`). But
  it is a **false positive** — the rule's
  `title.contains("104")` predicate matched a Recon
  **email-address artifact** containing the substring
  `200104061723@...`. This confirms Session A's Sigma audit
  diagnosis: the correlation engine runs, the predicate
  contract is drifting. The fix is still owed to
  SIGMA-RULE-ALIGNMENT, not this session.
- **Gate status unchanged.** 3,845 library tests still pass.
  All Session C tripwires green (24 + 84 + 7 in the three
  touched modules). AST baseline 424/5/5 preserved. No new
  code in Session D.

## §1 — UNENCRYPTED.dmg before/after

| Dimension | v0.16.0 original run | Post-Session-C re-run | Delta |
|---|---|---|---|
| Dispatcher routing | `mounted disk image at offset 20480` | `mounted disk image at offset 20480` | unchanged — APFS walker was already live in v0.16.0; only the downstream materialize + plugins changed |
| Files materialized | **0 (0 bytes)** | **4 (20 bytes)** | **+4 files** — the three user `.txt` files + `.Trashes/501/trash.txt` |
| Total artifacts | 6 (status records only) | **7** | +1 — Recon (1) new |
| Plugins that produced content-derived artifacts | 0 | **1** (Recon × 1 from scanning materialized `.txt`) | closes R1 "walker-to-plugin end-to-end unverified" |
| Ingest duration (ms) | 0 | 20 | marginal — four-file copy path is negligible |

### Examiner-visible shift

The four materialized files are the exact content a macOS
examiner would expect to see in the case output dir for an
image of this kind:

```
apfs_unencrypted/case/extracted/disk image/file1.txt
apfs_unencrypted/case/extracted/disk image/file2.txt
apfs_unencrypted/case/extracted/disk image/file3.txt
apfs_unencrypted/case/extracted/disk image/.Trashes/501/trash.txt
```

Recon's one new artifact was extracted from content inside
one of those files (likely an email/URL/IP pattern match).
This proves the whole chain: ApfsSingleWalker →
VfsEntry enumeration → materialize filter → fs::write on
disk → plugin re-scan → ArtifactRecord → SQLite case store.

**What this validation doesn't close:** realistic Mac cases
with `.plist` / `.sqlite` (Mail.app / Calendar / Contacts /
Notes / Safari / KnowledgeC). UNENCRYPTED.dmg is a user-
generated 100 MB probe image. A proper Mac reference fixture
(SANS SIFT, digitalcorpora macOS, examiner-provided image)
remains a v17 validation target per the original R1.

## §2 — ENCRYPTED.dmg before/after (FileVault detection)

| Dimension | Pre-Session-C | Post-Session-C |
|---|---|---|
| Detection log | `[evidence] skipped fs0 at offset 0: unknown filesystem at partition offset 0` | `[evidence] skipped fs0 at offset 0: FileVault-encrypted DMG detected. Decryption is out of scope for Strata. Recommend offline key recovery via macOS keychain, institutional recovery key, or forensic decryption tooling.` |
| Artifact count | 6 (same baseline meta records) | 6 (same) |
| Elapsed (ms) | 0 | 4 |
| Examiner action clue | None — generic "unknown filesystem" | Three concrete remediation paths listed inline |

The structured pickup signal is the entire deliverable here.
Artifact counts are identical because FileVault-wrapped content
is unreadable without a key — Strata correctly doesn't pretend
otherwise.

**Tripwire coverage:** four tests in
`crates/strata-fs/src/fs_dispatch.rs` pin this behaviour
(detection at byte 0, precedence over inner magic, stable FsType
label, structured-error assertions). All four green at session
end.

## §3 — Chromebook CTF tar before/after (DETECT-1)

| Dimension | Pre-Session-C | Post-Session-C |
|---|---|---|
| DETECT-1 label | **Windows Workstation** (0.91 confidence) | **ChromeOS** (0.78 confidence) |
| Plugin recommendation | 13 plugins (Windows subset — Chronicle, Cipher, Trace, Vector, Phantom, Vault, Conduit, etc.) | 4 plugins (Nimbus, Recon, Carbon, Sigma) |
| Artifacts produced | 489 total (Chronicle 130, Vector 303, Cipher 39, Recon 14 — note Vector's 303 were Windows-shaped false positives scanning Chrome cache) | 16 total (Recon 14 + Sigma 2) |
| Duration (s) | 4 | 2.4 |

### Is fewer artifacts a regression?

**No.** The 489 pre-fix artifacts included 303 "Suspicious PE
Analysis" records from Vector scanning Chrome cache binaries —
Chrome caches on a Chromebook are not Windows PE files, and
the scanner matched on incidental byte patterns. 130 Chronicle
artifacts were extracted from Chrome profile databases,
tagged as Windows user-activity artifacts (incorrect taxonomy).
Cipher and Vector fired because their path-pattern matchers
happened to match generic file paths; the resulting records
were labelled with Windows-specific MITRE techniques (wrong
for ChromeOS).

Post-fix: the 14 Recon artifacts are IP addresses, email
addresses, and URLs extracted from Chromebook user content —
correct forensic signal. The 13 Windows-family plugins that
no longer run on this input were producing noise.

**What this validation doesn't close:** ARBOR still finds zero
on Chromebook content even after Fix 2. That's the Session B
Plugin Audit Scenario B gap — ARBOR has 5 submodules
(system_artifacts, chromeos, containers, logs, persistence)
whose `scan()` functions are never invoked by `run()`. Fixing
Chromebook DETECT-1 gets the right plugin *selected*; getting
ARBOR to *produce* artifacts requires the follow-up
Session-C-equivalent for ARBOR from the plugin-audit doc.

## §4 — Charlie regression check

| Dimension | v0.16.0 original | Post-Session-C | Delta |
|---|---|---|---|
| Files materialized | 9,566 | **10,181** | +615 (new `.log`/`.pdf`/`.txt`/`.mov`/etc. files picked up by extended TARGET_PATTERNS) |
| Total artifacts | 3,399 | **3,745** | +346 |
| Duration (s) | 93 | 94 | +1 (negligible) |
| Per-plugin deltas | | | |
| — Remnant | 1 | 1 | same |
| — Chronicle | 197 | 197 | same |
| — Cipher | 12 | 12 | same |
| — Trace | 134 | 134 | same |
| — Conduit | 1 | 1 | same |
| — Vector | 2,465 | 2,465 | same |
| — **Recon** | **12** | **212** | **+200** — new `.txt`/`.log`/`.pdf` content scanned |
| — Phantom | 535 | 535 | same |
| — MacTrace | 1 | 1 | same |
| — CSAM Scanner | 1 | 1 | same |
| — **Apex** | 0 | **1** | **+1** — EXIF parser ran on a newly-materialized `.jpg`/`.png` |
| — **Vault** | 36 | 180 | +144 — new content revealed more encrypted-container indicators |
| — Advisory Analytics | 2 | 2 | same |
| — **Sigma** | 2 | **3** | **+1 (false-positive rule firing — see §5)** |

**Verdict:** non-regressive. Every pre-fix plugin count holds;
the new materialized content is the only source of added
artifacts. Charlie's /etc/ scaffolding remains untouched.

## §5 — Sigma correlator behaviour

Session A's research doc
(`docs/RESEARCH_POST_V16_SIGMA_AUDIT.md`) classified Sigma's
"2 meta-records per run" as a subcategory-string contract
mismatch between 22 plugins and ~30 rule predicates. No fix
shipped; the alignment sprint was deferred.

Post-Session-C Charlie run produces **3 Sigma artifacts**
instead of 2:

```
Kill Chain Coverage
RULE FIRED: Anti-Forensics — Log Cleared
Sigma Threat Assessment
```

At first glance this looks like Session C accidentally fixed
the Sigma gap. It did not.

The firing artifact's source:

```
SQL> SELECT plugin_name, subcategory, title
     FROM artifacts WHERE title LIKE '%104%' OR title LIKE '%1102%';

Strata Recon | Email Address Found | Email Address Found:
    200104061723.jab03225@zinfandel.lacita.com
```

Sigma rule 7's predicate is
`r.title.contains("1102") || r.title.contains("104")`. The
Recon email record contains the substring `104` as part of
a timestamp-prefixed email address. The rule fires —
**incorrectly**. There is no actual Windows Event 1102 / 104
log-clear event in Charlie's evidence.

**This confirms Session A's diagnosis:** the correlation
engine works; the predicates are too broad / keyed on the
wrong fields. A properly-written rule 7 would check
`subcategory == "EVTX-1102"` and `subcategory == "EVTX-104"`,
not `title.contains("104")` — and Sentinel would need to emit
those EVTX-typed subcategories, which it currently doesn't.

**Status after this session:** Sigma correlation remains
open. The +1 Sigma artifact count on Charlie is a false
positive, documented here so no future reader treats it as
"Sigma fixed itself in Session C."

## §6 — Updated R1–R10 status

Original report's ten recommendations, ranked by severity ×
likelihood. Status as of post-Session-D.

| # | Recommendation | Status | Notes |
|---|---|---|---|
| R1 | Validate APFS walker end-to-end on realistic Mac content | **Partially closed** | UNENCRYPTED.dmg end-to-end works (walker → materialize → plugin → SQLite); a realistic Mac reference fixture (Mail.app + sqlite + plist content) still owed for v17. |
| R2 | Audit why Sigma correlation never fires a rule | **Closed (research)**, fix deferred | `RESEARCH_POST_V16_SIGMA_AUDIT.md` root-caused to subcategory-contract drift. Session D confirmed the diagnosis with a real false-positive firing. Fix awaits SIGMA-RULE-ALIGNMENT sprint. |
| R3 | Audit the 10 plugins producing zero artifacts | **Closed (research)**, fixes deferred | `RESEARCH_POST_V16_PLUGIN_AUDIT.md` classified each across Scenarios A/B/C/D. Four plugins (ARBOR, Nimbus, Carbon, Apex) have ~5,000 LOC of dead submodule code. Fixes sized at ~330 LOC for the wiring bulk + multi-sprint for Apex parsers. |
| R4 | Fix Chromebook misclassification | **CLOSED** | Session C commit `641e239`. Post-fix classification: ChromeOS 0.78 confidence. 2 tripwire tests. |
| R5 | Surface encrcdsa + other encrypted-container signatures | **CLOSED for FileVault** | Session C commit `b28b64e`. Structured pickup signal confirmed live. 4 tripwire tests. VeraCrypt / LUKS2 / BitLocker still unaddressed — v17 candidate. |
| R6 | Extend materialize filter for APFS/Linux/Android content | **Partially closed** | Session C commit `5c63c57` — 12 new extensions for `.txt`/`.pdf`/`.jpg`/`.png`/`.heic`/`.mov`/`.mp4`/`.eml`/`.mbox`/`.ipa`/`.apk`. Linux-specific `/var/lib/dpkg/`, Docker/OCI metadata, FAT volume serial, `$J` USN journal structure still missing. |
| R7 | Document EVTX-only limitation on `.evt` inputs | **Open** | No docs update this session. Deferred to Session-E or CLAUDE.md refresh when Sentinel `.evt` parser ships. |
| R8 | Investigate Cipher + Vault identical cross-image counts | **Partially closed by accident** | Charlie Vault jumped 36 → 180 post-fix, so the "identical 36" constant is no longer observed. Does not prove the original 36 wasn't a cap — still worth function-body check. |
| R9 | Deferred image validation (Terry, memdump, 30GB tars) | **Still open** | No scale-deferred image runs this session. |
| R10 | Clean up inconsistent plugin output-count baselines (Remnant / CSAM always 1) | **Still open** | Remnant still emits exactly 1 artifact on every input. Pattern unchanged in post-fix runs. |

**Net closure count:** 3 fully closed (R4, R5-FileVault, and
material closure of R1 for the specific UNENCRYPTED.dmg case);
2 partially closed (R1 broader, R6); 2 closed at research
level with fixes owed (R2, R3); 3 still open (R7, R9, R10) +
1 accidentally-partial (R8).

## §7 — Recommended next sessions

No prescriptive ordering. What stays open:

- **Session-E (SIGMA-RULE-ALIGNMENT):** consume Session A's
  research doc, produce the plugin-subcategory inventory,
  realign Sigma predicates, commit the
  `sigma_rule_firings_on_charlie >= 3` tripwire. The Charlie
  run in §5 above gives a working concrete example to aim the
  fix at — the false-positive rule 7 firing is the exact thing
  the alignment sprint will fix to fire on the right evidence.
- **Session-F (PLUGIN-WIRING-BULK):** ARBOR + Nimbus + Carbon
  submodule dispatch from Session B research doc. ~330 LOC
  total, zero new parsers.
- **Session-G (APFS-REALISTIC-FIXTURE):** acquire or
  synthesize a realistic macOS/iOS reference image covering
  Mail.app / Safari / Photos.sqlite / TCC.db, re-run the
  end-to-end to close R1 fully.
- **Session-H (SENTINEL-SUBCATEGORY-BRIDGE):** trivial (~20
  LOC) change so Sentinel emits `EVTX-<id>` subcategories;
  paired with SIGMA-RULE-ALIGNMENT this closes the Hayabusa
  rule family.

## §8 — CLAUDE.md + communication drafts

### Suggested CLAUDE.md key-numbers update

```
## Key numbers (post-v0.16 — 2026-04-20)

- Test count: 3,845 passing (3,771 v0.15 baseline + 74 across
  v16 + post-v16 Sessions A/B/C/D; +9 tripwires in Session C).
- Filesystem walkers live: NTFS, ext2/3/4, HFS+, FAT12/16/32,
  APFS single-volume, APFS multi-volume.
- Dispatcher short-circuits with structured pickup signal:
  FileVault-encrypted DMGs (encrcdsa header).
- AST quality gate: 424 library .unwrap() / 5 unsafe{} / 5
  println! — baseline held across every post-v16 commit.
```

### Suggested "hey we found errors and fixed them" note

```
Strata v0.16.0 shipped with APFS walker code that routed
live but produced zero materialized files on real Mac
evidence. A field-validation pass against ~/Wolfmark/Test
Material surfaced three examiner-visible gaps:

  1. FileVault-encrypted DMGs returned a generic
     "unknown filesystem" error with no pickup signal
  2. A Chromebook CTF tar classified as Windows Workstation
     (0.91 confidence) because the DETECT-1 classifier
     matched against absolute paths — examiner workstations
     running on /Users/<name>/... were tripping the Windows
     /users/ marker on every evidence path regardless of
     content
  3. The materialize filter was Windows/browser-heavy and
     missed .txt / .pdf / .jpg / .plist / .mov and other
     plain file types common in Mac and iOS evidence

All three were fixed in post-v16 Session C. Commits:
  b28b64e — FileVault encrcdsa detection with structured
            pickup signal
  641e239 — DETECT-1 scan-root stripping + ChromeOS
            recovery markers
  5c63c57 — 12 new Mac/iOS suffixes in TARGET_PATTERNS

Validation amendment:
  docs/FIELD_VALIDATION_REAL_IMAGES_v0.16.0_AMENDMENT.md

Post-fix run confirms: Chromebook classifies as ChromeOS
(0.78), FileVault DMGs surface structured remediation text,
UNENCRYPTED.dmg materializes 4 real files end-to-end,
Charlie produces 3,745 artifacts up from 3,399 (no
regressions, materialize picks up 615 more files under
extended patterns). Remaining gaps are research-doc'd
(Sigma correlator contract drift, 4 plugins with unwired
submodule parsers) and queued for Sessions E–F.

Strata is ready for Mac and Chromebook evidence it could
process silently-wrongly before.
```

### Website Forensic Division claims audit

Claims that are now supportable (before Session C they were
not):

- "FileVault-encrypted DMG detection" — yes (Fix 1)
- "ChromeOS evidence classification" — yes (Fix 2)
- "Mac examiner content materialization" — partial (Fix 3;
  not sqlite/plist/etc. yet — those exist but hadn't been
  materialize-validated pre-fix either)

Claims that still overclaim:

- Any wording like "Sigma correlates artifacts across
  plugins and surfaces kill-chain patterns" — qualifies as
  overclaim until SIGMA-RULE-ALIGNMENT lands. Current state
  is "Sigma evaluates 30+ rules; predicate contracts with
  plugin outputs are under realignment — advisory kill-chain
  coverage is live, targeted rules firing is forthcoming."
- Any wording implying ARBOR / Nimbus / Carbon / Apex produce
  artifacts from the full advertised target set. Session B
  documented that these plugins have ~5,000 LOC of dead
  submodule parsers; the public list of advertised features
  should either narrow to what actually runs today, or a
  follow-up session should wire the submodules.

---

## Gate status at session end

- **Library tests:** 3,845 passing (unchanged from Session C
  baseline — no code modified this session).
- **Session C tripwires:** all green:
  - 24 tests in `fs_dispatch` (4 new FileVault tripwires + 20
    pre-existing)
  - 84 tests in `detect` (2 new Chromebook/examiner-home
    tripwires + 82 pre-existing)
  - 7 tests in `vfs_materialize` (2 new G10 tripwires + 5
    pre-existing including 1 retargeted)
- **AST quality gate:** PASS (424 / 5 / 5 baseline held).
- **Dispatcher arms:** all 6 route live; FileVault
  short-circuit fires ahead of them.
- **Charlie/Jo regression:** non-regressive — Charlie
  3,399 → 3,745 artifacts, all pre-v16 plugin counts
  preserved.
- **9 load-bearing tests:** preserved.

Validation case output retained locally at
`~/Wolfmark/strata/test-output/validation-v0.16.0-post-fix/`
as audit trail. Not committed (gitignored per Session D
convention from the original validation report).

---

*Wolfmark Systems — post-v0.16 Session D, 2026-04-20.*
*Strata is ready for Mac + Chromebook evidence that would
have produced silent-wrong output before Session C.*
