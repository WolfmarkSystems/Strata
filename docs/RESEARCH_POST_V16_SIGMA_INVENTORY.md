# RESEARCH_POST_V16_SIGMA_INVENTORY.md

**Prerequisite for:** SIGMA-RULE-ALIGNMENT (Sprint 2).
**Parent artifacts:** `RESEARCH_POST_V16_SIGMA_AUDIT.md`,
`FIELD_VALIDATION_REAL_IMAGES_v0.16.0_AMENDMENT.md` §5.
**Date:** 2026-04-20.
**Scope:** Research-only. No Strata library or plugin code
modified. Output is this document + a session-state summary.

Inventory of every subcategory string the 22 production
plugins **actually emit** (queried from Charlie + Jo SQLite
cases) cross-referenced against every Sigma rule predicate
(inspected from `plugins/strata-plugin-sigma/src/lib.rs`).
Produces the gap analysis Sprint 2 needs to realign rules
against observed plugin output.

## TL;DR

Three structural findings dominate the gap analysis:

1. **Sentinel emits `subcategory = "Windows Event"` on every
   record.** 20+ Sigma rules key on `subcategory ==
   "EVTX-<id>"` (e.g., `EVTX-4624`, `EVTX-4688`, `EVTX-7045`).
   **Zero match is possible.** This gates out the entire
   Hayabusa-style EVTX rule family — rules 13–27 by rule order
   in the source — on any Windows image, regardless of
   whether the underlying events were extracted. Sentinel
   *does* parse typed EVTX events internally; it just
   flattens every record to `"Windows Event"` on emission.
2. **Phantom emits 18 distinct persistence subcategories on
   Charlie, including all six the Sprint 2 target set
   requires; zero Sigma rules key on any of those six
   strings.** Rule 4 ("New Account + Persistence Installed")
   is the only persistence-aware rule, and its predicate is
   `subcategory == "Service" || subcategory == "AutoRun" ||
   subcategory == "BAM/DAM"` — no Active Setup, no Winlogon,
   no IFEO, no Boot Execute, no Shell Execute Hook, no BHO.
   120 persistence artifacts across Charlie + Jo (60 per
   image) never reach a rule predicate.
3. **Rule 7 ("Anti-Forensics — Log Cleared") has the
   false-positive contract the amendment report identified:**
   `r.title.contains("1102") || r.title.contains("104")`. On
   Charlie this fires on a Recon email-address artifact whose
   source string contains "200104061723@…". The fix is a one-
   line change to `r.subcategory == "EVTX-1102" || r.subcategory
   == "EVTX-104"` — but that fix is gated on Sentinel emitting
   EVTX-typed subcategories (finding #1), so the rule-7 bug is
   a downstream symptom of the same root cause.

**Sprint 2 scope recommendation:** six persistence rules
drafted new (one per Phantom subcategory on the target
list) PLUS Sentinel's subcategory emission fixed to emit
`"EVTX-<id>"` for every typed event (20-LOC change in
`SentinelPlugin::execute()`). The six new rules tripwire on
Charlie as `sigma_rule_firings_on_charlie >= 8` (the six
persistence rules + the two existing meta-records). The
EVTX-family rules then fire incidentally on Charlie/Jo
because typed event records suddenly match their
predicates — but the exact count depends on which event
IDs Sentinel's current parser captures; verify at merge
time, don't promise a specific count.

## §1 — Plugin emission inventory (from Charlie + Jo SQLite)

Queried: `SELECT plugin_name, subcategory, COUNT(*) FROM
artifacts GROUP BY plugin_name, subcategory`.
Sources: `test-output/validation-v0.16.0/charlie_11_12/case/
artifacts.sqlite`, `.../jo_11_16/case/artifacts.sqlite`.

Counts shown as Charlie | Jo when both emit; single number
when only one does. Zero rows where plugin produced no
artifacts in either image.

### Plugins observed emitting in validation (14 / 22)

#### Strata Phantom (Windows registry persistence)

**18 distinct subcategories, 1,120+ records across Charlie+Jo.**
Source: `plugins/strata-plugin-phantom/src/lib.rs`.

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| Service | 321 | 322 | 643 |
| Installed Program | 74 | 73 | 147 |
| **Active Setup** | **27** | **27** | **54** |
| **Winlogon Persistence** | **24** | **24** | **48** |
| Winsock LSP | 20 | 20 | 40 |
| USB Device | 14 | 12 | 26 |
| Print Monitor | 10 | 10 | 20 |
| LSA Security Package | 8 | 8 | 16 |
| Network Provider | 6 | 6 | 12 |
| AutoRun | 5 | 5 | 10 |
| Time Provider | 4 | 4 | 8 |
| **Browser Helper Object** | **3** | **3** | **6** |
| Computer Identity | 3 | 3 | 6 |
| OS Version | 2 | 2 | 4 |
| RDP State | 2 | 2 | 4 |
| Security Hive | 2 | 2 | 4 |
| LSA Authentication Package | 2 | 2 | 4 |
| **IFEO Debugger** | **2** | **2** | **4** |
| **Boot Execute** | **2** | **2** | **4** |
| **Shell Execute Hook** | **2** | **2** | **4** |
| Pending File Rename | 1 | 1 | 2 |
| Network Adapter | 1 | 1 | 2 |

**Bold = Sprint 2 target six persistence categories.** All six
are emitted consistently across both Windows images. Phantom is
the persistence-extraction workhorse; its subcategory
contract is well-defined.

#### Strata Vector (malicious file analysis)

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| Suspicious PE Analysis | 2,465 | 2,435 | 4,900 |
| Suspicious Script | 13 | 13 | 26 |
| Known Malware String | 3 | 3 | 6 |

#### Strata Chronicle (Windows user activity)

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| Recent Files | 143 | 141 | 284 |
| Browser History | 14 | 125 | 139 |
| Prefetch Executions | 40 | 54 | 94 |
| RunMRU | 0 | 1 | 1 |
| Recent Document | 0 | 1 | 1 |

#### Strata Trace (Windows execution)

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| Timestomp Detected | 46 | 46 | 92 |
| LOLBIN | 46 | 46 | 92 |
| Prefetch | 40 | 54 | 94 |
| SYSTEM Hive | 2 | 2 | 4 |

#### Strata Vault (credentials / secrets)

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| Hidden Storage Indicator | 36 | 36 | 72 |

**Note:** Identical count across images was flagged as
potentially suspicious in the original R8. Post-Session-C
Charlie jumped to 180 with extended materialize patterns —
the "36 constant" was not a cap but a stable extraction
count that the new patterns surfaced more of.

#### Strata Cipher (credentials and secrets)

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| Encrypted Container | 12 | 12 | 24 |

#### Strata Recon (IOC extraction)

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| IP Address Reference | 9 | 7 | 16 |
| Email Address Found | 2 | 2 | 4 |
| System Username | 1 | 1 | 2 |

#### Strata Conduit (network config)

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| Hosts File Entry | 1 | 1 | 2 |

#### Strata MacTrace (macOS system artifacts)

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| Firefox Places (macOS) | 1 | 1 | 2 |

*(MacTrace firing on Windows images suggests a
path-pattern-based false fire. Out of scope for this
inventory; flag for Session-G plugin hardening.)*

#### Strata Sigma (correlation)

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| Kill Chain Coverage | 1 | 1 | 2 |
| Sigma Threat Assessment | 1 | 1 | 2 |

#### Strata Remnant (deletion artifacts)

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| Carved | 1 | 1 | 2 |

**Bug observation:** subcategory is the literal string
`"Carved "` (trailing space). Rule 1's
`r.subcategory.contains("Recycle") || r.subcategory.contains("USN")`
predicate misses these because Remnant never emits
"Recycle" or "USN" substrings on Charlie/Jo despite
documentation promising those families. Separate R3
plugin audit entry, not a Sigma gap.

#### Strata CSAM Scanner

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| CSAM Scanner | 1 | 1 | 2 |

Meta-record (scanner ran), not a hit. Rules 28/29 key on
`subcategory == "CSAM Hit"` which is a distinct string —
never emitted on Charlie/Jo because no hash matches
occurred. Correct behaviour.

#### Strata Advisory Analytics (ML summary / anomaly / obstruction)

| Subcategory | Charlie | Jo | Combined |
|---|---:|---:|---:|
| ML Summary | 1 | 1 | 2 |
| ML Obstruction | 1 | 1 | 2 |
| ML Anomaly | 0 | 6 | 6 |

Rules 31–35 key on `subcategory == "ML Anomaly"`. Jo has
6, Charlie has 0 — so ML rules fire on Jo and not Charlie.
This is **correct** behaviour; not a gap.

### Plugins silent in Charlie + Jo corpus (8 / 22)

| Plugin | Expected on Win? | Observed? | Root cause (per Session B audit) |
|---|---|---|---|
| Sentinel | Yes — EVTX on Charlie/Jo is legacy `.evt` not `.evtx` | **No** | Extension filter correctly skips; no `.evt` parser exists. Docs gap R7. |
| Guardian | Possibly — Defender only post-Win8; these are 2009 images | **No** | Correct empty; path-sep bug latent. |
| Wraith | Yes — `hiberfil.sys`/`pagefile.sys` should exist | **No** | `MAX_MATERIALIZE_BYTES = 512 MB` excludes typical file sizes. |
| NetFlow | Only if web server / DNS logs present | **No** | No IIS/Apache/DNS logs in these images. |
| Nimbus | Only if cloud configs present | **No** | No OneDrive/Teams/Slack in 2009 user profiles. |
| Apex | Only if Mac content | **No** | Windows images. |
| Carbon | Only if Google apps | **No** | Windows images. |
| Pulse | Only if iOS/Android | **No** | Windows images. |
| Specter | Only if Android `.ab` | **No** | Windows images. |
| ARBOR | Only if Linux | **No** | Windows images. |

**Flag for Sigma alignment:** Sentinel silent on Charlie/Jo is
the biggest concern. Even the `.evt` parser gap isn't the
headline — the headline is that *even when Sentinel does
parse EVTX* it emits `subcategory = "Windows Event"` (see
§1.1 below), so rules keying on `"EVTX-<id>"` will still miss.

### §1.1 — Sentinel's subcategory contract (source-inspected)

`plugins/strata-plugin-sentinel/src/lib.rs:274–340`
(`SentinelPlugin::execute`). Per v15 Lesson 1 this inspection
is body-based not signature-based.

```rust
records.push(ArtifactRecord {
    category,
    subcategory: "Windows Event".to_string(),   // line 303
    timestamp: ...,
    title: a.data.get("title").cloned()...,
    detail: a.data.get("detail").cloned()...,
    mitre_technique: a.data.get("mitre").cloned(),
    ...
});
```

Every record flattens to `"Windows Event"` regardless of the
underlying event ID. The event ID is available upstream in
`a.data.get("mitre")` (MITRE technique) and presumably
somewhere in title/detail, but never surfaced as a typed
subcategory.

**Consequence:** 15 Sigma rules keyed on `EVTX-<id>` cannot
fire. Ever. The cross-reference in §3 confirms.

**Fix scope:** ~20 LOC in `execute()` — extract event ID from
`a.data`, format as `format!("EVTX-{}", id)`, use that as the
subcategory. No new parsing required; the ID is already
carried through `parse_one_evtx`.

### §1.2 — Source-declared subcategories with no Charlie/Jo observation

Plugins whose source declares subcategory strings not
observed in validation output. These are **potential
downstream rule targets** but also **potential Scenario B
dead-code indicators** per Session B's plugin audit:

- **Sentinel:** source declares only `"Windows Event"` — no
  gap at the source level; the gap is the one-string
  flattening above.
- **NetFlow:** source emits `file_type = "PCAP"`,
  `"DNS Query"`, `"IDS Alert"`, `"IIS Log"`, `"Access Log"`,
  `"Web Attack"`, `"DNS Zone"`. Only the last family
  reaches Sigma (rule 6's `subcategory == "Web Attack"`). No
  Charlie observation because no web server logs in the
  corpus. Not a bug — feature-gated.
- **Guardian:** source emits `"Defender Log"`, `"Defender
  Quarantine"`, `"Avast Log"`, `"MalwareBytes Log"`,
  `"WER Crash"`. Rule 3 covers Defender Log/Quarantine +
  Avast Log. No Charlie observation because these images
  predate Defender. Not a bug.
- **Wraith:** source emits `"Hibernation File"`,
  `"Page File Artifact"`, `"Crash Dump"`, `"Memory String"`,
  `"LSASS Dump"`, `"Suspicious Dump"`. Zero rules key on any
  of these. **Gap.** LSASS dump is forensically critical —
  a rule matching `subcategory == "LSASS Dump"` would fire
  on a detected Mimikatz artifact and it doesn't exist.
- **Nimbus:** source emits `"OneDrive Activity"`,
  `"Google Drive Activity"`, `"Dropbox Sync Event"`,
  `"Microsoft Teams Activity"`, `"Slack Activity"`,
  `"Zoom Activity"`. Rule 8 checks
  `subcategory.contains("Cloud") || subcategory.contains("OneDrive")`
  — the Cloud substring isn't in any declared file_type, and
  only OneDrive Activity matches. The others silently miss.
- **Apex:** source emits only `"EXIF Metadata"`. Source
  declares many more (Mail, Contacts, Notes) that Session B
  confirmed don't exist. No Sigma rule keys on "EXIF Metadata"
  or any Apex-emitted string.
- **Carbon:** source emits `"Chromium/Login Data"`,
  `"Chromium/Autofill"`, `"Chromium/History Download"`,
  `"Chromium/Cookies"`, etc. Rule 4's persistence predicate
  matches none; no dedicated Carbon rules exist.
- **Pulse:** source emits per-app records (iOS KnowledgeC,
  iOS DataUsage, WhatsApp iOS/Android, Signal iOS/Android,
  Telegram iOS, Snapchat). Rule 10 keys on
  `subcategory == "WhatsApp Android" || "Signal" || "Telegram"`
  — partial match possible; the Signal/Telegram strings
  drop "iOS"/"Android" suffix so only raw `"Signal"` or
  `"Telegram"` substring would fire, but Pulse's actual
  emission is `"Signal iOS"`, `"Signal Android"`, etc. **Gap.**
- **Specter:** source emits `"iOS App Usage (KnowledgeC)"`,
  `"iOS Network Usage"`, `"Android ADB Backup"`, `"Snapchat
  Data"`, `"Facebook Data (Android)"`. Zero rules key on any.
- **ARBOR:** source emits `"Linux Log Event"`, `"Linux
  Persistence"`, `"Shell History"`, `"Shell History Summary"`,
  `"Shell Init Persistence"`, `"Docker Container"`,
  `"Power Efficiency Report"`, `"qBittorrent Config"`,
  `"qBittorrent Log"`. Zero rules key on any. **Major gap:
  Linux persistence is uncovered by Sigma.**

## §2 — Sigma rule predicate inventory

Source: `plugins/strata-plugin-sigma/src/lib.rs` — 35 rules.
Ordered by source appearance (not rule ID — the source uses
"RULE FIRED:" title strings rather than numeric IDs).

Each entry: title · predicate · key fields matched.

### Rules 1–12 — Cross-plugin correlation

| # | Title | Predicate | Keys on |
|---|---|---|---|
| 1 | USB Exfiltration Sequence | `phantom_usb && chron_recent && remnant_delete` | `subcategory == "USB Device"` + `subcategory == "Recent Files"/"OpenSavePidlMRU"` + `subcategory.contains("Recycle")/"USN"` |
| 2 | Archive + Exfiltration Staging | `archive_tool && chron_recent` | `subcategory == "7-Zip"/"WinRAR"/"Rclone Config"/"MEGAsync Config"/"WinSCP Config"` + `subcategory == "Recent Files"/"OpenSavePidlMRU"` |
| 3 | AV Evasion + File Deletion | `av_detection && remnant_delete && no_quarantine` | `subcategory == "Defender Log"/"Avast Log"` + `contains "Recycle"/"USN"` + `!contains "Defender Quarantine"` |
| 4 | New Account + Persistence Installed | `new_account && persistence` | `subcategory == "SAM Account"/"Cloud Identity"` + `subcategory == "Service"/"AutoRun"/"BAM/DAM"` |
| 5 | Shimcache Ghost Executable | `shimcache > 0 && prefetch == 0` | `subcategory == "ShimCache"`, `subcategory == "Prefetch"` |
| 6 | Web Server Attack Detected | `web_attack` | `subcategory == "Web Attack"` |
| 7 | **Anti-Forensics — Log Cleared** | **`r.title.contains("1102")` \|\| `r.title.contains("104")`** | **title substring (BUG — amendment §5)** |
| 8 | Archive + Exfil Pattern (extended) | `phantom_archive && (exfil_tool \|\| phantom_usb \|\| nimbus_cloud)` | `subcategory == "Archive Tool"` + others |
| 9 | Office Macro Execution Chain | `trust_record && (bam_suspicious \|\| scheduled_task \|\| suspicious_script)` | `"Office Trust Record"` + `"BAM/DAM" is_suspicious` + `contains "Scheduled Task"` + `"Suspicious Script"` |
| 10 | Selective Wipe Pattern | `factory_reset && mobile_messaging` | `"Factory Reset"` + `"WhatsApp Android"/"Signal"/"Telegram"` |
| 11 | SRUM + Exfil Tool Co-Presence | `srum && (exfil_tool \|\| P2P Client)` | `"SRUM Database"` + exfil + `"P2P Client"` |
| 12 | Suspicious Capability Access | `capability_abuse` | `"Capability Access" && is_suspicious` |

### Rules 13–27 — EVTX-typed (all gate on Sentinel emitting EVTX-<id>)

| # | Title | Predicate (counts events with `subcategory == "EVTX-<id>"`) |
|---|---|---|
| 13 | Security Audit Log Cleared | `has_evtx(1102)` |
| 14 | System Log Cleared | `has_evtx(104)` |
| 15 | Failed Logon Burst | `count_evtx(4625) >= 10` |
| 16 | Account Lockout | `has_evtx(4740)` |
| 17 | Scheduled Task Created | `has_evtx(4698)` |
| 18 | New Service Installed | `has_evtx(7045) \|\| has_evtx(4697)` |
| 19 | Local Account Created + Group Membership | `has_evtx(4720) && has_evtx(4732)` |
| 20 | Potential Kerberoasting | `count_evtx(4769) >= 20` |
| 21 | Obfuscated PowerShell | `r.subcategory == "EVTX-4104"` + detail tokens |
| 22 | RDP Logon From External IP | `r.subcategory == "EVTX-4624"` + type 10 check |
| 23 | Explicit Credential Logon Burst | `count_evtx(4648) >= 5` |
| 24 | LSASS Process Access (Sysmon) | `r.subcategory == "EVTX-10"` |
| 25 | WMI Event Subscription (Sysmon) | `has_evtx(19) \|\| has_evtx(20) \|\| has_evtx(21)` |
| 26 | Defender RTP Disabled | `has_evtx(5001) \|\| has_evtx(5010)` |
| 27 | High-Frequency Privilege Assignment | `count_evtx(4672) >= ...` |

**Gate:** 100 % of these rules require Sentinel to emit
`subcategory == "EVTX-<id>"`. Currently Sentinel emits
`"Windows Event"`. All 15 rules silent on any Windows image
regardless of content, forever, until Sentinel's execute()
is fixed.

### Rules 28–35 — CSAM + ML + DNS

| # | Title | Predicate |
|---|---|---|
| 28 | CSAM Hash Match Detected | `subcategory == "CSAM Hit"` |
| 29 | Probable CSAM Variant Detected | `subcategory == "CSAM Hit"` perceptual |
| 30 | DNS Query to Suspicious TLD (Sysmon) | `r.subcategory == "EVTX-22"` |
| 31 | ML Temporal Anomaly Detected | `r.subcategory == "ML Anomaly"` |
| 32 | ML Stealth Execution Detected | `subcategory == "ML Anomaly"` |
| 33 | ML Timestamp Manipulation Confirmed | `subcategory == "ML Anomaly"` |
| 34 | ML Anti-Forensic Chain Detected | `subcategory == "ML Anomaly"` |
| 35 | ML Abnormal Exfiltration Pattern | `subcategory == "ML Anomaly"` |

Rules 28–29 require CSAM hits (absent from Charlie/Jo —
correctly zero). Rules 31–35 require `ML Anomaly` records
(Jo has 6; Charlie has 0 — so these fire on Jo, not
Charlie). Rule 30 requires EVTX-22 — same Sentinel gate as
rules 13–27.

## §3 — Cross-reference mapping: plugin output → rules that should fire → rules that do fire

Columns: plugin subcategory · rule(s) referencing it ·
fires on Charlie+Jo? · reason if not.

Entries ordered by "rules that should fire" coverage gap,
highest-impact first.

| Plugin | Emitted subcategory | Observed count (C+J) | Rules keying on it | Fires? | Why not |
|---|---|---:|---|---|---|
| Sentinel | *"Windows Event"* | 0 (silent; extension mismatch) | **none** (15 EVTX rules need `EVTX-<id>`) | **NO** | Flat subcategory; Sentinel also gated on `.evtx` extension which Charlie/Jo lack |
| Phantom | **Active Setup** | 54 | **none** | **NO** | No rule keys on this persistence string |
| Phantom | **Winlogon Persistence** | 48 | **none** | **NO** | No rule keys on this string |
| Phantom | Winsock LSP | 40 | none | NO | No rule |
| Phantom | USB Device | 26 | Rule 1 (USB Exfil) | partial | Needs `Recent Files` + `Recycle`/`USN` co-occurrence — on Charlie/Jo remnant emits `"Carved "` not "Recycle" |
| Phantom | Print Monitor | 20 | none | NO | No rule |
| Phantom | LSA Security Package | 16 | none | NO | No rule |
| Phantom | Network Provider | 12 | none | NO | No rule |
| Phantom | AutoRun | 10 | Rule 4 (New Account + Persistence) | gated | Needs `SAM Account`/`Cloud Identity` co-presence, neither emitted on C/J |
| Phantom | Time Provider | 8 | none | NO | No rule |
| Phantom | **Browser Helper Object** | 6 | **none** | **NO** | No rule |
| Phantom | **IFEO Debugger** | 4 | **none** | **NO** | No rule |
| Phantom | **Boot Execute** | 4 | **none** | **NO** | No rule |
| Phantom | **Shell Execute Hook** | 4 | **none** | **NO** | No rule |
| Phantom | Service | 643 | Rule 4 (persistence) | gated on SAM/Cloud Identity | same as AutoRun |
| Vector | Suspicious PE Analysis | 4,900 | none | NO | No rule |
| Vector | Suspicious Script | 26 | Rule 9 (Office Macro Chain) | gated on `Office Trust Record` (not emitted C/J) | |
| Chronicle | Recent Files | 284 | Rules 1, 2, 8 | gated on co-presence rules | |
| Chronicle | Browser History | 139 | none | NO | No rule |
| Chronicle | Prefetch Executions | 94 | Rule 5 (Shimcache Ghost) | **rule expects `"Prefetch"` not `"Prefetch Executions"`** — substring vs equality mismatch | |
| Trace | Prefetch | 94 | Rule 5 (Shimcache Ghost) | **matches** but gated on shimcache presence (`"ShimCache"` not emitted on C/J) | |
| Trace | Timestomp Detected | 92 | none | NO | No rule (flagged in Session B as v17 candidate) |
| Trace | LOLBIN | 92 | none | NO | No rule |
| Vault | Hidden Storage Indicator | 72 | none | NO | No rule |
| Cipher | Encrypted Container | 24 | none | NO | No rule |
| Recon | IP Address Reference | 16 | Rule 7 (**BUG**) | **false-positive fires** | title substring match on timestamp-prefixed email |
| Recon | Email Address Found | 4 | Rule 7 (BUG) | false-positive fires (see rule 7) | |
| Advisory | ML Anomaly | 6 | Rules 31–35 | **fires on Jo** (6 records) | correct |
| Advisory | ML Obstruction | 2 | none | NO | No rule (ML rules only check "ML Anomaly") |
| Advisory | ML Summary | 2 | none | NO | No rule |
| Conduit | Hosts File Entry | 2 | none | NO | No rule |
| Remnant | **"Carved "** (trailing space) | 2 | Rule 1 (Recycle/USN) | **NO — substring mismatch** | Rule 1 expects "Recycle"/"USN" but Remnant emits "Carved " |
| CSAM | CSAM Scanner | 2 (meta-record) | Rules 28/29 | NO (rules key on "CSAM Hit", distinct) | correct |
| MacTrace | Firefox Places (macOS) | 2 | none | NO | No rule (also a false-positive fire on Windows images — separate bug) |
| Phantom | Installed Program | 147 | none | NO | No rule |
| Phantom | Computer Identity / OS Version / RDP State / Security Hive / LSA Auth Package / Pending File Rename / Network Adapter | 2–6 each | none | NO | No rule |

## §4 — Gap analysis ranked by Charlie/Jo persistence artifact count affected

**Severity = artifact count × likelihood × forensic value.**

Ordered by persistence-artifact volume the gap gates out.

### Tier 1 — Sentinel subcategory flattening

- **Affects:** 15 EVTX-typed rules (13–27, 30), plus rule 7
  once its predicate is fixed.
- **Evidence count gated:** theoretical on Charlie/Jo because
  `.evt` vs `.evtx` is a separate gate; but on any Win8+
  evidence with proper EVTX files, flatter-than-100% of
  Hayabusa rules are silent.
- **Fix scope:** 20 LOC in `SentinelPlugin::execute` to
  extract event ID from `a.data` and format as
  `"EVTX-<id>"`.
- **Impact multiplier:** every Windows Sigma demo today
  depends on this fix.
- **Priority:** **highest**. Ship in Sprint 2.

### Tier 2 — Six persistence rules missing entirely

Phantom emits 120 records (60 per image) across Active Setup
(54), Winlogon (48), BHO (6), IFEO (4), Boot Execute (4),
Shell Execute Hook (4). Zero rules key on any of these
strings.

- **Affects:** 6 uncovered persistence categories.
- **Evidence count gated:** 120 across Charlie + Jo, 60 per
  Windows image on average.
- **Fix scope:** six new rules, each ~15 LOC in the pattern
  of existing Rule 4. Predicates:
  ```rust
  if all_records.iter().any(|r| r.subcategory == "Active Setup") { /* rule 36 */ }
  if all_records.iter().any(|r| r.subcategory == "Winlogon Persistence") { /* rule 37 */ }
  if all_records.iter().any(|r| r.subcategory == "IFEO Debugger") { /* rule 38 */ }
  if all_records.iter().any(|r| r.subcategory == "Boot Execute") { /* rule 39 */ }
  if all_records.iter().any(|r| r.subcategory == "Shell Execute Hook") { /* rule 40 */ }
  if all_records.iter().any(|r| r.subcategory == "Browser Helper Object") { /* rule 41 */ }
  ```
- **Total new LOC:** ~90 (6 rules × ~15).
- **Priority:** **highest**. Ship in Sprint 2. This IS the
  Windows demo readiness deliverable.

### Tier 3 — Rule 7 predicate bug

- **Affects:** 1 rule (Anti-Forensics — Log Cleared) with a
  demonstrable Charlie false-positive firing on a Recon
  email-address artifact.
- **Fix scope:** 1 LOC — change `r.title.contains("1102") ||
  r.title.contains("104")` to `r.subcategory == "EVTX-1102"
  || r.subcategory == "EVTX-104"`.
- **Dependency:** Tier 1 (Sentinel must emit EVTX-<id>
  first, else the fixed predicate silently never fires).
- **Priority:** **high**. Ship in Sprint 2 alongside Tier 1.

### Tier 4 — Missing rules for high-value unassigned subcategories

Plugins emit forensically-significant records that no rule
references:

- **Wraith LSASS Dump** — Mimikatz signature artifact; zero
  rules key on it.
- **Vault Hidden Storage Indicator** — 72 Charlie+Jo
  records; zero rules.
- **Vector Known Malware String** — 6 records; zero rules.
- **Vector Suspicious PE Analysis** — 4,900 records; zero
  rules (arguably too noisy to rule on, but a suspicious-
  count threshold rule is an option).
- **Cipher Encrypted Container** — 24 records; zero rules.
- **Chronicle Browser History** — 139 records; zero rules
  (TOR/bad-reputation URL detection would be a natural rule).
- **ARBOR Linux Persistence / Shell Init Persistence /
  Docker Container** — zero rules (would fire on Chromebook
  and Linux evidence if ARBOR's submodules get wired per
  Session B).

- **Priority:** **medium**. Sprint 3 candidate.

### Tier 5 — Co-occurrence gates that never co-occur on real images

- **Rule 4 (New Account + Persistence):** needs `SAM Account`
  or `Cloud Identity` record plus Service/AutoRun. Phantom
  emits Services at scale (643 on Charlie+Jo), but no SAM
  Account / Cloud Identity records appear. Likely Phantom
  parser coverage gap — should emit `SAM Account`
  subcategory when a new account appears in SAM hive.
- **Rule 1 (USB Exfiltration):** needs USB Device + Recent
  Files + (Recycle || USN). Remnant emits `"Carved "` not
  Recycle/USN substrings on C/J — so USB Exfil silent even
  though all three evidence types are likely present.
- **Rule 8 (Archive Pattern):** needs `Archive Tool` + others.
  No plugin emits `Archive Tool` subcategory.

- **Priority:** **medium**. Mostly plugin-side fixes, out of
  Sprint 2 scope.

### Tier 6 — Rule 5 substring mismatch

- **Rule 5 (Shimcache Ghost Executable):** predicate is
  `subcategory == "Prefetch"`. Trace emits `"Prefetch"` (94
  C+J). But Chronicle emits `"Prefetch Executions"` (94
  C+J). Rule only sees Trace output, not Chronicle.
- **Priority:** low. Arguably correct (Trace is the
  prefetch-data-extraction source). Flag for review in
  Sprint 3.

## §5 — Sprint 2 scope recommendations

**In-scope for Sprint 2 (Sigma rule alignment):**

1. **Sentinel subcategory fix** — emit `EVTX-<id>` instead
   of flat `"Windows Event"`. ~20 LOC in `execute()`. Hard
   dependency for the EVTX-family rules.
2. **Six new persistence rules** — one per Phantom
   subcategory: Active Setup, Winlogon, IFEO, Boot Execute,
   Shell Execute Hook, Browser Helper Object. ~90 LOC
   total. Each rule emits a `RULE FIRED:` record with the
   appropriate MITRE technique.
3. **Rule 7 predicate fix** — change from
   `title.contains("1102")||("104")` to
   `subcategory == "EVTX-1102" || "EVTX-104"`. 1-LOC change.
   Eliminates the Charlie email-address false positive.

**Tripwire test targets:**
- `sigma_rule_firings_on_charlie >= 8` (the six new
  persistence rules + the two existing meta-records on
  Charlie/Jo).
- `sigma_rule_firings_on_charlie_does_not_include_log_cleared_false_positive`
  — Charlie's Recon email must NOT cause rule 7 to fire.
- Existing `rule_28_does_not_fire_with_no_csam_hits` and
  related CSAM tests must still pass.

**Deferred (out of Sprint 2 scope):**
- Tier 4 — new rules for Wraith/Vault/Vector/Cipher/
  Chronicle/ARBOR categories. ~Sprint 3.
- Tier 5 — co-occurrence gate failures. Partly plugin-side
  fixes (Phantom SAM Account emission, Remnant subcategory
  alignment). Partly rule-side widening. Multi-session scope.
- Tier 6 — Rule 5 substring mismatch. Low-priority audit.
- Sentinel `.evt` legacy parser. Separate session.

**Non-negotiables for Sprint 2:**
- All 3,845 pre-sprint tests must still pass.
- AST baseline 424/5/5 preserved.
- All 6 dispatcher arms + FileVault short-circuit still
  live.
- No plugin other than Sentinel touched (and Sentinel only
  in its emission-subcategory logic — not its EVTX parser).
- The six persistence rules fire on Charlie post-alignment;
  the Tripwire test assertion is the concrete ship criterion.

## §6 — Document provenance + validation notes

- Plugin emissions queried live from:
  - `test-output/validation-v0.16.0/charlie_11_12/case/artifacts.sqlite`
    (3,399 artifacts, v0.16.0 baseline)
  - `test-output/validation-v0.16.0/jo_11_16/case/artifacts.sqlite`
    (3,483 artifacts, v0.16.0 baseline)
- Rule predicates inspected from
  `plugins/strata-plugin-sigma/src/lib.rs` via grep +
  body-read per v15 Lesson 1.
- No synth subcategory strings introduced. The observed list
  is authoritative for "what plugins emit in production today."
- Source-declared-but-unobserved subcategories flagged
  separately (§1.2) as Scenario B candidates for follow-up,
  not mistaken for emissions.

---

*Wolfmark Systems — post-v0.16 Sigma Inventory Sprint,
2026-04-20. No code modified. Output: this doc +
SESSION_STATE.*
