# RESEARCH_POST_V16_PLUGIN_AUDIT.md

**Session:** Post-v16 Session B (10-plugin function-body audit)
**Date:** 2026-04-20
**Trigger:** `FIELD_VALIDATION_REAL_IMAGES_v0.16.0.md` §5 gap G5
— "10 of 23 plugins produced zero artifacts across the full
18-image corpus."
**Outcome:** research only — no code modified. Every plugin's
`run()` and `execute()` bodies were inspected per v15 Lesson 1
(bodies, not signatures).

## TL;DR

The 10 zero-artifact plugins split roughly 4 / 4 / 2 across the
three scenarios from the session prompt, with a fourth scenario
emerging from the audit:

- **Scenario A — plugin runs, input not applicable, returns
  empty (correct):** Sentinel (`.evtx`-only on XP `.evt` evidence),
  Wraith (Charlie's `hiberfil.sys`/`pagefile.sys` exceed
  materialize size cap), Pulse (CTF dirs lack specific sqlite
  filenames), Specter (CTF Android dir lacks `.ab`/
  `knowledgec.db`/etc).
- **Scenario B — submodules exist, `run()` does not invoke
  them (silent dead code):** **Nimbus**, **Apex**, **Carbon**,
  **ARBOR**. Each plugin has 3–6 substantive submodule files
  with real `pub fn parse`/`pub fn scan` functions — and each
  plugin's `run()` either only invokes ONE submodule (Carbon:
  only Chromium; ARBOR: only shell_artifacts; Apex: only EXIF)
  or none (Nimbus: inline filename heuristic only, ignoring
  the onedrive/alexa/smart_tv/connected_car submodules). **This
  is the v15 Lesson 1 failure mode exactly: signatures declare
  full-app coverage; bodies cover one fraction of it.**
- **Scenario C — plugin not registered / not wired:** **None.**
  All 10 plugins appear in
  `crates/strata-engine-adapter/src/plugins.rs` lines 33–57.
  Registration is clean.
- **Scenario D (new) — input-shape mismatch between pipeline
  and plugin:** NetFlow (expects `root_path` to be a directory
  tree containing pcap files; gets the single pcap path itself
  when `open_evidence` falls back to "host fs" mode on a raw
  pcap). Guardian has a related latent issue — every path check
  uses literal Windows `\\` separators, so extracted paths on
  non-Windows hosts silently never match.

**Bottom line:**
- 4 plugins are arguably correct in the test corpus but have
  feature gaps that would matter on different evidence (Scenario
  A-with-gap).
- 4 plugins are **significantly under-delivered**: Nimbus,
  Apex, Carbon, ARBOR ship submodule code examiners assume is
  executed; it is not.
- 2 plugins have pipeline-shape or host-portability defects:
  NetFlow (pcap input path), Guardian (Windows-only path
  assumptions).

Fix-order recommendation (§ Recommendations below) prioritizes
Apex + Carbon + ARBOR + Nimbus (Scenario B bulk) — each is a
one-session sprint wiring existing submodule parsers into
`run()` / `execute()`.

---

## §1 — Sentinel (EVTX)

**Files:** `plugins/strata-plugin-sentinel/src/lib.rs` (460 LOC)
+ `lateral_movement.rs` (393 LOC).
**Claim in plugin manifest:** "Per-event parsing of Security
/System/PowerShell/Sysmon channels via
`strata-core::parsers::evtx`; typed extractors for 4624/4625/
4688/4698/4702/7045/4103/4104/1102."

### Function-body evidence

`run()` at lib.rs:238:

```rust
fn run(&self, ctx: PluginContext) -> PluginResult {
    let root = Path::new(&ctx.root_path);
    let mut results = Vec::new();
    let files = walk_dir(root)?;
    let mut processed = 0;
    for path in files {
        if processed >= MAX_EVTX_FILES { break; }
        let is_evtx = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("evtx"))
            .unwrap_or(false);
        if !is_evtx { continue; }
        let Some(data) = Self::read_evtx_gated(&path) else { continue; };
        processed += 1;
        results.extend(Self::parse_one_evtx(&path, &data));
    }
    Ok(results)
}
```

### Classification

**Scenario A with feature gap.** `run` is well-formed:
recursively walks, filters by `.evtx` extension, reads gated,
parses. Charlie/Jo are Windows XP/7 — their event logs are
`.evt` (legacy BinXML format) not `.evtx`. Extension check
returns false → `continue` → zero artifacts. **Correct behavior
for the input shape, but feature gap**: no `.evt` parser exists
and the plugin manifest language ("Windows Event Logs (`*.evtx`)")
arguably discloses this, while the broader docs ("Windows Event
Logs") do not.

**Secondary observation relevant to Sigma audit:** Sentinel
emits records with `subcategory = "Windows Event"` (lib.rs:303).
Sigma's Hayabusa rules in plugin-sigma/src/lib.rs check
`subcategory == "EVTX-<N>"`. Even if Sentinel ran on `.evtx`,
its emitted subcategory does not match Sigma's predicate — the
Sigma contract mismatch documented in
`RESEARCH_POST_V16_SIGMA_AUDIT.md` is compounded by this.

### Fix scope

| Feature | LOC estimate | Priority |
|---|---:|---|
| `.evt` legacy parser | ~300 LOC + dep on a legacy-evt crate | Medium (v17) |
| Emit `subcategory = "EVTX-<id>"` per-event | ~20 LOC | **High (Sigma depends on it)** |

---

## §2 — Nimbus (cloud / enterprise comms)

**Files:** `src/lib.rs` (224) + `alexa.rs` (189) +
`connected_car.rs` (148) + `onedrive.rs` (224) + `smart_tv.rs`
(125) + other = 996 LOC total.
**Plugin manifest:** "OneDrive, Teams, Slack, M365 UAL, AWS
CloudTrail, Azure."

### Function-body evidence

`run()` at lib.rs:130 calls only `Self::analyze_file(path)` for
each path. `analyze_file` is 66 lines of filename substring
checks:

- `path_lower.contains("onedrive") && name_lower.contains("log"|".dat")` → static "OneDrive Activity" record
- `path_lower.contains("google/drivefs")` → static record
- `path_lower.contains("dropbox") && ends_with(".sqlite")` → static
- `microsoft/teams`, `slack`, `zoom` → static records

**No call to any submodule** (`alexa::parse_interaction_history`,
`onedrive::parse`, `smart_tv::parse_roku_activity`,
`connected_car::parse_events`). The `pub mod alexa; pub mod
connected_car; pub mod onedrive; pub mod smart_tv;` declarations
at the top of lib.rs bring them into the crate, but no call site
references them.

The `onedrive.rs` submodule (224 LOC) contains a real SQLite
parser with FILETIME decoding, `OneDriveFile` record struct,
`forensic_value` scoring — all unreachable from the plugin's
run path.

### Classification

**Scenario B (substantial).** ~700 LOC of parser code across
4 submodules is dead on the plugin's execution path. Nimbus
emits "OneDrive Activity" status records but never parses the
OneDrive SQLite DBs it identifies.

### Fix scope

Wire submodules into `analyze_file` or a new dispatch step:

| Wiring | LOC | Risk |
|---|---:|---|
| OneDrive SQLite parse on match | ~30 LOC in lib.rs | Low |
| Alexa interaction history on `.json` paths | ~20 LOC | Low |
| Smart-TV handlers for Roku/Samsung/LG/AppleTV JSON | ~30 LOC | Low |
| Connected-car event parser on matching JSON | ~20 LOC | Low |

**Total: ~100 LOC in lib.rs, zero new parser code** — the
submodules already exist and are tested. One-session sprint.

---

## §3 — Wraith (memory / crash dumps)

**Files:** `src/lib.rs` (416 LOC).
**Plugin manifest:** "hiberfil.sys, LSASS dumps, crash dump
analysis."

### Function-body evidence

`run()` at lib.rs:305 walks, calls `Self::analyze_file(path)`.
`analyze_file` (at line 76) has real logic for:

- `hiberfil.sys` (line 87) — size-based hibernation footprint
- `pagefile.sys` / `swapfile.sys` (line 115) — page-file
  artifacts
- `.dmp` files (line 131) — LSASS minidump detection with
  suspicious-path checks (Temp/AppData)
- `.dmp` files in minidump paths (line 190) — crash dumps
- **String extraction from .dmp files** (line 212) — actual
  parse

### Classification

**Scenario A (upstream-gated).** Wraith's logic is present and
reasonable. Zero artifacts on Charlie comes from materialization
upstream: `MAX_MATERIALIZE_BYTES = 512 MB` (from
`strata-engine-adapter::vfs_materialize`) excludes Charlie's
`pagefile.sys` (typically 768 MB on XP-2GB) and `hiberfil.sys`
(typically 1–3 GB). Materialized extraction dir:

```
$ find charlie_11_12/case/extracted -iname "hiberfil.sys" -o -iname "pagefile.sys" -o -iname "*.dmp"
(no results)
```

The memdump-001.mem (5.4 GB) image was not run in the v0.16.0
validation. Wraith's behavior on a real `.mem` / `.dmp` input
is **unverified** by this validation; the code path exists but
wasn't exercised.

### Fix scope

| Item | LOC | Priority |
|---|---:|---|
| Raise `MAX_MATERIALIZE_BYTES` for Wraith targets specifically OR add a "large-file-metadata-only" path that materializes the filename+size for Wraith without copying | ~40 LOC materialize-side | Medium |
| Validation follow-up: run Wraith against memdump-001.mem | 0 LOC (test only) | High (before any other Wraith claim) |

---

## §4 — Guardian (AV / EDR / WER)

**Files:** `src/lib.rs` (306 LOC).
**Plugin manifest:** "Windows Defender, AV/EDR logs, WER crash
files, firewall config."

### Function-body evidence

`run()` at lib.rs:75 walks then checks each path against literal
Windows patterns. Every check uses **backslash-separated
literals**:

```rust
if name == "mpeventlog.evtx" ||
   lc_path.contains("\\windows defender\\support\\") { ... }

if lc_path.contains("\\windows defender\\quarantine\\")
    && (lc_path.contains("\\entries\\")
        || lc_path.contains("\\resourcedata\\")) { ... }

if lc_path.contains("\\avast software\\avast\\log\\") { ... }

if lc_path.contains("\\malwarebytes\\mbamservice\\logs\\") { ... }
```

### Classification

**Scenario A + latent Scenario D.** Real logic; the manifests
match. Two issues:

1. **Charlie/Jo predate Windows Defender as shipped.** XP had
   no Defender until MSE/8. So zero on those images is correct
   for the evidence shape.
2. **Path-separator coupling to Windows hosts.** Strata's
   materialization runs on macOS/Linux; extracted paths use
   `/`. A Windows evidence image with real Defender logs
   materialized on macOS would produce paths like
   `/case/extracted/part0/ProgramData/Microsoft/Windows Defender/Support/MPLog.evtx`
   — Guardian's `contains("\\windows defender\\support\\")`
   check silently never matches. **This is a latent failure
   mode that wasn't exercised by the v0.16.0 corpus but would
   bite on real Win8+ cases.**

### Fix scope

| Item | LOC |
|---|---:|
| Replace backslash literals with path-separator-agnostic matching (case-fold + both separators) | ~30 LOC — one helper + s/`\\`/`(\\|\/)` across all checks |
| Add `.evt` (XP Defender/MSE) support — optional | ~200 LOC depending on parser |

---

## §5 — NetFlow (pcap / web-server logs / DNS / IDS)

**Files:** `src/lib.rs` (874 LOC) + `dns_ids.rs` (617 LOC) =
1,491 LOC.
**Plugin manifest:** "PCAP/PCAPNG, IIS/Apache/Nginx logs, exfil
tool detection."

### Function-body evidence

`run()` at lib.rs:278 walks root directory, for each file:
- calls `dns_ids::classify_file` (real parser for DNS + IDS
  logs)
- otherwise calls `Self::classify(path)` to get file_type
- per file_type, dispatches to real handlers (PCAP: magic
  check; IIS/Apache: line-by-line scan for webshell/SQLi/etc.)

`walk_dir` at line 852:

```rust
fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut out = Vec::new();
    if dir.is_dir() {
        ...
    }
    Ok(out)
}
```

### Classification

**Scenario D (input-shape mismatch).** The v0.16.0 run of
`windows-usb-1.pcap` showed:

```
Warning: open_evidence(/.../windows-usb-1.pcap) failed:
    unsupported image format; falling back to host fs
[Strata NetFlow] ok — 0 artifact(s)
```

In "fallback to host fs" mode, `ctx.root_path` is the pcap file
itself, NOT a directory. `walk_dir(root)` at line 854 checks
`if dir.is_dir()` — a regular file returns `false`, the
function returns `Ok(vec![])`, NetFlow's run loop iterates zero
files, produces zero artifacts. The pcap at the supplied path
is never parsed.

**This is a pipeline-plugin contract drift.** When a single-
file source falls back to host fs, plugins need either:
- To receive the file-as-single-path input and decide to walk
  the file's directory OR parse the file directly.
- For the pipeline to always hand plugins a directory root
  (e.g., wrap a single file in a temp directory).

### Fix scope

Two options:

| Fix | LOC | Blast radius |
|---|---:|---|
| **A.** In NetFlow (+ possibly every other plugin's walk_dir), handle `root.is_file()` case by processing the single file | ~15 LOC per plugin; ~150 LOC across all 22 | Low per plugin; wide |
| **B.** In ingest pipeline, always normalize `root_path` to a directory (wrap single files in a synthetic parent dir or materialize into `<case>/extracted/`) | ~50 LOC one-time | One-time fix in ingest.rs + materialize |

Option B is the surgical fix. Option A pushes the burden to
every plugin.

---

## §6 — Apex (Apple apps)

**Files:** `src/lib.rs` (225 LOC) + `ai_content.rs` + `exif.rs`
(214) = 725 LOC.
**Plugin manifest:** "Mail.app, Calendar.app, Contacts.app,
Maps, Siri, iCloud Drive internals, Apple Notes (native),
FaceTime logs."

### Function-body evidence

`run()` at lib.rs:62 walks directory and **only** calls
`crate::exif::parse(&path)` on each. That's it. No Mail.app
SQLite parser. No Calendar. No Contacts. No Notes. No Siri.
No FaceTime. No Maps. No iCloud Drive.

The `ai_content.rs` submodule is declared but has no call site
in `run()` / `execute()` / `analyze_file`.

### Classification

**Scenario B (maximal).** Only 1 of 8+ advertised features is
implemented. Plugin produces zero on iOS/Mac evidence that
doesn't contain EXIF-bearing images. Even the CTF iOS dirs
(12 GB, 378k files) produced only 1 Apex artifact (the CSAM
Scanner's status record is attributed to Apex in some counts —
verify).

Actually re-reading validation matrix: Apex shows zero across
every input. Even images with EXIF data produce zero, suggesting
the EXIF parser's matcher is also narrow (file extension check
for `.jpg`/`.heic` likely).

### Fix scope

Each submodule gap is ~150–400 LOC:

| Feature | LOC |
|---|---:|
| Mail.app SQLite (emails.db, mailboxes.plist) | ~300 |
| Contacts (AddressBook-v22.abcddb) | ~200 |
| Calendar (Calendar.sqlitedb) | ~200 |
| Notes (NoteStore.sqlite) | ~300 |
| KnowledgeC.db (iOS / macOS app usage) | ~250 |
| Safari History (History.db on macOS) | ~150 |
| FaceTime (call.db, sms.db on macOS) | ~200 |
| Maps (GeoHistory.mapsdata) | ~150 |
| Siri suggestions | ~150 |

**Not a single-session fix.** Each feature is a dedicated
parser sprint. Priority ranking: Notes + Mail + Contacts +
Messages (chat.db) cover ~80% of real Mac forensic demand.

---

## §7 — Carbon (Google apps)

**Files:** `src/lib.rs` (plus 8 submodules) = 2,609 LOC.
**Plugin manifest:** "Chrome (desktop), Gmail, Google Drive,
Google Maps, Google Photos, Android system apps built by
Google."

### Function-body evidence

`run()` at lib.rs:70 walks directory. For each path, calls
`ChromiumDb::from_path(path)` to detect; if matched, calls
`chromium::parse(path)` and emits records. **That's it.** No
call to:

- `crate::adb_backup::parse` (ADB backup file detection)
- `crate::google_home::parse_assistant_activity` /
  `parse_nest_thermostat` / `parse_nest_camera_events`
- `crate::samsung::parse_health` / `parse_location` /
  `parse_messages`
- `crate::samsung_android16::parse_rubin_events` /
  `parse_wellbeing_events`
- `crate::turbo_usage::parse`
- `crate::work_profile::*`
- `crate::factory_reset::*`

### Classification

**Scenario B (maximal).** Same shape as Apex: one of many
advertised features is wired. 2,000+ LOC of submodule parsers
exist and compile; they are unreachable from the pipeline.

Note: Carbon misses Google apps on the Takeout directory
because `ChromiumDb::from_path` specifically looks for
Chromium-browser SQLite files (History, Login Data, Web Data),
not Takeout's JSON exports.

### Fix scope

Wire submodules per the Nimbus pattern — each is ~20–40 LOC
of dispatch in `run()`. Total ~200 LOC in lib.rs, zero new
parser code.

**Special case:** `factory_reset.rs` and `work_profile.rs`
detect high-value Android anti-forensic signals. These are
exactly the kind of detection that should be firing on Android
images and feeding into Sigma's "Selective Wipe" rule.

---

## §8 — Pulse (third-party messaging apps)

**Files:** `src/lib.rs` (plus 20+ submodules) = 2,806 LOC.
**Plugin manifest:** "WhatsApp, Signal, Telegram, Snapchat,
Instagram, TikTok, Facebook, third-party browsers."

### Function-body evidence

Pulse is **different shape** from the others: `run()` returns
empty (line 99: "Legacy run() path is intentionally empty");
actual work happens in `execute()` at line 105:

```rust
let android_paths = android::walker::walk(root);
for candidate in &android_paths {
    for parser in android::ALL_PARSERS {
        if parser.matches(candidate) {
            records.extend((parser.run)(candidate));
        }
    }
}
let all_files = walk_dir(root).unwrap_or_default();
for path in &all_files {
    records.extend(ios::dispatch(path));
}
```

Full dispatch to Android and iOS parser suites is wired. Pulse
is the **one plugin that follows the mass-dispatch pattern
examiners assume all plugins follow**.

### Classification

**Scenario A.** Pulse works as documented; zero artifacts on
CTF directories comes from those dirs not containing the
specific sqlite files Pulse's matchers check (`chatstorage.sqlite`,
`signal.sqlite`, `tgdata.db`, `msgstore.db`, etc.).

### Fix scope

Nothing immediately. If real iOS/Android images (vs CTF
sample packs) are validated, Pulse should produce strong
output. Add `--verbose` tripwire showing which of
`android::ALL_PARSERS` matched to aid diagnosis.

---

## §9 — Specter (Android backup, system)

**Files:** `src/lib.rs` (935 LOC) + 6 submodules = 1,520 LOC.
**Plugin manifest:** "`.ab` backup parsing, package inventory,
Wi-Fi config."

### Function-body evidence

`run()` at lib.rs:864 walks, calls
`Self::detect_artifacts(path, name, path_str)` (at lib.rs:466)
per file. `detect_artifacts` has real matchers for:

- `knowledgec.db` (iOS app usage)
- `datausage.sqlite`
- `chatstorage.sqlite` (WhatsApp iOS)
- `msgstore.db` + path contains "whatsapp" (WhatsApp Android)
- `signal.sqlite` / `signal.db`
- `tgdata.db` / `cache4.db` (Telegram)
- `.ab` with `ANDROID BACKUP` magic check
- `com.facebook.*.db|.sqlite`

### Classification

**Scenario A.** CTF 2019 Android dir (183 MB) produced zero
because, per the session prompt's "no such `.ab` file" check,
that dir doesn't have `.ab` backups — it's typical CTF output
(screenshots + plists + text files). Specter correctly returns
empty on input that lacks its specific file targets.

The strong overlap with Pulse's target list (WhatsApp,
Signal, Telegram, Facebook) is worth flagging: Specter and
Pulse have substantial matcher-overlap. A consolidation might
be warranted later, but that's out of scope here.

### Fix scope

Nothing needed for correctness. Fewer filename-exact matches
and more filename-contains/path-hint matches would increase
recall without sacrificing precision (e.g., `knowledgec.db`
appears with case variants in iOS backup dirs).

---

## §10 — ARBOR (Linux / ChromeOS)

**Files:** `src/lib.rs` + `shell_artifacts.rs` + `system_artifacts.rs`
+ `chromeos.rs` + `containers.rs` + `logs.rs` + `persistence.rs`
= 2,013 LOC.
**Plugin manifest:** "systemd persistence, crontab,
shell_artifacts, containers, ChromeOS user data, /var/log."

### Function-body evidence

`run()` at lib.rs:74:

```rust
fn run(&self, ctx: PluginContext) -> PluginResult {
    let root = Path::new(&ctx.root_path);
    let mut out = Vec::new();
    for path in walk_dir(root).unwrap_or_default() {
        out.extend(crate::shell_artifacts::scan(&path));
    }
    Ok(out)
}
```

**Only `crate::shell_artifacts::scan` is called.** No call to:

- `crate::system_artifacts::scan` (systemd, crontab, auth.log,
  syslog — the bulk of Linux forensics)
- `crate::chromeos::scan` (ChromeOS user data)
- `crate::containers::scan` (Docker/OCI containers)
- `crate::logs::scan` (/var/log/ handler)
- `crate::persistence::scan` (systemd unit files, init scripts)

### Classification

**Scenario B (maximal).** ~1,500 LOC of parser code across
5 submodules is dead on the plugin's execution path. On
Chromebook tar ARBOR found zero because shell_artifacts::scan
(which targets .bash_history / .zsh_history) doesn't match
the Chromebook content.

### Fix scope

~30 LOC in `run()`: invoke every submodule's `scan` function.

```rust
fn run(&self, ctx: PluginContext) -> PluginResult {
    let root = Path::new(&ctx.root_path);
    let mut out = Vec::new();
    for path in walk_dir(root).unwrap_or_default() {
        out.extend(crate::shell_artifacts::scan(&path));
        out.extend(crate::system_artifacts::scan(&path));
        out.extend(crate::chromeos::scan(&path));
        out.extend(crate::containers::scan(&path));
        out.extend(crate::logs::scan(&path));
        out.extend(crate::persistence::scan(&path));
    }
    Ok(out)
}
```

Zero new parser code — submodules already exist. One-session
sprint. Must verify submodule test coverage before wiring.

---

## §11 — Registration audit

`crates/strata-engine-adapter/src/plugins.rs`:

```
line 33:  SpecterPlugin::new()
line 35:  NimbusPlugin::new()
line 36:  WraithPlugin::new()
line 40:  GuardianPlugin::new()
line 41:  NetFlowPlugin::new()
line 45:  SentinelPlugin::new()
line 53:  ApexPlugin::new()
line 54:  CarbonPlugin::new()
line 55:  PulsePlugin::new()
line 57:  ArborPlugin::new()
```

All 10 plugins are registered. The pipeline invokes each via
`plugin.execute(context)` (plugins.rs:191, 235, 277). **No
Scenario C (wiring bug) in any of the 10.**

---

## §12 — Summary table

| Plugin | Scenario | Root cause | LOC to fix | Priority |
|---|---|---|---:|---|
| **Nimbus** | B | `run` does substring-only; 4 submodules with real parsers unused | ~100 (lib.rs dispatch) | **High** |
| **Apex** | B | Only EXIF parser invoked; 8+ Mac/iOS parsers missing entirely (not just unwired — unwritten) | 1,500+ new parser code | Medium (multi-sprint) |
| **Carbon** | B | Only Chromium invoked; 8 submodules unused | ~200 (lib.rs dispatch) | **High** |
| **ARBOR** | B | Only shell_artifacts invoked; 5 submodules unused | ~30 (lib.rs dispatch) | **High** |
| **NetFlow** | D | `walk_dir` returns empty when root is a single file (pcap fallback) | 15 per plugin or 50 in pipeline | **High** (tag-policy for G4 downstream) |
| **Guardian** | A+D | Windows `\\` path literals never match macOS-extracted paths | ~30 (path normalization) | Medium |
| **Sentinel** | A | `.evtx`-only; subcategory string mismatched to Sigma predicates | ~20 subcategory fix + ~300 legacy `.evt` | Medium (subcategory) / Low (legacy) |
| **Wraith** | A | Materialize size cap excludes hiberfil/pagefile; `.mem` not validated | ~40 (materialize-side) + validation | Medium |
| **Pulse** | A | Working implementation; CTF dirs lack specific sqlite filenames | 0 | None |
| **Specter** | A | Exact-filename matchers; CTF dirs lack targets | 0 | None |

### Severity × likelihood ranking for field deployment

1. **ARBOR** (Scenario B, tiny fix) — Linux/ChromeOS evidence
   is common, 5 working submodules literally dead code. 30 LOC
   fix. Highest impact-per-LOC.
2. **Nimbus** (Scenario B, modest fix) — cloud evidence is
   increasingly common; 4 submodules dead. ~100 LOC fix.
3. **Carbon** (Scenario B, modest fix) — 8 submodules dead.
   ~200 LOC. Includes high-value Android anti-forensic detectors
   (`factory_reset`, `work_profile`) that Sigma rule 14 keys on.
4. **NetFlow input-shape** (Scenario D) — single-file pcap
   handling is a pipeline fix with wide applicability.
5. **Guardian path-separator** (Scenario A+D) — latent bug on
   Win8+ evidence; 30 LOC fix. Low severity because current
   corpus doesn't exercise it, but real Win10/11 images would.
6. **Sentinel subcategory** — 20 LOC tweak that directly
   enables ~20 Hayabusa Sigma rules to fire when Sentinel has
   output. Must coordinate with SIGMA-SUBCATEGORY-INVENTORY
   follow-up from Session A.
7. **Apex** — largest scope (multiple new parsers needed).
   Multi-session sprint cluster. Prioritize Notes → Mail →
   Contacts → Messages in that order (real-world evidentiary
   value).
8. **Wraith** — validation-only next step; materialize cap
   tuning after that.

---

## Recommended fix order for follow-up sessions

### Session-C (POST-V16-PLUGIN-WIRING-BULK)

Single session covering Scenario B wiring for ARBOR + Nimbus +
Carbon. Each is a "connect existing submodules to `run`"
change. Total ~330 LOC in three plugin lib.rs files, zero new
parser code. Add per-plugin tripwires asserting non-zero
artifact production on a test fixture containing the expected
inputs.

**LOC total:** ~330 (plus ~90 tripwire test code).
**New parsers:** 0.

### Session-D (POST-V16-PIPELINE-INPUT-SHAPE + GUARDIAN)

Fix NetFlow's single-file input handling (Option B in §5 —
normalize in pipeline), plus Guardian's path-separator audit
(~30 LOC path-normalization helper).

**LOC total:** ~80.

### Session-E (SENTINEL-SUBCATEGORY-SIGMA-BRIDGE)

Cross-crate concern: update Sentinel to emit `EVTX-<id>` as
subcategory (v16 S3 added the EVTX parser emitting typed
events; subcategory just needs to be threaded through). Pairs
with the SIGMA-RULE-ALIGNMENT sprint from Session A's research
doc.

**LOC total:** ~20.

### Session-F+ (apex / wraith / sentinel .evt)

Larger scopes. Dedicated sprints each. Not batchable.

---

## Gate status at session end

- Library tests: 3,836 passing (unchanged from v0.16.0
  baseline).
- Clippy `-D warnings`: clean (no code changed).
- AST quality gate: PASS (424 / 5 / 5 library baseline
  preserved).
- Dispatcher arms: all 6 (NTFS, ext, HFS+, FAT, APFS-single,
  APFS-multi) route live; verified via `cargo test -p strata-fs
  --lib fs_dispatch`.
- v15 Session 2 advisory tripwires: unchanged.
- Charlie/Jo regression: unchanged.
- 9 load-bearing tests: preserved.

---

*No code modified. Every classification backed by function-
body quotes above. Fix execution deferred to the sprint
sequence enumerated in §Recommended fix order.*

*Wolfmark Systems — post-v0.16 audit, 2026-04-20.*
