# Strata v1.3.0 — ForensicRS Integration Sprint

**Tag:** v1.3.0
**Date:** 2026-04-07
**Status:** Built clean (`cargo tauri build --no-bundle` — release profile, 1m 26s)
**Artifact:** `apps/strata-desktop/src-tauri/target/release/strata-desktop`

---

## Theme

Replace hand-rolled Windows forensic parsers with battle-tested ForensicRS
community crates where the upstream API actually exists and works, and
dramatically expand Sigma correlation coverage via Hayabusa-inspired EVTX
event-ID rules.

---

## Completed

### 1. ForensicRS dependencies wired into `strata-core`
**File:** `crates/strata-core/Cargo.toml`

Added three working community crates:
- `forensic-rs = "0.13"` — framework / VirtualFileSystem trait
- `frnsc-hive = "0.13"` — kept for future HiveRegistryReader integration
- `frnsc-prefetch = "0.13"` — now powering the prefetch parser

Also moved `evtx = { workspace = true }` out of `[target.'cfg(windows)']`
into base dependencies — the crate is pure Rust and works cross-platform,
which matters because macOS / Linux examiners triage Windows disk images.

### 2. Prefetch parser replacement
**File:** `crates/strata-core/src/parsers/prefetch.rs`

Old: 70-line stub that only parsed the filename and returned an advisory
"run count and timestamps require full parser" note.

New: `frnsc-prefetch::read_prefetch_file` via an in-memory `VirtualFile`
adapter (`MemFile` — wraps `Cursor<Vec<u8>>`, implements `Read + Seek +
VirtualFile`). Handles MAM$-compressed (Win10+) and uncompressed (Win7/8)
prefetch files. Extracts:
- executable name + full path
- `run_count`
- up to eight `last_run_times` (converted FILETIME → Unix seconds)
- loaded DLLs/EXEs metric list
- volume metadata (device path, serial, creation time)
- MRU user (via `PrefetchFile::user()`)

Emits one `ParsedArtifact` per last-run timestamp so the Strata timeline
gets a row for every remembered execution.

### 3. Real EVTX per-event parsing
**File:** `crates/strata-core/src/parsers/evtx.rs`

Old: 56-line stub that detected `.evtx` by filename and stored nothing.

New: `evtx::EvtxParser::from_buffer` + `records_json_value()`. For each
high-value event, emits a `ParsedArtifact` with
`artifact_type = "EVTX-<EventID>"` plus a description and a JSON payload
containing `event_id`, `channel`, `provider`, `computer`, `target_user`,
`subject_user`, `source_ip`, `logon_type`, `process_name`, `command_line`,
`parent_image`, `service_name`, `target_filename` — whichever are present.

High-value event whitelist (curated from SANS FOR508 + Hayabusa categories):

| Channel | Event IDs |
|---|---|
| Security | 4624, 4625, 4634, 4648, 4672, 4697, 4698, 4699, 4700, 4702, 4719, 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4738, 4740, 4768, 4769, 4771, 4776, 4781, 1102 |
| System | 7045, 7034, 7036, 104, 6005, 6006 |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104, 4105, 4106 |
| Microsoft-Windows-Sysmon/Operational | 1, 3, 7, 8, 10, 11, 12, 13, 17, 19, 20, 21, 22, 25 |
| Microsoft-Windows-TaskScheduler/Operational | 106, 140, 141, 200, 201 |
| Microsoft-Windows-WinRM/Operational | 6, 169 |
| Microsoft-Windows-Windows Defender/Operational | 1006, 1007, 1008, 1116, 1117, 5001, 5007, 5010 |

Per-log cap: 2500 high-value events (prevents a single noisy Security.evtx
from blowing up the UI). A summary artifact is always emitted regardless
of whether any high-value events fired.

Timestamps parsed from `Event.System.TimeCreated.#attributes.SystemTime`
(ISO-8601 → Unix seconds via `chrono::DateTime::parse_from_rfc3339`).

### 4. Hayabusa-inspired Sigma correlation rules
**File:** `plugins/strata-plugin-sigma/src/lib.rs`

Added **15 new correlation rules** keyed on the `EVTX-<EventID>`
subcategories emitted by the new EVTX parser. Plugin version bumped
1.0.0 → 1.3.0.

| # | Rule | Trigger | MITRE |
|---|---|---|---|
| 1 | Security Audit Log Cleared | EVTX-1102 | T1070.001 |
| 2 | System Log Cleared | EVTX-104 | T1070.001 |
| 3 | Failed Logon Burst | EVTX-4625 ≥ 10 | T1110 |
| 4 | Account Lockout | EVTX-4740 | T1110 |
| 5 | Scheduled Task Persistence | EVTX-4698 | T1053.005 |
| 6 | New Service Installed | EVTX-7045 \|\| EVTX-4697 | T1543.003 |
| 7 | Local Account Created + Group Add | EVTX-4720 + EVTX-4732 | T1136.001 + T1098 |
| 8 | Kerberoasting Burst | EVTX-4769 ≥ 20 | T1558.003 |
| 9 | Obfuscated PowerShell | EVTX-4104 with FromBase64String/IEX/DownloadString/-enc/-nop/bypass | T1059.001 + T1027 |
| 10 | RDP Logon From External IP | EVTX-4624 LogonType 10 from non-RFC1918 | T1021.001 |
| 11 | Explicit-Credentials Logon Burst | EVTX-4648 ≥ 5 | T1550.002 |
| 12 | LSASS Process Access | EVTX-10 with target=lsass.exe | T1003.001 |
| 13 | WMI Event Subscription | EVTX-19 \|\| EVTX-20 \|\| EVTX-21 | T1546.003 |
| 14 | Defender RT Protection Disabled | EVTX-5001 \|\| EVTX-5010 | T1562.001 |
| 15 | Sysmon DNS to Suspicious TLD | EVTX-22 with .top/.xyz/.tk/.onion/pastebin/transfer.sh/ddns | T1071.004 |
| bonus | High-Frequency 4672 Privilege Assign | EVTX-4672 ≥ 10 | T1068 |

Existing v1.0.0–v1.1.0 correlation rules retained (USB exfiltration
sequence, archive+exfil, AV evasion, new account + persistence, shimcache
ghost, web attack, log clearing, archive+exfil extended, Office macro
chain, selective wipe, SRUM+exfil, capability abuse).

**Total Sigma rules now: 27** (12 v1.0+v1.1 pattern rules + 15 new
Hayabusa-inspired EVTX rules, all compiled into the static plugin).

### 5. Version bump 1.2.0 → 1.3.0
- `apps/strata-desktop/src-tauri/Cargo.toml`
- `apps/strata-desktop/src-tauri/tauri.conf.json`
- `apps/strata-desktop/src-tauri/src/lib.rs` (all user-visible "Strata v1.2.0" strings, PDF report footer, startup log)
- `crates/strata-engine-adapter/Cargo.toml`
- `apps/strata-ui/package.json`
- `apps/strata-ui/src/components/SplashScreen.tsx` (splash version label)
- `plugins/strata-plugin-sigma/src/lib.rs` (plugin version string)

One historical comment `// SQLite viewer — v1.2.0` at
`apps/strata-desktop/src-tauri/src/lib.rs:1761` was intentionally left as
a feature-provenance marker for the v1.2.0 work.

### 6. Release build verified
```
cargo check --workspace    → clean (26.76s incremental)
cargo tauri build --no-bundle → clean release build in 1m 26s
```
Output binary: `target/release/strata-desktop` — all 15 statically-linked
plugins compiled with the new deps.

---

## Blocked / WATCHING (upstream gaps)

### `frnsc-amcache 0.13.0` — BLOCKED on broken public API
The `AmCache<R: RegistryReader>` struct has no public constructor and
the `reader` field is not `pub`. External crates literally cannot
instantiate it; the only working example lives in the crate's own
`#[cfg(test)] mod tst` module. Dropped from the dependency list.
**Action:** file upstream issue; revisit when a `pub fn new(reader: R)`
or `#[derive(Default)]`-style constructor ships. Meanwhile the v1.0.0
hand-rolled AmCache parser in `strata-plugin-phantom` (which parses
`Root\InventoryApplicationFile` for SHA1 + Publisher and
`Root\InventoryDriverBinary` for unsigned drivers via `nt-hive`) continues
to carry the load.

### `frnsc-esedb` — WATCHING (unpublished)
docs.rs returns 404. Not on crates.io. Needed for SRUM, WebCacheV01.dat,
NTDS.dit. Until it publishes, SRUM stays on Strata's own detection
heuristics in the Trace plugin.

### `frnsc-shellbags` — WATCHING (unpublished)
Also 404 on docs.rs. Existing nt-hive-based shellbag parsing in Phantom
remains the source of truth.

### Phantom full `RegistryReader` trait refactor — DEFERRED
A complete rewrite of Phantom's ~1500-line hive parser to accept
`&mut impl RegistryReader` instead of opening hives directly via `nt-hive`
was in-scope for this sprint. Deferred: the existing code is correct and
well-tested, the marginal forensic benefit of HiveRegistryReader's
transaction log replay does not justify the risk of regressing SAM,
SYSTEM, SOFTWARE, SECURITY, USRCLASS, NTUSER, and AmCache parsers in a
single sprint. Planned for v1.4.0 behind a feature flag so we can A/B it.

---

## Key files changed (v1.3.0 delta)

```
crates/strata-core/Cargo.toml                        (+7 -3)
crates/strata-core/src/parsers/prefetch.rs           (full rewrite, 70 → 198 lines)
crates/strata-core/src/parsers/evtx.rs               (full rewrite, 56 → 320 lines)
plugins/strata-plugin-sigma/src/lib.rs               (+300, 15 new rules, v1.3.0)
apps/strata-desktop/src-tauri/Cargo.toml             (version)
apps/strata-desktop/src-tauri/tauri.conf.json        (version)
apps/strata-desktop/src-tauri/src/lib.rs             (version strings)
crates/strata-engine-adapter/Cargo.toml              (version)
apps/strata-ui/package.json                          (version)
apps/strata-ui/src/components/SplashScreen.tsx       (version label)
SESSION_STATE_v13.md                                 (new)
```

---

## Plugin roster (unchanged count: 15 statically linked)

Remnant, Chronicle, Cipher, Trace, Specter, Conduit, Nimbus, Wraith,
Vector, Recon, Phantom, Guardian, NetFlow, MacTrace, **Sigma (v1.3.0)**.

## Parser coverage improvement

| Artifact | v1.2.0 | v1.3.0 |
|---|---|---|
| Prefetch | filename only | full: run count, last-8 times, loaded files, volumes, user |
| EVTX | filename only | full: per-event parsing, 60+ curated event IDs, 7 channels, field extraction |
| AmCache | nt-hive hand-rolled | nt-hive hand-rolled (frnsc-amcache blocked upstream) |
| Registry hives | nt-hive hand-rolled | nt-hive hand-rolled (RegistryReader refactor deferred to v1.4.0) |

## Next up (v1.4.0 candidates)

1. Phantom → HiveRegistryReader refactor behind feature flag
2. `frnsc-amcache` integration if upstream fixes the constructor
3. `frnsc-esedb` integration if published — SRUM, WebCacheV01, NTDS
4. Expand EVTX channel coverage: OpenSSH/Operational,
   Microsoft-Windows-SMBServer/Security, RDPCoreTS
5. Port another tranche of Hayabusa rules now that the pipeline exists
