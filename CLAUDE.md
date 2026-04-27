# Strata — Claude Code Guidelines

Strata is a Rust/Tauri digital forensics platform for court-ready evidence analysis. It uses a plugin architecture to parse artifacts from Windows, macOS, Android, and iOS sources. Read and understand existing code before modifying it. Think before coding — simplicity first, surgical changes only.

---

## Key numbers (post-Sprint 21 integration audit, 2026-04-27)

- **Current version:** latest git tag is `v1.5.0-dev11`; CLI crate version remains `0.16.0`.
- **Test count:** 4,024 passing across `cargo test --workspace` after Sprint 21 integration-audit tripwires.
- **Charlie end-to-end demo output:** `charlie-2009-11-12.E01` extracted 3,757 artifacts in the Sprint 21 fixture run; 24/24 plugins completed, 0 failed. Sigma emitted 9 findings.
- **MacBookPro fixture output:** `Test Material/MacBookPro` extracted 8,097 artifacts in the Sprint 21 fixture run; 13/13 recommended plugins completed, 0 failed. The first run exposed an `nt-hive` assertion panic in Phantom; Sprint 21 routed all hive opens through the panic-safe helper and the rerun completed without panic output.
- **Examiner-facing report command:** `strata report --case-dir <path>` — consumes plugin SQLite + case metadata directly, renders 7 sections (Evidence Integrity, Findings, MITRE ATT&CK Coverage, Per-Plugin Summary, Chain of Custody, Examiner Certification, Limitations). Replaced legacy `report-skeleton` (retired in Sprint 6.5 after producing all-zero reports against the wrong database schema).
- **Filesystem walkers live through the dispatcher:**
  - NTFS (since v11, `strata-fs::ntfs_walker`)
  - ext2/ext3/ext4 (v15 Session B, wraps `ext4-view = 0.9`)
  - HFS+ (v15 Session D, in-tree walker with real B-tree iteration, v16 Session 3 added `read_file` extent reading)
  - FAT12/FAT16/FAT32 (v15 Session E, in-tree walker)
  - APFS single-volume (v16 Session 4, wraps `apfs = 0.2`)
  - APFS multi-volume (v16 Session 5, CompositeVfs with `/vol{N}:/path` scoping; dispatcher auto-detects via `fs_oids` count)
- **Dispatcher short-circuits with structured pickup signal:**
  - FileVault-encrypted DMGs (`encrcdsa` header at byte 0) — returns `"FileVault-encrypted DMG detected. Decryption is out of scope for Strata. Recommend offline key recovery via macOS keychain, institutional recovery key, or forensic decryption tooling."` (post-v16 Session C, commit `b28b64e`)
- **Dispatcher deferrals with explicit pickup signals:**
  - exFAT — `"exFAT walker deferred — see roadmap"` (v17 candidate)
- **Explicit out-of-scope deferrals (tripwired):**
  - APFS snapshot enumeration — current-state only per `apfs_walker_walks_current_state_only_pending_snapshot_enumeration` (v17 candidate)
  - APFS fusion drives — `"APFS fusion drives not yet supported"` rejected at walker open()
  - APFS decryption — examiner offline key recovery out of scope permanently
- **AST quality gate baseline** (enforced by `tools/strata-verify-quality`): 398 library `.unwrap()` / 5 `unsafe{}` (VHD/VMDK FFI waiver) / 4 `println!`. Sprint 21 ratcheted the waiver down to the measured codebase state; do not raise it to hide new violations.
- **9 load-bearing tests preserved** (see below).

---

## Working Principles (Karpathy skills)

*Source: [forrestchang/andrej-karpathy-skills/CLAUDE.md](https://github.com/forrestchang/andrej-karpathy-skills/blob/main/CLAUDE.md).
Merged into Strata's CLAUDE.md in v16 Session 3. Behavioral
guidelines to reduce common LLM coding mistakes — these sit
above the "Hard Rules" because how to approach work matters
before what rules apply.*

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

### How these apply to Strata specifically

Two places where Strata's existing discipline is more prescriptive than the Karpathy defaults — documented here so the interaction is explicit rather than a point of silent conflict:

- **Simplicity First vs. forensic-correctness requirements.** Strata has non-negotiable features that look like overengineering at first glance: every `ArtifactRecord` MUST populate `mitre_technique`; every ML finding MUST carry `is_advisory = true` + `ADVISORY_NOTICE`; every deferred behavior MUST have a tripwire test pinning its current state (`_still_X` / `_pending_Y` / `_pinned_as_unsupported_until_Z`). These are spec requirements, not "flexibility." When Simplicity First and a forensic-correctness requirement conflict, forensic correctness wins — document the justification inline.
- **Surgical Changes vs. research-doc-driven cleanups.** When a session's queue explicitly invites a retirement/replacement (e.g., v16 Session 3's "delete in-tree APFS modules and adopt external crate" instruction), the cleanup is the user's request — not an un-asked improvement. The Surgical-Changes test ("every changed line should trace directly to the user's request") still applies; the tracing just goes through the queue instead of a single inline sentence.

---

## Hard Rules

### Code Safety

- **Zero `.unwrap()` calls.** Use `?` operator or `match`. No exceptions.
- **Zero `unsafe {}` blocks.** If a dependency requires unsafe, that dependency needs justification before being added.
- **No `println!`.** Use `log::debug!`, `log::info!`, `log::warn!`, or `log::error!`. The CLI and Tauri layer both capture structured logs; raw stdout breaks that pipeline.
- **No unnecessary dependencies.** Every new `Cargo.toml` entry must justify itself. Prefer crates already in the workspace. Avoid crates that pull in large transitive trees for minor convenience.

### Build artifact requirement (FIX-4)

Every Strata release must produce a working clickable application:

- **macOS** bundle: `apps/strata-desktop/src-tauri/target/release/bundle/macos/Strata.app`
  and DMG: `apps/strata-desktop/src-tauri/target/release/bundle/dmg/Strata_<version>_aarch64.dmg`
- **Windows** binary: `apps/strata-desktop/src-tauri/target/release/strata-desktop.exe`
  and MSI installer under `apps/strata-desktop/src-tauri/target/release/bundle/msi/`
- **Linux** binary: `apps/strata-desktop/src-tauri/target/release/strata-desktop`
  and AppImage under `apps/strata-desktop/src-tauri/target/release/bundle/appimage/`

CI must verify these artifacts exist and are runnable. A build that
does not produce a clickable desktop application is not shippable.
The CLI (`target/release/strata`) is the fallback for headless /
air-gapped contexts — the GUI is the primary tool for day-to-day
casework.

Note: Tauri writes into `apps/strata-desktop/src-tauri/target/`, NOT
into the workspace root `target/`. Release workflows and release
notes must reference the `src-tauri/target/` paths above.

### Testing

- **Never remove load-bearing tests.** If a test is blocking you, understand why it exists. Fix the code, not the test. The project has 2,685+ tests; any net reduction requires an explicit explanation.
- Each plugin module must have a minimum of 3 unit tests per parser.

### Artifact Parsers

- **Field-level documentation is required.** Every struct field in a parser must have a doc comment explaining what the field represents and its forensic significance.
- **MITRE ATT&CK mapping is required.** Every `ArtifactRecord` produced by a parser must populate its `mitre_technique` field. Unmapped artifacts are incomplete artifacts. Use the [ATT&CK Enterprise/Mobile matrices](https://attack.mitre.org).

---

## Load-Bearing Tests — Never Remove

These 9 tests must always pass. If one is blocking you, fix the code, not the test:

```
build_lines_includes_no_image_payload
hash_recipe_byte_compat_with_strata_tree
rule_28_does_not_fire_with_no_csam_hits
advisory_notice_present_in_all_findings
is_advisory_always_true (strata-ml-anomaly)
advisory_notice_always_present_in_output
examiner_approved_defaults_to_false
summary_status_defaults_to_draft
is_advisory_always_true (strata-ml-charges)
```

---

## Sprint 14-20 Feature Inventory

These features are shipped and wired as of the Sprint 21 integration audit:

- Timeline view and `get_artifacts_timeline` Tauri/IPC path
- IOC hunt and `search_iocs` Tauri/IPC path
- Chain-of-custody log and `get_custody_log` Tauri/IPC path
- Evidence integrity verification and `verify_evidence_integrity` Tauri/IPC path
- NSRL hash-set import/list/delete/stats Tauri/IPC path
- Artifact notes save/load/list Tauri/IPC path
- Court-ready report system with dynamic artifact-category sections
- Artifact confidence score/basis display
- Advisory artifact banner display for ML/AUGUR-derived findings
- macOS keychain depth for `genp`, `inet`, and `cert`
- AmCache.hve parser
- Full USB device artifact chain
- EVTX structured analytics
- MRU registry keys: RecentDocs, OpenSavePidlMRU, LastVisitedPidlMRU, RunMRU, Office MRU
- Zone.Identifier ADS parser
- Thumbcache parser
- LNK deep parsing
- AUGUR bridge plugin for advisory translation workflow
- ARBOR plugin for Linux and ChromeOS forensics
- Cryptocurrency artifact detection
- Tor/dark web artifact detection
- Financial artifact detection

---

## Project Structure

```
strata/
├── apps/
│   ├── strata-desktop/        # Primary Tauri 2 desktop app (case management + UI)
│   ├── forge/                 # Tauri prompt template + DFIR playbook editor
│   └── tree/                  # egui native viewer + tantivy full-text search (legacy)
├── crates/
│   ├── strata-core/           # Central forensic parsing engine (hives, prefetch, events)
│   ├── strata-fs/             # Filesystem abstraction (NTFS, EWF, evidence images)
│   ├── strata-plugin-sdk/     # StrataPlugin trait, ArtifactRecord schema, confidence scoring
│   ├── strata-artifacts/      # Shared artifact types and serialization
│   ├── strata-engine-adapter/ # JSON/Tauri IPC bridge; statically links all plugins
│   ├── strata-acquire/        # Evidence acquisition and chain-of-custody hashing
│   ├── strata-insight/        # Timeline enrichment and SQLite-based artifact queries
│   ├── strata-shield-engine/  # Headless analysis engine (CLI/daemon)
│   ├── strata-shield-cli/     # `strata` CLI binary
│   ├── strata-license/        # Ed25519 license validation, machine-uid binding, tier gating
│   ├── strata-csam/           # Hash + perceptual CSAM detection, audit logging
│   ├── strata-ml-anomaly/     # Statistical outlier detection (timestomping, staging patterns)
│   ├── strata-ml-summary/     # Plain-English case summary generation
│   ├── strata-ml-obstruction/ # Anti-forensic behavior scoring (0–100)
│   └── strata-charges/        # Charge and offense categorization
└── plugins/
    └── (see Plugin Architecture below)
```

---

## Plugin Architecture

All plugins implement `StrataPlugin` from `strata-plugin-sdk`. Each plugin's `execute()` returns a `PluginOutput` containing `Vec<ArtifactRecord>`. Plugins are statically linked in `strata-engine-adapter` for CJIS compliance (no dynamic loading at runtime).

### Plugin → Source Mapping

This is the canonical assignment. When adding or moving a parser, put it in the correct plugin:

| Plugin | Covers | Examples |
|--------|--------|---------|
| **Apex** | Apple-built app artifacts | Mail.app, Calendar.app, Contacts.app, Maps, Siri, iCloud Drive internals, Apple Notes (native), FaceTime logs |
| **ARBOR** | Linux / ChromeOS system artifacts | systemd persistence, crontab, shell history, `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/proc/net/tcp`, auth/syslog, containers, ChromeOS user data, `/var/log` |
| **Carbon** | Google-built app artifacts | Chrome (desktop), Gmail, Google Drive, Google Maps, Google Photos, Android system apps built by Google |
| **Pulse** | Third-party user-installed apps (iOS + Android) | WhatsApp, Signal, Telegram, Snapchat, Instagram, TikTok, Facebook, third-party browsers |
| **MacTrace** | macOS system-layer artifacts | LaunchAgents/Daemons, FSEvents, Unified Log, Gatekeeper, Quarantine, Time Machine, Biome, TCC, KnowledgeC |
| **Phantom** | Windows registry persistence | SYSTEM/SOFTWARE/SAM/SECURITY hives, AmCache, ShimCache, USBSTOR, 23 persistence mechanisms |
| **Sentinel** | Windows Event Logs (`*.evtx`) | Per-event parsing of Security/System/PowerShell/Sysmon channels via `strata-core::parsers::evtx`; typed extractors for 4624, 4625, 4688, 4698/4702, 7045, 4103/4104, 1102 |
| **Chronicle** | Windows user activity history | UserAssist, Jump Lists (LNK), Shellbags (CFB), Windows Timeline (ESE) |
| **Trace** | Windows execution evidence | Prefetch, BAM/DAM, Scheduled Tasks, BITS, SRUM ESE, timestomp detection |
| **Remnant** | Windows deletion artifacts | Recycle Bin ($I), USN Journal, ADS, VSS deletion, anti-forensic detection |
| **Guardian** | Security product logs | Windows Defender, AV/EDR logs, WER crash files, firewall config |
| **Cipher** | Credentials and secrets | WiFi passwords, browser credentials, SSH/AWS/Azure keys |
| **Nimbus** | Cloud service artifacts | OneDrive, Teams, Slack, M365 UAL, AWS CloudTrail, Azure |
| **Conduit** | Network configuration artifacts | WiFi profiles, RDP history, VPN artifacts, DNS cache |
| **NetFlow** | Network traffic and server logs | PCAP/PCAPNG, IIS/Apache/Nginx logs, exfil tool detection |
| **Vector** | Malicious file analysis and dark-web indicators | PE headers, VBA macros, PowerShell obfuscation, Cobalt Strike/Mimikatz detection, Tor Browser `.onion` history, Tor state, I2P, ProxyChains, VPN artifacts |
| **Wraith** | Memory and crash artifacts | hiberfil.sys, LSASS dumps, crash dump analysis |
| **Recon** | Extracted IOC data | Usernames, emails, IPs, AWS AKIA keys, SID history |
| **Specter** | Android backup artifacts | `.ab` backup parsing, package inventory, Wi-Fi config |
| **Vault** | Hidden storage, crypto, and financial artifacts | VeraCrypt/TrueCrypt, hidden partitions, photo vaults, crypto wallets, exchange exports, hardware wallets, QuickBooks/QBO/OFX, financial statements, wire-transfer CSVs |
| **AUGUR** | Translation advisory bridge | Foreign-language audio/video/image/document triage; advisory only until certified human review |
| **Advisory Analytics** | ML advisory findings | anomaly, obstruction, summary, and charge/offense advisory artifacts; always `is_advisory = true` |
| **Sigma** | Correlation engine | Runs last; receives all prior plugin results; applies MITRE ATT&CK kill-chain rules |
| **CSAM** | Child exploitation detection | Hash + dHash perceptual matching, NCMEC/Project VIC import, immutable audit log |

**Total plugin directories:** 25 under `plugins/`.
**Static backend registry entries:** 24 in `strata-engine-adapter::plugins::build_plugins()`.
**Frontend plugin cards:** 24 in `apps/strata-ui/src/types/index.ts::PLUGIN_DATA`.

The count difference is intentional: `strata-plugin-index` is a cdylib-only dynamic-loader scaffold, `strata-plugin-tree-example` is a reference/template plugin, and `AUGUR` is a static bridge entry without a local `plugins/strata-plugin-augur` directory.

The 23 local plugin directories that participate in the forensic/advisory fleet are:

- `strata-plugin-advisory`
- `strata-plugin-apex`
- `strata-plugin-arbor`
- `strata-plugin-carbon`
- `strata-plugin-chronicle`
- `strata-plugin-cipher`
- `strata-plugin-conduit`
- `strata-plugin-csam`
- `strata-plugin-guardian`
- `strata-plugin-mactrace`
- `strata-plugin-netflow`
- `strata-plugin-nimbus`
- `strata-plugin-phantom`
- `strata-plugin-pulse`
- `strata-plugin-recon`
- `strata-plugin-remnant`
- `strata-plugin-sentinel`
- `strata-plugin-sigma`
- `strata-plugin-specter`
- `strata-plugin-trace`
- `strata-plugin-vault`
- `strata-plugin-vector`
- `strata-plugin-wraith`

The remaining two plugin directories are infrastructure:

- `strata-plugin-index` — builds the full-text / metadata index consumed by the UI
- `strata-plugin-tree-example` — reference / template plugin for the tree SDK

**Rule:** Sigma always runs last. Do not add correlation logic to other plugins — put cross-artifact rules in Sigma.

**Plugin separation principle:**
- Apple-built apps → **Apex**
- Google-built apps → **Carbon**
- Third-party user-installed apps → **Pulse**
- macOS system artifacts → **MacTrace**
- Do not mix OS-specific logic across plugins

### Source file ownership

Each evidence source file has exactly one owning plugin. When two
plugins both parse the same file, every artifact appears twice in the
examiner's view — Sprint 11 P4 added query-layer deduplication as a
safety net, but the *right* fix is single ownership.

**MacTrace owns:**
- `chat.db` (iMessage / SMS — macOS Messages.app and the iOS backup mirror)
- `sms.db` (iOS SMS database)
- `KnowledgeC.db` (Apple usage telemetry)
- `interactionC.db` (Contacts / call interaction graph)
- CoreDuet databases
- LaunchAgents / LaunchDaemons plists
- WhatsApp on macOS / iOS (`ChatStorage.sqlite`)
- PowerLog (`CurrentPowerlog.PLSQL`)
- macOS / iOS system-layer databases generally (TCC, FSEvents, Unified Log,
  Biome, locationd, AddressBook, CallHistory)

**Pulse owns:** third-party user-installed app databases —
- Signal, Telegram, Snapchat, Instagram, TikTok, Facebook
- Third-party browsers
- WhatsApp **only** on platforms where MacTrace doesn't already claim it
  (i.e. Android `msgstore.db` — not the iOS `ChatStorage.sqlite` which
  belongs to MacTrace)

**Rule when adding a new parser:** before writing the file matcher,
grep the existing plugins for the filename. If another plugin already
claims it, either route through that plugin or coordinate the
ownership change explicitly — do **not** silently duplicate. The
query-layer dedup will hide the symptom; the underlying double-parse
still costs ingest time and memory and may diverge over time as the
two parsers evolve independently.

### ArtifactRecord Requirements

Every record produced by a parser must set:

```rust
ArtifactRecord {
    mitre_technique: "T1547.001".into(), // required — never leave empty
    confidence: 85,                       // 0–100; document your reasoning
    // ... all other fields
}
```

---

## Evidence Pipeline

```
strata-fs (mount image)
  → strata-core (parse raw artifacts)
    → plugins (enrich, classify, correlate)
      → strata-engine-adapter (serialize to JSON)
        → Tauri IPC → UI
```

For CLI usage: `strata-shield-engine` → `strata-shield-cli` (bypasses Tauri).

---

## Development Patterns

### Error Handling

```rust
// Correct
fn parse_artifact(path: &Path) -> Result<Vec<ArtifactRecord>, ForensicError> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT ...")?;
    // ...
}

// Wrong — never do this
let conn = Connection::open(path).unwrap();
```

### Logging

```rust
// Correct
log::debug!("Parsing {} records from {:?}", count, path);
log::warn!("Expected table not found in {:?}, skipping", path);

// Wrong
println!("Parsing {} records", count);
```

### Parser Structure

```rust
/// Parses the SMS message database from an iOS backup.
pub struct SmsParser;

impl SmsParser {
    /// Returns true if this path matches the iOS SMS database filename pattern.
    /// Matching is filename-only (cheap) — no file I/O at this stage.
    pub fn matches(path: &Path) -> bool { ... }

    /// Parses SMS message records from the SQLite database at `path`.
    ///
    /// Opens the database read-only. Returns an empty vec (not an error) if
    /// the table exists but contains no rows.
    pub fn parse(path: &Path) -> Vec<ArtifactRecord> { ... }
}
```

### Parallel Processing

Rayon is enabled via the `parallel` feature flag (default on). Use `par_iter()` for CPU-bound parser loops. Do not add threading primitives directly — route through Rayon.

### License Tier Gating

Tier checks live in `strata-engine-adapter`. Do not add tier logic inside individual plugins — plugins are tier-agnostic.

---

## Branch Conventions

- `hermes/Q-XXX-description` — Qwen-built output, awaiting FORGE-DEV review
- `forge/sprint-description` — FORGE-DEV weekly reset work
- Never commit directly to `main` or `dev` without review
- Hermes branches are auto-generated — review before merging

---

## Testing

Run the full test suite before any PR:

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

Parser tests must cover:
1. A known-good fixture file (real artifact, expected output verified)
2. A missing/empty input (returns empty vec, does not panic)
3. A malformed/corrupt input (returns empty vec or error, does not panic)

Place test fixtures in the plugin's `tests/fixtures/` directory.

---

## What Not to Do

- Do not add `serde_json::Value` as a catch-all — define typed structs.
- Do not mix OS-specific artifact logic across plugins (e.g., Windows registry parsing does not belong in MacTrace).
- Do not add a new dependency to solve a problem already handled by a workspace crate.
- Do not leave `TODO` or `FIXME` comments in committed code — file an issue instead.
- Do not write parsers that modify the evidence source. All access is read-only.
- Do not remove or skip load-bearing tests — fix the code, not the test.
- Do not add tier gating logic inside plugins — that belongs in strata-engine-adapter.
