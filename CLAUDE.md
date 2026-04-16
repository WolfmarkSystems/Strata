# Strata — Claude Code Guidelines

Strata is a Rust/Tauri digital forensics platform for court-ready evidence analysis. It uses a plugin architecture to parse artifacts from Windows, macOS, Android, and iOS sources. Read and understand existing code before modifying it. Think before coding — simplicity first, surgical changes only.

---

## Hard Rules

### Code Safety

- **Zero `.unwrap()` calls.** Use `?` operator or `match`. No exceptions.
- **Zero `unsafe {}` blocks.** If a dependency requires unsafe, that dependency needs justification before being added.
- **No `println!`.** Use `log::debug!`, `log::info!`, `log::warn!`, or `log::error!`. The CLI and Tauri layer both capture structured logs; raw stdout breaks that pipeline.
- **No unnecessary dependencies.** Every new `Cargo.toml` entry must justify itself. Prefer crates already in the workspace. Avoid crates that pull in large transitive trees for minor convenience.

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
| **Apex** *(planned)* | Apple-built app artifacts | Mail.app, Calendar.app, Contacts.app, Maps, Siri, iCloud Drive internals, Apple Notes (native), FaceTime logs |
| **Carbon** *(planned)* | Google-built app artifacts | Chrome (desktop), Gmail, Google Drive, Google Maps, Google Photos, Android system apps built by Google |
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
| **Vector** | Malicious file analysis | PE headers, VBA macros, PowerShell obfuscation, Cobalt Strike/Mimikatz detection |
| **Wraith** | Memory and crash artifacts | hiberfil.sys, LSASS dumps, crash dump analysis |
| **Recon** | Extracted IOC data | Usernames, emails, IPs, AWS AKIA keys, SID history |
| **Specter** | Android backup artifacts | `.ab` backup parsing, package inventory, Wi-Fi config |
| **Sigma** | Correlation engine | Runs last; receives all prior plugin results; applies 34 MITRE ATT&CK kill-chain rules |
| **CSAM** | Child exploitation detection | Hash + dHash perceptual matching, NCMEC/Project VIC import, immutable audit log |

**Rule:** Sigma always runs last. Do not add correlation logic to other plugins — put cross-artifact rules in Sigma.

**Plugin separation principle:**
- Apple-built apps → **Apex**
- Google-built apps → **Carbon**
- Third-party user-installed apps → **Pulse**
- macOS system artifacts → **MacTrace**
- Do not mix OS-specific logic across plugins

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
