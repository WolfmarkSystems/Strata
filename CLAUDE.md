# CLAUDE.md — Strata / Wolfmark Systems
# This file is the single source of truth for every Claude Code agent working in this repo.
# Read this ENTIRELY before touching any code.
# Last updated: 2026-04-09

---

## WHO YOU ARE WORKING WITH

You are working for Korbyn, Founder of Wolfmark Systems. He is a US Army
Counterintelligence Special Agent and Digital Forensic Examiner. He built Strata
because the tools he needed in the field didn't exist. Every line of code here
matters — this tool will be used in real criminal investigations.

Korbyn reviews every commit before it goes anywhere near production. Your job is
to write production-quality Rust that he can review, push, and trust in court.

---

## WHAT STRATA IS

Strata is a professional digital forensics platform:
- 89% pure Rust, single binary, cross-platform (macOS, Windows, Linux)
- 16 forensic plugins + Sigma (always runs last)
- 29 Sigma correlation rules with full MITRE ATT&CK kill chain
- Free for .gov/.mil permanently
- CSAM detection built-in and free on all tiers
- Air-gapped by design — no cloud, no telemetry, no license server
- Court-ready reports with SHA256-chained audit trail
- Current version: v1.4.0

---

## REPOSITORY STRUCTURE

```
~/Wolfmark/strata/
├── Cargo.toml                          # Workspace root
├── CLAUDE.md                           # This file — READ FIRST
├── apps/
│   └── tree/
│       └── strata-tree/                # Main egui desktop app
│           ├── src/
│           │   ├── main.rs
│           │   ├── state.rs            # AppState — central state
│           │   ├── state_csam.rs       # CSAM scan state + bridge
│           │   ├── license_state.rs
│           │   ├── plugin_host.rs      # Plugin orchestration
│           │   └── ui/
│           │       ├── plugins_view.rs # Plugin results UI
│           │       └── dialogs/
├── crates/
│   ├── strata-core/                    # Core forensic engine
│   │   └── src/
│   │       ├── parsers/
│   │       │   ├── evtx.rs             # EVTX parser (has pre-existing warning line 76)
│   │       │   └── ...
│   │       └── classification/
│   │           └── recyclebin.rs       # Has pre-existing platform-gated test
│   ├── strata-csam/                    # CSAM detection module (NEW in v1.4.0)
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── audit.rs               # SHA256-chained audit (load-bearing test inside)
│   │       ├── hash_db.rs             # NCMEC/Project VIC hash sets
│   │       ├── perceptual.rs          # dHash perceptual matching (load-bearing test inside)
│   │       ├── scanner.rs             # Parallel rayon scanner
│   │       └── report.rs              # PDF/JSON reports (load-bearing test inside)
│   ├── strata-engine-adapter/          # IPC bridge for Forge desktop
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── plugins.rs             # Has pre-existing type_complexity warning line 50
│   │       └── csam.rs                # CSAM IPC commands (NEW in v1.4.0)
│   ├── strata-fs/                      # VirtualFileSystem + EvidenceSource
│   ├── strata-license/                 # Ed25519 license keypair
│   │   └── tests.rs                   # Has pre-existing macOS machine-ID failures
│   ├── strata-plugin-sdk/              # StrataPlugin trait + PluginTier enum
│   └── strata-shield-engine/           # Shield analysis engine
│       └── tests/
│           └── vhd_integration_tests.rs # Has pre-existing single_match warning line 92
├── plugins/
│   ├── strata-plugin-csam/             # CSAM Sentinel plugin (NEW in v1.4.0)
│   ├── strata-plugin-guardian/         # Windows Defender, AV/EDR
│   │   └── src/lib.rs                 # Has pre-existing doc_overindented warnings (6 sites)
│   ├── strata-plugin-phantom/          # Windows Registry
│   │   └── src/lib.rs                 # Has pre-existing doc_overindented + needless_lifetimes
│   ├── strata-plugin-sigma/            # Sigma correlation rules (29 rules, always last)
│   │   └── src/lib.rs                 # Rules 28+29 are CSAM rules — DO NOT MODIFY
│   └── strata-plugin-*/               # All other plugins
└── .github/
    └── workflows/                      # CI: macOS ✅ Linux ✅ Windows ✅
```

---

## CURRENT BUILD STATE — v1.4.0

```
cargo test --workspace    → 871 passing, 4 pre-existing failures (platform-gated)
cargo clippy --workspace  → 16 pre-existing warnings (none in v1.4.0 work)
Binary: macOS 24MB · Windows 26.5MB · Linux 39.1MB
CI: macOS ✅ Linux ✅ Windows ✅
```

---

## LOAD-BEARING TESTS — DO NOT REMOVE EVER

These three tests are permanent. They cannot be removed, renamed, or weakened.
Each has a comment in the source marking it as load-bearing:

1. `build_lines_includes_no_image_payload`
   File: `crates/strata-csam/src/report.rs`
   Why: Guarantees Strata never embeds image content in court reports.
   Court admissibility depends on this.

2. `hash_recipe_byte_compat_with_strata_tree`
   File: `crates/strata-csam/src/audit.rs`
   Why: Guarantees the CSAM audit hash chain is byte-compatible with
   the unified strata-tree audit log. Break this = broken chain of custody.

3. `rule_28_does_not_fire_with_no_csam_hits`
   File: `plugins/strata-plugin-sigma/src/lib.rs`
   Why: Guarantees Sigma CSAM rules require subcategory == "CSAM Hit".
   Without this, any record with [confidence=Confirmed] in its detail
   could silently fire CSAM rules on unrelated data.

---

## PRE-EXISTING ISSUES — DO NOT FIX UNLESS ASSIGNED

These exist before your work. Do not touch them unless your task explicitly
says to fix them. Do not introduce new ones.

### Clippy warnings (16 total):
1.  `crates/strata-core/src/parsers/evtx.rs:76` — manual_range_patterns
2.  `crates/strata-engine-adapter/src/plugins.rs:50` — type_complexity
3.  `crates/strata-shield-engine/src/tests/integration_tests.rs:2` — module_inception
4.  `crates/strata-shield-engine/tests/vhd_integration_tests.rs:92` — single_match
5-10. `plugins/strata-plugin-guardian/src/lib.rs` — doc_overindented_list_items (6 sites)
11-16. `plugins/strata-plugin-phantom/src/lib.rs` — doc_overindented_list_items + needless_lifetimes

### Test failures (4 total — platform-gated):
1. `ui::dialogs::carve_dialog::tests::carve_default_output_uses_non_c_evidence_drive`
   Reason: Asserts Windows drive letter "F:", fails on macOS. Missing #[cfg(windows)].
2. `tests::test_machine_id_generation` (strata-license)
   Reason: macOS machine ID generation. Pre-existing.
3. `tests::test_machine_id_consistency` (strata-license)
   Reason: Same.
4. `classification::recyclebin::tests::extract_sid_from_path_detects_sid_component`
   Reason: SID parser test. Pre-existing.

---

## CODING RULES — NON-NEGOTIABLE

### Rust standards
- Zero new `cargo clippy` warnings. Run `cargo clippy -p <crate> --all-targets` after every change.
- Zero new test failures. Run `cargo test -p <crate>` after every change.
- No `unwrap()` in production paths. Use `?` or explicit error handling.
- No `unsafe` blocks without explicit approval from Korbyn.
- All new public functions must have doc comments.
- All new parsers must have a minimum of 3 tests.

### Architecture rules
- EvidenceSource abstraction — NEVER read files directly. Always go through
  the EvidenceSource VFS. This is what makes air-gap work.
- Streaming reads — use `read_file_range()` for large files. Never load
  an entire evidence image into memory.
- Plugin isolation — plugins communicate through PluginOutput / ArtifactRecord.
  Never share mutable state between plugins.
- Sigma always runs last — the plugin host enforces this. Never change it.
- CSAM Sentinel is PluginTier::Free — never change this to any other tier.
  CSAM detection must always be free for all users.

### Commit rules
- One commit per logical task. Not one commit per file.
- Commit message format: `type(scope): description`
  Examples:
  - `feat(pulse): add ALEAPP AccountsGoogle parser`
  - `fix(trace): add #[cfg(windows)] gate to carve_dialog test`
  - `chore(clippy): fix pre-existing warnings in strata-core`
- Always run `cargo test -p <affected_crate>` before committing.
- Always run `cargo clippy -p <affected_crate> --all-targets` before committing.
- Never commit with failing tests that weren't already failing before your work.
- Never commit binary files, target/ directory, or .env files.

### CSAM module rules (extra strict)
- Never auto-display matched images. The review modal requires explicit examiner action.
- Every CSAM hit must go through `publish_csam_plugin_output()` in state_csam.rs.
- The detail format `[match_type=X] [confidence=Y] [source=Z] [sha256=...]` is
  load-bearing. Never change it without updating Sigma rules 28+29 in lockstep.
- Every CSAM report must include the 18 U.S.C. § 2258A mandatory reporting notice.
- The three load-bearing tests (listed above) must pass after any CSAM work.

---

## PLUGIN ARCHITECTURE

### How plugins work
```rust
// Plugin trait (strata-plugin-sdk/src/lib.rs)
pub trait StrataPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn run(&self, context: PluginContext) -> PluginOutput;
    fn required_tier(&self) -> PluginTier { PluginTier::Professional } // default
}

// CSAM Sentinel overrides to Free:
fn required_tier(&self) -> PluginTier { PluginTier::Free }
```

### Plugin output format
```rust
// ArtifactRecord fields:
category: ArtifactCategory  // Media, Network, Registry, etc.
subcategory: String          // e.g. "CSAM Hit", "EVTX Match"
forensic_value: ForensicValue // Critical, High, Medium, Low
mitre_technique: Option<String>
is_suspicious: bool
detail: String               // bracket-delimited for CSAM, free text for others
```

### Adding a new parser to an existing plugin
1. Add the parser function to the relevant plugin crate
2. Register it in the plugin's `run()` method
3. Return `ArtifactRecord`s via `PluginOutput`
4. Add at minimum 3 tests in a `#[cfg(test)]` module
5. Run clippy and test before committing

### Adding a new artifact category (app schema parser)
For ALEAPP-style Android parsers (add to strata-plugin-pulse or new crate):
```rust
// Pattern: path glob → SQLite query → ArtifactRecord fields
const DB_PATH: &str = "*/com.android.appname/databases/database.db";
const QUERY: &str = "SELECT field1, field2, timestamp FROM table_name";

pub fn parse_appname(evidence: &EvidenceSource) -> Vec<ArtifactRecord> {
    // 1. Find database via evidence.find_files(DB_PATH)
    // 2. Open with rusqlite
    // 3. Execute QUERY
    // 4. Map rows to ArtifactRecord
    // 5. Return Vec<ArtifactRecord>
}
```

---

## EVIDENCE SOURCE PATTERN

```rust
// ALWAYS use this pattern — never raw file access
let files = evidence.find_files("*/path/to/artifact.*");
for file_path in files {
    let data = evidence.read_file_range(&file_path, 0, size)?;
    // process data
}
```

---

## SIGMA RULES PATTERN

When adding a new Sigma rule to `plugins/strata-plugin-sigma/src/lib.rs`:

```rust
// Pattern used by all 29 existing rules:
let matching_records: Vec<_> = prior_results
    .iter()
    .flat_map(|output| &output.records)
    .filter(|r| {
        r.subcategory == "Your Subcategory"
            && r.detail.contains("[your_field=value]")
    })
    .collect();

if !matching_records.is_empty() {
    let mut a = Artifact::new("Sigma Rule", "sigma");
    a.add_field("title", "RULE FIRED: Your Rule Name");
    a.add_field("detail", &format!(
        "Found {} matching records. [narrative explaining what this means]",
        matching_records.len()
    ));
    a.add_field("file_type", "Sigma Rule");
    a.add_field("suspicious", "true");
    results.push(a);
}
```

---

## KNOWN ARCHITECTURAL NOTES

### strata-tree (egui app)
- Single-threaded egui — no case-level mutex. Per-evidence inner mutex on engine-adapter side.
- CSAM events route through `log_action()` directly — no separate flush.
- Plugin results stored in `self.plugin_results` — CSAM replaces prior entry on re-scan.
- Lock order documented at top of `crates/strata-engine-adapter/src/csam.rs`.

### engine-adapter (Forge desktop)
- `plugins.rs` line 147: `prior_results: Vec::new()` — Sigma has no correlation input in Forge.
  This is a known pre-existing issue. Do NOT fix it unless assigned.
- CSAM runs through `csam.rs` IPC commands.

### strata-fs (VFS)
- `EvidenceSource` is the abstraction layer over all evidence formats.
- `read_file_range()` is the only safe way to read file content.
- Never bypass EvidenceSource even in tests — use mock evidence sources.

---

## WHAT STRATA DOES NOT DO (DO NOT IMPLEMENT WITHOUT APPROVAL)

- No live device acquisition (hardware required)
- No cloud API connections (air-gap by design)
- No auto-posting to external services
- No telemetry, phone-home, or usage tracking of any kind
- No license server calls
- No network requests during evidence analysis

---

## CURRENT DEVELOPMENT PRIORITIES

### v1.5.0 targets (implement in this order):
1. Fix 16 pre-existing clippy warnings
2. Fix 4 platform-gated test failures (add #[cfg] gates)
3. Large evidence audit (read ~/Wolfmark/opus_large_evidence_audit.md)
4. UFDR ingestion — parse Cellebrite UFDR (ZIP + report.xml path reconstruction)
5. Volume snapshot architecture (index all metadata first, never re-read)
6. VSS (Volume Shadow Copy) support
7. 100+ new app artifact parsers from ALEAPP/iLEAPP schemas
8. UI redesign to Wolfmark dark aesthetic
9. Regression test corpus in CI

### Artifact parser targets (study these open source repos):
- ALEAPP: github.com/abrignoni/ALEAPP — Android SQLite parsers
- iLEAPP: github.com/abrignoni/iLEAPP — iOS SQLite/plist parsers
- mac_apt: github.com/ydkhatri/mac_apt — macOS artifact parsers
- ForensicArtifacts: github.com/ForensicArtifacts/artifacts — YAML definitions
- EricZimmerman tools: github.com/EricZimmerman — Windows artifact schemas

---

## SECURITY AND LEGAL

- Copyright: US Copyright Office Case #1-15137320181 (registered 2026-04-08)
- License keys: Ed25519 keypair in ~/Wolfmark/keys/ — NEVER commit these
- Never commit .env files, API keys, or credentials of any kind
- CSAM hash databases: NEVER bundled with Strata. Examiner imports their own.
- The CSAM module is designed to comply with 18 U.S.C. § 2258A mandatory reporting

---

## VERIFICATION CHECKLIST (run before every commit)

```bash
# 1. Clippy — zero new warnings
cargo clippy -p <your_crate> --all-targets 2>&1 | grep "^warning" | grep -v "pre-existing"

# 2. Tests — zero new failures
cargo test -p <your_crate> 2>&1 | tail -5

# 3. Load-bearing tests still pass (if you touched CSAM or Sigma)
cargo test -p strata-csam build_lines_includes_no_image_payload
cargo test -p strata-csam hash_recipe_byte_compat_with_strata_tree
cargo test -p strata-plugin-sigma rule_28_does_not_fire_with_no_csam_hits

# 4. Build still compiles
cargo check -p strata
```

---

## DAILY LOG FORMAT

After completing work, write a daily log to:
`~/Wolfmark/strata/logs/DAILY_LOG_YYYY-MM-DD.md`

Format:
```markdown
# Strata Daily Log — YYYY-MM-DD

## Completed
- [list of completed tasks with commit hashes]

## Test counts
- Before: XXX passing
- After: XXX passing
- New tests added: XX

## Clippy
- New warnings introduced: 0
- Pre-existing warnings remaining: 16

## Highlights for Herald
[2-3 postable technical highlights for social media]

## Blockers
[anything that needs Korbyn's decision]
```

---

## CONTACT

Korbyn reviews every commit. If something is ambiguous — stop and document
the ambiguity in the daily log rather than guessing. Wrong assumptions in
forensic tools have real consequences.

wolfmarksystems.com | contact@wolfmarksystems.com | @WolfmarkSystems
