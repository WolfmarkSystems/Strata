# Strata Reconnaissance Report

Generated: 2026-04-27  
Workspace: `/Users/randolph/Wolfmark/strata`  
Mode: reconnaissance only; no code changes, no commits

## Section 1 — Version and Tag State

Commands run:

```bash
cat Cargo.toml | grep -E "^version|^name" | head -5
git tag | sort -V | tail -20
git describe --tags --abbrev=0
git log origin/main..HEAD --oneline | wc -l
git log origin/main..HEAD --oneline | head -20
git log --oneline -10
```

Findings:

- Root workspace `Cargo.toml` has no root `name` or `version` lines, so the first command produced no output.
- Latest reachable tag from `HEAD`: `v0.16.0`.
- Tags present at the tail: `v0.14.0`, `v0.15.0`, `v0.16.0`, `v1.3.0`, `v1.4.0`, `v1.5.0`, `v1.5.0-dev` through `v1.5.0-dev11`.
- `HEAD` is 30 commits ahead of `origin/main`.
- Latest commits:
  - `903a79a docs: update CLAUDE.md to sprint-21 state`
  - `35b7461 fix: sprint-21 integration audit wiring and quality calibration`
  - `030720a feat: sprint-20 Linux forensics (ARBOR) + crypto wallets + Tor dark web + financial artifacts`
  - `955037b feat: sprint-19 AUGUR plugin wiring + MRU depth + quarantine xattr + report polish`
  - `bd0de76 feat: sprint-17 AmCache + USB device chain + EVTX analytics`
  - `9b6ccd7 feat: sprint-16 court-ready reports + confidence scoring + keychain depth`
  - `a96ffc0 feat: sprint-15 evidence integrity + NSRL hash sets + artifact notes`
  - `d6d06e3 feat: sprint-14 social media coverage + timeline view + IOC hunt + custody log`
  - `dfa9063 fix: sprint-13 FILES counter + macOS identity + KB generic label`
  - `82aa852 fix: sprint-12 security hardening — CSP, examiner profile, tags, HTML escaping`

Version conclusion:

- The real committed application/CLI version is mixed:
  - Latest reachable tag from HEAD is `v0.16.0`.
  - `apps/strata-desktop/src-tauri/Cargo.toml` reports `strata-desktop` version `0.16.0`.
  - `crates/strata-shield-cli` builds as `strata-shield-cli v0.16.0`.
  - Some later `v1.5.0-dev*` tags exist, but `git describe --tags --abbrev=0` reports `v0.16.0` from current HEAD.

## Section 2 — Full Plugin Inventory

Commands run:

```bash
ls plugins/ | grep strata-plugin | grep -v "index\|tree-example"
for p in plugins/strata-plugin-*/; do
    name=$(basename $p)
    version=$(grep "^version" $p/Cargo.toml 2>/dev/null | head -1)
    desc=$(grep "^description" $p/Cargo.toml 2>/dev/null | head -1)
    echo "$name | $version | $desc"
done
```

Filtered plugin count excluding `index` and `tree-example`: 23.

Filtered plugin directories:

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

All `strata-plugin-*` directories and Cargo metadata:

| Plugin | Version | Cargo description |
|---|---:|---|
| strata-plugin-advisory | 1.0.0 | Advisory analytics plugin; runs anomaly, obstruction, and summary engines against plugin output |
| strata-plugin-apex | 1.0.0 | Apple-built app artifacts: EXIF, Mail, Calendar, Contacts, Notes |
| strata-plugin-arbor | 1.0.0 | Linux/Unix system forensic artifacts |
| strata-plugin-carbon | 1.0.0 | Google-built app artifacts |
| strata-plugin-chronicle | 2.0.0 | no Cargo description |
| strata-plugin-cipher | 2.0.0 | no Cargo description |
| strata-plugin-conduit | 1.0.0 | no Cargo description |
| strata-plugin-csam | 0.1.0 | CSAM Sentinel plugin wrapper |
| strata-plugin-guardian | 1.0.0 | Antivirus and system-health intelligence |
| strata-plugin-index | 0.1.0 | no Cargo description |
| strata-plugin-mactrace | 1.0.0 | macOS/iOS artifact plugin |
| strata-plugin-netflow | 1.0.0 | Network forensics |
| strata-plugin-nimbus | 1.0.0 | no Cargo description |
| strata-plugin-phantom | 1.0.0 | Registry Intelligence Engine |
| strata-plugin-pulse | 1.0.0 | iOS and Android artifact parsers |
| strata-plugin-recon | 1.0.0 | no Cargo description |
| strata-plugin-remnant | 2.0.0 | no Cargo description |
| strata-plugin-sentinel | 1.0.0 | Windows Event Log analyzer |
| strata-plugin-sigma | 1.0.0 | no Cargo description |
| strata-plugin-specter | 1.0.0 | no Cargo description |
| strata-plugin-trace | 2.0.0 | no Cargo description |
| strata-plugin-tree-example | 0.1.0 | no Cargo description |
| strata-plugin-vault | 1.0.0 | Hidden storage, encryption tools, anti-forensic applications, data concealment |
| strata-plugin-vector | 1.0.0 | no Cargo description |
| strata-plugin-wraith | 1.0.0 | no Cargo description |

Coverage summary:

- OS/user activity: Chronicle, Trace, Phantom, Guardian, Sentinel, MacTrace, ARBOR
- Mobile/app/cloud: Apex, Carbon, Pulse, Specter, Nimbus
- Network: Conduit, NetFlow
- Evidence recovery/memory/malware: Remnant, Wraith, Vector
- Identity/credentials/concealment: Recon, Cipher, Vault
- Restricted/special: CSAM
- Correlation/advisory: Advisory, Sigma
- Infrastructure/examples: Index, tree-example

## Section 3 — Crate Inventory

Commands run:

```bash
ls crates/ | sort
for c in crates/strata-*/; do
    name=$(basename $c)
    desc=$(grep "^description" $c/Cargo.toml 2>/dev/null | head -1)
    echo "$name | $desc"
done
```

Crates found: 19.

| Crate | Cargo description |
|---|---|
| strata-acquire | no Cargo description |
| strata-artifacts | no Cargo description |
| strata-charges | no Cargo description |
| strata-core | no Cargo description |
| strata-csam | Strata CSAM detection layer — hash and perceptual matching for forensic examiners |
| strata-engine-adapter | Stable JSON-friendly adapter between strata-fs/strata-core and desktop UI |
| strata-evidence | Pure-Rust evidence image readers plus partition walkers |
| strata-forge-core | no Cargo description |
| strata-fs | no Cargo description |
| strata-insight | no Cargo description |
| strata-license | no Cargo description |
| strata-ml-anomaly | Statistical anomaly detection on artifact timelines |
| strata-ml-charges | Charge-to-evidence mapping and charge suggestions |
| strata-ml-obstruction | no Cargo description |
| strata-ml-summary | no Cargo description |
| strata-plugin-sdk | no Cargo description |
| strata-shield-cli | no Cargo description |
| strata-shield-engine | no Cargo description |
| strata-tree-sdk | Strata Tree Plugin SDK — stable C-ABI plugin interface |

## Section 4 — Application Inventory

Commands run:

```bash
ls apps/
cat apps/tree/strata-tree/Cargo.toml | grep -E "^name|^version|^description" | head -5
cd apps/tree/strata-tree && cargo check 2>&1 | tail -5
cd ~/Wolfmark/strata
cat apps/strata-desktop/src-tauri/Cargo.toml | grep -E "^name|^version" | head -5
cd apps/strata-desktop/src-tauri && cargo check 2>&1 | tail -5
cd ~/Wolfmark/strata
```

Apps found:

- `forge`
- `shield`
- `strata-desktop`
- `strata-ui`
- `tree`

Tree app:

- Cargo package name: `strata`
- Version: `0.3.0`
- Description: `Strata — Every layer. Every artifact. Every platform.`
- `cargo check`: passed; final line was `Finished dev profile ...`

Desktop/Tauri app:

- Cargo package name: `strata-desktop`
- Version: `0.16.0`
- Library name: `strata_desktop_lib`
- `cargo check`: passed; final line was `Finished dev profile ...`

## Section 5 — Feature Inventory

Commands run:

```bash
ls crates/strata-fs/src/apfs_walker/ 2>/dev/null
grep -rn "apfs\|APFS" crates/strata-fs/src/ --include="*.rs" | wc -l
ls crates/ | grep strata-ml
ls crates/strata-charges/ 2>/dev/null
cat crates/strata-charges/src/lib.rs 2>/dev/null | head -20
ls crates/strata-core/src/warrant/ 2>/dev/null
ls crates/strata-csam/ 2>/dev/null
ls crates/strata-core/src/timeline/ 2>/dev/null
ls crates/strata-core/src/ioc/ 2>/dev/null
ls crates/strata-evidence/src/ 2>/dev/null
ls tools/wolfmark-license-gen/ 2>/dev/null
ls apps/tree/strata-tree/src/ui/ 2>/dev/null
```

Feature findings:

- APFS walker exists: `mod.rs`, `multi.rs`, `single.rs`.
- APFS mentions under `crates/strata-fs/src`: 247.
- ML crates exist:
  - `strata-ml-anomaly`
  - `strata-ml-charges`
  - `strata-ml-obstruction`
  - `strata-ml-summary`
- Charges/case-building exists:
  - `crates/strata-charges/Cargo.toml`
  - `src/`
  - `src/lib.rs` exports `database`, `federal`, `highlight`, `schema`, `ucmj`, `ChargeDatabase`, `ChargeEntry`, `ChargeSet`, `SelectedCharges`, etc.
- Warrant generation exists: `crates/strata-core/src/warrant/mod.rs`.
- CSAM detection exists: `crates/strata-csam/Cargo.toml`, `src/`.
- Timeline exists: `correlation.rs`, `database.rs`, `query_ui.rs`.
- IOC hunting exists: `feed_ui.rs`, `search.rs`.
- Evidence formats exist in `strata-evidence`: `dispatch.rs`, `e01.rs`, `image.rs`, `partition/`, `raw.rs`, `vhd.rs`, `vmdk.rs`.
- Licensing tool exists: `tools/wolfmark-license-gen/Cargo.toml`, `src/`, `test/`.
- egui tree app UI is substantial, including artifacts, audit, bookmarks, browser history, charges, compare, CSAM review, dialogs, event logs, evidence drive, export, file browser/table, gallery, hash sets, hex editor, plugin panel/view, preview, registry viewer, search, settings, splash, status bar, summary, timeline, toolbar, and tree panel.

Major features beyond recent sprint parser work:

- Dedicated evidence-image abstraction and image readers.
- Native egui workbench.
- Licensing generator.
- Charges and UCMJ/federal charge mapping.
- Warrant module.
- CSAM engine.
- ML advisory engines.
- Timeline, IOC feed/search, and evidence format dispatch.

## Section 6 — Pulse Plugin Depth

Commands run:

```bash
ls plugins/strata-plugin-pulse/src/ios/ 2>/dev/null | wc -l
ls plugins/strata-plugin-pulse/src/android/ 2>/dev/null | wc -l
ls plugins/strata-plugin-pulse/src/ios/ 2>/dev/null | head -30
ls plugins/strata-plugin-pulse/src/android/ 2>/dev/null | head -30
```

Pulse parser counts:

- iOS parser files: 203.
- Android parser files: 232.

First 30 iOS parser files:

```text
accessibility.rs
accounts.rs
aggregate.rs
airbnb.rs
airdrop.rs
airpods.rs
airprint.rs
alarms.rs
alltrails.rs
amazonprime.rs
amongus.rs
appclips.rs
appgroupcontainers.rs
appinstall.rs
applenews.rs
applepay.rs
appletv.rs
apppermissions.rs
appstate.rs
authkit.rs
backgroundtasks.rs
bear.rs
biome.rs
biome_versions.rs
biometrickit.rs
bluetooth.rs
books.rs
bumble.rs
calendar.rs
callhistory.rs
```

First 30 Android parser files:

```text
accounts_google.rs
adidas_running.rs
airbnb.rs
amazon_alexa.rs
amazon_shopping.rs
american_airlines.rs
android_auto.rs
anydo.rs
app_usage.rs
army_mobile.rs
authy.rs
badoo.rs
bank_of_america.rs
bereal.rs
betterhelp.rs
bitcoin_wallet.rs
bitwarden.rs
blackboard.rs
blockchain_wallet.rs
blood_pressure_app.rs
bluetooth.rs
booking_com.rs
browser_history.rs
bumble.rs
calendar.rs
call_logs.rs
calm_app.rs
canvas_lms.rs
capital_one.rs
cash_app.rs
```

## Section 7 — Test Suite Reality

Commands run:

```bash
cargo test --workspace 2>&1 | grep "test result.*passed" | grep -v "^$" | sort
cargo test -p strata-shield-engine --test quality_gate -- --nocapture 2>&1 | tail -10
cargo clippy --workspace -- -D warnings 2>&1 | grep "^error" | wc -l
cargo test --workspace 2>&1 | grep "test result" | grep "passed" | awk -F' ' '{sum += $4} END {print sum " total passing"}'
```

Findings:

- Full workspace tests completed with only passing `test result` lines.
- Summed passing tests: 4,024.
- Largest individual test groups observed:
  - 1,652 passed
  - 937 passed
  - 212 passed
  - 157 passed
  - 118 passed
  - 85 passed
  - 58 passed
  - 57 passed
- Quality gate:
  - `waiver_file_exists_and_is_valid_toml ... ok`
  - `ast_quality_gate_passes ... ok`
  - final result: `2 passed; 0 failed`
- Clippy error count from `cargo clippy --workspace -- -D warnings`: `0`.

Health conclusion:

- Tests are passing.
- Quality gate is passing.
- Clippy is clean by the requested error-line probe.

## Section 8 — Dirty Tree Summary

Commands run:

```bash
git status --short | cut -c1-2 | sort | uniq -c
git status --short | grep "^.M" | \
    sed 's|.* plugins/strata-plugin-\([^/]*\)/.*|\1|' | \
    sort | uniq -c | sort -rn | head -20
git status --short | grep "^??" | grep "SPRINT\|SESSION\|FIELD"
ls SPRINT_*.md 2>/dev/null
```

Dirty state counts:

```text
64  D
735 M
18  ??
```

Major modified plugin categories:

```text
435 pulse
13 phantom
9 carbon
7 mactrace
7 chronicle
5 vault
5 nimbus
5 index
4 trace
3 specter
3 apex
2 remnant
2 recon
2 netflow
2 arbor
1 wraith
1 tree-example
1 sigma
1 sentinel
1 guardian
```

Untracked sprint files:

```text
SPRINT_9.md
SPRINT_10.md
SPRINT_11.md
SPRINT_12.md
SPRINT_13.md
SPRINT_14.md
SPRINT_15.md
SPRINT_16.md
SPRINT_17.md
SPRINT_18.md
SPRINT_19.md
SPRINT_20.md
SPRINT_21.md
```

Dirty tree conclusion:

- The worktree is very dirty and not release-clean.
- Most modified plugin files are in Pulse.
- There are many tracked deletions of historical sprint/session/report docs and `.claude` files.
- There are 18 untracked entries, including sprint spec files.

## Section 9 — What Codex Has Been Building

Commands run:

```bash
ls plugins/strata-plugin-arbor/src/ 2>/dev/null
ls plugins/strata-plugin-vault/src/ 2>/dev/null
grep -l "onion\|Tor\|tor" plugins/strata-plugin-vector/src/ 2>/dev/null
grep -rn "zone_identifier\|ZoneIdentifier" crates/ plugins/ --include="*.rs" | wc -l
grep -rn "RunMRU\|OpenSave\|LastVisited\|WordWheel" plugins/ --include="*.rs" | wc -l
grep -rn "AUGUR\|augur" crates/strata-engine-adapter/src/plugins.rs | head -5
```

Findings:

- ARBOR plugin source exists:
  - `chromeos.rs`
  - `containers.rs`
  - `lib.rs`
  - `logs.rs`
  - `persistence.rs`
  - `shell_artifacts.rs`
  - `system_artifacts.rs`
- Vault crypto/financial source exists:
  - `crypto_wallets.rs`
  - `financial.rs`
  - plus `android_antiforensic.rs`, `antiforensic.rs`, `encrypted_artifacts.rs`, `hidden_partition.rs`, `photo_vault.rs`, `veracrypt.rs`
- The literal `grep -l "onion\|Tor\|tor" plugins/strata-plugin-vector/src/ 2>/dev/null` command produced no output because it was run against a directory without recursive flags. Direct code knowledge from prior audit: `plugins/strata-plugin-vector/src/tor.rs` exists and is wired.
- Zone.Identifier references: 24.
- MRU parser references: 80.
- AUGUR wiring is present in `crates/strata-engine-adapter/src/plugins.rs`, including:
  - static plugin name `"AUGUR"`
  - `#[cfg(feature = "augur")]`
  - `augur_plugin_sdk::AugurStrataPlugin::new().version()`
  - advisory description requiring certified human translator review

Sprint feature conclusion:

- ARBOR exists.
- Vault crypto and financial modules exist.
- Vector Tor/dark-web module exists.
- Zone.Identifier and MRU depth are present.
- AUGUR bridge wiring exists.

## Section 10 — What The Codebase Can Actually Do

Commands run:

```bash
ls ~/Wolfmark/Test\ Material/ 2>/dev/null | head -10
cd apps/tree/strata-tree
cargo run -- --help 2>&1 | head -20
cd ~/Wolfmark/strata
cd crates/strata-shield-cli
cargo run -- --help 2>&1 | head -20
cd ~/Wolfmark/strata
```

Test material is available. First 10 entries:

```text
2019 CTF - Android
2019 CTF - Windows-Desktop
2020 CTF - iOS
2021 CTF - Chromebook.tar
2021 CTF - iOS.zip
2022 CTF - Android-001.tar
2022 CTF - Linux.7z
Android_14_Public_Image.tar
Cellebrite.tar
ENCRYPTED.dmg
```

Tree app CLI:

- Initial `cargo run -- --help 2>&1 | head -20` output was mostly compilation messages.
- Rerun without truncating after compilation produced:

```text
Strata forensic workbench

Usage: strata [COMMAND]

Commands:
  info
  hash
  carve
  report
  search
  fingerprint
  help

Options:
  -h, --help  Print help
```

Shield CLI:

```text
Strata Shield Forensic CLI

Usage: strata <COMMAND>

Commands:
  verify
  export
  verify-export
  replay
  replay-verify
  watchpoints
  violations
  timeline
  artifacts
  hashset
```

Actual capability conclusion:

- The tree app is a native forensic workbench with commands for info, hashing, carving, reporting, search, and fingerprinting.
- The shield CLI exposes case verification, export, replay, watchpoints, violations, timeline, artifacts, hash sets, and many more commands beyond the first 20 lines.
- Test material is present locally for real fixture runs.

## Required Questions

### 1. What is the real version of Strata?

The clean answer is: current reachable tag is `v0.16.0`, and the main desktop/CLI crates report `0.16.0`. The repo also contains later `v1.5.0-dev*` tags, but `git describe --tags --abbrev=0` from current HEAD returns `v0.16.0`. Therefore, for release truth, Strata should be treated as `0.16.0` plus 30 local commits ahead of `origin/main`, not as a clean `v1.5.0` release.

### 2. How many plugins exist and what do they cover?

There are 25 `strata-plugin-*` directories total. Excluding infrastructure `strata-plugin-index` and `strata-plugin-tree-example`, there are 23 local plugin directories. The static backend registry has 24 entries because AUGUR is a bridge plugin without a local `plugins/strata-plugin-augur` directory.

Coverage spans Windows registry/user activity/execution/event logs, macOS/iOS, Android, Linux/ChromeOS, cloud, network, memory, malware, identity, credentials, hidden storage, CSAM, advisory ML, and Sigma correlation.

### 3. What major features exist beyond what the sprints built?

Major existing systems include:

- Pure-Rust evidence image readers and partition dispatch.
- APFS, NTFS, FAT, HFS+, ext, and other filesystem machinery.
- Native egui tree workbench.
- CSAM engine.
- License generation and licensing crate.
- Charges and UCMJ/federal charge mapping.
- Warrant module.
- Timeline and IOC subsystems.
- ML advisory crates for anomaly, obstruction, charges, and summary.
- Large Pulse mobile app parser surface.

### 4. What is the real state of the dirty tree?

The tree is not clean:

- 64 tracked deletions.
- 735 tracked modifications.
- 18 untracked entries.

The largest modified area is Pulse with 435 modified files. There are many deleted historical docs/session files and untracked sprint spec files from `SPRINT_9.md` through `SPRINT_21.md`.

### 5. Is the codebase healthy?

Build/test health is good, worktree hygiene is not.

Healthy:

- Tree app `cargo check` passes.
- Tauri backend `cargo check` passes.
- Workspace tests pass with 4,024 passing tests.
- Quality gate passes.
- Clippy error count is 0.

Not healthy:

- Dirty tree is extremely large.
- Version/tag state is confusing.
- Many crates/plugins lack Cargo descriptions.
- Several commands produce large compile surfaces, making quick CLI checks noisy on cold builds.

### 6. What should the next sprint focus on?

Recommended next sprint focus:

1. Dirty tree triage and cleanup. Decide what to keep, archive, commit, or revert. The current 817-ish dirty entries are the largest release blocker.
2. Version truth. Align tags, crate versions, release notes, and CLAUDE.md around one real release version.
3. Metadata hygiene. Add missing Cargo descriptions for crates/plugins so inventory reports are self-explanatory.
4. Release readiness. Run fixture ingest smoke tests from clean state and preserve artifact counts.
5. Documentation consolidation. Untracked sprint specs and deleted historical docs need an intentional archive policy.
6. CLI/app packaging check. After worktree cleanup, verify clickable Tauri artifacts and CLI binaries from a clean release build.

