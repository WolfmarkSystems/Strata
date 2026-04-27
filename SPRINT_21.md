# Sprint 21 — Full Integration Audit + Health Check
# FOR CODEX — Read AGENTS.md before starting

_Date: 2026-04-26_
_Agent: Codex (OpenAI)_
_Approved by: KR_
_Working directory: ~/Wolfmark/strata/_

---

## Before you start

1. Read AGENTS.md completely
2. Run `git pull`
3. Run `cargo test -p strata-shield-engine --test quality_gate`
4. Run `cargo test --workspace 2>&1 | tail -5`
5. Both must pass. Baseline: 4,017 tests.

---

## Hard rules

- Zero new `.unwrap()` in production code
- Zero new `unsafe{}` without justification
- Zero new `println!` in library code
- Quality gate must pass after every priority
- All 9 load-bearing tests must always pass
- `cargo clippy --workspace -- -D warnings` clean
- `npm run build --prefix apps/strata-ui` clean
- Do NOT use `git add -A` — stage only files you modified

---

## PURPOSE OF THIS SPRINT

Strata has grown rapidly across Sprints 8-20. This sprint is a
full integration audit — not new features, but ensuring everything
that was built actually works correctly together.

Specifically:

1. Every plugin in the registry runs without panic on real evidence
2. The plugin count in CLAUDE.md is accurate
3. New plugins (ARBOR, Sprint 20 additions) are fully wired
4. The UI correctly displays all artifact categories
5. The report system includes all new artifact types
6. The quality gate reflects the real codebase state
7. AUGUR plugin integration compiles and doesn't break the build
8. Charlie and MacBookPro fixture counts are documented

This is the sprint that proves the codebase is solid before
we tag v1.0.0.

---

## PRIORITY 1 — Plugin Registry Audit

### Step 1 — Count and verify all plugins

```bash
# Count plugin directories
ls plugins/ | grep strata-plugin | grep -v "tree-example\|index"

# Count plugins registered in engine adapter
grep -n "plugin_name\|PLUGIN_NAMES\|\"Phantom\"\|\"ARBOR\"\|\"Vault\"\|\"Vector\"" \
    crates/strata-engine-adapter/src/plugins.rs | head -40

# Count plugins in frontend
grep -n "name:\|pluginName" \
    apps/strata-ui/src/data/ -r --include="*.ts" | head -40
```

Document the exact list:
- How many plugin directories exist?
- How many are registered in `plugins.rs`?
- How many are in the frontend PLUGIN_DATA?
- Are all three counts the same?

### Step 2 — Fix any mismatches

If a plugin exists on disk but isn't registered → add it.
If a plugin is registered but doesn't exist → remove dead entry.
If frontend count doesn't match backend → sync them.

**Known plugins as of Sprint 20:**

Backend plugins (should all be registered):
```
strata-plugin-apex        iOS system + Apple apps
strata-plugin-arbor       Linux forensics (new Sprint 20)
strata-plugin-carbon      Android system + Google apps
strata-plugin-chronicle   Windows user activity
strata-plugin-cipher      Windows credentials
strata-plugin-conduit     Network artifacts
strata-plugin-csam        CSAM detection
strata-plugin-guardian    Windows AV/EDR
strata-plugin-mactrace    macOS system
strata-plugin-netflow     Network forensics
strata-plugin-nimbus      Cloud + enterprise
strata-plugin-phantom     Windows registry
strata-plugin-pulse       Third-party apps
strata-plugin-recon       Identity extraction
strata-plugin-remnant     Deleted files
strata-plugin-sentinel    Event logs (EVTX)
strata-plugin-sigma       Correlation engine
strata-plugin-specter     Mobile/gaming
strata-plugin-trace       Windows execution
strata-plugin-vault       Hidden storage + crypto + financial
strata-plugin-vector      Malware + Tor/dark web
strata-plugin-wraith      Memory forensics
```

### Step 3 — Update CLAUDE.md plugin count

Find the plugin count reference in CLAUDE.md and update to the
correct number. It should say exactly how many forensic plugins
exist, what they are, and what each owns.

### Step 4 — Verify plugin registry ordering

The plugin registry should run plugins in a logical order:
1. File system plugins first (they index files)
2. Registry plugins next (they need the file index)
3. Application plugins (depend on file paths)
4. Correlation/SIGMA last (depends on all other results)

Check `plugins.rs` ordering and fix if Sigma/correlation runs
before the artifact plugins it correlates.

### Tests

```rust
#[test]
fn all_registered_plugins_have_valid_names() {
    // Every plugin in PLUGIN_REGISTRY has a non-empty name
    // and non-empty version
    for plugin in PLUGIN_REGISTRY.iter() {
        assert!(!plugin.name().is_empty());
        assert!(!plugin.version().is_empty());
    }
}

#[test]
fn plugin_count_matches_expected() {
    // Update this number after the audit
    assert_eq!(PLUGIN_REGISTRY.len(), /* correct count */);
}
```

### Acceptance criteria — P1

- [ ] Exact plugin count documented
- [ ] All plugins registered in backend
- [ ] Frontend plugin count matches backend
- [ ] CLAUDE.md plugin count accurate
- [ ] Sigma runs last in registry order
- [ ] 2 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 2 — New Plugin Wire-Up Verification

### Context

Sprints 14-20 added many new parsers. This priority verifies
each new addition is correctly wired — not just implemented but
actually running and producing artifacts.

### Step 1 — ARBOR plugin verification

```bash
# Verify ARBOR is in workspace
grep "strata-plugin-arbor" Cargo.toml

# Verify ARBOR is in engine adapter
grep "arbor\|ARBOR\|Arbor" crates/strata-engine-adapter/src/plugins.rs

# Check ARBOR artifacts show in UI categories
grep -rn "Linux\|arbor\|ARBOR" \
    apps/strata-ui/src/data/ --include="*.ts" | head -10
```

If ARBOR isn't in the workspace `Cargo.toml` members list → add it.
If ARBOR isn't in `plugins.rs` → add it.
If "Linux" category isn't in frontend → add it to PLUGIN_DATA.

### Step 2 — Vault plugin crypto/financial verification

Sprint 20 added `crypto_wallets.rs` and `financial.rs` to Vault.
Verify they're wired into `plugins/strata-plugin-vault/src/lib.rs`:

```bash
grep -n "crypto_wallets\|financial\|mod " \
    plugins/strata-plugin-vault/src/lib.rs | head -20
```

If the modules aren't declared → add `mod crypto_wallets;` and
`mod financial;` and wire into `run()`.

### Step 3 — Vector plugin Tor verification

Sprint 20 added `tor.rs` to Vector.
Verify it's wired:

```bash
grep -n "tor\|mod " \
    plugins/strata-plugin-vector/src/lib.rs | head -20
```

If not wired → add `mod tor;` and call from `run()`.

### Step 4 — Sprint 14-19 feature verification

Check each major Sprint 14-19 feature is actually reaching the UI:

```bash
# Timeline view — does get_artifacts_timeline exist in lib.rs?
grep -n "get_artifacts_timeline\|artifacts_timeline" \
    apps/strata-desktop/src-tauri/src/lib.rs | head -5

# IOC search — does search_iocs exist?
grep -n "search_iocs" \
    apps/strata-desktop/src-tauri/src/lib.rs | head -5

# Custody log — does get_custody_log exist?
grep -n "get_custody_log\|custody_log" \
    apps/strata-desktop/src-tauri/src/lib.rs | head -5

# Evidence integrity — does verify_evidence_integrity exist?
grep -n "verify_evidence_integrity\|evidence_integrity" \
    apps/strata-desktop/src-tauri/src/lib.rs | head -5

# NSRL hash sets — does import_hash_set exist?
grep -n "import_hash_set\|hash_set" \
    apps/strata-desktop/src-tauri/src/lib.rs | head -5

# Artifact notes — does save_artifact_note exist?
grep -n "save_artifact_note\|artifact_note" \
    apps/strata-desktop/src-tauri/src/lib.rs | head -5
```

For any that are missing → locate the implementation and add
the Tauri command registration in `lib.rs`.

### Step 5 — Frontend IPC verification

```bash
# Check all IPC functions are exported from ipc/index.ts
grep -n "export\|getArtifactsTimeline\|searchIocs\|getCustodyLog\|importHashSet\|saveArtifactNote" \
    apps/strata-ui/src/ipc/index.ts | head -30
```

Any missing → add the TypeScript wrapper.

### Tests

```rust
#[test]
fn arbor_plugin_produces_artifacts_on_linux_paths() {
    // Create temp dir with synthetic /etc/passwd content
    // Run ARBOR plugin against it
    // Verify at least 1 artifact returned
}

#[test]
fn vault_crypto_module_detects_btc_address() {
    // Text containing BTC address
    // Run through crypto scanner
    // Verify match returned
}

#[test]
fn vector_tor_module_detects_onion_url() {
    // Synthetic places.sqlite with .onion URL
    // Run through Tor detector
    // Verify dark web artifact emitted
}
```

### Acceptance criteria — P2

- [ ] ARBOR in workspace Cargo.toml
- [ ] ARBOR in engine adapter plugin registry
- [ ] Vault crypto/financial modules wired into run()
- [ ] Vector Tor module wired into run()
- [ ] All Sprint 14-19 Tauri commands confirmed present
- [ ] All Sprint 14-19 IPC functions in ipc/index.ts
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 3 — UI Category Audit

### Context

Every new plugin and artifact type needs a corresponding UI
category. This priority ensures the frontend correctly handles
all artifact categories that plugins now produce.

### Step 1 — Audit all artifact categories

```bash
# Get all unique categories emitted by plugins
grep -rn "category.*=\|category:.*\"" \
    plugins/ crates/strata-core/ \
    --include="*.rs" | \
    grep -oP '"[^"]*"' | sort -u | head -40
```

Document every unique category string found. Then check each
exists in the frontend category definitions:

```bash
grep -rn "category\|Category" \
    apps/strata-ui/src/data/ --include="*.ts" | \
    grep -v "//\|import" | head -30
```

### Step 2 — Add missing categories to frontend

Categories that likely need adding based on Sprint 20:

```typescript
// In the appropriate data file, ensure these exist:
'Linux System',        // ARBOR
'Cryptocurrency',      // Vault crypto_wallets
'Dark Web',            // Vector tor.rs
'Financial',           // Vault financial.rs
'Network Forensics',   // NetFlow
```

Each category needs:
- Display name
- Icon (use existing icon set — don't add new deps)
- Color (use existing plugin color)
- Sort order in the sidebar

### Step 3 — Artifact detail panel audit

The artifact detail panel renders artifact fields. New artifact
types from Sprints 14-20 may have fields the panel doesn't know
about:

```bash
grep -rn "pub struct.*Artifact\|forensic_value\|mitre_technique\|confidence_score\|is_advisory" \
    crates/strata-engine-adapter/src/types.rs | head -20
```

Verify the detail panel renders:
- `confidence_score` and `confidence_basis` (Sprint 16)
- `is_advisory` with amber warning banner (Sprint 19)
- `advisory_notice` text when present
- `mitre_technique` as a clickable badge

### Step 4 — Report system category coverage

The court-ready report (Sprint 16) groups artifacts by category.
Ensure new categories appear in the report:

```bash
grep -n "category\|section\|findings" \
    apps/strata-desktop/src-tauri/src/lib.rs | \
    grep -i "report\|generate" | head -20
```

If the report hardcodes specific categories → make it dynamic
so any category with artifacts gets a section.

### Tests

```rust
#[test]
fn all_artifact_categories_have_display_names() {
    // Every category string emitted by any plugin
    // has a corresponding display name in the frontend data
    // (This is a documentation/compilation test)
}
```

### Acceptance criteria — P3

- [ ] All unique category strings documented
- [ ] Missing categories added to frontend
- [ ] Linux System, Cryptocurrency, Dark Web, Financial categories present
- [ ] Artifact detail panel renders confidence score
- [ ] Advisory artifacts show amber warning banner
- [ ] Report system dynamically includes all categories
- [ ] Quality gate passes

---

## PRIORITY 4 — Quality Gate Calibration

### Context

The quality gate runs two checks. As the codebase grew from 19
to 25 plugins across Sprints 8-20, the unwrap/unsafe baseline
may have drifted. This priority calibrates the gate to reflect
the actual current state.

### Step 1 — Run the quality gate and read the baseline

```bash
cargo test -p strata-shield-engine --test quality_gate -- --nocapture 2>&1
```

Read the exact output. What does it report for:
- Current unwrap count?
- Current unsafe count?
- Current println count?
- What are the thresholds it checks against?

### Step 2 — Check CLAUDE.md baseline numbers

```bash
grep -n "unwrap\|unsafe\|println\|baseline\|waivers" CLAUDE.md | head -20
grep -n "unwrap\|unsafe\|println\|baseline" \
    crates/strata-shield-engine/tests/quality_gate.rs | head -20
```

### Step 3 — Update waivers.toml if needed

If new legitimate uses of unwrap were added in Sprints 8-20
(e.g., in test code, CLI handlers, or with proper justification
comments), update `waivers.toml`:

```bash
cat waivers.toml 2>/dev/null || echo "no waivers.toml found"
```

The goal: the gate should pass on the current codebase and fail
if NEW unwrap/unsafe are added without justification.

Do NOT simply raise the threshold to hide problems. Only update
the baseline if you can verify each new instance is justified.

### Step 4 — Verify Charlie and MacBookPro artifact counts

Run against the test fixtures to document current baseline counts:

```bash
# If Test Material is available
ls ~/Wolfmark/Test\ Material/ 2>/dev/null | head -10
```

If Charlie.E01 or MacBookPro test material is available:
- Run a full ingest
- Document the per-plugin artifact counts
- Update CLAUDE.md with the new numbers

If test material is not available in this environment, skip
this step and note it in the report.

### Step 5 — Verify all 9 load-bearing tests still pass

```bash
cargo test -p strata-shield-engine -- --nocapture 2>&1 | head -30
```

Document which 9 tests are the load-bearing ones. If any have
been renamed or modified, restore or re-establish them.

### Tests

The quality gate IS the test for this priority. After calibration:

```bash
cargo test -p strata-shield-engine --test quality_gate 2>&1 | tail -5
```

Must show: `test result: ok. 2 passed`

### Acceptance criteria — P4

- [ ] Quality gate passes with accurate baseline
- [ ] waivers.toml updated if needed
- [ ] CLAUDE.md baseline numbers accurate
- [ ] All 9 load-bearing tests documented and passing
- [ ] No hidden threshold inflation
- [ ] Charlie/MacBookPro counts documented (or noted as unavailable)

---

## PRIORITY 5 — Uncommitted Sprint Work

### Context

Codex has been explicitly told not to use `git add -A` across
every sprint. As a result, many sprint deliverables are sitting
uncommitted in the dirty tree. This priority produces a clean
set of selective commits covering all of Sprint 8 through 20.

### Step 1 — Audit the dirty tree

```bash
git status --short | head -60
git diff --stat HEAD | head -40
```

Understand what is uncommitted and which sprint it belongs to.

### Step 2 — Produce clean commits by sprint

Group files by sprint and commit them selectively:

**Sprint 14 (if not committed):**
```bash
git add \
    apps/strata-desktop/src-tauri/src/lib.rs \
    apps/strata-ui/src/views/TimelineView.tsx \
    apps/strata-ui/src/views/IocHuntView.tsx \
    apps/strata-ui/src/views/CustodyLogView.tsx \
    crates/strata-engine-adapter/src/custody.rs \
    plugins/strata-plugin-pulse/src/macos_social.rs \
    plugins/strata-plugin-pulse/src/lib.rs
git commit -m "feat: sprint-14 social media + timeline + IOC hunt + custody log"
```

**Sprint 15 (if not committed):**
```bash
git add \
    crates/strata-engine-adapter/src/evidence.rs \
    crates/strata-engine-adapter/src/hash_sets.rs \
    apps/strata-ui/src/views/SettingsView.tsx \
    apps/strata-ui/src/components/ArtifactDetail.tsx
git commit -m "feat: sprint-15 evidence integrity + NSRL hash sets + artifact notes"
```

**Sprint 16 (if not committed):**
```bash
git add \
    plugins/strata-plugin-mactrace/src/identity.rs \
    crates/strata-engine-adapter/src/types.rs \
    apps/strata-ui/src/components/ArtifactResults.tsx \
    apps/strata-ui/src/components/TopBar.tsx
git commit -m "feat: sprint-16 court-ready reports + confidence scoring + keychain depth"
```

Continue for Sprints 17, 18, 19, 20 using the same selective
staging pattern. Check `git log --oneline -20` to see what is
already committed before staging anything.

**Critical:** Only stage files that belong to each sprint.
Use `git diff <file>` to verify content before staging.

### Step 3 — Verify clean tree

After all commits:
```bash
git status --short
git log --oneline -10
```

The working tree should be clean or have only intentionally
untracked files.

### Acceptance criteria — P5

- [ ] All sprint work from 14-20 committed
- [ ] Each commit message clearly identifies the sprint
- [ ] No mixed-sprint commits
- [ ] Clean working tree after all commits
- [ ] `git log --oneline -10` shows sprint history clearly
- [ ] Tests still pass after all commits applied

---

## PRIORITY 6 — CLAUDE.md Ground Truth Update

### Context

CLAUDE.md is the source of truth that guides all future agent
sessions. After 12 sprints of rapid development, it needs to
be updated to reflect the actual current state.

### What to update in CLAUDE.md

**Plugin list:** Update to exact current plugin list with
correct count, ownership, and file paths.

**Test count:** Update from whatever old number is there to 4,017.

**Feature list:** Add the major features shipped in Sprints 14-20:
- Timeline view
- IOC hunt
- Chain of custody log
- Evidence integrity verification
- NSRL hash set import
- Artifact notes
- Court-ready report system
- Artifact confidence scoring
- macOS keychain depth (genp/inet/cert)
- AmCache.hve parser
- Full USB device artifact chain
- EVTX structured analytics
- MRU registry keys (5 types)
- Zone.Identifier ADS parser
- Thumbcache parser
- LNK deep parsing
- AUGUR plugin (#24)
- ARBOR plugin (Linux forensics)
- Cryptocurrency artifact detection
- Tor/dark web artifact detection
- Financial artifact detection

**Version:** Update to current version (should be v0.16.0 or
determine the correct current version from git tags).

**Quality gate baseline:** Update the unwrap/unsafe/println
counts to match current actual state.

**Hard rules section:** Verify the 9 hard rules are still
accurate and add any new ones established during sprints.

### Acceptance criteria — P6

- [ ] CLAUDE.md plugin count accurate
- [ ] CLAUDE.md test count accurate (4,017)
- [ ] CLAUDE.md feature list includes all Sprint 14-20 features
- [ ] CLAUDE.md version accurate
- [ ] CLAUDE.md quality gate baseline accurate
- [ ] CLAUDE.md committed with `docs: update CLAUDE.md to sprint-20 state`

---

## After all priorities complete

```bash
cargo test --workspace 2>&1 | grep "test result" | grep "passed" | \
    awk -F' ' '{sum += $4} END {print sum " total passing"}'
cargo test -p strata-shield-engine --test quality_gate 2>&1 | tail -3
cargo clippy --workspace -- -D warnings 2>&1 | grep "^error" | head -5
npm run build --prefix apps/strata-ui 2>&1 | tail -3
git status --short | wc -l
git log --oneline -10
```

Report:
- Exact plugin count (backend + frontend)
- Any plugins that were missing and were added
- Any uncommitted sprint work found and committed
- Quality gate calibration results
- CLAUDE.md changes made
- Whether the working tree is clean

---

## What this sprint is NOT

- Not new features
- Not new parsers
- Not new UI components
- Not performance optimization

This sprint is about proving what we built actually works
correctly together as a complete system. Every feature from
Sprint 14-20 should be verifiably present and integrated.

After this sprint passes, Strata is ready for v1.0.0 tag
consideration.

---

_Sprint 21 for Codex — read AGENTS.md first_
_KR approval: granted_
_This is the integration audit. Do it thoroughly._
_Quality over speed on this one._
