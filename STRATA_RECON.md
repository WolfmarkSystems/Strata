# Strata Reconnaissance — Full Codebase State Report
# FOR CODEX — Read AGENTS.md before starting

_Date: 2026-04-26_
_Agent: Codex (OpenAI)_
_Approved by: KR_
_Working directory: ~/Wolfmark/strata/_

---

## PURPOSE

This is not a build sprint. Do not write new code.
Do not commit anything. Do not modify any files.

This is a full reconnaissance of the actual current state of
the Strata codebase. The goal is to produce an accurate picture
of what exists, what works, and what version we are really at.

Read files. Run commands. Report findings. Nothing else.

---

## SECTION 1 — Version and Tag State

```bash
# What version is the workspace at?
cat Cargo.toml | grep -E "^version|^name" | head -5

# What git tags exist?
git tag | sort -V | tail -20

# What is the latest tag?
git describe --tags --abbrev=0

# What commits are ahead of origin/main?
git log origin/main..HEAD --oneline | wc -l
git log origin/main..HEAD --oneline | head -20

# What is the last committed state?
git log --oneline -10
```

Report: exact version string, latest tag, how many commits ahead
of origin, and what those commits contain.

---

## SECTION 2 — Full Plugin Inventory

```bash
# Count all plugin directories
ls plugins/ | grep strata-plugin | grep -v "index\|tree-example"

# For each plugin, get its version and a one-line description
for p in plugins/strata-plugin-*/; do
    name=$(basename $p)
    version=$(grep "^version" $p/Cargo.toml 2>/dev/null | head -1)
    desc=$(grep "^description" $p/Cargo.toml 2>/dev/null | head -1)
    echo "$name | $version | $desc"
done
```

Report: exact count of plugins, their names, versions.

---

## SECTION 3 — Crate Inventory

```bash
# List all crates
ls crates/ | sort

# For each crate, one-line what it does
for c in crates/strata-*/; do
    name=$(basename $c)
    desc=$(grep "^description" $c/Cargo.toml 2>/dev/null | head -1)
    echo "$name | $desc"
done
```

Report: full crate list with descriptions.

---

## SECTION 4 — Application Inventory

```bash
# What apps exist?
ls apps/

# What is the tree app?
cat apps/tree/strata-tree/Cargo.toml | grep -E "^name|^version|^description" | head -5

# Does apps/tree build?
cd apps/tree/strata-tree && cargo check 2>&1 | tail -5
cd ~/Wolfmark/strata

# What is the strata-desktop app?
cat apps/strata-desktop/src-tauri/Cargo.toml | grep -E "^name|^version" | head -5

# Does strata-desktop build?
cd apps/strata-desktop/src-tauri && cargo check 2>&1 | tail -5
cd ~/Wolfmark/strata
```

Report: all apps, what they are, whether they build.

---

## SECTION 5 — Feature Inventory

Run targeted searches for major features to understand what
actually exists vs what was built in recent sprints.

```bash
# APFS walker
ls crates/strata-fs/src/apfs_walker/ 2>/dev/null
grep -rn "apfs\|APFS" crates/strata-fs/src/ --include="*.rs" | wc -l

# ML systems
ls crates/ | grep strata-ml

# Charges / case building
ls crates/strata-charges/ 2>/dev/null
cat crates/strata-charges/src/lib.rs 2>/dev/null | head -20

# Warrant generation
ls crates/strata-core/src/warrant/ 2>/dev/null

# CSAM detection
ls crates/strata-csam/ 2>/dev/null

# Timeline
ls crates/strata-core/src/timeline/ 2>/dev/null

# IOC hunting
ls crates/strata-core/src/ioc/ 2>/dev/null

# Evidence formats
ls crates/strata-evidence/src/ 2>/dev/null

# Licensing
ls tools/wolfmark-license-gen/ 2>/dev/null

# egui tree app features
ls apps/tree/strata-tree/src/ui/ 2>/dev/null
```

Report: which major features exist, what files they contain.

---

## SECTION 6 — Pulse Plugin Depth

```bash
# Count iOS app parsers
ls plugins/strata-plugin-pulse/src/ios/ 2>/dev/null | wc -l

# Count Android app parsers
ls plugins/strata-plugin-pulse/src/android/ 2>/dev/null | wc -l

# List some of the most notable ones
ls plugins/strata-plugin-pulse/src/ios/ 2>/dev/null | head -30
ls plugins/strata-plugin-pulse/src/android/ 2>/dev/null | head -30
```

Report: exact count of iOS and Android parsers, notable ones.

---

## SECTION 7 — Test Suite Reality

```bash
# Full test count by crate
cargo test --workspace 2>&1 | grep "test result.*passed" | \
    grep -v "^$" | sort

# Quality gate state
cargo test -p strata-shield-engine --test quality_gate -- --nocapture 2>&1 | tail -10

# Clippy state
cargo clippy --workspace -- -D warnings 2>&1 | grep "^error" | wc -l
```

Report: test count per crate, quality gate status, clippy errors.

---

## SECTION 8 — Dirty Tree Summary

```bash
# How many files are in each state?
git status --short | cut -c1-2 | sort | uniq -c

# What are the major categories of dirty files?
git status --short | grep "^.M" | \
    sed 's|.* plugins/strata-plugin-\([^/]*\)/.*|\1|' | \
    sort | uniq -c | sort -rn | head -20

# How many untracked sprint files?
git status --short | grep "^??" | grep "SPRINT\|SESSION\|FIELD"

# What sprint files exist untracked?
ls SPRINT_*.md 2>/dev/null
```

Report: breakdown of dirty tree by category.

---

## SECTION 9 — What Codex Has Been Building

The recent sprint work (Sprints 8-21) added parsers and features.
Verify they actually made it in:

```bash
# ARBOR plugin
ls plugins/strata-plugin-arbor/src/ 2>/dev/null

# Vault crypto/financial
ls plugins/strata-plugin-vault/src/ 2>/dev/null

# Vector tor
grep -l "onion\|Tor\|tor" plugins/strata-plugin-vector/src/ 2>/dev/null

# Zone.Identifier
grep -rn "zone_identifier\|ZoneIdentifier" crates/ plugins/ \
    --include="*.rs" | wc -l

# MRU parsers
grep -rn "RunMRU\|OpenSave\|LastVisited\|WordWheel" plugins/ \
    --include="*.rs" | wc -l

# AUGUR plugin wiring
grep -rn "AUGUR\|augur" crates/strata-engine-adapter/src/plugins.rs | head -5
```

Report: confirm which sprint features are present.

---

## SECTION 10 — What The Codebase Can Actually Do

```bash
# Run against Charlie fixture if available
ls ~/Wolfmark/Test\ Material/ 2>/dev/null | head -10

# Check if the tree app has a working CLI
cd apps/tree/strata-tree
cargo run -- --help 2>&1 | head -20
cd ~/Wolfmark/strata

# What does the shield CLI do?
cd crates/strata-shield-cli
cargo run -- --help 2>&1 | head -20
cd ~/Wolfmark/strata
```

Report: what the actual executables can do.

---

## DELIVERABLE

Produce a single document called `STRATA_RECON_REPORT.md` in
the strata root directory with all findings organized under
the 10 sections above.

The report should answer:
1. What is the real version of Strata?
2. How many plugins exist and what do they cover?
3. What major features exist beyond what the sprints built?
4. What is the real state of the dirty tree?
5. Is the codebase healthy (tests passing, clippy clean)?
6. What should the next sprint focus on?

Do NOT commit anything.
Do NOT modify any files.
Do NOT write new code.

Write the report file and stop.

---

_Strata Reconnaissance — read only_
_KR approval: granted_
_Output: STRATA_RECON_REPORT.md in strata root_
