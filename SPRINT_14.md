# Strata Overnight Sprint — Social Media + Memory + Timeline + Report
# Execute autonomously. Report when complete or blocked.

_Date: 2026-04-26_
_Model: claude-opus-4-7_
_Approved by: KR_
_Working directory: ~/Wolfmark/strata/_

---

## Before starting

1. Read CLAUDE.md completely
2. Read AGENTS.md completely  
3. Run `git pull` to get latest
4. Run `cargo test -p strata-shield-engine --test quality_gate`
5. Run `cargo test --workspace 2>&1 | tail -5`
6. Both must pass before any code changes

Current state:
- Version: v0.16.0
- Tests: 3,953 passing
- Quality gate: passing
- Sprints 8-13 complete
- GUI works: 31,062 artifacts on MacBookPro, 3,756 on Charlie

---

## Hard rules (absolute)

- Zero NEW `.unwrap()` in production code paths
- Zero NEW `unsafe{}` without explicit justification
- Zero NEW `println!` in production
- Quality gate must pass after every priority
- All 9 load-bearing tests must always pass
- `cargo clippy --workspace -- -D warnings` clean
- `npm run build --prefix apps/strata-ui` clean
- No new TODO/FIXME in committed code

---

## PRIORITY 1 — Social Media Artifact Coverage

### Context

The MacBookPro CTF image (31,062 artifacts) shows Social Media
category at 0. Modern forensic casework heavily involves social
media evidence. This is a major coverage gap.

### Investigation first

```bash
grep -rn "social\|twitter\|instagram\|facebook\|tiktok\|snapchat" \
    plugins/ --include="*.rs" | grep -v target | head -20

grep -rn "SocialMedia\|social_media" \
    apps/strata-ui/src/ --include="*.ts" --include="*.tsx" | head -10
```

Determine:
- What social media parsers exist (if any)?
- What databases do these apps leave on macOS/iOS?
- Which plugins currently own social media artifacts?

### macOS social media database locations

```
Twitter/X:
  ~/Library/Application Support/Twitter/
  ~/Library/Containers/com.twitter.twitter-mac/

Instagram:
  ~/Library/Application Support/Instagram/

Snapchat (iOS mirror on macOS via iCloud):
  ~/Library/Application Support/Snapchat/

TikTok:
  ~/Library/Application Support/TikTok/

Facebook Messenger:
  ~/Library/Application Support/Facebook/
  ~/Library/Application Support/Messenger/

WhatsApp (already handled by Pulse — do not duplicate):
  Already owned by Pulse plugin per CLAUDE.md
```

### What to implement

For each social media app found on the MacBookPro image or
in standard macOS paths:

1. Check if SQLite databases exist with message/activity data
2. Parse the most forensically valuable tables
3. Emit artifacts with:
   - `category: "Social Media"`
   - `artifact_type: "social_[app]_[type]"` e.g. `social_twitter_dm`
   - `mitre_technique`: T1552.003 (Credentials from Password Stores)
     or T1636.002 (Contact List) depending on content
   - `confidence: Confidence::Medium` (app DB schemas change)
   - `is_advisory: false` (deterministic parse)

Add new parsers to the appropriate plugin — check CLAUDE.md for
source file ownership before writing a new parser. If no plugin
owns social media for a given platform, add to Pulse (third-party
apps) per the ownership table.

### Tests

Minimum 3 tests:
- One per new parser added
- Each test uses hardcoded test data, not network access
- All pass without any downloads

### Acceptance criteria — P1

- [ ] At least 2 social media app parsers implemented
- [ ] Social Media category shows > 0 on MacBookPro image
- [ ] Source file ownership respected (no duplication with Pulse/MacTrace)
- [ ] MITRE technique mapping correct
- [ ] 3+ new tests pass
- [ ] Quality gate passes
- [ ] All 9 load-bearing tests green

---

## PRIORITY 2 — Unified Timeline View

### Context

Right now artifacts are browsed by category. An examiner working
a real case needs to see ALL artifacts sorted by timestamp — a
unified timeline showing exactly what happened when across all
categories. This is standard in AXIOM and Cellebrite.

### Implementation

**Backend: `get_artifacts_timeline` IPC command**

In `apps/strata-desktop/src-tauri/src/lib.rs`, add:

```rust
#[tauri::command]
async fn get_artifacts_timeline(
    evidence_id: String,
    start_ts: Option<i64>,   // Unix timestamp filter start
    end_ts: Option<i64>,     // Unix timestamp filter end
    limit: Option<usize>,    // default 500
) -> Result<Vec<ArtifactRecord>, String>
```

Implementation:
1. Collect all artifacts from ARTIFACT_CACHE for the evidence_id
2. Filter to only artifacts with a timestamp (skip None/0)
3. Sort by timestamp ascending
4. Apply start_ts/end_ts filter if provided
5. Apply limit (default 500 to prevent UI overload)
6. Return sorted slice

**Frontend: Timeline view**

Add a new view accessible via the left sidebar icon (clock icon).
The timeline view shows:

```
TIMELINE — 3,247 events with timestamps

TIMESTAMP           ARTIFACT                    CATEGORY        SOURCE
2025-11-04 17:19   iMessage 6700: Nice!...     Communications  MacTrace
2025-11-04 17:20   iMessage 6700: Mint Mob...  Communications  MacTrace  
2025-11-25 09:00   File accessed: report.pdf   User Activity   Chronicle
2025-11-25 09:01   LNK → winword.exe           User Activity   Chronicle
2025-11-26 19:57   iMessage ?: STOP            Communications  MacTrace
```

- Click any row → shows artifact detail in right panel
- Filter bar at top: date range picker
- "Jump to date" input
- Export button (exports filtered timeline as CSV)

**Wire into IPC**

Add `getArtifactsTimeline` to `apps/strata-ui/src/ipc/index.ts`
and register the Tauri command.

### Tests

```rust
#[test]
fn timeline_sorts_artifacts_chronologically() {
    // 5 artifacts with mixed timestamps
    // Verify sorted ascending
}

#[test]
fn timeline_filters_by_date_range() {
    // 10 artifacts spanning 10 days
    // Filter to 3-day range
    // Verify only matching artifacts returned
}

#[test]
fn timeline_excludes_artifacts_without_timestamps() {
    // Mix of timestamped and null-timestamp artifacts
    // Verify null-timestamp ones excluded from timeline
}
```

### Acceptance criteria — P2

- [ ] `get_artifacts_timeline` IPC command returns sorted artifacts
- [ ] Timeline view renders in frontend
- [ ] Date range filter works
- [ ] Clicking timeline row shows artifact detail
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 3 — Global IOC Search

### Context

Incident responders working malware cases need to search for
Indicators of Compromise (IOCs) across all evidence at once.
An examiner should be able to paste a list of IPs, domains,
hashes, or filenames and see every artifact that matches.

### Implementation

**Backend: `search_iocs` IPC command**

```rust
#[derive(serde::Deserialize)]
pub struct IocQuery {
    pub indicators: Vec<String>,  // IPs, domains, hashes, filenames
    pub evidence_id: String,
}

#[derive(serde::Serialize)]
pub struct IocMatch {
    pub indicator: String,
    pub artifact: ArtifactRecord,
    pub match_field: String,    // "value", "name", "source_path"
    pub confidence: String,     // "exact" or "partial"
}

#[tauri::command]
async fn search_iocs(query: IocQuery) -> Result<Vec<IocMatch>, String>
```

Implementation:
1. For each artifact in ARTIFACT_CACHE for the evidence_id
2. For each IOC in the query:
   - Check if IOC appears in artifact.value (case insensitive)
   - Check if IOC appears in artifact.name
   - Check if IOC appears in artifact.source_path
3. Return all matches with which field matched

**Frontend: IOC search panel**

Add to the search bar area or as a dedicated "IOC Hunt" tab.
Input: multiline textarea (one IOC per line)
Output: table of matches grouped by IOC

Example:
```
Searching 47 IOCs across 31,062 artifacts...

192.168.1.100 — 3 matches
  → Network Artifact: TCP connection to 192.168.1.100:443  [Conduit]
  → User Activity: LNK → \\192.168.1.100\share\malware.exe [Chronicle]
  → Web Activity: http://192.168.1.100/payload.php          [Vector]

evilhash.exe — 1 match
  → Execution History: PE Analysis: evilhash.exe            [Vector]
```

### Tests

```rust
#[test]
fn ioc_search_finds_exact_ip_match() {
    // Artifact with "192.168.1.100" in value
    // Search for "192.168.1.100"
    // Verify match returned
}

#[test]
fn ioc_search_is_case_insensitive() {
    // Artifact with "MALWARE.EXE" in name
    // Search for "malware.exe"
    // Verify match returned
}

#[test]
fn ioc_search_returns_no_matches_for_clean_evidence() {
    // Search for IOC not present in any artifact
    // Verify empty results, no panic
}
```

### Acceptance criteria — P3

- [ ] `search_iocs` command searches across all cached artifacts
- [ ] IP addresses, domains, hashes, filenames all searchable
- [ ] Case insensitive matching
- [ ] Results grouped by IOC in frontend
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 4 — Chain of Custody Logging

### Context

For court-admissible evidence, every action an examiner takes
must be logged with timestamp, examiner identity, and action
description. This is chain of custody documentation.

### Implementation

**Backend: custody log**

Add `crates/strata-engine-adapter/src/custody.rs`:

```rust
use std::sync::Mutex;
use once_cell::sync::Lazy;

#[derive(serde::Serialize, Clone)]
pub struct CustodyEntry {
    pub timestamp: i64,          // Unix timestamp
    pub examiner: String,        // from ExaminerProfile
    pub action: String,          // "evidence_loaded", "plugin_run", etc
    pub evidence_id: String,
    pub details: String,
    pub hash_before: Option<String>, // for evidence integrity
    pub hash_after: Option<String>,
}

static CUSTODY_LOG: Lazy<Mutex<Vec<CustodyEntry>>> =
    Lazy::new(|| Mutex::new(Vec::new()));

pub fn log_custody(entry: CustodyEntry) {
    if let Ok(mut log) = CUSTODY_LOG.lock() {
        log.push(entry);
    }
}

pub fn get_custody_log(evidence_id: &str) -> Vec<CustodyEntry> {
    CUSTODY_LOG.lock()
        .map(|log| log.iter()
            .filter(|e| e.evidence_id == evidence_id)
            .cloned()
            .collect())
        .unwrap_or_default()
}
```

**Log these events automatically:**
- Evidence loaded (with file path and hash)
- Plugin run started
- Plugin run completed (with artifact count)
- Report generated (with output path)
- Hash All triggered
- Export triggered

**IPC command: `get_custody_log`**

```rust
#[tauri::command]
async fn get_custody_log(evidence_id: String) 
    -> Result<Vec<CustodyEntry>, String>
```

**Frontend: Custody Log tab**

In the notes/annotation area or as a dedicated tab, show the
chain of custody log for the current evidence. Each entry shows
timestamp, examiner, action, details. Export as PDF or JSON.

### Tests

```rust
#[test]
fn custody_log_records_evidence_load() {
    // Load evidence, verify custody entry created
}

#[test]
fn custody_log_is_append_only() {
    // Log 3 entries, verify all 3 present and in order
}
```

### Acceptance criteria — P4

- [ ] Custody log records evidence load, plugin runs, exports
- [ ] `get_custody_log` IPC command returns entries
- [ ] Frontend shows custody log for current evidence
- [ ] Log is append-only (no edits or deletions)
- [ ] 2 new tests pass
- [ ] Quality gate passes

---

## After all priorities complete

```bash
cargo test --workspace 2>&1 | grep "test result" | head -5
cargo test -p strata-shield-engine --test quality_gate 2>&1 | tail -3
cargo clippy --workspace -- -D warnings 2>&1 | grep "^error" | head -5
npm run build --prefix apps/strata-ui 2>&1 | tail -3
```

All must pass. Then commit:

```bash
git add -A
git commit -m "feat: sprint-14 social media coverage + timeline view + IOC search + custody log"
```

Report:
- Which priorities passed
- Test count before and after (should be 3,953 → 3,964+)
- Social Media category count on MacBookPro image
- Timeline view screenshot description
- Any deviations from spec

---

## What this sprint does NOT touch

- exFAT walker (dedicated sprint)
- Memory dump ingestion (.mem/.dmp)
- DMG decompression
- VERIFY code (separate repo)
- The 9 load-bearing tests (never modify)
- waivers.toml baseline (never raise)
- CLAUDE.md (never modify without KR approval)

---

_Sprint 14 authored by: Claude (architect) + KR (approved)_
_Execute autonomously. Only stop for hard rule violations_
_or architectural decisions not covered by this spec._
_This is an overnight run. Go deep._
