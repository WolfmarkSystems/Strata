# Strata GUI-CLI Contract Checklist

**Document Type:** GUI-CLI Contract Validation Checklist  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Purpose:** Verify GUI pages do not overclaim beyond what CLI commands return

---

## Purpose

The GUI is a view on CLI output. Every claim the GUI makes must be traceable to a CLI command response. This checklist validates that GUI pages correctly interpret CLI contracts and do not exceed their bounds.

Strata uses this checklist to:
- Audit existing GUI pages
- Validate new page implementations
- Identify GUI-CLI contract mismatches

---

## Section 1: Command Adapter Mode Checks

### 1.1: Envelope vs Raw JSON Identification
**Why it matters:** GUI must know whether to parse the full envelope or raw JSON.

**What to check:**
- Pages using `--json-result` parse `CliResultEnvelope` structure
- Pages using `--stdout-json` parse direct JSON response
- Pages using `--stdout-text` display as-is, not parse

**Signs of failure:**
- GUI expects envelope fields from stdout_json command
- GUI tries to parse text output as JSON

**Pass criteria:** Each page's command adapter matches command output mode

**When to escalate:** If command output mode is misidentified

---

### 1.2: Required Envelope Fields Presence
**Why it matters:** GUI must check for required fields before using them.

**What to check:**
- GUI checks `envelope.status` before displaying data
- GUI checks `envelope.error` before assuming success
- GUI handles `data: None` gracefully

**Signs of failure:**
```javascript
// BAD: Assuming data exists
const entries = response.data.entries;  // Crashes if data is null

// BAD: Ignoring error field
displayData(response.data);  // Error might be ignored
```

**Pass criteria:**
```javascript
// CORRECT: Checking status first
if (response.status === "error") {
    displayError(response.error);
    return;
}
const entries = response.data?.entries ?? [];
```

**When to escalate:** If missing field causes crash or incorrect display

---

### 1.3: Warning Field Surfacing
**Why it matters:** Warnings indicate partial success or noteworthy conditions.

**What to check:**
- GUI displays warning banner when `envelope.warning` is present
- Warning does not prevent data display (warnings coexist with "ok")
- Warning text is visible, not hidden in console

**Signs of failure:**
- Warning field silently dropped
- Warning only logged, not displayed
- Warning treated as error (prevents display)

**Pass criteria:** Warning banner visible in UI when `envelope.warning` present

**When to escalate:** If warnings are dropped

---

## Section 2: Required Context Checks

### 2.1: Case/Database Context
**Why it matters:** Most commands require a loaded case or evidence.

**What to check:**
- Pages verify case is loaded before making case-dependent commands
- Pages show "no case loaded" state when appropriate
- Commands include required `--case` argument

**Signs of failure:**
- Page makes command without case context
- "No case" state shows stale data
- Missing case argument causes CLI error

**Pass criteria:** Pages handle missing case gracefully, commands include case argument

**When to escalate:** If missing context causes incorrect behavior

---

### 2.2: Evidence Path Validation
**Why it matters:** Evidence-dependent commands need valid paths.

**What to check:**
- Pages verify evidence is loaded before evidence commands
- File paths in commands are from loaded evidence, not hardcoded
- Path handling works with spaces and special characters

**Signs of failure:**
- Commands use stale evidence path
- Paths with spaces cause parsing errors
- Evidence unloaded but commands still issued

**Pass criteria:** Evidence path validated before command execution

**When to escalate:** If path handling is incorrect

---

### 2.3: State Synchronization
**Why it matters:** GUI state must match CLI state.

**What to check:**
- Page refreshes data when case/evidence changes
- State changes in one page propagate to others
- No cached stale data displayed after state change

**Signs of failure:**
- Page shows data from previous case
- Evidence tree doesn't update after reload
- Timeline shows mixed data from multiple cases

**Pass criteria:** All pages re-fetch data on relevant state changes

**When to escalate:** If stale data is displayed

---

## Section 3: Empty and Error State Review

### 3.1: Empty State Display
**Why it matters:** Empty results must be displayed honestly.

**What to check:**
- "0 results" is shown as "0", not "Analysis Complete"
- Empty states have explanatory message
- Empty is distinguished from "loading" and "error"

**Signs of failure:**
- "0 entries" displayed as "Success"
- Empty timeline shows "Timeline Generated"
- No indicator that nothing was found

**Pass criteria:** Empty state clearly labeled, not conflated with success

**When to escalate:** If empty is presented as success

---

### 3.2: Error State Handling
**Why it matters:** Errors must be surfaced, not hidden.

**What to check:**
- CLI errors display user-friendly message
- Error details available for debugging (expandable/log)
- Error state is recoverable (user can retry)

**Signs of failure:**
- Error causes blank page
- Error message is raw CLI output
- Error cannot be dismissed

**Pass criteria:** Error displayed with context and recovery path

**When to escalate:** If errors are hidden or unhelpful

---

### 3.3: Partial State Indication
**Why it matters:** Partial results must be labeled as such.

**What to check:**
- Partial results show "Partial" indicator
- Partial cause is explained (e.g., "2 of 5 parsers failed")
- Partial results are not presented as complete

**Signs of failure:**
- Partial timeline shows no indicator
- Missing parsers not mentioned
- UI shows "Complete" for partial data

**Pass criteria:** Partial states explicitly labeled per TRUTHFULNESS_RULES.md

**When to escalate:** If partial results are presented as complete

---

## Section 4: Fallback Mode Visibility

### 4.1: Embedding Backend Fallback
**Why it matters:** Regex-token fallback is less capable than sentence-transformers.

**What to check (KB bridge):**
- Health endpoint shows `embedding_backend` field
- UI shows "(fallback)" when using regex-token
- Fallback reason is logged

**Pass criteria:** Fallback mode labeled in UI

**When to escalate:** If fallback is not labeled

---

### 4.2: Container Format Fallback
**Why it matters:** Some container formats are partial or stubbed.

**What to check:**
- VHD/VMDK results show partial indicator
- Stubbed formats show warning
- Partial enumeration count is visible

**Pass criteria:** Partial container support labeled per KNOWN_GAPS.md

**When to escalate:** If partial formats are presented as complete

---

### 4.3: Parser Fallback
**Why it matters:** Some artifact types may have limited parser support.

**What to check:**
- Failed parsers are listed in warning
- Available parsers show correct count
- Missing artifact types are documented

**Pass criteria:** Parser availability is accurate, gaps are documented

**When to escalate:** If parser claims exceed implementation

---

## Section 5: Count and Value Truthfulness

### 5.1: Displayed Counts Match CLI
**Why it matters:** Counts must be accurate.

**What to check:**
- File count matches `filetable` total
- Artifact count matches `timeline` total
- Hash count matches `hashset list` entries

**Signs of failure:**
- UI shows 1000 files but CLI returned 500
- Timeline shows 500 entries but CLI returned 1000
- Hashset shows 5 hashes but CLI returned 3

**Pass criteria:** UI counts exactly match CLI response values

**When to escalate:** If counts don't match CLI

---

### 5.2: Hash Values Accurate
**Why it matters:** Hashes must be traceable to actual computation.

**What to check:**
- SHA256 displayed matches `open-evidence` hash field
- Hashes are non-zero/non-placeholder
- Hash format is standard (lowercase hex)

**Signs of failure:**
- Hash shown as "N/A" or "pending"
- Hash doesn't match CLI output
- Placeholder hash (e.g., "0000...0") displayed

**Pass criteria:** Hash values exactly match CLI output, properly formatted

**When to escalate:** If hashes are incorrect or placeholder

---

### 5.3: Timestamp Accuracy
**Why it matters:** Timestamps must be correctly formatted and sourced.

**What to check:**
- Timeline timestamps match evidence timestamps
- Date formats are consistent and readable
- Timezone is documented (UTC or local)

**Signs of failure:**
- Timestamps shown in wrong timezone
- "0" or epoch timestamp displayed
- Inconsistent timestamp formats across page

**Pass criteria:** Timestamps accurate, consistent, and documented

**When to escalate:** If timestamps are incorrect

---

## Section 6: Page-by-Page Contract Review

### 6.1: Dashboard Page

**Depends on:** `capabilities`, `doctor`, `smoke-test`

**What it may safely claim:**
- Engine version and build info
- Loaded capability counts by category
- System health check results
- Available container/parser counts

**What it must never claim without proof:**
- Specific format support when not verified
- Complete capability coverage
- Passed health checks that actually warn

**Fallback behavior:** Show "Health Unknown" if `doctor` fails, don't assume green

**Status:** [ ] Checked | [ ] Pass | [ ] Fail

---

### 6.2: Case Overview Page

**Depends on:** `verify`, `case list`

**What it may safely claim:**
- Case ID, name, creation date
- Verification status from envelope
- Hash chain validity from `verify`

**What it must never claim without proof:**
- "Verified" when envelope shows violations
- Complete chain-of-custody when gaps exist
- Evidence integrity without running `verify`

**Fallback behavior:** Show "Not Verified" if `verify` not run, "Verification Failed" if violations found

**Status:** [ ] Checked | [ ] Pass | [ ] Fail

---

### 6.3: Evidence Sources Page

**Depends on:** `open-evidence`, `open-evidence list`

**What it may safely claim:**
- Container type (RAW, E01, Directory)
- Evidence size and hash values
- Filesystem type when detected

**What it must never claim without proof:**
- Complete filesystem enumeration (APFS/XFS may be partial)
- Encryption status when undetected
- File count when enumeration failed

**Fallback behavior:** Show partial indicator for VHD/VMDK, "Encryption Unknown" if not detected

**Status:** [ ] Checked | [ ] Pass | [ ] Fail

---

### 6.4: File Explorer Page

**Depends on:** `filetable`, `load_evidence_and_build_tree`

**What it may safely claim:**
- Directory tree structure from `tree` field
- File metadata (size, timestamps) from entries
- Pagination cursor for large directories

**What it must never claim without proof:**
- Complete file list (may be partial for some filesystems)
- Accurate file counts for partial enumeration
- All files present when tree shows empty

**Fallback behavior:** Show "Partial Enumeration" warning for APFS/XFS, "Empty" when tree truly empty

**Status:** [ ] Checked | [ ] Pass | [ ] Fail

---

### 6.5: Timeline Page

**Depends on:** `timeline`

**What it may safely claim:**
- Entry count from `total_count` field
- Artifact entries from `entries` array
- Pagination info from `pagination` field

**What it must never claim without proof:**
- Complete timeline (some parsers may fail)
- All artifact types present
- Zero missing entries when parsers warn

**Fallback behavior:** Show "Partial Timeline" if warning present, "0 entries" with warning if empty

**Status:** [ ] Checked | [ ] Pass | [ ] Fail

---

### 6.6: Artifacts Page

**Depends on:** `examine` or filtered `timeline`

**What it may safely claim:**
- Artifact count per type
- Artifact details from `ParsedArtifact` fields
- Source paths for provenance

**What it must never claim without proof:**
- Complete artifact coverage
- All artifacts of a type found
- Accurate counts when some parsers failed

**Fallback behavior:** Show "Showing X of Y" when filtering, warn if source filtering reduced results

**Status:** [ ] Checked | [ ] Pass | [ ] Fail

---

### 6.7: Hash Sets Page

**Depends on:** `hashset list`, `hashset stats`

**What it may safely claim:**
- Hashset names and types
- Entry counts from envelope
- Match statistics from `stats` output

**What it must never claim without proof:**
- Edit capability (hashset editing is stubbed per KNOWN_GAPS.md)
- Complete NSRL metadata access
- Accurate category breakdowns

**Fallback behavior:** Show "Read-Only" badge, "NSRL Metadata Limited" if access is partial

**Status:** [ ] Checked | [ ] Pass | [ ] Fail

---

### 6.8: Logs Page

**Depends on:** Local log files, `activity_log` from case

**What it may safely claim:**
- Activity entries from case database
- Log timestamps and event types
- Integrity chain status

**What it must never claim without proof:**
- Complete audit trail if gaps exist
- Integrity verified without running `verify`
- Specific user actions without log entries

**Fallback behavior:** Show "Logs Unavailable" if database inaccessible, "Chain Incomplete" if gaps found

**Status:** [ ] Checked | [ ] Pass | [ ] Fail

---

### 6.9: Settings Page

**Depends on:** Configuration files, environment variables

**What it may safely claim:**
- Current configuration values
- Path settings
- Feature flags from `capabilities`

**What it must never claim without proof:**
- Complete feature availability
- Performance characteristics
- Remote service status

**Fallback behavior:** Show "Using Defaults" when config unavailable, "Unknown" for unverified features

**Status:** [ ] Checked | [ ] Pass | [ ] Fail

---

### 6.10: Integrity Watchpoints Page

**Depends on:** `watchpoints`, `violations`

**What it may safely claim:**
- Active watchpoint count
- Violation list when present
- Severity levels from envelope

**What it must never claim without proof:**
- Zero violations when watchpoints not run
- Complete coverage without running `verify`
- Specific table/operation details without envelope data

**Fallback behavior:** Show "Not Monitored" if `watchpoints` not configured, "Violations Found" with details

**Status:** [ ] Checked | [ ] Pass | [ ] Fail

---

## Section 7: Command-to-Field Mapping

### 7.1: Envelope Field Extraction
**Why it matters:** GUI must extract fields correctly from envelope.

| Command | Required Fields | GUI Must Extract |
|---------|-----------------|-----------------|
| `capabilities` | `capabilities[].name`, `.status`, `.category` | Capability list |
| `doctor` | `checks[].name`, `.status`, `.detail` | Health indicators |
| `smoke-test` | `tests[].name`, `.passed`, `overall` | Pass/fail summary |
| `verify` | `verification_status`, `hash_chain_valid`, `violations` | Verification badge |
| `triage-session` | `files_categorized`, `artifacts_extracted`, `bundle_path` | Triage summary |
| `examine` | `preset`, `stages_completed`, `stages_failed`, `artifacts_found` | Progress |
| `watchpoints` | `watchpoints[].id`, `.table`, `.operation`, `.active` | Watchpoint list |
| `violations` | `violations[].id`, `.table_name`, `.severity` | Violation list |
| `timeline` | `entries[]`, `total_count`, `pagination` | Timeline entries |
| `hashset list` | `hashsets[].name`, `.type`, `.entries` | Hashset list |
| `hashset stats` | `hashset_name`, `total_hashes`, `categories` | Stats detail |
| `open-evidence` | `container_type`, `container_size`, `hash`, `filesystems` | Evidence info |
| `filetable` | `entries[]`, `total_count`, `cursor` | File list |

---

## Section 8: Warning and Error Preservation

### 8.1: CLI Warning Preservation
**Check:** Does GUI preserve CLI warnings?  
**Expected:** `warning` field from envelope displayed  
**Pass criteria:** Warning visible in UI  
**On fail:** Document which warnings are dropped

### 8.2: CLI Error Preservation
**Check:** Does GUI preserve CLI errors?  
**Expected:** `error` field from envelope displayed  
**Pass criteria:** Error visible with details  
**On fail:** Document which errors are dropped

### 8.3: Hint Field Usage
**Check:** Does GUI use `hint` field when present?  
**Expected:** Hints displayed as actionable guidance  
**Pass criteria:** Hints visible and actionable  
**On fail:** Document hint field ignoring

### 8.4: Error Type Classification
**Check:** Does GUI classify errors by `error_type`?  
**Expected:** Different handling for different error types  
**Pass criteria:** Error type influences display/action  
**On fail:** Document uniform error handling

---

## Contract Validation Summary

| Section | Checks | Passed | Failed | Skipped |
|---------|--------|--------|--------|---------|
| 1. Adapter Mode | 3 | | | |
| 2. Context | 3 | | | |
| 3. Empty/Error | 3 | | | |
| 4. Fallback Visibility | 3 | | | |
| 5. Truthfulness | 3 | | | |
| 6. Page Contracts | 10 | | | |
| 7. Field Mapping | 1 | | | |
| 8. Warning/Error | 4 | | | |
| **Total** | **30** | | | |

### Page Contract Status

| Page | Checked | Pass | Fail |
|------|---------|------|------|
| Dashboard | [ ] | [ ] | [ ] |
| Case Overview | [ ] | [ ] | [ ] |
| Evidence Sources | [ ] | [ ] | [ ] |
| File Explorer | [ ] | [ ] | [ ] |
| Timeline | [ ] | [ ] | [ ] |
| Artifacts | [ ] | [ ] | [ ] |
| Hash Sets | [ ] | [ ] | [ ] |
| Logs | [ ] | [ ] | [ ] |
| Settings | [ ] | [ ] | [ ] |
| Integrity | [ ] | [ ] | [ ] |

### Overall Contract Status
- [ ] **PASS** — All pages respect CLI contracts
- [ ] **ISSUES FOUND** — Documented mismatches require fixes
- [ ] **CRITICAL** — Truthfulness violations found

### Sign-Off
Auditor: Strata  
Date: _________________  
Status: _________________

---

## Document Maintenance

Update this checklist when:
- New pages are added
- Command contracts change
- New envelope fields are added
- Page behavior changes

Location: `D:\forensic-suite\guardian\STRATA_GUI_CLI_CONTRACT_CHECKLIST.md`
