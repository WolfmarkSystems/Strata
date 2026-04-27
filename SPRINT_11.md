# Sprint 11 — Examiner Experience: Conversation View + Jump to Source + Timestamps + Deduplication

_Date: 2026-04-25_
_Model: claude-opus-4-7_
_Approved by: KR_
_Working directory: ~/Wolfmark/strata/_

---

## Context

Live testing on the MacBookPro CTF image (31,062 artifacts) confirmed
Strata surfaces real forensic data correctly. Four UX gaps prevent
examiners from using it effectively in casework:

1. Communications artifacts display as isolated rows — no conversation
   view. Cellebrite and AXIOM both render threaded message chains.
2. No way to jump from an artifact to its source file in the evidence
   tree. Examiners need to verify artifacts against raw data for court.
3. Timestamps missing on most macOS artifacts — shows "—" in the
   TIMESTAMP column. Required for timeline analysis and testimony.
4. Duplicate artifacts appearing in directory ingestion path — same
   artifact surfaced multiple times, inflating counts and confusing
   examiners.

These are the features that separate a prototype from a tool examiners
will actually use in casework. This sprint builds them.

---

## Hard rules (always)

- Zero NEW `.unwrap()` in production code paths
- Zero NEW `unsafe{}` without explicit justification
- Zero NEW `println!` in production — use `log::` macros
- All errors handled explicitly
- All 9 load-bearing tests must pass after every change
- `cargo test --workspace` must pass
- `cargo clippy --workspace -- -D warnings` must be clean
- No new TODO/FIXME in committed code

---

## PRIORITY 1 — Conversation / Thread View

### The problem

iMessage, SMS, WhatsApp, Signal, and Zoom artifacts surface as
individual database rows. An examiner sees:

```
iMessage 6700: Mint Mobile...  rowid=3  2025-11-04
iMessage 6700: Nice! Yo...     rowid=2  2025-11-04
iMessage 6700: Got it...       rowid=5  2025-11-04
```

They need to see:

```
Thread: Mint Mobile (802) 495-4197
  17:20  Mint Mobile → You are all set, new number live
  17:21  alexmaurie  → Got it. Thanks!
  17:22  Mint Mobile → Nice! You're all set.
```

Grouped by thread/handle, sorted by timestamp, rendered as a
readable conversation. This is how Cellebrite and AXIOM display
message evidence and how examiners present it in court.

### Implementation approach

**Step 1 — Understand the current Communications artifact structure**

Read the existing Communications artifact output from MacTrace,
Pulse, and any other plugins that emit message artifacts.

For each plugin, identify:
- What fields are present (handle, thread_id, rowid, text,
  timestamp, direction, service)
- How thread grouping would work (thread_id? handle? both?)
- Whether timestamps are already present in the artifact data
  or need to be parsed from the source

**Step 2 — Add thread grouping to the artifact schema**

In `strata-plugin-sdk`, check whether `ArtifactRecord` has fields
for thread grouping. If not, add:

```rust
// Optional thread context for conversation-type artifacts
pub struct ThreadContext {
    pub thread_id: String,       // unique thread identifier
    pub participant: String,     // the other party (phone/handle/name)
    pub direction: MessageDir,   // Inbound / Outbound / Unknown
    pub service: String,         // iMessage, SMS, WhatsApp, Signal
}

pub enum MessageDir {
    Inbound,
    Outbound,
    Unknown,
}
```

Add `thread_context: Option<ThreadContext>` to `ArtifactRecord`.
This is backwards-compatible — existing artifacts that don't set
it remain unchanged.

**Step 3 — Update MacTrace and Pulse plugins**

For artifacts that represent messages, populate `thread_context`
with the thread_id, participant handle, direction, and service.

The iMessage schema in chat.db:
- `handle.id` → participant phone/handle
- `message.is_from_me` → direction (0=inbound, 1=outbound)
- `message.service` → "iMessage" or "SMS"
- `chat.chat_identifier` → thread identifier

**Step 4 — Conversation view in the frontend**

In `apps/strata-ui/src/`, when a user selects a Communications
artifact category:

Current behavior: flat list of all artifacts.

New behavior: two-panel layout:
- Left panel: thread list (grouped by participant/thread_id,
  showing participant name, last message preview, message count)
- Right panel: conversation view for selected thread (messages
  sorted by timestamp, rendered as chat bubbles or alternating
  rows with direction indicated)

```
┌─────────────────────┬──────────────────────────────────────┐
│ THREADS             │ Mint Mobile (802) 495-4197           │
│─────────────────────│──────────────────────────────────────│
│ Mint Mobile    (5)  │  17:20  [Mint Mobile]                │
│ Unknown        (47) │  Aw yeah. Your fresh new number...   │
│                     │                                      │
│                     │  17:21  [alexmaurie]                 │
│                     │  Got it. Thanks!                     │
│                     │                                      │
│                     │  17:22  [Mint Mobile]                │
│                     │  Nice! You're all set.               │
└─────────────────────┴──────────────────────────────────────┘
```

The conversation view only activates when the selected category
is Communications AND the artifacts have thread_context populated.
For other artifact types, the existing flat list remains.

**Step 5 — New IPC command**

Add `get_artifacts_by_thread(evidence_id, category)` Tauri command
that returns artifacts grouped by thread_id with participant info.

**Step 6 — Tests**

```rust
#[test]
fn thread_grouping_sorts_messages_chronologically() {
    // 5 messages with thread_id "thread_1", verify sorted by timestamp
}

#[test]
fn inbound_outbound_direction_is_preserved() {
    // Verify is_from_me maps to correct MessageDir
}

#[test]
fn artifacts_without_thread_context_render_as_flat_list() {
    // Verify backwards compatibility
}
```

### Acceptance criteria — P1

- [ ] Communications view shows thread list on left, conversation
  on right when thread_context is populated
- [ ] iMessage threads from MacBookPro grouped correctly by participant
- [ ] Messages sorted chronologically within each thread
- [ ] Direction (inbound/outbound) visually indicated
- [ ] Flat list preserved for non-Communications categories
- [ ] 3 new tests pass
- [ ] All 9 load-bearing tests still green
- [ ] No new `.unwrap()`, clippy clean

---

## PRIORITY 2 — Jump to Source File

### The problem

Every artifact shows a SOURCE PATH pointing to the file it came from.
There is no way to navigate from that artifact to the actual file in
the evidence tree. Examiners need this for court testimony — they must
be able to show the raw data underlying any artifact.

### Implementation

**Step 1 — Understand the current evidence tree navigation**

Read `get_tree_root` and `get_tree_children` in `lib.rs`.
Understand how node IDs are constructed and how the tree is navigated.

**Step 2 — Add navigate_to_path IPC command**

```rust
#[tauri::command]
async fn navigate_to_path(
    evidence_id: String,
    file_path: String,
) -> Result<TreeNode, String>
```

This command:
1. Takes the file path from the artifact's source_path field
2. Walks the evidence tree to find the node at that path
3. Returns the node ID and its parent chain (breadcrumb)
4. The frontend uses this to expand the tree to that node and
   select it

**Step 3 — Add "Go to Source" button to artifact detail panel**

In `apps/strata-ui/src/` the artifact detail panel (right side)
currently shows VALUE, SOURCE FILE, SOURCE PATH, MITRE ATT&CK.

Add a "→ Go to Source" button below SOURCE PATH.

On click:
1. Call `navigate_to_path(evidence_id, source_path)`
2. Switch view to the Evidence Tree tab
3. Expand tree nodes along the path to the file
4. Select and highlight the target node
5. Show the file's metadata/hex in the right panel

**Step 4 — Highlight the selected node**

The evidence tree needs a "selected" state that persists when
navigated to programmatically. Currently selection only happens
on user click. Add a `navigated_to` state that:
- Highlights the node in the tree
- Scrolls the tree to make it visible
- Shows a subtle indicator that this node was jumped to from
  an artifact

**Step 5 — Tests**

```rust
#[test]
fn navigate_to_path_resolves_existing_path() {
    // Given a known file path in the evidence
    // navigate_to_path returns the correct node ID
}

#[test]
fn navigate_to_path_returns_error_for_nonexistent_path() {
    // Does not panic, returns clear error
}
```

### Acceptance criteria — P2

- [ ] "→ Go to Source" button visible in artifact detail panel
- [ ] Clicking it switches to Evidence Tree and selects the file
- [ ] Tree expands automatically to show the selected file
- [ ] Selected node is visually highlighted
- [ ] Works for the MacBookPro chat.db path verified in testing
- [ ] 2 new tests pass
- [ ] All 9 load-bearing tests still green
- [ ] No new `.unwrap()`, clippy clean

---

## PRIORITY 3 — Timestamp Population for macOS Artifacts

### The problem

The TIMESTAMP column shows "—" for most macOS artifacts. Timestamps
are required for timeline analysis and for testimony ("the message
was sent at 17:20 on November 4, 2025").

### Investigation first

Before writing any fix:

```bash
grep -rn "timestamp\|Timestamp\|TIMESTAMP" \
    plugins/strata-plugin-mactrace/src/ \
    plugins/strata-plugin-pulse/src/ \
    --include="*.rs" | grep -v target | head -30
```

Determine:
- Are timestamps being parsed from the source data?
- Are they being set in ArtifactRecord?
- Are they being passed through the IPC layer?
- Are they being rendered in the frontend?

The iMessage timestamp format in chat.db uses Apple's Core Data
timestamp — seconds since January 1, 2001 (not Unix epoch).

```rust
fn apple_timestamp_to_unix(apple_ts: i64) -> i64 {
    // Apple epoch: 2001-01-01 00:00:00 UTC
    // Unix epoch:  1970-01-01 00:00:00 UTC
    // Difference:  978307200 seconds
    apple_ts + 978_307_200
}
```

Note: iMessage timestamps in modern iOS/macOS are stored in
nanoseconds, not seconds. Check the actual values:
- If timestamp > 1_000_000_000_000_000_000 → nanoseconds
  (divide by 1_000_000_000 to get seconds, then add Apple epoch)
- If timestamp > 1_000_000_000 → seconds (add Apple epoch directly)

**Fix each timestamp gap found:**

For each plugin that emits artifacts without timestamps:
1. Find where the source timestamp field is in the database/file
2. Parse it correctly (Apple epoch, FILETIME, Unix, or other)
3. Convert to Unix timestamp
4. Set `ArtifactRecord.timestamp`

**Frontend timestamp display**

Confirm that `ArtifactRecord.timestamp` flows through to the
frontend correctly. If the field exists but shows "—", the
frontend rendering may be dropping it.

### Tests

```rust
#[test]
fn apple_timestamp_converts_correctly() {
    // Known Apple timestamp → expected Unix timestamp
    // 0 → 978307200 (midnight Jan 1 2001)
    // 1762276748 → (verify against known date)
}

#[test]
fn imessage_nanosecond_timestamp_converts_correctly() {
    // High-value timestamp (nanoseconds) → correct Unix seconds
}
```

### Acceptance criteria — P3

- [ ] iMessage timestamps populate in TIMESTAMP column
- [ ] Apple epoch conversion correct (unit tested)
- [ ] Nanosecond vs second detection working
- [ ] At least 80% of Communications artifacts show timestamps
- [ ] Timestamps display in human-readable format in UI
  (e.g. "2025-11-04 17:20:03 UTC")
- [ ] 2 new tests pass
- [ ] All 9 load-bearing tests still green
- [ ] Clippy clean

---

## PRIORITY 4 — Artifact Deduplication

### The problem

Several artifacts appear twice in the MacBookPro results. Looking at
the Communications category, iMessage rows appear duplicated. This
inflates counts and confuses examiners who see the same evidence twice.

### Investigation first

```bash
grep -rn "dedup\|deduplicate\|seen\|visited" \
    crates/strata-engine-adapter/src/ \
    --include="*.rs" | grep -v target
```

Determine:
- Is there existing deduplication logic?
- At what layer are duplicates introduced?
- Is it the plugin running twice on the same file?
- Is it two plugins both parsing the same source?
- Is it the ARTIFACT_CACHE being populated multiple times?

For directory ingestion specifically — the materialize step extracts
files to a scratch directory. If plugins are running against both
the original directory AND the scratch directory, every artifact
appears twice.

### Fix approach

**If duplicates come from double-running:**
Add a guard in `run_all_on_evidence` that tracks which paths
have already been processed and skips re-processing.

**If duplicates come from two plugins parsing the same file:**
Add a deduplication step after all plugins complete that removes
artifacts with identical (source_path, artifact_type, value) tuples.

**If duplicates come from ARTIFACT_CACHE:**
Check whether `ARTIFACT_CACHE.insert` is being called multiple
times for the same evidence_id.

```rust
fn deduplicate_artifacts(artifacts: Vec<ArtifactRecord>) 
    -> Vec<ArtifactRecord> 
{
    // Key: (source_path, artifact_type, value)
    // Keep first occurrence, discard subsequent duplicates
    // Log count of duplicates removed at log::debug! level
}
```

### Tests

```rust
#[test]
fn deduplication_removes_exact_duplicates() {
    // Two identical artifacts → one in output
}

#[test]
fn deduplication_preserves_distinct_artifacts() {
    // Two artifacts with different values → both in output
}

#[test]
fn deduplication_logs_removed_count() {
    // Verify log::debug! fires when duplicates are removed
}
```

### Acceptance criteria — P4

- [ ] Root cause of duplicates identified and documented
- [ ] Duplicate Communications artifacts eliminated
- [ ] MacBookPro artifact count more accurate after dedup
- [ ] Distinct artifacts preserved — no false deduplication
- [ ] 3 new tests pass
- [ ] All 9 load-bearing tests still green
- [ ] Clippy clean

---

## What this sprint does NOT touch

- VERIFY (separate repo — Sprint 2 pending)
- Memory artifact ingestion (.mem/.dmp)
- DMG decompression
- exFAT walker
- ShimCache improvements (already shipped in Sprint 10)
- Social Media artifact parsing
- Identity/Credentials gap on macOS images

---

## Session log format

```
## Sprint 11 — [date]

P1 Conversation view: PASSED / FAILED
  - Thread grouping working: yes/no
  - iMessage threads from MacBookPro: [count]
  - Direction indicator working: yes/no

P2 Jump to source: PASSED / FAILED
  - Go to Source button: yes/no
  - Tree navigation working: yes/no
  - chat.db navigation tested: yes/no

P3 Timestamps: PASSED / FAILED
  - Apple epoch conversion: correct/incorrect
  - % of Communications with timestamps: [%]
  - Frontend display: working/broken

P4 Deduplication: PASSED / FAILED
  - Root cause: [describe]
  - Duplicates eliminated: yes/no
  - MacBookPro artifact count after dedup: [number]

Final test count: [number]
Load-bearing tests: ALL GREEN
Clippy: CLEAN
```

---

## Commit format

```
feat: sprint-11-P1 conversation view — threaded iMessage/SMS display
feat: sprint-11-P2 jump to source — Go to Source navigates evidence tree
fix: sprint-11-P3 macOS timestamps — Apple epoch conversion, ns detection
fix: sprint-11-P4 artifact deduplication — root cause fixed, 3 tests
```

---

_Sprint 11 authored by: Claude (architect) + KR (approved)_
_Execute with: claude-opus-4-7 in ~/Wolfmark/strata/_
_P1 and P2 are the features that make Strata usable in court._
_Get them right before moving to timestamps and dedup._
