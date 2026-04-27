# Sprint 13 — FILES Counter + Mobile Plugin Coverage + Knowledge Base Expansion
# FOR CODEX — Read AGENTS.md before starting

_Date: 2026-04-26_
_Agent: Codex (OpenAI)_
_Approved by: KR_
_Working directory: ~/Wolfmark/strata/_

---

## Before you start

1. Read AGENTS.md completely
2. Run `git pull` to get latest commits
3. Run `cargo test -p strata-shield-engine --test quality_gate` — confirm passing
4. Run `cargo test --workspace 2>&1 | tail -5` — confirm passing
5. Do not start until both pass

---

## Context

Live testing on the MacBookPro CTF image (31,062 artifacts) revealed
three remaining gaps:

1. FILES counter shows 0 for folder/directory ingestion — cosmetic
   but damages examiner credibility when presenting results
2. Identity & Accounts and Credentials categories show 0 on macOS
   images — macOS keychain and account data not surfacing
3. Knowledge Base panel shows generic extension-level content when
   a filename-specific match doesn't exist — misleading for less
   experienced examiners

---

## Hard rules — read AGENTS.md

- Zero new `.unwrap()` in production code
- Zero new `unsafe{}` without justification
- Zero new `println!` in library code
- Quality gate must pass after every priority
- All 9 load-bearing tests must still pass
- `cargo clippy --workspace -- -D warnings` clean

---

## PRIORITY 1 — FILES Counter for Directory Ingestion

### The problem

When evidence is loaded via `+ Open Folder`, the FILES counter in
the TopBar shows 0 throughout. The materialize step runs correctly
(artifacts are produced) but `guard.files` is never populated for
the directory ingestion path.

### Root cause (already diagnosed)

In `crates/strata-engine-adapter/src/plugins.rs:621`, the file
population block is gated on `if source_path.is_file()`. For
directory ingestion, `source_path.is_dir()` is true so the block
is skipped entirely.

### Fix

Add a parallel branch for directory ingestion:

```rust
} else if source_path.is_dir() {
    // Directory ingestion — walk the source directory and
    // populate guard.files with stub CachedFile entries
    // so the FILES counter reflects the actual file count
    if let Ok(entries) = walk_host_dir(&source_path) {
        let mut guard = evidence.lock()
            .map_err(|_| EngineError::LockPoisoned)?;
        for entry in entries {
            let cached = CachedFile {
                path: entry.to_string_lossy().to_string(),
                name: entry.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string(),
                size: entry.metadata()
                    .map(|m| m.len())
                    .unwrap_or(0),
                ..Default::default()
            };
            guard.files.insert(cached.path.clone(), cached);
        }
        log::debug!(
            "Directory ingestion: populated {} files in guard",
            guard.files.len()
        );
    }
}
```

### Also fix the tree node badge

In `crates/strata-engine-adapter/src/evidence.rs:610`, the tree
node badge currently shows subdirectory count (`n.child_ids.len()`).

Change to return both file count and subdirectory count:

```rust
// Instead of:
count: n.child_ids.len()

// Return a struct:
pub struct TreeNodeCount {
    pub files: usize,
    pub subdirs: usize,
}
```

Update the frontend to render `"7 files · 3 folders"` on each
tree node badge. This matches Finder behavior and is what examiners
expect.

### Tests

```rust
#[test]
fn files_counter_populates_for_directory_ingestion() {
    // Create a temp dir with 5 files
    // Load via directory ingestion path
    // Verify guard.files.len() == 5
}

#[test]
fn tree_node_badge_shows_files_and_subdirs() {
    // Verify TreeNodeCount has both files and subdirs fields
}
```

### Acceptance criteria — P1

- [ ] FILES counter populates correctly after folder load
- [ ] Tree node badges show "N files · M folders"
- [ ] MacBookPro folder shows accurate file count
- [ ] 2 new tests pass
- [ ] All 9 load-bearing tests still green
- [ ] Quality gate passes

---

## PRIORITY 2 — macOS Identity & Credentials

### The problem

Identity & Accounts and Credentials categories show 0 on the
MacBookPro CTF image. These should surface:
- macOS user accounts
- Keychain entries (app passwords, WiFi passwords, certificates)
- Login items
- Saved passwords from browsers

### Investigation first

Before writing any code:

```bash
grep -rn "keychain\|Keychain\|identity\|Identity\|credential\|Credential" \
    plugins/strata-plugin-mactrace/src/ \
    plugins/strata-plugin-phantom/src/ \
    --include="*.rs" | grep -v target | head -20
```

Determine:
- Is there existing keychain parsing code?
- What artifact category do identity artifacts map to?
- Why is the category showing 0 — missing parser or wrong category?

### macOS keychain locations

```
~/Library/Keychains/login.keychain-db       ← user keychain
/Library/Keychains/System.keychain          ← system keychain
~/Library/Keychains/*/                      ← iCloud keychain sync
```

The keychain database is a SQLite-compatible format.
The `security` CLI can dump keychain metadata (not secrets).

### macOS user accounts

```
/var/db/dslocal/nodes/Default/users/*.plist ← local user accounts
/private/var/db/dslocal/nodes/Default/users/
```

### Implementation approach

If no keychain parser exists, add basic keychain metadata extraction
to MacTrace:

```rust
// Extract keychain entry metadata (not secrets — just what exists)
pub fn parse_keychain_metadata(path: &Path) -> Vec<ArtifactRecord> {
    // Open keychain-db as SQLite
    // Query: SELECT label, svce, acct, cdat, mdat FROM genp
    // Each row = one credential entry (label, service, account, dates)
    // Do NOT extract passwords — metadata only
    // Map to: category=Credentials, artifact_type="keychain_entry"
}
```

### Acceptance criteria — P2

- [ ] Root cause of 0 Identity/Credentials identified
- [ ] At least basic user account detection working
- [ ] Keychain metadata (labels only, no passwords) surfacing
- [ ] Identity & Accounts > 0 on MacBookPro image
- [ ] No new `.unwrap()` in keychain parsing code
- [ ] Quality gate passes

---

## PRIORITY 3 — Knowledge Base Generic Match Label

### The problem

The Knowledge Base panel in the file detail view shows generic
extension-level content when no filename-specific entry exists.
`FlagMailboxes.plist` shows generic "macOS Property List" content
rather than anything specific to FlagMailboxes.

Less experienced examiners may think this generic content is
specific to the file they're looking at.

### Location

`apps/strata-ui/src/data/knowledgeBank.ts` — `lookupKnowledge()`
function. It tries filename first, then extension as fallback.

### Fix

When the match is by extension only (fallback), add a subtle
label above the Knowledge Base panel:

```tsx
{knowledgeMatch.matchType === 'extension' && (
  <div className="knowledge-generic-label">
    Generic match — applies to all .{extension} files
  </div>
)}
```

In `lookupKnowledge()`, return the match type alongside the content:

```typescript
interface KnowledgeMatch {
  content: KnowledgeEntry;
  matchType: 'filename' | 'extension';
}
```

Style the label subtly — small text, muted color, italic. It should
be visible but not distracting. The knowledge content is still
useful — it just needs context about its specificity.

### Tests

```typescript
// In knowledgeBank.test.ts
test('filename match returns matchType filename', () => {
  const result = lookupKnowledge('NTUSER.DAT', 'dat');
  expect(result?.matchType).toBe('filename');
});

test('extension fallback returns matchType extension', () => {
  const result = lookupKnowledge('FlagMailboxes.plist', 'plist');
  expect(result?.matchType).toBe('extension');
});
```

### Acceptance criteria — P3

- [ ] `matchType` returned from `lookupKnowledge`
- [ ] Generic label visible when match is by extension
- [ ] No label shown when match is by filename
- [ ] FlagMailboxes.plist shows "Generic match — applies to all .plist files"
- [ ] NTUSER.DAT shows no generic label (filename match)
- [ ] Frontend builds clean

---

## After all priorities complete

```bash
cargo test --workspace 2>&1 | grep "test result" | head -5
cargo test -p strata-shield-engine --test quality_gate 2>&1 | tail -3
cargo clippy --workspace -- -D warnings 2>&1 | grep "^error" | head -5
npm run build --prefix apps/strata-ui 2>&1 | tail -3
```

All must pass. Then:

```bash
git add -A
git commit -m "fix: sprint-13 FILES counter + macOS identity + KB generic label"
```

Report:
- Which priorities passed
- Test count before and after
- Quality gate status
- MacBookPro FILES counter value after fix

---

## What this sprint does NOT touch

- The 9 load-bearing tests
- CLAUDE.md (without KR approval)
- waivers.toml baseline numbers
- Any VERIFY code
- Plugin logic outside of keychain/identity parsing

---

_Sprint 13 for Codex — read AGENTS.md first_
_KR approval: granted_
