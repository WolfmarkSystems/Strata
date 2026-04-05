# OPUS TASK — Rename Strata Tree to Strata
# Priority: HIGH — Brand identity for flagship product
# Date: 2026-04-03

---

## CONTEXT

Strata Tree is being renamed to Strata.
This is the flagship product of Wolfmark Systems.

```
OLD NAME:  Strata Tree
NEW NAME:  Strata
TAGLINE:   "Every layer. Every artifact. Every platform."
COMPANY:   Wolfmark Systems
```

Strata is a court-defensible digital forensic examination platform.
Single binary. 22MB. USB-portable. Cross-platform.

---

## THE TASK

Perform a complete rename of Strata Tree → Strata throughout
the codebase. This is a mechanical rename — do NOT change
any functionality, logic, or architecture.

---

## RENAME SCOPE

### Binary / App Names
```
OLD:  strata-tree (binary name in Cargo.toml)
NEW:  strata

OLD:  Strata Tree (display name in UI)
NEW:  Strata

OLD:  strata-tree-sdk
NEW:  strata-sdk (if this crate exists)
```

### Window Title
```
OLD:  "Strata Tree" or "Strata Tree v0.3.0"
NEW:  "Strata" or "Strata v0.3.0"
```

### About Dialog / Version String
```
OLD:  Strata Tree v0.3.0
NEW:  Strata v0.3.0 by Wolfmark Systems
```

### File Format / Case File Extension
```
Keep: .vtp extension for now (change in v1.0)
Note: Document that .vtp will become .stp in v1.0
```

### App Directory / Config Paths
```
OLD:  ~/strata-tree/ or ~/.strata/tree/
NEW:  ~/strata/ or ~/.strata/
```

### Cargo.toml Changes
```
In apps/tree/Cargo.toml:
  name = "strata" (was strata-tree or tree)
  description = "Strata — Every layer. Every artifact. Every platform."

In workspace Cargo.toml:
  Update member path if directory is renamed
```

### Directory Rename (if safe)
```
apps/tree/ → apps/strata/
  Only rename if it doesn't break workspace references
  If Cargo workspace uses path = "apps/tree", 
  update that reference too
  
  If rename is risky, keep apps/tree/ internally
  but change all display names and binary names
```

### Source Code String References
```
Search for and replace (case-sensitive and case-insensitive):
  "Strata Tree" → "Strata"
  "strata-tree" → "strata"
  "strata_tree" → "strata"
  "StrataTree"  → "Strata"
  
DO NOT replace:
  "strata" alone (other crates keep the strata- prefix)
  Any logic, algorithm, or functionality
  Test fixture names that reference file content
  Comments that explain historical context
```

### UI Text
```
Splash screen / loading text:
  OLD: "Strata Tree"
  NEW: "Strata"

Menu bar app name:
  OLD: "Strata Tree"  
  NEW: "Strata"

Window title format:
  NEW: "Strata — [case name]" or "Strata v0.3.0"

Footer/status bar:
  If "Strata Tree" appears → replace with "Strata"
```

### README / Documentation
```
If apps/tree/README.md exists:
  Update product name to Strata
  Update tagline to:
  "Every layer. Every artifact. Every platform."
  Keep all technical documentation intact
```

---

## WHAT NOT TO CHANGE

```
DO NOT change:
  Any crate named strata-* (except strata-tree-sdk if it exists)
  Any logic, parsers, or algorithms
  Any test logic or assertions
  Any file format parsing
  The .vtp case file format (document for future change)
  Internal variable names that would require logic changes
  Git history
  Any API surface of libraries
```

---

## VERIFICATION

After all renames:

```bash
cargo check --workspace
cargo test --workspace  
cargo clippy --workspace -- -D warnings
```

All must pass clean with zero regressions.

Search for any remaining references:
```bash
grep -r "Strata Tree" apps/ --include="*.rs" --include="*.toml" --include="*.md"
grep -r "strata-tree" apps/ --include="*.rs" --include="*.toml"
grep -r "strata_tree" apps/ --include="*.rs" --include="*.toml"
```

Target: zero results in the above grep.

---

## DELIVERABLE

1. All display names updated to "Strata"
2. Binary name updated to "strata"  
3. Cargo.toml updated with new name and tagline
4. Directory renamed if safe, or documented if kept as apps/tree/
5. cargo check + cargo test + cargo clippy all passing clean
6. Report: what was renamed, what was kept, any edge cases

---

## NOTE ON TIMING

This rename can happen in parallel with or after the
NTFS MFT Walker task. Both are independent changes.
If running sequentially, do NTFS first then rename.
If the NTFS work is already on a branch, rename on main
and merge carefully.

---

*Wolfmark Systems — Strata Forensic Platform*
*Product Rename: Strata Tree → Strata*
*April 2026*
EOF