# security-reviewer — Strata security-sensitive code review

Loaded when reviewing changes to CSAM handling, hash verification,
custody logging, evidence reads, or anything that crosses the
NemoClaw sandbox boundary. These rules are always in effect — review
is a blocking gate, not a suggestion.

## CSAM module rules (always)

* **Never log hash values that match CSAM hashes.** Match metadata
  may be logged (hit count, source file); hash bytes themselves must
  not cross into `log::*` calls, stdout, or error messages.
* **Advisory notice must always be present in findings output**
  (`advisory_notice_present_in_all_findings` test is load-bearing).
  Any finding emitted without the notice is a blocker.
* **`examiner_approved` defaults to `false`.** Never default to
  `true`; never auto-flip. Only an examiner action — logged in
  custody — can change it.
* **CSAM results must never auto-submit anywhere.** No network calls,
  no cloud sync, no email, no webhooks. Human-reviewed only.
* **NCMEC / Project VIC hash sets remain on disk only**, never in
  logs, never in telemetry, never in crash dumps.

## Evidence integrity rules

* **Parsers must never modify input bytes.** Open with
  `OpenFlags::SQLITE_OPEN_READ_ONLY`, `File::open` (not
  `OpenOptions::write`). Memory-map as read-only.
* **All reads are read-only.** No write, rename, chmod, or delete
  operations on evidence files.
* **Hash verification uses constant-time comparison**
  (`subtle::ConstantTimeEq` or equivalent). Never `==` on hash bytes.
* **Checksums are re-computed at read time** where the original
  acquisition hash is known; mismatches are surfaced as a WARN
  artifact, not silently discarded.

## Chain of custody rules

* **`artifact.source` is the original evidence path**, never the
  working copy. If the evidence lives inside a mounted image, record
  the full in-image path plus the image file path.
* **Timestamps preserve original timezone info** where available. Do
  not blanket-convert to UTC until the last serialization step, and
  record the offset in metadata when the source carried one.
* **Paths are not truncated or normalized** in a way that changes
  meaning. Canonical-case-fold is permitted for matching; the
  displayed `source` must be verbatim.
* **Every file open is logged through the custody layer**
  (`strata-core/src/custody.rs`), with SHA-256 captured at first
  read.

## NemoClaw sandbox awareness

* Sandbox name: `wolfmarksystems`.
* Security: Landlock + seccomp + netns.
* Agents run in isolated containers and **cannot reach evidence
  volumes or key material** outside the sandbox.
* Any PR that would allow an agent process to read `$WOLFMARK_KEYS`
  or `$WOLFMARK_EVIDENCE` outside the container is a blocker.
* Network access inside agents is disabled by default. Adding it
  requires an explicit sandbox policy change.

## Review output format

Match `code-reviewer.md`: bullet list under **Blocker**, **Should fix
before merge**, **Nits**. CSAM-related findings are always
**Blocker** unless the diff is a pure test change inside
`strata-csam/tests/`.
