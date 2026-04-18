# SPRINTS_v7.md — STRATA LATEST OS COVERAGE + LEGACY VERSION GAPS
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md and SPRINTS_v7.md. Execute all incomplete sprints in order.
#         For each sprint: implement, test, commit, then move to the next."
# Last updated: 2026-04-17
# Prerequisite: SPRINTS.md through SPRINTS_v6.md complete
# Current state: 3,357+ tests, 26 plugins registered
# Focus: Bring Strata current with latest OS releases + close legacy version gaps
#
# Context: Research revealed that Strata covers common OS versions well but has
# genuine gaps in:
#   1. Latest OS releases (iOS 26, macOS Tahoe 26, Windows 25H2, Android 15/16)
#   2. Legacy version-specific artifacts (iOS 15-18 quirks, Windows 7/XP,
#      macOS Ventura/Sonoma/Sequoia Biome evolution)
#
# This sprint queue closes both gaps so Strata handles any OS version an
# examiner encounters in the real casework mix.

---

## HOW TO EXECUTE

Read CLAUDE.md first. Then execute each sprint below in order.
For each sprint:
1. Implement exactly as specified
2. Run `cargo test --workspace` — all tests must pass
3. Run `cargo clippy --workspace -- -D warnings` — must be clean
4. Verify zero `.unwrap()`, zero `unsafe{}`, zero `println!`
5. Commit with message: "feat: [sprint-id] [description]" or "fix: [sprint-id] [description]"
6. Move to next sprint immediately

---

## COMPLETED SPRINTS (skip these)

None yet — this is v7.

---

# ═══════════════════════════════════════════════════════
# PART 1 — LATEST OS COVERAGE
# ═══════════════════════════════════════════════════════

## SPRINT APPLE26-1 — iOS 26 iMessage Schema Updates

Enhance `plugins/strata-plugin-pulse/src/ios/imessage.rs` for iOS 26.

**Problem statement:**
Apple renamed iOS from 19 to 26 (year-based numbering). iOS 26 brought
significant iMessage changes making it more Signal-like. Existing iMessage
parsers built for iOS 18 and earlier miss new artifact fields.

**Implementation:**

**Chat Backgrounds (NEW in iOS 26):**
Location: `~/Library/SMS/chat.db`
Schema: `chat` table → `chat_properties` column → binary PLIST
Within PLIST: `backgroundProperties` key contains:
- Background type (solid color / gradient / image)
- Color values (RGB for solid, gradient stops)
- Image reference (if custom image background)
- Image data stored in KTX format (Apple thumbnail format)
- Per-chat basis — different chat = different background

Parse and emit:
```rust
pub struct ImessageBackground {
    pub chat_id: i64,
    pub background_type: String,  // Solid/Gradient/Image
    pub color_primary: Option<String>,
    pub color_secondary: Option<String>,
    pub image_ktx_data: Option<Vec<u8>>,
    pub modified_date: Option<DateTime<Utc>>,
}
```

**Enhanced Encryption Indicators:**
iOS 26 adds `encryption_state` column or equivalent to message table.
Parse encryption state changes per message.

**Updated Attachment Metadata:**
New fields in `attachment` table:
- `is_translated` — indicates message passed through Live Translation
- Translation metadata — what language was detected, what was displayed
- Note: original pre-translation text may NOT be stored (see APPLE26-2)

**Live Translation Integration Markers:**
Messages processed by Live Translation flagged with:
- Translation direction (source_language → target_language)
- Whether original or translated version shown to user
- Timestamp of translation event

**KTX thumbnail format support:**
KTX is Apple's texture format. Parse basic KTX header:
- Magic: `«KTX 11»` (with specific byte signature)
- Endianness byte
- Format identifier
- Width × height
- Extract as identifiable thumbnail for examiner review

Emit `Artifact::new("iOS 26 iMessage Background", path_str)` per background.
Emit `Artifact::new("iOS 26 Live Translation Event", path_str)` per translation.

MITRE: T1005 (data from local system).
forensic_value: Medium for backgrounds, High for translation markers.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT APPLE26-2 — iOS/macOS 26 Live Translation Evidence Loss Detection

Create `crates/strata-core/src/detect/translation_gaps.rs`.

**Problem statement:**
iOS 26 and macOS 26 Live Translation runs entirely on-device using
proprietary AI models. This creates a forensic challenge:
- Messages composed in one language may be translated before storage
- Original input may NOT be stored anywhere on device
- Audio translations during FaceTime/Phone calls processed in real-time
  and typically not retained
- Only final translated version may remain

Examiners need to be explicitly warned when translation may have
obscured original evidence.

**Implementation:**

Detection heuristics:
1. Messages with `is_translated=true` flag — definite translation event
2. Messages in language inconsistent with device locale — possible
   pre-translation storage
3. FaceTime calls with Live Translation enabled (check FaceTime settings) —
   audio content unrecoverable
4. System preference `com.apple.languagetranslate.on=1` — translation
   feature was enabled system-wide

```rust
pub struct TranslationGap {
    /// Where the evidence loss occurred
    pub artifact_path: String,
    /// What kind of evidence may be missing
    pub gap_type: TranslationGapType,
    /// Available evidence (translated version, metadata)
    pub what_is_present: String,
    /// What is likely missing
    pub what_is_missing: String,
    /// Evidentiary impact for the examiner
    pub examiner_warning: String,
    /// Confidence this is a real gap vs. false positive
    pub confidence: f64,
}

pub enum TranslationGapType {
    MessageTranslatedBeforeSend,     // Original language text lost
    MessageTranslatedOnReceive,      // Translation shown, original retained
    FaceTimeLiveTranslation,         // Real-time audio translation, audio lost
    PhoneCallLiveTranslation,        // Phone audio translation, lost
    SystemWideTranslationEnabled,    // Feature was on, scope uncertain
}
```

**Examiner warning templates:**
For each gap type, produce clear warning text:

> "TRANSLATION EVIDENCE GAP: This message was processed by Live Translation.
> The translated version displayed to the user is preserved, but the original
> language input may not have been stored on device. Investigators attempting
> to verify original message content, intent, or linguistic context should
> be aware that pre-translation text may be unavailable. Forensic confidence
> in message attribution reduced for this artifact."

Include this warning in:
- Artifact description
- Report section for this chat/call
- Overall case report "Evidence Limitations" section

**Court-ready reporting:**
Add a "Translation Evidence Limitations" section to the expert witness
report format (UX-1 / WF-10). This is a legitimate legal concern when
translated content is presented as evidence.

Emit `Artifact::new("Translation Evidence Gap", path_str)`.
suspicious=false (this is a limitation, not suspicious activity).
forensic_value: Medium — important context, not direct evidence.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT APPLE26-3 — macOS Tahoe 26 Clipboard History Parser

Create `plugins/strata-plugin-mactrace/src/clipboard_history.rs`.

**Problem statement:**
macOS 26 introduces a MAJOR new forensic artifact: persistent Clipboard
History. Previously clipboard was memory-only and lost at reboot. Now:
- Clipboard data persists to disk
- Searchable via Spotlight
- Contains copied text, document snippets, command-line output, sensitive material
- Retroactively reveals user intent and action sequence

This is among the most significant macOS forensic additions in years.

**Implementation:**

**Likely storage locations (research needed — validate with actual macOS 26 image):**
Primary candidates:
- `~/Library/Containers/com.apple.pboard/`
- `~/Library/Preferences/com.apple.pboard.plist`
- `~/Library/Application Support/com.apple.pboard/ClipboardHistory.db` (SQLite likely)
- Spotlight index references in `~/Library/Metadata/`

Parse SQLite database if present:
```rust
pub struct ClipboardEntry {
    /// When the item was copied
    pub timestamp: DateTime<Utc>,
    /// Type of content (Text/Image/File/RichText/URL/Code)
    pub content_type: String,
    /// The copied content (for text types)
    pub content_text: Option<String>,
    /// Source application that had focus when copied
    pub source_app: Option<String>,
    /// Source document/URL if detectable
    pub source_context: Option<String>,
    /// Size in bytes
    pub size: u64,
    /// Whether content was detected as sensitive (passwords, SSN, etc.)
    pub sensitive_detected: bool,
}
```

**Content analysis:**
Flag sensitive clipboard entries:
- Password-like patterns (mixed case, numbers, symbols, length 8-64)
- Credit card numbers (Luhn check)
- SSN patterns
- Private key markers (BEGIN PRIVATE KEY, ssh-rsa, etc.)
- API keys (AKIA prefix, sk- prefix, etc.)
- URLs with credentials (https://user:pass@...)

**Court value:**
Clipboard history can prove:
- User intent (copied text before pasting into email)
- Evidence of exfiltration (copying from sensitive document)
- Knowledge (user copied specific content indicating awareness)
- Timeline reconstruction (sequence of copy operations)

Emit `Artifact::new("macOS 26 Clipboard History", path_str)` per entry.
suspicious=true for sensitive content matches.
MITRE: T1115 (clipboard data).
forensic_value: High — this is a primary new evidence source.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT APPLE26-4 — iOS/macOS 26 FaceTime Database Restructure

Enhance FaceTime parsers for iOS 26 and macOS Tahoe 26 schema changes.

**Problem statement:**
FaceTime database underwent structural changes in iOS 26 / macOS 26:
- Tables reorganized
- Call history metadata stored differently
- Timestamps, duration, contact associations in new schemas

Old parsers miss or misinterpret FaceTime data on iOS 26+ devices.

**Implementation:**

**iOS FaceTime:**
Location: `~/Library/Preferences/com.apple.FaceTime.plist` + `CallHistory.storedata`
New schema fields (iOS 26+):
- `ZDATE` migration to new timestamp format
- New `ZANSWERED` column semantics
- Group FaceTime participant tracking
- Live Translation integration

**macOS FaceTime:**
Location: `~/Library/Application Support/CallHistoryDB/CallHistory.storedata`
Similar schema updates as iOS.

Handle both old and new schemas — detect by looking for presence of new columns.

```rust
pub struct FaceTimeCall {
    pub call_id: String,
    pub participants: Vec<String>,        // Multiple for group calls
    pub direction: String,                 // Incoming/Outgoing
    pub started: DateTime<Utc>,
    pub ended: Option<DateTime<Utc>>,
    pub duration_seconds: Option<u64>,
    pub answered: bool,
    pub call_type: String,                 // Audio/Video/Group
    pub live_translation_used: bool,
    pub live_translation_languages: Vec<String>,
    pub device_os_version: Option<String>, // Schema version detected
}
```

**Group FaceTime handling:**
iOS 26 improved group call metadata. Track:
- All participants per call
- Who joined when, who left when
- Call initiator

**Live Translation integration:**
Flag calls where Live Translation was used:
- Cross-reference with system translation logs
- Note audio content likely unrecoverable (per APPLE26-2)

MITRE: T1005 (data from local system).
forensic_value: High — communications evidence.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT APPLE26-5 — iOS/macOS 26 Notes + Apple Intelligence Artifacts

Create `plugins/strata-plugin-pulse/src/ios/notes_ai.rs` and
`plugins/strata-plugin-mactrace/src/notes_ai.rs`.

**Problem statement:**
iOS 26 and macOS 26 introduced Apple Intelligence features:
- AI-enhanced Notes with summarization and rewriting
- Writing Tools (rewrite, proofread, summarize)
- Image Playground (AI-generated images)
- Genmoji (AI-generated emoji)
- Apple Intelligence request/response logs

These leave artifacts in new system paths that no tool parses yet.

**Implementation:**

**Notes app enhancements:**
Standard Notes database: `NoteStore.sqlite` in:
- iOS: `/private/var/mobile/Containers/Shared/AppGroup/{GUID}/NoteStore.sqlite`
- macOS: `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

New iOS/macOS 26 tables/columns:
- AI-generated content markers (`ZAI_GENERATED_FLAG` or similar)
- Rewrite history (original vs AI-rewritten versions)
- Summarization metadata
- Smart folders with AI categorization

Extract:
```rust
pub struct NotesAIArtifact {
    pub note_id: i64,
    pub title: String,
    pub creation_date: DateTime<Utc>,
    pub modification_date: DateTime<Utc>,
    pub contains_ai_content: bool,
    pub ai_operations: Vec<String>,  // "Summarize", "Rewrite", "Proofread"
    pub original_text_available: bool,
    pub ai_modified_text: Option<String>,
    pub original_text: Option<String>,
    pub writing_tools_used: Vec<String>,
}
```

**Apple Intelligence request logs:**
Location candidates:
- `~/Library/Logs/AppleIntelligence/`
- Unified Log entries with subsystem `com.apple.intelligence`

Parse for:
- Request timestamp
- Request type (text generation, image generation, summarization)
- App that initiated the request
- Whether processed on-device or on Private Cloud Compute

**Image Playground artifacts:**
Location: `~/Library/Images/Playground/` (likely)
- AI-generated images with prompt metadata
- Generation timestamps
- Source prompts (forensically significant — what did user ask AI to create?)
- Style parameters

**Genmoji artifacts:**
Custom AI-generated emoji stored with prompts.

**Writing Tools usage in Messages/Mail/Notes:**
Track when AI writing tools modified user content.

Emit `Artifact::new("Apple Intelligence Request", path_str)`.
Emit `Artifact::new("Image Playground Generation", path_str)`.
Emit `Artifact::new("Notes AI Enhancement", path_str)`.

**Forensic significance:**
- Proves user asked AI to do something specific
- Image Playground prompts may reveal intent
- AI-modified content vs user-written content distinction matters legally

MITRE: T1005 (data from local system).
forensic_value: High — proves AI-assisted actions and potential intent.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT ANDROID16-1 — Android 14+ Turbo App Usage Parser

Create `plugins/strata-plugin-carbon/src/turbo_usage.rs`.

**Problem statement:**
Android 14 introduced Turbo App Usage tracking via Google's Device
Personalization Services. This is a comprehensive app usage tracking
system that many commercial tools have not fully integrated.

**Implementation:**

Location: `/data/com.google.android.as/databases/reflection_gel_events.db`

Schema (SQLite):
Key tables typically include:
- `reflection_events` — app launch/close/interaction events
- `app_usage_metadata` — daily aggregate usage stats

Key columns:
- `package_name` — which app
- `event_type` — launch, close, notification, interaction
- `timestamp` — Unix milliseconds
- `duration` — session length
- `foreground_time` — time actively used

```rust
pub struct TurboUsageEvent {
    pub package_name: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub duration_seconds: Option<u64>,
    pub foreground_time_seconds: Option<u64>,
    pub interaction_count: Option<u32>,
}
```

**Correlation with Digital Wellbeing:**
Samsung devices have Digital Wellbeing / Rubin which duplicates some
tracking. Correlate Turbo Usage with existing Digital Wellbeing artifacts
for confidence validation.

**Also parse:**
`/data/com.google.android.as/databases/SimpleStorage` — additional app usage data.

**Forensic significance:**
- Precise app usage patterns (what did user have open at specific time?)
- Validates or contradicts user statements about device usage
- Critical in alibi cases and trafficking investigations

Emit `Artifact::new("Turbo App Usage", path_str)` per event.
MITRE: T1005 (data from local system).
forensic_value: High — comprehensive app usage evidence.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT ANDROID16-2 — Samsung Rubin + Digital Wellbeing Schema Updates

Enhance `plugins/strata-plugin-carbon/src/samsung.rs` for Android 15/16 schemas.

**Problem statement:**
Samsung's Rubin service (security layer) and Digital Wellbeing have
received schema updates in Android 15/16. Existing parsers may miss
new fields or misinterpret updated schemas.

**Implementation:**

**Samsung Rubin updates:**
Location: `/data/com.samsung.android.rubin.app/databases/`
New fields in Android 15/16:
- Location-based app suggestions (proves location at time of suggestion)
- Routine trigger events (when user's pattern triggered automation)
- Context detection events (driving, at home, at work)

**Digital Wellbeing updates:**
Location: `/data/com.google.android.apps.wellbeing/databases/app_usage`
New schema elements:
- Focus mode usage (when did user enable focus, what apps were blocked)
- Bedtime mode activation
- App timer configurations and overrides
- Sleep insights data

**Screen time aggregation:**
Cross-correlate:
- Turbo Usage (granular events)
- Digital Wellbeing (daily summaries)
- Samsung Rubin (context)
- Accessibility logs (screen state changes)

Emit `Artifact::new("Samsung Rubin Event", path_str)`.
Emit `Artifact::new("Android Wellbeing Activity", path_str)`.

MITRE: T1005.
forensic_value: Medium-High depending on case.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT ANDROID16-3 — Modern Android File-Wiping Tool Detection

Create `plugins/strata-plugin-vault/src/android_antiforensic.rs`.

**Problem statement:**
2026 research published in Journal of Forensic Sciences documented
specific artifact patterns left by file-wiping applications on modern
Android. These tools overwrite data areas with specific patterns.
Detecting their use is critical for investigations where evidence
destruction is suspected.

**Implementation:**

**Known file-wiping apps to detect:**
- Secure Delete (com.protectstar.securedelete)
- iShredder (com.protectstar.ishredder)
- File Shredder (com.hyperionics.fileshredder)
- Android Shredder (various packages)
- Secure Eraser (com.ascomp.secureeraser)
- Mr Wiper (com.mrwiper)

**Detection methods:**

1. **Package installation records:**
   `/data/system/packages.xml`, `packages.list`
   Presence of known wiper package names

2. **App execution traces:**
   Turbo Usage, Digital Wellbeing, UsageStats showing wiper app launches

3. **Wiping pattern signatures:**
   Research-documented patterns left in overwritten data:
   - 0xFF repeated (single pass overwrite)
   - 0x00 repeated
   - DoD 5220.22-M pattern (3-pass)
   - Gutmann pattern (35-pass, rare on Android)
   - Random pattern with specific entropy signature

4. **File system anomalies:**
   - Sudden gaps in `$UsnJrnl` equivalent (Android's metadata changelog)
   - Mass modifications at specific timestamps
   - Unallocated blocks with non-random repeated patterns

5. **Correlation with time windows:**
   If wiper app was launched AND large numbers of files disappeared
   within same window — high confidence evidence destruction.

```rust
pub struct AndroidWipingIndicator {
    pub indicator_type: String,
    pub wiper_app_detected: Option<String>,
    pub installation_time: Option<DateTime<Utc>>,
    pub execution_times: Vec<DateTime<Utc>>,
    pub pattern_signatures_found: Vec<String>,
    pub estimated_files_wiped: Option<u64>,
    pub confidence: f64,
    pub legal_significance: String,
}
```

**Legal significance templates:**
For each detection, produce examiner-ready language:

> "ANTI-FORENSIC ACTIVITY DETECTED: Evidence consistent with use of
> commercial file-wiping application '[name]' was identified. Application
> installed on [date], executed at [time(s)]. [N] files appear to have been
> intentionally overwritten using [pattern] technique. This activity may
> constitute obstruction of justice or spoliation of evidence."

**Output to obstruction scoring:**
Detected wiping events heavily weighted in obstruction score (strata-ml-obstruction).
A confirmed wiping event moves the 0-100 score significantly toward 100.

Emit `Artifact::new("Android File Wiping Indicator", path_str)`.
suspicious=true always.
MITRE: T1485 (data destruction), T1070 (indicator removal).
forensic_value: Critical — evidence of evidence destruction.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT WIN25H2-1 — Windows AI Actions File Explorer Artifacts

Create `plugins/strata-plugin-chronicle/src/ai_actions.rs`.

**Problem statement:**
Windows 11 24H2/25H2 introduced "AI Actions" in File Explorer allowing
right-click AI operations on images (JPG/JPEG/PNG):
- Bing Visual Search
- Blur Background
- Erase Objects (Generative Erase)
- Remove Background

These operations leave execution traces that prove user used AI tools
on specific files. Critical for cases involving:
- Image manipulation (evidence tampering)
- CSAM context (detecting use of AI on suspect images)
- Counter-surveillance (blurring license plates, faces)

**Implementation:**

**Registry indicators:**
Location: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AIActions\`
Check for:
- Last used timestamps per action type
- File paths operated upon (may be stored)
- Usage counts per action

**Event log:**
`Microsoft-Windows-Shell-Core/Operational.evtx`
Look for:
- Events related to ContextMenu AI operations
- AI service invocations

**AppData traces:**
Location: `%LOCALAPPDATA%\Microsoft\Windows\Explorer\AIActions\`
May contain:
- Cache of recent operations
- Preview images before/after
- Operation metadata

**Prefetch:**
AI Action handler executables leave Prefetch entries showing execution.

**Bing Visual Search specifically:**
Separate artifact — URL queries with attached images.
`%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History` — may contain
Bing Visual Search query history.

```rust
pub struct WindowsAIAction {
    pub action_type: String,  // VisualSearch/BlurBackground/EraseObjects/RemoveBackground
    pub timestamp: DateTime<Utc>,
    pub source_file_path: Option<String>,
    pub source_file_hash: Option<String>,
    pub result_file_path: Option<String>,
    pub user_context: String,
}
```

**Correlation with Windows Recall (W-14):**
If Recall was enabled, screenshots around the AI Action timestamps may
show what the user was working on. Cross-reference.

**Forensic significance:**
- Image manipulation evidence (Blur Background on faces/license plates =
  potential counter-surveillance)
- Generative Erase on original document = potential tampering
- Bing Visual Search queries may reveal what user was trying to identify

Emit `Artifact::new("Windows AI Action", path_str)`.
suspicious=true for manipulation actions (Blur/Erase/Remove).
MITRE: T1070 (if manipulation detected), T1027 (defense evasion).
forensic_value: High — image manipulation proof.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT WIN25H2-2 — Click to Do + Semantic Indexing Artifacts

Create `plugins/strata-plugin-chronicle/src/click_to_do.rs`.

**Problem statement:**
Windows 11 25H2 on Copilot+ PCs has "Click to Do" and Semantic Indexing
features that provide AI-driven content recognition and actions on
whatever is currently on screen. These leave unique artifacts showing
what users did with AI on their files and screen content.

**Implementation:**

**Click to Do artifacts:**
Location candidates (need validation):
- `%LOCALAPPDATA%\Microsoft\Windows\ClickToDo\`
- Unified event store for AI interactions

Parse:
- Action type (Text Action / Image Action / Text+Image Action)
- Target content (what was clicked on — text snippet, image region)
- Action taken (Search, Translate, Summarize, Copy Enhanced, etc.)
- Timestamp
- Source app

**Semantic Indexing:**
Semantic Indexing creates an AI-indexed database of documents for
natural language search. Location:
- `%LOCALAPPDATA%\Microsoft\Windows\SemanticIndex\`
- Database structure (likely SQLite)

Parse:
- Indexed file paths
- Extracted semantic tags/topics per file
- Index creation/update timestamps
- User search queries against the index

**Windows Copilot Assistant:**
Location: `%LOCALAPPDATA%\Microsoft\Windows\Copilot\`
- Interaction logs
- Queries made to Copilot
- Responses/actions taken

```rust
pub struct ClickToDoEvent {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub target_content_type: String,  // Text/Image/Mixed
    pub target_content_preview: Option<String>,
    pub action_taken: String,
    pub source_application: Option<String>,
    pub source_document: Option<String>,
}

pub struct SemanticIndexEntry {
    pub file_path: String,
    pub indexed_date: DateTime<Utc>,
    pub extracted_topics: Vec<String>,
    pub document_summary: Option<String>,
}
```

**Forensic significance:**
Copilot+ PC users are leaving an unprecedented trail of AI interactions:
- What questions did user ask AI?
- What documents did AI index? (proves user had these files)
- What actions were taken via AI?

This is Recall-level forensic value. Critical for modern Windows forensics.

Emit `Artifact::new("Click to Do Event", path_str)`.
Emit `Artifact::new("Semantic Index Entry", path_str)`.
Emit `Artifact::new("Copilot Interaction", path_str)`.

MITRE: T1005, T1083 (file and directory discovery).
forensic_value: High — AI interaction proof.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 2 — LEGACY OS VERSION GAPS
# ═══════════════════════════════════════════════════════

## SPRINT LEGACY-IOS-1 — iOS Biome Format Version Handling

Enhance `plugins/strata-plugin-pulse/src/ios/biome.rs` for format versions.

**Problem statement:**
Biome binary file format introduced in iOS 15, remained same in iOS 16,
changed significantly in iOS 17, and likely evolved again in iOS 26.
Existing Biome parser may only handle one version.

**Implementation:**

**Version detection:**
Parse Biome SEGB file header to detect format version:
- iOS 15/16: Original Biome SEGB format
- iOS 17: Restructured SEGB format (different record layout)
- iOS 18: Minor schema refinements
- iOS 26: Further changes (research needed)

**Format switcher:**
```rust
pub enum BiomeFormatVersion {
    V15_16,  // Original format (iOS 15 and 16)
    V17,     // Restructured for iOS 17
    V18,     // iOS 18 refinements
    V26,     // iOS 26 (latest)
}

impl BiomeFormatVersion {
    pub fn detect(header_bytes: &[u8]) -> Self {
        // Parse header signature bytes to determine version
    }
}
```

**Per-version parsers:**
Implement separate parsing logic per format version. Common output
structure so downstream correlation works regardless of source version.

**Fallback:**
If version cannot be determined, attempt all parsers — report whichever
produces sensible output. Log uncertainty.

**Streams to parse across all versions:**
- `app/inFocus` — app focus events
- `safariHistory` — browsing history
- `photos/assetAdded` — when photos added
- `messaging/sent` — message send events
- `location/significant` — location visits
- `app/intents` — Siri intent invocations
- `app/launch` — app launches

**Tests required:**
- Parse iOS 15 Biome successfully
- Parse iOS 16 Biome successfully
- Parse iOS 17 Biome successfully
- Parse iOS 18 Biome successfully
- Version detection correctness

Zero unwrap, zero unsafe, Clippy clean, six tests minimum.

---

## SPRINT LEGACY-IOS-2 — iOS 16 Unsent Messages + AirDrop "Boop"

Create `plugins/strata-plugin-pulse/src/ios/ios16_features.rs`.

**Problem statement:**
iOS 16 introduced the ability to unsend messages. A forensic artifact
shows when messages were unsent, preserving evidence even after user
attempts to hide it. iOS 16.2+ also introduced the AirDrop "boop"
service for transferring files without being contacts.

**Implementation:**

**Unsent Messages (iOS 16+):**
Location: `chat.db`
Schema additions for unsent messages:
- `ZDELETEDAT` or similar column indicates unsend timestamp
- Original message content may be preserved with deletion flag
- Separate `unsend_message` or `message_deletion` record

Parse:
```rust
pub struct UnsentMessage {
    pub message_id: i64,
    pub chat_id: i64,
    pub original_text: Option<String>,  // May or may not be preserved
    pub sent_timestamp: DateTime<Utc>,
    pub unsent_timestamp: DateTime<Utc>,
    pub time_before_unsent_seconds: u64,  // How fast user unsent
    pub sender: String,
    pub recipient: String,
}
```

**Forensic significance:**
- User attempted to delete evidence after sending
- Short time between send and unsend = knowledge of content
- Court will find this highly probative

**AirDrop "Boop" Service (iOS 16.2+):**
Location: `/private/var/mobile/Library/Preferences/com.apple.sharingd.plist`
and AirDrop transfer logs in `unified logs`.

Parse:
- Files transferred via "boop" (non-contact transfers)
- Recipient device identifiers
- File names and types
- Transfer timestamps

**Significance:**
"Boop" transfers happen to people not in contacts — suggests meeting
strangers. Relevant in trafficking, drug cases, clandestine communication.

```rust
pub struct AirDropBoopTransfer {
    pub timestamp: DateTime<Utc>,
    pub direction: String,  // Sent/Received
    pub file_name: Option<String>,
    pub file_size: Option<u64>,
    pub recipient_or_sender_device: String,
    pub transfer_type: String,  // Boop/Standard
}
```

Emit `Artifact::new("iOS Unsent Message", path_str)`.
Emit `Artifact::new("AirDrop Boop Transfer", path_str)`.
suspicious=true for unsent messages (intent to hide).
MITRE: T1070 (indicator removal) for unsent messages.
forensic_value: High for unsent messages (evidence destruction attempt).

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT LEGACY-IOS-3 — iOS 17 Message Retention Settings

Enhance `plugins/strata-plugin-pulse/src/ios/imessage.rs` for retention.

**Problem statement:**
In iOS 17+, the default message retention setting is Forever. When set
to Forever, the `com.apple.MobileSMS.plist` no longer contains the
`KeepMessageForDays` key. Examiners hunting for deleted messages need
to validate current message retention settings before concluding
messages were intentionally deleted.

**Implementation:**

Parse `com.apple.MobileSMS.plist`:
```rust
pub struct MessageRetentionSetting {
    pub current_setting: MessageRetention,
    pub setting_has_changed: bool,
    pub historical_settings: Vec<HistoricalRetention>,
    pub messages_expected_present: Option<u64>,
    pub messages_actually_present: u64,
    pub gap_detected: bool,
    pub gap_explanation: String,
}

pub enum MessageRetention {
    Forever,         // Default in iOS 17+
    OneYear,         // 365 days
    ThirtyDays,      // 30 days
    Unknown,
}

pub struct HistoricalRetention {
    pub setting: MessageRetention,
    pub detected_at: DateTime<Utc>,
    pub source: String,  // Plist backup, shadow copy, etc.
}
```

**Examiner guidance output:**
For each chat thread, calculate:
- Expected message count based on retention setting and thread age
- Actual message count present
- Gap between expected and actual

If gap detected:
- If retention = 30 days and missing messages are older: NORMAL, not deletion
- If retention = Forever and messages missing: POSSIBLE DELETION, investigate
- If retention changed from Forever → 30 days recently: INTENTIONAL EVIDENCE
  DESTRUCTION likely

**Warning templates:**

> "MESSAGE RETENTION ANALYSIS: User had message retention set to [X]. Thread
> with [contact] spans [Y] months. Expected [N] messages given setting,
> found [M]. Gap analysis: [explanation]."

> "ALERT: Message retention setting was changed from 'Forever' to '30 days'
> on [date], which resulted in older messages being purged. This action
> may constitute intentional evidence destruction if preceded investigation."

**Court value:**
Prevents false conclusions that messages were deleted when they simply
aged out of retention. Also identifies when retention setting changes
correlate suspiciously with legal process.

Emit `Artifact::new("iOS Message Retention Setting", path_str)`.
suspicious=true if retention changed to shorter period near incident date.
forensic_value: High — prevents examiner error.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT LEGACY-IOS-4 — iCloud Shared Photo Library (iOS 14-18)

Enhance `plugins/strata-plugin-pulse/src/ios/photos.rs` for iCloud SPL.

**Problem statement:**
iCloud Shared Photo Library introduced at WWDC 2022 for iOS 16. Parses
from Photos.sqlite ZSHARE table and supports iOS 14-18. Covers sharing
of photos with family members or other contacts — important for
understanding who had access to what images.

**Implementation:**

Parse `Photos.sqlite` ZSHARE table:
```rust
pub struct ICloudSharedLibrary {
    pub share_id: i64,
    pub library_name: String,
    pub creator: String,
    pub created_date: DateTime<Utc>,
    pub participants: Vec<SharedLibraryParticipant>,
    pub asset_count: u64,
    pub is_active: bool,
}

pub struct SharedLibraryParticipant {
    pub apple_id: String,
    pub role: String,  // Creator/Contributor/Participant
    pub invite_date: Option<DateTime<Utc>>,
    pub accept_date: Option<DateTime<Utc>>,
    pub removed_date: Option<DateTime<Utc>>,
}

pub struct SharedAsset {
    pub asset_id: i64,
    pub contributor_apple_id: String,
    pub contribution_date: DateTime<Utc>,
    pub file_path: Option<String>,
    pub original_filename: Option<String>,
    pub moved_from_personal: bool,  // Was originally in user's personal library
}
```

**Three levels of parsing:**

1. **Library metadata** — who created, who's invited, when
2. **Assets contributed by device user** — what did this user add to shared library
3. **Assets contributed by OTHERS** — what did other participants add (critical for scope questions)

**Forensic significance:**
- Determines who had access to specific photos
- Scope issue: if user is participant but not contributor, photo evidence
  may not be attributable to them
- Trafficking investigations: shared library with suspicious contributors
- CSAM investigations: critical to understand who uploaded vs who viewed

**Integration with CSAM detection:**
When CSAM hash matches occur, flag if the asset came from:
- User's personal library (high attribution confidence)
- User's contributions to shared library (high confidence)
- Other user's contributions to shared library (attribution uncertain —
  critical examiner note)

Emit `Artifact::new("iCloud Shared Photo Library", path_str)`.
Emit `Artifact::new("Shared Library Asset", path_str)`.
forensic_value: High — attribution evidence.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT LEGACY-WIN-1 — Windows 7 Shellbag Format

Enhance `plugins/strata-plugin-chronicle/src/shellbags.rs` for Windows 7.

**Problem statement:**
Windows 7 Shellbag format differs significantly from both Windows XP and
Windows 10/11. The familiar Shell, ShellNoRoam, and StreamMRU categories
(XP) were consolidated into the Shell subkey in Windows 7. Windows 7
systems still appear in active casework and parsers built for newer
Windows versions may misinterpret the data.

**Implementation:**

**Windows 7 Shellbag locations:**
NTUSER.DAT:
- `Software\Microsoft\Windows\Shell\Bags`
- `Software\Microsoft\Windows\Shell\BagMRU`
- `Software\Microsoft\Windows\ShellNoRoam\Bags` (legacy)
- `Software\Microsoft\Windows\ShellNoRoam\BagMRU` (legacy)

USRCLASS.DAT:
- `Local Settings\Software\Microsoft\Windows\Shell\Bags`
- `Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

**Parse hierarchy:**
Shellbag entries are hierarchical — each subkey represents a folder
the user navigated to. Timestamps reveal first access, last access,
last modified.

```rust
pub struct Windows7Shellbag {
    pub bag_number: u32,
    pub mru_index: u32,
    pub folder_path: String,  // Reconstructed from hierarchy
    pub folder_type: String,  // Local/Network/Removable/Unknown
    pub first_accessed: Option<DateTime<Utc>>,
    pub last_accessed: Option<DateTime<Utc>>,
    pub last_modified: Option<DateTime<Utc>>,
    pub shell_item_data: Vec<u8>,
    pub windows_version: String,  // "Windows 7" detected
}
```

**Forensic significance:**
Shellbags prove user accessed specific folders, even if folder was
later deleted or on removable media no longer present. Windows 7 bags
often retain information from USB drives inserted years earlier.

**Critical in cases involving:**
- Data theft (accessed sensitive folders)
- USB drive usage (removable media folders in shellbags)
- Network share access
- CP/CSAM (folders opened even if content deleted)

Emit `Artifact::new("Windows 7 Shellbag", path_str)`.
MITRE: T1083 (file and directory discovery).
forensic_value: High — folder access evidence.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT LEGACY-WIN-2 — Windows XP Artifact Layer

Create `plugins/strata-plugin-chronicle/src/winxp.rs`.

**Problem statement:**
Windows XP still appears in investigations — seized older systems,
industrial control systems, kiosk machines, legacy business systems.
XP has completely different artifact structures than Windows 10/11.

**Implementation:**

**XP Recycle Bin (INFO2):**
Location: `C:\RECYCLER\S-1-5-21-{SID}\INFO2`
Format:
- 820 bytes per record
- Original filename (ASCII and Unicode)
- Original path
- Deleted timestamp (FILETIME)
- File size

Different from $I/$R format used by Vista+.

**XP Shellbags:**
As noted in LEGACY-WIN-1, XP uses:
- Shell (local folders)
- ShellNoRoam (network folders)
- StreamMRU (removable devices)
Three separate hives versus consolidated Shell in Win7+.

**XP UserAssist:**
Location: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
Different GUID structure than Windows 7+:
- `{75048700-EF1F-11D0-9888-006097DEACF9}` (Active Desktop)
- `{5E6AB780-7743-11CF-A12B-00AA004AE837}` (Internet Explorer)

ROT13 encoded like newer versions but different fields.

**XP Prefetch:**
Format version 17 (vs version 23 for Vista+, 30 for Win10, 31 for Win11).
Different header structure.

**XP Event Logs (.evt not .evtx):**
Classic event log format — pre-XML. Different parser required.

**XP Registry Hive format:**
Actually similar to modern Windows but some subtle differences in
transaction log handling.

**XP Link Files (.lnk):**
MS-SHLLINK format older version — subtle differences in
extended attribute structures.

**XP Internet Explorer History:**
- `index.dat` files (binary, not SQLite)
- Location: `C:\Documents and Settings\{user}\Local Settings\Temporary Internet Files\Content.IE5\`
- Separate parser required

```rust
pub enum WindowsXPArtifact {
    Recycler(RecyclerEntry),
    ShellbagStream(StreamShellbag),
    UserAssist(XPUserAssist),
    Prefetch(XPPrefetch),
    EventLog(EvtEntry),
    IEHistory(IndexDatEntry),
}
```

**Detection:**
Auto-detect Windows XP by presence of:
- `C:\Documents and Settings\` (instead of Users\)
- `C:\RECYCLER\`
- `.evt` files in `C:\Windows\System32\config\`
- Registry ProductName = "Microsoft Windows XP"

**Forensic significance:**
XP systems often hold the ONLY record of older activity:
- Legacy business records
- Old ICAC investigations (cold cases)
- Industrial systems with historical process data
- Kiosk/POS system investigations

Emit `Artifact::new("Windows XP [Type]", path_str)` per artifact.
forensic_value: Varies — but absence = complete coverage gap.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT LEGACY-WIN-3 — Windows 10 vs 11 Format Variants

Enhance existing parsers with version-aware handling.

**Problem statement:**
Windows 10 and Windows 11 share many artifacts but have subtle format
differences — especially ShimCache, UserAssist, and event log schemas.
Windows 10 end-of-life October 2025 means Win10 systems will be in
casework for years.

**Implementation:**

Systematic version detection and branching:

**ShimCache format versions:**
- Windows 7: Version 2 (different from 8+)
- Windows 8/8.1: Version 3
- Windows 10: Version 4
- Windows 11: Version 5

Each version has different record structure. Detect version by magic
bytes and use appropriate parser.

**AmCache format versions:**
- Windows 7: Does not exist
- Windows 8/8.1: Early format
- Windows 10 1607+: Modern format
- Windows 11: Extended format

Already partially handled but worth validating coverage.

**UserAssist encoding:**
- XP: ROT13 with XP-specific GUIDs
- Windows 7: ROT13 with updated GUID set
- Windows 10: ROT13 with additional telemetry fields
- Windows 11: ROT13 with Recall integration GUIDs

**Registry transaction log versions:**
- Pre-Win8.1: `.LOG` files (legacy)
- Win8.1+: `.LOG1` and `.LOG2` files
- Win10 1709+: Enhanced transaction log (newer format)

Recovery of unsaved registry changes requires version-aware transaction
log parsing.

**Event log (EVTX) schema:**
Core format same across Win7+, but Event IDs and schemas vary by version:
- Some events only in Windows 10+
- Some events renamed or merged between versions
- Sysmon-style events in Windows 11 Defender logs

**Implementation approach:**
Add version detection to each affected parser. Branch parsing logic by
detected version. Emit version in artifact metadata for examiner reference.

**No new plugin — enhance existing:**
- `plugins/strata-plugin-phantom/` — ShimCache, AmCache, registry
- `plugins/strata-plugin-chronicle/` — UserAssist
- `plugins/strata-plugin-sentinel/` — Event log schemas
- `plugins/strata-plugin-trace/` — Prefetch versions

**Tests required:**
Test images for each Windows version. Validate correct parser selection
and output.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT LEGACY-MAC-1 — macOS Monterey/Ventura/Sonoma/Sequoia Biome Evolution

Enhance `plugins/strata-plugin-mactrace/src/biome.rs` for version handling.

**Problem statement:**
macOS Biome was introduced in Ventura (13) and has evolved through
Sonoma (14) and Sequoia (15). Tahoe (26) adds further changes.
Stream types added, schemas refined, new data sources captured per
version. Parsers must handle all versions an examiner may encounter.

**Implementation:**

**Per-version stream inventory:**

Monterey (12) and earlier: No Biome — use KnowledgeC only

Ventura (13): Biome introduced with initial streams:
- `app/inFocus`
- `app/intents`
- `app/launch`
- `safariHistory`
- `notifications`
- `mediaPlayback`

Sonoma (14) added:
- `networkUsage`
- `locationActivity` (enhanced)
- `deviceLocked`
- `photos/assetAdded` (new structure)

Sequoia (15) added:
- `appleIntelligence/requests` (precursor)
- More refined `mediaPlayback` with casting events
- Enhanced `networkUsage` per-app

Tahoe (26) covered in APPLE26-5.

**Detection:**
Use SystemVersion.plist ProductVersion to determine macOS version.
Apply version-appropriate stream parsers.

**Common output schema:**
Regardless of source version, emit unified artifact type so downstream
correlation works:

```rust
pub struct MacOSBiomeEvent {
    pub stream_type: String,
    pub timestamp: DateTime<Utc>,
    pub source_app: Option<String>,
    pub event_data: HashMap<String, String>,
    pub macos_version: String,
    pub biome_format_version: String,
}
```

**System volume read-only handling (Sonoma+):**
In macOS Sonoma+, System volume is read-only and sealed. Some system
files live on separate volume (Data volume). Account for:
- `/System/Library/` — read-only system files (seal verification)
- `/Users/` — Data volume user files
- Firmlinks/synthetic files that bridge the volumes

Treat as single logical filesystem when parsing, note volume separation
in audit log.

**Time Machine on Sonoma+:**
Snapshot format slightly changed. Local snapshots in `/.Time Machine Local Snapshots/`
require updated parser.

MITRE: T1005.
forensic_value: High — primary user activity source.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 3 — VERSION-AWARE VALIDATION
# ═══════════════════════════════════════════════════════

## SPRINT VALIDATE-v7-1 — Cross-Version Image Matrix Testing

Run full validation across OS version matrix.

**Test image matrix (to be populated in Test Material):**

Apple:
- iOS 15, 16, 17, 18, 26 — FFS extractions or iTunes backups
- macOS Monterey, Ventura, Sonoma, Sequoia, Tahoe 26

Windows:
- Windows XP SP3 (from NPS or public DFIR dataset)
- Windows 7 (existing in Test Material)
- Windows 10 (various builds)
- Windows 11 24H2 and 25H2

Android:
- Android 13, 14, 15, 16 devices
- Samsung, Pixel, OEM variations

**For each image:**
1. Run Strata ingestion
2. Verify correct version auto-detection (DETECT-1 from v6)
3. Verify appropriate version-specific parsers fired
4. Verify no parser errors on valid data
5. Validate artifact counts against expected baseline
6. Check for false positives (parser misinterpreting newer/older schema)

**Deliverable:**
`FIELD_VALIDATION_v7_REPORT.md` with:
- Version detection accuracy table
- Per-version parser health
- New artifacts surfaced per version
- Any version-specific issues

---

## SPRINT VALIDATE-v7-2 — Fix Version-Specific Issues

Fix any blockers or majors surfaced by VALIDATE-v7-1.

Use same methodology as v5 VALIDATE-2:
- Reproduce on failing image
- Write regression test
- Fix properly
- Verify fix
- Commit

---

# ═══════════════════════════════════════════════════════
# COMPLETION CRITERIA
# ═══════════════════════════════════════════════════════

SPRINTS_v7.md is complete when:

**Latest OS coverage (Part 1):**
- APPLE26-1 through APPLE26-5 shipped — iOS 26 and macOS Tahoe 26 covered
- ANDROID16-1 through ANDROID16-3 shipped — Android 15/16 covered
- WIN25H2-1 through WIN25H2-2 shipped — Windows 25H2 AI features covered

**Legacy coverage (Part 2):**
- LEGACY-IOS-1 through LEGACY-IOS-4 shipped — iOS 15-18 gaps closed
- LEGACY-WIN-1 through LEGACY-WIN-3 shipped — Windows 7, XP, 10/11 versions covered
- LEGACY-MAC-1 shipped — macOS Ventura through Sequoia Biome evolution handled

**Validation (Part 3):**
- VALIDATE-v7-1 confirms version detection and parser selection
- VALIDATE-v7-2 closes any issues found

**Quality gates:**
- Test count: 3,357+ plus new tests
- All tests passing
- Clippy clean workspace-wide
- Zero unwrap/unsafe/println introduced
- Load-bearing tests preserved
- Public API unchanged

**Ready:**
- Strata handles any OS version an examiner encounters
- From 2002 Windows XP to 2026 macOS Tahoe
- Cross-version evidence correlation works
- Complete temporal coverage of the forensic image collection

---

*STRATA AUTONOMOUS BUILD QUEUE v7*
*Wolfmark Systems — 2026-04-17*
*Part 1: Latest OS releases (iOS 26, macOS Tahoe, Windows 25H2, Android 16)*
*Part 2: Legacy version gaps (iOS 15-18, Windows XP/7/10, macOS Ventura-Sequoia)*
*Part 3: Cross-version validation*
*Mission: Strata handles ANY OS version in real casework*
*Execute all incomplete sprints in order. Ship everything.*
