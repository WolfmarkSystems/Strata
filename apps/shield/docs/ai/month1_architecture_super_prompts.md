# Month 1 Architecture Super Prompts

These prompts are tuned for deterministic engineering work inside `d:\forensic-suite`. Each one assumes the model should inspect the existing Rust workspace first, preserve evidence integrity, and emit production-ready code with tests.

## Prompt 1: Cross-Platform VHD and VMDK Container Completion

**Goal**
Design and implement a cross-platform parser and virtual disk bridge for VHD/VMDK containers in the Strata Shield engine.

**Input**
- Existing workspace: `d:\forensic-suite`
- Target modules:
  - `engine/src/container/vhd.rs`
  - `engine/src/container/vmdk.rs`
  - `engine/src/virtualization/vhd.rs`
  - `engine/src/virtualization/mod.rs`
- Reference docs:
  - `docs/parser-contract.md`
  - `FEATURES.md`
  - `SUITE_REALITY_REPORT.md`

**Output**
- Complete Rust implementation for one container path at a time
- Updated volume translation logic and safe read path
- Unit tests and container smoke tests
- Build commands and known limitations

**Constraints**
- No `unsafe` Rust
- Preserve no-touch evidence handling
- Return structured `ForensicError` values
- No silent partial reads

**Rationale**
This prompt anchors one of the most visible engine gaps and forces the model to work from the real stubs already in the repository.

## Prompt 2: KB Bridge Integration Into Tauri Backend

**Goal**
Integrate the DFIR KB bridge into the Strata Shield Tauri backend so the suite can query indexed engineering and forensic documentation through a typed Rust client.

**Input**
- Existing workspace: `d:\forensic-suite`
- AI bridge workspace: `d:\DFIR Coding AI`
- Target modules:
  - `gui/src-tauri/src/lib.rs`
  - new module under `gui/src-tauri/src`
- Reference docs:
  - `docs/canonical-model.md`
  - `docs/parser-contract.md`
  - `docs/timeline-api-contract.md`

**Output**
- Rust HTTP client module
- Tauri commands for KB health and KB search
- Integration test for query `NTFS parser`
- Minimal user-facing error messages with full log detail

**Constraints**
- No shelling out from Rust for bridge calls
- Timeouts must be explicit
- JSON request/response must be typed
- Handle bridge-down scenarios cleanly

**Rationale**
This prompt upgrades the suite from static documentation to a usable AI-assisted engineering surface without coupling the UI directly to Python.

## Prompt 3: AI-Protected Background Services for Strata Shield

**Goal**
Design a safe background-service model for Strata Shield where AI builders and long-running categorization tasks are isolated from evidence-processing workflows.

**Input**
- Existing workspace: `d:\forensic-suite`
- Target surfaces:
  - Tauri backend service startup
  - Active jobs UI contract
  - logging and watchdog behavior
- Reference docs:
  - `docs/latency-budget.md`
  - `docs/validation-policy.md`
  - `docs/ux-acceptance-checklist.md`

**Output**
- Service architecture proposal
- Rust service manager skeleton
- Event model for background jobs
- Failure handling matrix

**Constraints**
- Evidence loading must remain available even if AI components fail
- No shared mutable state without synchronization
- Explicit cancellation and timeout paths

**Rationale**
This prompt keeps AI augmentation from destabilizing core forensic workflows and makes background jobs auditable.

## Prompt 4: Cross-Platform Registry and Artifact Builder Contract Hardening

**Goal**
Refactor artifact-builder contracts so email, media, registry, and timeline builders share a stable typed interface across Windows and Linux.

**Input**
- Existing workspace: `d:\forensic-suite`
- Target modules:
  - `gui/src-tauri/src/lib.rs`
  - `engine/src/evidence`
  - `engine/src/timeline`
- Reference docs:
  - `docs/canonical-model.md`
  - `docs/timeline-api-contract.md`

**Output**
- Typed contract definitions
- Builder orchestration updates
- Compatibility tests for empty, partial, and fully populated datasets

**Constraints**
- Maintain existing frontend data shapes unless explicitly versioned
- No duplicate artifact rows from the same logical source
- Timestamp handling must remain explicit and loss-aware

**Rationale**
This prompt is aimed at reducing UI stalls and inconsistent artifact loading by tightening backend contracts first.

## Prompt 5: Secure AI-Assisted Stub Completion Workflow

**Goal**
Create a deterministic AI-assisted completion workflow for unfinished modules, using code generation, review, and integration gates that operate on shared files.

**Input**
- Existing workspace: `d:\forensic-suite`
- Agent workflow config and scripts under `docs/ai` and `scripts`
- Candidate stubs from `engine/src/virtualization`, `engine/src/container`, and parser modules

**Output**
- Workflow-ready prompt pack
- Required handoff schema
- Test command checklist
- Failure and rollback rules

**Constraints**
- Every generated patch must name touched files
- Review stage must explicitly evaluate evidence integrity
- Integration stage must reject undocumented API drift

**Rationale**
This prompt makes the AI system part of the engineering process rather than an untracked side channel.

