# AI/ML Marketing Claims Audit — Strata v0.14.0

**Date:** 2026-04-18
**Scope:** Four claims under the "07 / ML Analysis — AI-Powered Scoring" section of wolfmarksystems.com
**Method:** Read-only source audit. Ripgrep + AST + test-harness enumeration across `crates/`, `plugins/`, `apps/`, and `docs/`. No files modified.

---

## Executive summary for anyone skimming

Three real ML crates exist with real implementations and real unit tests: `strata-ml-anomaly` (1,840 LOC, 23 tests), `strata-ml-obstruction` (812 LOC, 12 tests), `strata-ml-summary` (1,316 LOC, 20 tests). The implementations are honest — IQR-based statistical outlier detection, weighted factor scoring with documented multipliers, Handlebars-template narrative generation. None of them load a model file, and none of them make a network call.

**Critical integration gap:** the three ML engines are called only by the **legacy** `apps/tree/` viewer (called out as legacy in CLAUDE.md § Project Structure). The **primary** Tauri desktop app at `apps/strata-desktop/` does not depend on any of the three ML crates. The CLI pipeline at `strata-shield-cli`'s `ingest run` does not call any of them. The Sigma plugin (which is documented as the place cross-artifact rules live) references AnomalyEngine *output* in comments at `plugins/strata-plugin-sigma/src/lib.rs:883, 910, 936` — but Sigma does not depend on `strata-ml-anomaly` and no plugin in the pipeline produces records with `subcategory == "ML Anomaly"`, so those three rules never fire on a real case.

The "no cloud, no model files" claim is technically true. Everything else on the marketing page overstates the state of end-to-end integration.

---

## Claim 1 — "Anomaly detection flags statistical outliers"

### Verdict: **(B) PARTIALLY SHIPPING**

### Evidence

- `crates/strata-ml-anomaly/src/features.rs` — real statistical primitives:
  - `BaselineStats { mean, std_dev, median, iqr, q1, q3 }` (lines 49–58)
  - `is_outlier_iqr(value)` — standard 1.5 × IQR rule
  - `is_extreme_outlier_iqr(value)` — 3.0 × IQR rule
  - z-score helper: `(value - mean) / std_dev`
- `crates/strata-ml-anomaly/src/engine.rs` — `AnomalyEngine::analyze(case_id, outputs) -> AnomalyReport` at lines 43–65. Dispatches to five detectors:
  - `detectors/timestamps.rs` (timestomp via $SI/$FN mismatch)
  - `detectors/temporal.rs` (activity outside typical-hour baseline)
  - `detectors/antiforensic.rs` (tool co-occurrence + deletion clustering)
  - `detectors/deletion.rs` (bulk-delete rate outliers)
  - `detectors/stealth.rs` (single-run, no-interaction artifacts)

### Test coverage

23 tests across the crate: 6 in `engine.rs` + 6 in `features.rs` + 4 in `antiforensic.rs` + 4 in `stealth.rs` + 4 in `timestamps.rs` + 3 in `temporal.rs` + 2 in `deletion.rs`. Load-bearing tests present: `advisory_notice_present_in_all_findings`, `is_advisory_always_true` (CLAUDE.md § Load-Bearing Tests).

### What it actually does, plain language

Given a set of plugin outputs already produced by the forensic pipeline, the engine computes per-series descriptive statistics (mean/std-dev/quartiles) and flags individual events whose values fall outside standard IQR or z-score thresholds. Every finding is tagged with `ADVISORY NOTICE` text and `is_advisory = true` to prevent downstream code from mistaking the output for a forensic conclusion.

### What it does NOT do that the claim might imply

- It is **never run by the production ingest pipeline**. Grep for `AnomalyEngine::new` / `AnomalyEngine::default` / `\.analyze\(` outside the crate's own tests returns **zero hits** in `apps/strata-desktop/`, `plugins/`, `crates/strata-engine-adapter/`, `crates/strata-shield-cli/`, `crates/strata-shield-engine/`. The only external call is `apps/tree/strata-tree/` (the legacy egui viewer), and even that import path routes through the summary view, not via an automated post-ingest hook.
- The Sigma plugin's Rules 30/31/32 claim to "fire when AnomalyEngine finds …" (`plugins/strata-plugin-sigma/src/lib.rs:883, 910, 936`) but Sigma has no Cargo dependency on `strata-ml-anomaly` and reads `subcategory == "ML Anomaly"` from `ctx.prior_results` — no plugin or pipeline stage produces such records, so these rules are dead code.
- "Statistical outlier" means IQR/z-score, not machine-learned. No training, no model, no adaptive baseline — just descriptive statistics.

### What would make the claim fully honest

Wire `AnomalyEngine::analyze` into the `strata ingest run` pipeline (most likely after all plugins run, before Sigma) so its findings flow into the persisted artifact store and the Sigma rules fire. Until that wiring lands, the claim promises a capability the shipping pipeline does not exercise on a real case.

---

## Claim 2 — "Executive case summaries in plain English"

### Verdict: **(B) PARTIALLY SHIPPING**

### Evidence

- `crates/strata-ml-summary/src/generator.rs` — `SummaryGenerator::new() -> Result<Self, anyhow::Error>` and `generate(input: &SummaryInput) -> Result<GeneratedSummary, anyhow::Error>` at lines 8–24. Multi-phase pipeline: structured extraction → template rendering → claim-source annotation.
- `crates/strata-ml-summary/src/template_engine.rs` — Handlebars-backed renderer loading five `.hbs` templates via `include_str!`:
  - `templates/overview.hbs`
  - `templates/charged_conduct.hbs`
  - `templates/destruction_event.hbs`
  - `templates/focus_recommendation.hbs`
  - `templates/advisory.hbs`
- `crates/strata-ml-summary/src/extractor.rs` — `FindingExtractor::extract_charge_relevant` / `extract_destruction_events` / `extract_highlights` / `extract_narrative_timeline` / `generate_focus_recommendations`.
- Every generated summary is stamped `SummaryStatus::Draft` and `examiner_approved: false` on creation.

### Test coverage

20 tests across the crate: 9 in `generator.rs`, 4 in `extractor.rs`, 4 in `template_engine.rs`, 3 in `types.rs`. Load-bearing tests: `summary_status_defaults_to_draft`, `examiner_approved_defaults_to_false`, `advisory_notice_always_present_in_output`.

### What it actually does, plain language

Takes the artifacts produced by the plugin pipeline, extracts a fixed taxonomy of findings (charge-relevant artifacts, destruction events, focus recommendations, highlights), fills handlebars templates with those findings, and returns a multi-section text report marked as a Draft pending examiner approval.

### What it does NOT do that the claim might imply

- **No LLM. No neural model.** Grep for `openai|anthropic|claude\.ai|ollama|candle|ort|tch|hf_hub|tokenizers|llama|mistral|gpt-` across the ML crates returns zero hits. The "plain English" is the English the templates were written in by a human.
- Only the legacy `apps/tree/strata-tree/src/ui/summary_view.rs` calls `SummaryGenerator::new()`. The primary `apps/strata-desktop/` does not depend on `strata-ml-summary`. The CLI has no summary subcommand.
- Template output is deterministic: same input, same output, bit-for-bit. It does not adapt language to audience, does not rank findings by narrative importance, does not synthesize — it fills slots.

### What would make the claim fully honest

Either (a) wire `SummaryGenerator` into the primary desktop app and/or CLI export flow so a "generate summary" button exists on production cases, or (b) reword the website copy to make the template-based nature explicit ("template-rendered case summary" rather than "AI-powered").

---

## Claim 3 — "Anti-forensic obstruction scoring (0–100) catches VSS deletion, log clearing, and evidence destruction"

### Verdict: **(B) PARTIALLY SHIPPING**

### Evidence

- `crates/strata-ml-obstruction/src/scorer.rs:7–23` — the `WEIGHTS` table with 13 labeled behaviors and integer weights, including all three named in the claim:
  - `VSS_DELETION` — weight 35 ("Volume Shadow Copy deletion")
  - `EVTX_SECURITY_CLEAR` — weight 22 ("Windows Security Event Log cleared")
  - `EVTX_SYSTEM_CLEAR` — weight 15 ("Windows System Event Log cleared")
  - plus SECURE_DELETE_TOOL, TIMESTAMP_STOMP, MFT_LOG_GAP, HIBERNATE_DISABLED, PAGEFILE_CLEAR, EVENT_LOG_AUDIT_OFF, ENCRYPTED_CONTAINER, ANTIFORENSIC_SEARCH, RECYCLE_MASS_DELETE, BROWSER_HIST_CLEAR.
- `crates/strata-ml-obstruction/src/scorer.rs:93–…` — `ObstructionScorer::score(case_id, behaviors, seizure_time) -> ObstructionAssessment` with clamping to 0–100, severity bands (Minimal/Low/Moderate/High/Significant), and multiplier logic for behaviors co-occurring with VSS deletion (lines 102–122).
- `crates/strata-ml-obstruction/src/detector.rs` — concrete detection routines keyed to plugin output strings:
  - `detect_vss_deletion` (line 39) — matches `"vssadmin"` / `"delete shadows"` in artifact details
  - `detect_evtx_clearing` (line 56) — matches event-log clear signals
  - `detect_secure_delete_tool` — checks for ccleaner / eraser / sdelete / `cipher.exe /w` (line 94).

### Test coverage

12 tests in `scorer.rs` including `vss_deletion_adds_correct_weight` (line 346) and `is_advisory_always_true` (line 408). Detector-layer unit tests present in `scorer.rs` but not in `detector.rs` (0 test attributes in that file).

### What it actually does, plain language

Given a list of detected anti-forensic behaviors (produced by the detector layer scanning plugin output strings), produces a 0–100 score, a severity label, and an itemized factor table documenting which behavior contributed which weight. Score is always tagged `is_advisory = true` and carries an ADVISORY notice rejecting any interpretation as a legal finding.

### What it does NOT do that the claim might imply

- **Not integrated into the production pipeline.** `ObstructionScorer::score` is called only from the crate's own tests. `ObstructionDetector::detect` is not called from any app, plugin, CLI command, or engine adapter. On a real case run through `strata ingest run`, no obstruction assessment is produced.
- The detector keys on **artifact-detail string matching** (`.contains("vssadmin")`, etc.). If a plugin's detail string changes, detection silently misses the behavior. No $MFT journal gap analysis below the string level in the detector file.
- `detector.rs` has zero unit tests (verified: `grep -c "#\[test\]" detector.rs` returns 0). The scoring math is tested; the detection layer's matching logic is not.

### What would make the claim fully honest

Three items: (1) call `ObstructionDetector::detect` followed by `ObstructionScorer::score` inside the `ingest run` pipeline (or inside a new `strata obstruction assess` subcommand) and persist the assessment alongside artifacts.sqlite. (2) Add unit tests to `detector.rs` covering each `detect_*` method against realistic plugin-output fixtures. (3) Make the scoring band labels visible in whatever UI produces the PDF case export.

---

## Claim 4 — "All deterministic — no cloud, no model files"

### Verdict: **(A) FULLY SHIPPING**

### Evidence

- **LLM calls:** `grep -rE "openai|anthropic|claude\.ai|api\.openai|ollama|candle::|ort::|burn::|tch::|hf_hub|tokenizers::|llama|mistral|gpt-[34]|gpt_[34]"` across `crates/` and `plugins/` excluding tests/comments returns **zero matches** for library-code LLM invocations. The grep hits that do appear are:
  - `crates/strata-core/src/parsers/analysis/ai_triage.rs` — this is a forensic parser that identifies AI-tool artifacts **left by other tools** on the evidence (Copilot logs, Cursor sessions, etc.). It does not call an AI service.
  - String "gpt" inside unrelated partition-detection code (GPT partition tables).
- **Model files on disk:** `find crates/ plugins/ apps/ -type f -name "*.onnx" -o -name "*.pt" -o -name "*.safetensors" -o -name "*.gguf" -o -name "*.h5" -o -name "*.pb" -o -name "*.tflite"` returns **zero results** excluding `target/`. The only `.bin` hits are:
  - `apps/shield/fixtures/parsers/ntfs_logfile_signals/win10/sample_win10_*.bin` — forensic parser fixtures (real NTFS logfile bytes for parser unit tests).
  - `apps/strata-desktop/src-tauri/keys/wolfmark-public.bin` — Ed25519 public key for license signature verification. Not a model.
- **Determinism:** the summary generator is Handlebars; the anomaly engine is IQR/z-score descriptive statistics; the obstruction scorer is a lookup table plus multipliers. All three paths are pure functions of their input.

### Test coverage

N/A — this is a negative claim (absence of cloud calls and model files). Verified by exhaustive search across all source trees.

### What it actually does, plain language

The code the marketing section calls "AI-powered" is deterministic numeric + template code. No network call is made; no model weights are loaded from disk or memory.

### What it does NOT do that the claim might imply

This claim is the most defensible of the four: it's a truthful description of what's under the hood, and it's forensically important (no network dependency = air-gap-safe, no model file = reproducible across machines). The only soft point is that it's bundled with the other three "AI-powered" claims, which invites the reader to assume there IS sophisticated ML under the hood just without cloud dependencies — the truth is more prosaic: there's no AI at all in the usual sense, only statistics and templates, and that's a feature, not a bug.

### What would make the claim fully honest

No code change required; the claim is true as written. A copy-tightening suggestion: replace "All deterministic — no cloud, no model files" with "All deterministic and local: statistical analysis and template rendering, no network dependency, no model weights" to pre-empt the inference that ML capability is present but simply offline.

---

## RECOMMENDED REWRITE

The current section title "07 / ML Analysis — AI-Powered Scoring" is indefensible for v0.14.0. The phrase "AI-Powered" with no model file anywhere in the codebase invites a defense attorney to call the tool a fraud. Replace it.

### Option A — Accurate, keep the section

Recommended for the next website revision.

> **07 / Advisory Analytics — Deterministic Statistics & Templates**
>
> Strata ships three *advisory* analytic layers that run locally against the
> artifact store produced by the forensic plugins. Every output is tagged
> ADVISORY and marked pending examiner approval.
>
> - **Statistical outlier detection.** IQR and z-score flagging over the
>   per-case timeline, execution history, and transfer volumes. Surfaces
>   timestomp candidates, activity outside the device's normal hours, and
>   single-run-no-interaction execution patterns. Descriptive statistics
>   only — no training, no neural model, no adaptation.
> - **Weighted obstruction factor scoring (0–100).** Thirteen documented
>   anti-forensic behaviors are each assigned an integer weight;
>   co-occurrence multipliers apply when VSS deletion accompanies event-log
>   clearing. Produces an itemized factor table showing which behavior
>   contributed which weight. Tests cover the scoring math; the detection
>   layer matches on plugin-output strings and has known gaps documented in
>   the tool output.
> - **Template-rendered case summaries.** Structured extraction of
>   charge-relevant findings, destruction events, focus recommendations,
>   and a narrative timeline, piped through Handlebars templates written by
>   forensic analysts. Every summary ships as a DRAFT requiring examiner
>   approval before distribution.
>
> All three are pure-Rust, pure-local code. No cloud call. No model files.
> Reproducible across machines.

### Option B — Remove the section

Recommended if the website copy cannot be updated quickly. Reason: the current claim-set crosses the line into overclaim territory (integration gap, not just overstatement), and the honest version isn't as compelling to a non-forensic reader as the forensic pipeline's headline numbers (3,400 artifacts on Charlie, 3,537 on Jo). Removing the section eliminates the courtroom risk and forces marketing to draft replacement copy with engineering sign-off.

### What must NOT ship as-is

- The phrase "AI-Powered" anywhere. No model files + no LLM calls = no AI. "Analytics" or "Advisory analytics" is accurate; "AI" is not.
- "Executive case summaries" without qualifying that they're Handlebars-rendered drafts requiring examiner approval. The current copy could be read as claiming an executive-quality narrative, which overstates Handlebars output.
- "Catches VSS deletion, log clearing, and evidence destruction" without noting that the detection layer is a string-match over plugin output and the production pipeline does not currently run it on real cases.

---

## COURTROOM RISK ASSESSMENT

| # | Claim | Risk | Reasoning |
|---|---|:---:|---|
| 1 | Anomaly detection flags statistical outliers | **4** / 5 | The code implements IQR/z-score, which an expert witness could describe as "basic statistics, not anomaly detection in the machine-learning sense," and — more damagingly — defense can demonstrate the pipeline does not actually invoke AnomalyEngine on a live case. "They advertised anomaly detection, then under cross showed their own tool never ran it" is a devastating impeachment. |
| 2 | Executive case summaries in plain English | **3** / 5 | "Plain English" is defensible (the templates are English), but "executive case summaries" implies narrative synthesis. Defense expert opens the `.hbs` files in court: "These are form letters with blanks." Risk is reputational more than technical. |
| 3 | Anti-forensic obstruction scoring (0–100) catches VSS deletion, log clearing, and evidence destruction | **5** / 5 | Highest risk. "Catches" is an active verb; the shipping pipeline does not run `ObstructionDetector::detect`. Defense produces the audit: "The feature that generated the score you're using to argue my client obstructed justice was never called on this case." Combined with `detector.rs` having zero unit tests, this is the claim most likely to get the whole tool excluded under a *Daubert* challenge. |
| 4 | All deterministic — no cloud, no model files | **1** / 5 | Defensible and verifiable on its face. The risk is only that it's bundled with three overstatements, and a defense attorney picking apart the other three may ask the witness to explain why the section is titled "AI-Powered" given the absence of AI — forcing an admission that weakens the tool's credibility. Removing "AI-Powered" from the section header eliminates this tail risk entirely. |

---

## Final note

None of this audit should be read as criticism of the ML code itself. The implementations are honest, tested, and well-structured — IQR outlier detection is the right tool for small-N timeline data, weighted factor scoring with published weights is an appropriate transparency choice for a courtroom tool, and Handlebars-based narrative is the correct call given the defensibility requirements of a forensic product (every sentence in a summary must be traceable to a deterministic template rendering).

The problem is the marketing copy, not the code. The copy advertises end-to-end capability; the code implements most of the capability but the final "wire it into the production pipeline and expose it to the examiner" step has not landed on a production case. Fix the copy (or ship the wiring). Do not leave the current copy in place — the integration gap is not something the defense will miss.
