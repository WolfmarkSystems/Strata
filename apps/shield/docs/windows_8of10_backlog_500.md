# Windows 8/10 Backlog (500 Tasks)

Status date: 2026-03-11
Goal: raise practical Windows capability from ~7/10 to >=8/10 with conservative, test-driven increments.

Legend: `PENDING` | `IN_PROGRESS` | `DONE`

## Workstream 1: Defender and Endpoint Artifact Pipeline

- [x] W8-0001 DONE Add new forensic_cli command `defender-artifacts` using existing forensic_engine defender parsers only.
- [x] W8-0002 DONE Wire `defender-artifacts` into help output, examples, and dispatch paths.
- [x] W8-0003 DONE Implement envelope-aware command output (`--json`, `--json-result`, `--quiet`) consistent with existing CLI pattern.
- [x] W8-0004 DONE Parse and surface Defender status fields (enabled/realtime/behavior/script/cloud/tamper/last_scan) with truthful null handling.
- [x] W8-0005 DONE Parse and surface AV product and exclusion collections with deterministic ordering and capped limits.
- [x] W8-0006 DONE Parse and surface Defender quarantine + scan-history records with normalized timestamps.
- [x] W8-0007 DONE Parse and surface Defender Endpoint alerts/indicators/file-profiles/machine-actions from existing JSON loaders.
- [x] W8-0008 DONE Add warnings for missing source files without crashing command execution.
- [x] W8-0009 DONE Add smoke tests for success and invalid-limit validation envelopes for `defender-artifacts`.
- [x] W8-0010 DONE Add golden JSON contract coverage for `defender-artifacts` payload and envelope paths.
- [x] W8-0011 DONE Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [x] W8-0012 DONE Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0013 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0014 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [x] W8-0015 DONE Add counts/summary quality block (total_available/returned/warnings).
- [x] W8-0016 DONE Add graceful-warning behavior for missing/unreadable sources.
- [x] W8-0017 DONE Document explicit coverage limits and unsupported sub-artifacts.
- [x] W8-0018 DONE Add benchmark script/runbook for medium and large fixture runtime.
- [x] W8-0019 DONE Run clippy cleanup and simplify low-value complexity before merge.
- [x] W8-0020 DONE Gate with full workspace build/test and record regression notes.

## Workstream 2: Windows ActivitiesCache Timeline Fidelity

- [ ] W8-0021 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0022 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0023 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0024 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0025 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0026 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0027 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0028 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0029 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0030 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0031 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0032 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0033 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0034 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0035 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0036 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0037 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0038 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0039 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0040 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 3: Shellbags Deep Coverage

- [ ] W8-0041 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0042 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0043 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0044 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0045 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0046 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0047 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0048 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0049 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0050 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0051 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0052 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0053 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0054 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0055 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0056 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0057 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0058 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0059 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0060 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 4: SRUM Deep Provider Expansion

- [ ] W8-0061 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0062 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0063 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0064 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0065 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0066 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0067 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0068 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0069 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0070 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0071 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0072 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0073 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0074 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0075 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0076 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0077 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0078 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0079 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0080 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 5: Registry UAC and Policy Ecosystem

- [ ] W8-0081 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0082 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0083 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0084 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0085 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0086 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0087 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0088 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0089 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0090 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0091 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0092 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0093 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0094 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0095 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0096 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0097 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0098 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0099 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0100 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 6: EVTX Security Semantic Expansion

- [ ] W8-0101 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0102 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0103 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0104 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0105 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0106 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0107 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0108 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0109 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0110 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0111 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0112 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0113 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0114 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0115 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0116 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0117 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0118 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0119 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0120 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 7: EVTX Sysmon Semantic Expansion

- [ ] W8-0121 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0122 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0123 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0124 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0125 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0126 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0127 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0128 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0129 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0130 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0131 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0132 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0133 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0134 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0135 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0136 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0137 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0138 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0139 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0140 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 8: NTFS MFT Edge-Case Fidelity

- [ ] W8-0141 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0142 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0143 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0144 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0145 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0146 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0147 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0148 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0149 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0150 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0151 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0152 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0153 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0154 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0155 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0156 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0157 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0158 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0159 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0160 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 9: USN Journal Reason and Source Correlation

- [ ] W8-0161 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0162 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0163 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0164 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0165 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0166 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0167 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0168 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0169 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0170 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0171 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0172 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0173 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0174 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0175 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0176 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0177 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0178 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0179 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0180 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 10: NTFS LogFile Signal Enrichment

- [ ] W8-0181 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0182 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0183 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0184 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0185 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0186 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0187 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0188 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0189 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0190 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0191 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0192 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0193 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0194 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0195 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0196 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0197 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0198 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0199 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0200 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 11: Prefetch Advanced Execution Semantics

- [ ] W8-0201 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0202 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0203 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0204 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0205 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0206 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0207 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0208 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0209 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0210 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0211 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0212 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0213 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0214 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0215 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0216 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0217 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0218 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0219 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0220 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 12: Jump List App-Specific Enrichment

- [ ] W8-0221 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0222 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0223 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0224 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0225 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0226 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0227 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0228 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0229 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0230 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0231 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0232 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0233 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0234 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0235 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0236 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0237 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0238 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0239 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0240 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 13: LNK Shortcut Provenance Enrichment

- [ ] W8-0241 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0242 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0243 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0244 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0245 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0246 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0247 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0248 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0249 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0250 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0251 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0252 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0253 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0254 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0255 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0256 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0257 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0258 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0259 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0260 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 14: Browser Multi-Profile and Cache Correlation

- [ ] W8-0261 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0262 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0263 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0264 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0265 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0266 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0267 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0268 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0269 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0270 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0271 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0272 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0273 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0274 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0275 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0276 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0277 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0278 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0279 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0280 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 15: RDP and Remote Access Lateral Movement Detail

- [ ] W8-0281 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0282 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0283 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0284 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0285 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0286 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0287 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0288 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0289 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0290 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0291 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0292 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0293 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0294 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0295 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0296 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0297 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0298 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0299 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0300 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 16: USB and Device Metadata Expansion

- [ ] W8-0301 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0302 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0303 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0304 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0305 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0306 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0307 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0308 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0309 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0310 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0311 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0312 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0313 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0314 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0315 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0316 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0317 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0318 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0319 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0320 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 17: Restore Points and Shadow Copy Correlation

- [ ] W8-0321 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0322 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0323 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0324 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0325 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0326 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0327 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0328 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0329 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0330 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0331 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0332 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0333 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0334 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0335 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0336 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0337 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0338 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0339 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0340 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 18: User Activity and MRU Cross-Source Linking

- [ ] W8-0341 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0342 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0343 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0344 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0345 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0346 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0347 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0348 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0349 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0350 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0351 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0352 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0353 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0354 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0355 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0356 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0357 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0358 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0359 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0360 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 19: Services, Drivers, and Startup Persistence

- [ ] W8-0361 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0362 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0363 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0364 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0365 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0366 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0367 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0368 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0369 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0370 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0371 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0372 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0373 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0374 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0375 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0376 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0377 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0378 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0379 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0380 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 20: WMI Persistence and Execution Graphing

- [ ] W8-0381 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0382 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0383 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0384 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0385 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0386 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0387 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0388 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0389 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0390 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0391 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0392 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0393 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0394 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0395 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0396 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0397 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0398 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0399 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0400 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 21: Execution Correlation Precision Improvements

- [ ] W8-0401 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0402 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0403 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0404 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0405 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0406 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0407 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0408 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0409 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0410 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0411 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0412 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0413 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0414 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0415 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0416 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0417 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0418 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0419 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0420 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 22: Timeline Query Performance and Scale

- [ ] W8-0421 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0422 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0423 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0424 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0425 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0426 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0427 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0428 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0429 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0430 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0431 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0432 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0433 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0434 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0435 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0436 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0437 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0438 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0439 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0440 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 23: Windows Artifact Robustness and Fuzzing

- [ ] W8-0441 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0442 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0443 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0444 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0445 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0446 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0447 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0448 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0449 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0450 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0451 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0452 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0453 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0454 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0455 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0456 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0457 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0458 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0459 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0460 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 24: Large-Image Throughput and Memory Tuning

- [ ] W8-0461 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0462 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0463 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0464 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0465 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0466 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0467 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0468 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0469 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0470 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0471 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0472 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0473 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0474 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0475 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0476 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0477 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0478 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0479 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0480 PENDING Gate with full workspace build/test and record regression notes.

## Workstream 25: Windows Coverage Documentation and Validation Gates

- [ ] W8-0481 PENDING Build fixture manifest with >=30 labeled samples across Windows 10/11 variants.
- [ ] W8-0482 PENDING Add strict input-shape detection with truthful parser-mode metadata.
- [ ] W8-0483 PENDING Implement primary parser pass with explicit null handling and no inferred fields.
- [ ] W8-0484 PENDING Implement fallback parser pass for partial/malformed input resilience.
- [ ] W8-0485 PENDING Normalize timestamps to unix + RFC3339 UTC with precision metadata.
- [ ] W8-0486 PENDING Normalize identity/path/process fields with canonical formatting.
- [ ] W8-0487 PENDING Add deterministic sort and tie-break rules with tests.
- [ ] W8-0488 PENDING Add dedupe policy and expose dedupe_reason metadata.
- [ ] W8-0489 PENDING Add parser-level unit tests for happy/partial/malformed paths.
- [ ] W8-0490 PENDING Add CLI smoke test using --json-result and envelope contract checks.
- [ ] W8-0491 PENDING Add CLI validation tests for missing/invalid args with EXIT_VALIDATION checks.
- [ ] W8-0492 PENDING Add JSON golden contract snapshot and backward-compatibility notes.
- [ ] W8-0493 PENDING Map records into timeline event shape with conservative severity mapping.
- [ ] W8-0494 PENDING Add execution/persistence correlation hooks where shared keys exist.
- [ ] W8-0495 PENDING Add counts/summary quality block (total_available/returned/warnings).
- [ ] W8-0496 PENDING Add graceful-warning behavior for missing/unreadable sources.
- [ ] W8-0497 PENDING Document explicit coverage limits and unsupported sub-artifacts.
- [ ] W8-0498 PENDING Add benchmark script/runbook for medium and large fixture runtime.
- [ ] W8-0499 PENDING Run clippy cleanup and simplify low-value complexity before merge.
- [ ] W8-0500 PENDING Gate with full workspace build/test and record regression notes.

