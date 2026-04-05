# Windows 7/10 Backlog (500 Tasks)

Status date: 2026-03-11
Goal: raise practical Windows capability from ~5/10 to >=7/10 with conservative, test-driven increments.

Legend: `PENDING` | `IN_PROGRESS` | `DONE`

## Workstream 1: SRUM (Raw ESE + Export Normalization)

- [x] W7-0001 DONE Build fixture manifest for SRUM (Raw ESE + Export Normalization) with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0002 DONE Add strict input-shape detector for SRUM (Raw ESE + Export Normalization) (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0003 DONE Implement primary parser pass for SRUM (Raw ESE + Export Normalization) with no inferred fields and explicit null handling.
- [x] W7-0004 DONE Implement secondary fallback parser pass for SRUM (Raw ESE + Export Normalization) to tolerate partially malformed records.
- [x] W7-0005 DONE Normalize timestamps for SRUM (Raw ESE + Export Normalization) into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0006 DONE Normalize identity fields for SRUM (Raw ESE + Export Normalization) (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0007 DONE Add deterministic sort order for SRUM (Raw ESE + Export Normalization) output and enforce tie-break keys in tests.
- [x] W7-0008 DONE Add dedupe rules for SRUM (Raw ESE + Export Normalization) and emit dedupe_reason metadata where rows collapse.
- [x] W7-0009 DONE Add parser-level unit tests for SRUM (Raw ESE + Export Normalization) covering happy path, partial records, and malformed input.
- [x] W7-0010 DONE Add CLI smoke test for SRUM (Raw ESE + Export Normalization) using --json-result and verify envelope + payload contract.
- [x] W7-0011 DONE Add CLI validation tests for SRUM (Raw ESE + Export Normalization) for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0012 DONE Add JSON golden contract snapshot for SRUM (Raw ESE + Export Normalization) and include backward-compatibility note on field changes.
- [x] W7-0013 DONE Map SRUM (Raw ESE + Export Normalization) rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0014 DONE Add correlation hooks so SRUM (Raw ESE + Export Normalization) can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0015 DONE Add counts/summary block for SRUM (Raw ESE + Export Normalization) (total_available, total_returned, quality flags, warning counts).
- [x] W7-0016 DONE Add graceful-warning behavior for SRUM (Raw ESE + Export Normalization) when source files are missing, unreadable, or unparseable.
- [x] W7-0017 DONE Document known coverage limits for SRUM (Raw ESE + Export Normalization) and list unsupported sub-artifacts explicitly.
- [x] W7-0018 DONE Add benchmark test for SRUM (Raw ESE + Export Normalization) parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0019 DONE Run clippy cleanup for SRUM (Raw ESE + Export Normalization) code paths and remove low-value complexity before merge.
- [x] W7-0020 DONE Gate SRUM (Raw ESE + Export Normalization) with full workspace build/test and record regression notes in weekly tracker.

## Workstream 2: EVTX Security Semantics

- [x] W7-0021 DONE Build fixture manifest for EVTX Security Semantics with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0022 DONE Add strict input-shape detector for EVTX Security Semantics (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0023 DONE Implement primary parser pass for EVTX Security Semantics with no inferred fields and explicit null handling.
- [x] W7-0024 DONE Implement secondary fallback parser pass for EVTX Security Semantics to tolerate partially malformed records.
- [x] W7-0025 DONE Normalize timestamps for EVTX Security Semantics into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0026 DONE Normalize identity fields for EVTX Security Semantics (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0027 DONE Add deterministic sort order for EVTX Security Semantics output and enforce tie-break keys in tests.
- [x] W7-0028 DONE Add dedupe rules for EVTX Security Semantics and emit dedupe_reason metadata where rows collapse.
- [x] W7-0029 DONE Add parser-level unit tests for EVTX Security Semantics covering happy path, partial records, and malformed input.
- [x] W7-0030 DONE Add CLI smoke test for EVTX Security Semantics using --json-result and verify envelope + payload contract.
- [x] W7-0031 DONE Add CLI validation tests for EVTX Security Semantics for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0032 DONE Add JSON golden contract snapshot for EVTX Security Semantics and include backward-compatibility note on field changes.
- [x] W7-0033 DONE Map EVTX Security Semantics rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0034 DONE Add correlation hooks so EVTX Security Semantics can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0035 DONE Add counts/summary block for EVTX Security Semantics (total_available, total_returned, quality flags, warning counts).
- [x] W7-0036 DONE Add graceful-warning behavior for EVTX Security Semantics when source files are missing, unreadable, or unparseable.
- [x] W7-0037 DONE Document known coverage limits for EVTX Security Semantics and list unsupported sub-artifacts explicitly.
- [x] W7-0038 DONE Add benchmark test for EVTX Security Semantics parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0039 DONE Run clippy cleanup for EVTX Security Semantics code paths and remove low-value complexity before merge.
- [x] W7-0040 DONE Gate EVTX Security Semantics with full workspace build/test and record regression notes in weekly tracker.

## Workstream 3: EVTX Sysmon Semantics

- [x] W7-0041 DONE Build fixture manifest for EVTX Sysmon Semantics with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0042 DONE Add strict input-shape detector for EVTX Sysmon Semantics (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0043 DONE Implement primary parser pass for EVTX Sysmon Semantics with no inferred fields and explicit null handling.
- [x] W7-0044 DONE Implement secondary fallback parser pass for EVTX Sysmon Semantics to tolerate partially malformed records.
- [x] W7-0045 DONE Normalize timestamps for EVTX Sysmon Semantics into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0046 DONE Normalize identity fields for EVTX Sysmon Semantics (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0047 DONE Add deterministic sort order for EVTX Sysmon Semantics output and enforce tie-break keys in tests.
- [x] W7-0048 DONE Add dedupe rules for EVTX Sysmon Semantics and emit dedupe_reason metadata where rows collapse.
- [x] W7-0049 DONE Add parser-level unit tests for EVTX Sysmon Semantics covering happy path, partial records, and malformed input.
- [x] W7-0050 DONE Add CLI smoke test for EVTX Sysmon Semantics using --json-result and verify envelope + payload contract.
- [x] W7-0051 DONE Add CLI validation tests for EVTX Sysmon Semantics for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0052 DONE Add JSON golden contract snapshot for EVTX Sysmon Semantics and include backward-compatibility note on field changes.
- [x] W7-0053 DONE Map EVTX Sysmon Semantics rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0054 DONE Add correlation hooks so EVTX Sysmon Semantics can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0055 DONE Add counts/summary block for EVTX Sysmon Semantics (total_available, total_returned, quality flags, warning counts).
- [x] W7-0056 DONE Add graceful-warning behavior for EVTX Sysmon Semantics when source files are missing, unreadable, or unparseable.
- [x] W7-0057 DONE Document known coverage limits for EVTX Sysmon Semantics and list unsupported sub-artifacts explicitly.
- [x] W7-0058 DONE Add benchmark test for EVTX Sysmon Semantics parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0059 DONE Run clippy cleanup for EVTX Sysmon Semantics code paths and remove low-value complexity before merge.
- [x] W7-0060 DONE Gate EVTX Sysmon Semantics with full workspace build/test and record regression notes in weekly tracker.

## Workstream 4: PowerShell Artifacts

- [x] W7-0061 DONE Build fixture manifest for PowerShell Artifacts with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0062 DONE Add strict input-shape detector for PowerShell Artifacts (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0063 DONE Implement primary parser pass for PowerShell Artifacts with no inferred fields and explicit null handling.
- [x] W7-0064 DONE Implement secondary fallback parser pass for PowerShell Artifacts to tolerate partially malformed records.
- [x] W7-0065 DONE Normalize timestamps for PowerShell Artifacts into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0066 DONE Normalize identity fields for PowerShell Artifacts (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0067 DONE Add deterministic sort order for PowerShell Artifacts output and enforce tie-break keys in tests.
- [x] W7-0068 DONE Add dedupe rules for PowerShell Artifacts and emit dedupe_reason metadata where rows collapse.
- [x] W7-0069 DONE Add parser-level unit tests for PowerShell Artifacts covering happy path, partial records, and malformed input.
- [x] W7-0070 DONE Add CLI smoke test for PowerShell Artifacts using --json-result and verify envelope + payload contract.
- [x] W7-0071 DONE Add CLI validation tests for PowerShell Artifacts for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0072 DONE Add JSON golden contract snapshot for PowerShell Artifacts and include backward-compatibility note on field changes.
- [x] W7-0073 DONE Map PowerShell Artifacts rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0074 DONE Add correlation hooks so PowerShell Artifacts can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0075 DONE Add counts/summary block for PowerShell Artifacts (total_available, total_returned, quality flags, warning counts).
- [x] W7-0076 DONE Add graceful-warning behavior for PowerShell Artifacts when source files are missing, unreadable, or unparseable.
- [x] W7-0077 DONE Document known coverage limits for PowerShell Artifacts and list unsupported sub-artifacts explicitly.
- [x] W7-0078 DONE Add benchmark test for PowerShell Artifacts parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0079 DONE Run clippy cleanup for PowerShell Artifacts code paths and remove low-value complexity before merge.
- [x] W7-0080 DONE Gate PowerShell Artifacts with full workspace build/test and record regression notes in weekly tracker.

## Workstream 5: Registry Core User Hives

- [x] W7-0081 DONE Build fixture manifest for Registry Core User Hives with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0082 DONE Add strict input-shape detector for Registry Core User Hives (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0083 DONE Implement primary parser pass for Registry Core User Hives with no inferred fields and explicit null handling.
- [x] W7-0084 DONE Implement secondary fallback parser pass for Registry Core User Hives to tolerate partially malformed records.
- [x] W7-0085 DONE Normalize timestamps for Registry Core User Hives into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0086 DONE Normalize identity fields for Registry Core User Hives (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0087 DONE Add deterministic sort order for Registry Core User Hives output and enforce tie-break keys in tests.
- [x] W7-0088 DONE Add dedupe rules for Registry Core User Hives and emit dedupe_reason metadata where rows collapse.
- [x] W7-0089 DONE Add parser-level unit tests for Registry Core User Hives covering happy path, partial records, and malformed input.
- [x] W7-0090 DONE Add CLI smoke test for Registry Core User Hives using --json-result and verify envelope + payload contract.
- [x] W7-0091 DONE Add CLI validation tests for Registry Core User Hives for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0092 DONE Add JSON golden contract snapshot for Registry Core User Hives and include backward-compatibility note on field changes.
- [x] W7-0093 DONE Map Registry Core User Hives rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0094 DONE Add correlation hooks so Registry Core User Hives can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0095 DONE Add counts/summary block for Registry Core User Hives (total_available, total_returned, quality flags, warning counts).
- [x] W7-0096 DONE Add graceful-warning behavior for Registry Core User Hives when source files are missing, unreadable, or unparseable.
- [x] W7-0097 DONE Document known coverage limits for Registry Core User Hives and list unsupported sub-artifacts explicitly.
- [x] W7-0098 DONE Add benchmark test for Registry Core User Hives parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0099 DONE Run clippy cleanup for Registry Core User Hives code paths and remove low-value complexity before merge.
- [x] W7-0100 DONE Gate Registry Core User Hives with full workspace build/test and record regression notes in weekly tracker.

## Workstream 6: Registry Persistence Ecosystem

- [x] W7-0101 DONE Build fixture manifest for Registry Persistence Ecosystem with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0102 DONE Add strict input-shape detector for Registry Persistence Ecosystem (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0103 DONE Implement primary parser pass for Registry Persistence Ecosystem with no inferred fields and explicit null handling.
- [x] W7-0104 DONE Implement secondary fallback parser pass for Registry Persistence Ecosystem to tolerate partially malformed records.
- [x] W7-0105 DONE Normalize timestamps for Registry Persistence Ecosystem into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0106 DONE Normalize identity fields for Registry Persistence Ecosystem (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0107 DONE Add deterministic sort order for Registry Persistence Ecosystem output and enforce tie-break keys in tests.
- [x] W7-0108 DONE Add dedupe rules for Registry Persistence Ecosystem and emit dedupe_reason metadata where rows collapse.
- [x] W7-0109 DONE Add parser-level unit tests for Registry Persistence Ecosystem covering happy path, partial records, and malformed input.
- [x] W7-0110 DONE Add CLI smoke test for Registry Persistence Ecosystem using --json-result and verify envelope + payload contract.
- [x] W7-0111 DONE Add CLI validation tests for Registry Persistence Ecosystem for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0112 DONE Add JSON golden contract snapshot for Registry Persistence Ecosystem and include backward-compatibility note on field changes.
- [x] W7-0113 DONE Map Registry Persistence Ecosystem rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0114 DONE Add correlation hooks so Registry Persistence Ecosystem can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0115 DONE Add counts/summary block for Registry Persistence Ecosystem (total_available, total_returned, quality flags, warning counts).
- [x] W7-0116 DONE Add graceful-warning behavior for Registry Persistence Ecosystem when source files are missing, unreadable, or unparseable.
- [x] W7-0117 DONE Document known coverage limits for Registry Persistence Ecosystem and list unsupported sub-artifacts explicitly.
- [x] W7-0118 DONE Add benchmark test for Registry Persistence Ecosystem parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0119 DONE Run clippy cleanup for Registry Persistence Ecosystem code paths and remove low-value complexity before merge.
- [x] W7-0120 DONE Gate Registry Persistence Ecosystem with full workspace build/test and record regression notes in weekly tracker.

## Workstream 7: ShimCache Deep Decode

- [x] W7-0121 DONE Build fixture manifest for ShimCache Deep Decode with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0122 DONE Add strict input-shape detector for ShimCache Deep Decode (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0123 DONE Implement primary parser pass for ShimCache Deep Decode with no inferred fields and explicit null handling.
- [x] W7-0124 DONE Implement secondary fallback parser pass for ShimCache Deep Decode to tolerate partially malformed records.
- [x] W7-0125 DONE Normalize timestamps for ShimCache Deep Decode into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0126 DONE Normalize identity fields for ShimCache Deep Decode (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0127 DONE Add deterministic sort order for ShimCache Deep Decode output and enforce tie-break keys in tests.
- [x] W7-0128 DONE Add dedupe rules for ShimCache Deep Decode and emit dedupe_reason metadata where rows collapse.
- [x] W7-0129 DONE Add parser-level unit tests for ShimCache Deep Decode covering happy path, partial records, and malformed input.
- [x] W7-0130 DONE Add CLI smoke test for ShimCache Deep Decode using --json-result and verify envelope + payload contract.
- [x] W7-0131 DONE Add CLI validation tests for ShimCache Deep Decode for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0132 DONE Add JSON golden contract snapshot for ShimCache Deep Decode and include backward-compatibility note on field changes.
- [x] W7-0133 DONE Map ShimCache Deep Decode rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0134 DONE Add correlation hooks so ShimCache Deep Decode can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0135 DONE Add counts/summary block for ShimCache Deep Decode (total_available, total_returned, quality flags, warning counts).
- [x] W7-0136 DONE Add graceful-warning behavior for ShimCache Deep Decode when source files are missing, unreadable, or unparseable.
- [x] W7-0137 DONE Document known coverage limits for ShimCache Deep Decode and list unsupported sub-artifacts explicitly.
- [x] W7-0138 DONE Add benchmark test for ShimCache Deep Decode parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0139 DONE Run clippy cleanup for ShimCache Deep Decode code paths and remove low-value complexity before merge.
- [x] W7-0140 DONE Gate ShimCache Deep Decode with full workspace build/test and record regression notes in weekly tracker.

## Workstream 8: Amcache Deep Decode

- [x] W7-0141 DONE Build fixture manifest for Amcache Deep Decode with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0142 DONE Add strict input-shape detector for Amcache Deep Decode (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0143 DONE Implement primary parser pass for Amcache Deep Decode with no inferred fields and explicit null handling.
- [x] W7-0144 DONE Implement secondary fallback parser pass for Amcache Deep Decode to tolerate partially malformed records.
- [x] W7-0145 DONE Normalize timestamps for Amcache Deep Decode into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0146 DONE Normalize identity fields for Amcache Deep Decode (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0147 DONE Add deterministic sort order for Amcache Deep Decode output and enforce tie-break keys in tests.
- [x] W7-0148 DONE Add dedupe rules for Amcache Deep Decode and emit dedupe_reason metadata where rows collapse.
- [x] W7-0149 DONE Add parser-level unit tests for Amcache Deep Decode covering happy path, partial records, and malformed input.
- [x] W7-0150 DONE Add CLI smoke test for Amcache Deep Decode using --json-result and verify envelope + payload contract.
- [x] W7-0151 DONE Add CLI validation tests for Amcache Deep Decode for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0152 DONE Add JSON golden contract snapshot for Amcache Deep Decode and include backward-compatibility note on field changes.
- [x] W7-0153 DONE Map Amcache Deep Decode rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0154 DONE Add correlation hooks so Amcache Deep Decode can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0155 DONE Add counts/summary block for Amcache Deep Decode (total_available, total_returned, quality flags, warning counts).
- [x] W7-0156 DONE Add graceful-warning behavior for Amcache Deep Decode when source files are missing, unreadable, or unparseable.
- [x] W7-0157 DONE Document known coverage limits for Amcache Deep Decode and list unsupported sub-artifacts explicitly.
- [x] W7-0158 DONE Add benchmark test for Amcache Deep Decode parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0159 DONE Run clippy cleanup for Amcache Deep Decode code paths and remove low-value complexity before merge.
- [x] W7-0160 DONE Gate Amcache Deep Decode with full workspace build/test and record regression notes in weekly tracker.

## Workstream 9: BAM/DAM Activity

- [x] W7-0161 DONE Build fixture manifest for BAM/DAM Activity with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0162 DONE Add strict input-shape detector for BAM/DAM Activity (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0163 DONE Implement primary parser pass for BAM/DAM Activity with no inferred fields and explicit null handling.
- [x] W7-0164 DONE Implement secondary fallback parser pass for BAM/DAM Activity to tolerate partially malformed records.
- [x] W7-0165 DONE Normalize timestamps for BAM/DAM Activity into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0166 DONE Normalize identity fields for BAM/DAM Activity (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0167 DONE Add deterministic sort order for BAM/DAM Activity output and enforce tie-break keys in tests.
- [x] W7-0168 DONE Add dedupe rules for BAM/DAM Activity and emit dedupe_reason metadata where rows collapse.
- [x] W7-0169 DONE Add parser-level unit tests for BAM/DAM Activity covering happy path, partial records, and malformed input.
- [x] W7-0170 DONE Add CLI smoke test for BAM/DAM Activity using --json-result and verify envelope + payload contract.
- [x] W7-0171 DONE Add CLI validation tests for BAM/DAM Activity for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0172 DONE Add JSON golden contract snapshot for BAM/DAM Activity and include backward-compatibility note on field changes.
- [x] W7-0173 DONE Map BAM/DAM Activity rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0174 DONE Add correlation hooks so BAM/DAM Activity can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0175 DONE Add counts/summary block for BAM/DAM Activity (total_available, total_returned, quality flags, warning counts).
- [x] W7-0176 DONE Add graceful-warning behavior for BAM/DAM Activity when source files are missing, unreadable, or unparseable.
- [x] W7-0177 DONE Document known coverage limits for BAM/DAM Activity and list unsupported sub-artifacts explicitly.
- [x] W7-0178 DONE Add benchmark test for BAM/DAM Activity parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0179 DONE Run clippy cleanup for BAM/DAM Activity code paths and remove low-value complexity before merge.
- [x] W7-0180 DONE Gate BAM/DAM Activity with full workspace build/test and record regression notes in weekly tracker.

## Workstream 10: Services and Drivers Artifacts

- [x] W7-0181 DONE Build fixture manifest for Services and Drivers Artifacts with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0182 DONE Add strict input-shape detector for Services and Drivers Artifacts (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0183 DONE Implement primary parser pass for Services and Drivers Artifacts with no inferred fields and explicit null handling.
- [x] W7-0184 DONE Implement secondary fallback parser pass for Services and Drivers Artifacts to tolerate partially malformed records.
- [x] W7-0185 DONE Normalize timestamps for Services and Drivers Artifacts into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0186 DONE Normalize identity fields for Services and Drivers Artifacts (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0187 DONE Add deterministic sort order for Services and Drivers Artifacts output and enforce tie-break keys in tests.
- [x] W7-0188 DONE Add dedupe rules for Services and Drivers Artifacts and emit dedupe_reason metadata where rows collapse.
- [x] W7-0189 DONE Add parser-level unit tests for Services and Drivers Artifacts covering happy path, partial records, and malformed input.
- [x] W7-0190 DONE Add CLI smoke test for Services and Drivers Artifacts using --json-result and verify envelope + payload contract.
- [x] W7-0191 DONE Add CLI validation tests for Services and Drivers Artifacts for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0192 DONE Add JSON golden contract snapshot for Services and Drivers Artifacts and include backward-compatibility note on field changes.
- [x] W7-0193 DONE Map Services and Drivers Artifacts rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0194 DONE Add correlation hooks so Services and Drivers Artifacts can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0195 DONE Add counts/summary block for Services and Drivers Artifacts (total_available, total_returned, quality flags, warning counts).
- [x] W7-0196 DONE Add graceful-warning behavior for Services and Drivers Artifacts when source files are missing, unreadable, or unparseable.
- [x] W7-0197 DONE Document known coverage limits for Services and Drivers Artifacts and list unsupported sub-artifacts explicitly.
- [x] W7-0198 DONE Add benchmark test for Services and Drivers Artifacts parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0199 DONE Run clippy cleanup for Services and Drivers Artifacts code paths and remove low-value complexity before merge.
- [x] W7-0200 DONE Gate Services and Drivers Artifacts with full workspace build/test and record regression notes in weekly tracker.

## Workstream 11: Scheduled Tasks Artifacts

- [x] W7-0201 DONE Build fixture manifest for Scheduled Tasks Artifacts with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0202 DONE Add strict input-shape detector for Scheduled Tasks Artifacts (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0203 DONE Implement primary parser pass for Scheduled Tasks Artifacts with no inferred fields and explicit null handling.
- [x] W7-0204 DONE Implement secondary fallback parser pass for Scheduled Tasks Artifacts to tolerate partially malformed records.
- [x] W7-0205 DONE Normalize timestamps for Scheduled Tasks Artifacts into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0206 DONE Normalize identity fields for Scheduled Tasks Artifacts (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0207 DONE Add deterministic sort order for Scheduled Tasks Artifacts output and enforce tie-break keys in tests.
- [x] W7-0208 DONE Add dedupe rules for Scheduled Tasks Artifacts and emit dedupe_reason metadata where rows collapse.
- [x] W7-0209 DONE Add parser-level unit tests for Scheduled Tasks Artifacts covering happy path, partial records, and malformed input.
- [x] W7-0210 DONE Add CLI smoke test for Scheduled Tasks Artifacts using --json-result and verify envelope + payload contract.
- [x] W7-0211 DONE Add CLI validation tests for Scheduled Tasks Artifacts for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0212 DONE Add JSON golden contract snapshot for Scheduled Tasks Artifacts and include backward-compatibility note on field changes.
- [x] W7-0213 DONE Map Scheduled Tasks Artifacts rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0214 DONE Add correlation hooks so Scheduled Tasks Artifacts can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0215 DONE Add counts/summary block for Scheduled Tasks Artifacts (total_available, total_returned, quality flags, warning counts).
- [x] W7-0216 DONE Add graceful-warning behavior for Scheduled Tasks Artifacts when source files are missing, unreadable, or unparseable.
- [x] W7-0217 DONE Document known coverage limits for Scheduled Tasks Artifacts and list unsupported sub-artifacts explicitly.
- [x] W7-0218 DONE Add benchmark test for Scheduled Tasks Artifacts parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0219 DONE Run clippy cleanup for Scheduled Tasks Artifacts code paths and remove low-value complexity before merge.
- [x] W7-0220 DONE Gate Scheduled Tasks Artifacts with full workspace build/test and record regression notes in weekly tracker.

## Workstream 12: WMI Persistence and Activity

- [x] W7-0221 DONE Build fixture manifest for WMI Persistence and Activity with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0222 DONE Add strict input-shape detector for WMI Persistence and Activity (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0223 DONE Implement primary parser pass for WMI Persistence and Activity with no inferred fields and explicit null handling.
- [x] W7-0224 DONE Implement secondary fallback parser pass for WMI Persistence and Activity to tolerate partially malformed records.
- [x] W7-0225 DONE Normalize timestamps for WMI Persistence and Activity into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0226 DONE Normalize identity fields for WMI Persistence and Activity (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0227 DONE Add deterministic sort order for WMI Persistence and Activity output and enforce tie-break keys in tests.
- [x] W7-0228 DONE Add dedupe rules for WMI Persistence and Activity and emit dedupe_reason metadata where rows collapse.
- [x] W7-0229 DONE Add parser-level unit tests for WMI Persistence and Activity covering happy path, partial records, and malformed input.
- [x] W7-0230 DONE Add CLI smoke test for WMI Persistence and Activity using --json-result and verify envelope + payload contract.
- [x] W7-0231 DONE Add CLI validation tests for WMI Persistence and Activity for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0232 DONE Add JSON golden contract snapshot for WMI Persistence and Activity and include backward-compatibility note on field changes.
- [x] W7-0233 DONE Map WMI Persistence and Activity rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0234 DONE Add correlation hooks so WMI Persistence and Activity can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0235 DONE Add counts/summary block for WMI Persistence and Activity (total_available, total_returned, quality flags, warning counts).
- [x] W7-0236 DONE Add graceful-warning behavior for WMI Persistence and Activity when source files are missing, unreadable, or unparseable.
- [x] W7-0237 DONE Document known coverage limits for WMI Persistence and Activity and list unsupported sub-artifacts explicitly.
- [x] W7-0238 DONE Add benchmark test for WMI Persistence and Activity parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0239 DONE Run clippy cleanup for WMI Persistence and Activity code paths and remove low-value complexity before merge.
- [x] W7-0240 DONE Gate WMI Persistence and Activity with full workspace build/test and record regression notes in weekly tracker.

## Workstream 13: NTFS MFT Fidelity

- [x] W7-0241 DONE Build fixture manifest for NTFS MFT Fidelity with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0242 DONE Add strict input-shape detector for NTFS MFT Fidelity (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0243 DONE Implement primary parser pass for NTFS MFT Fidelity with no inferred fields and explicit null handling.
- [x] W7-0244 DONE Implement secondary fallback parser pass for NTFS MFT Fidelity to tolerate partially malformed records.
- [x] W7-0245 DONE Normalize timestamps for NTFS MFT Fidelity into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0246 DONE Normalize identity fields for NTFS MFT Fidelity (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0247 DONE Add deterministic sort order for NTFS MFT Fidelity output and enforce tie-break keys in tests.
- [x] W7-0248 DONE Add dedupe rules for NTFS MFT Fidelity and emit dedupe_reason metadata where rows collapse.
- [x] W7-0249 DONE Add parser-level unit tests for NTFS MFT Fidelity covering happy path, partial records, and malformed input.
- [x] W7-0250 DONE Add CLI smoke test for NTFS MFT Fidelity using --json-result and verify envelope + payload contract.
- [x] W7-0251 DONE Add CLI validation tests for NTFS MFT Fidelity for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0252 DONE Add JSON golden contract snapshot for NTFS MFT Fidelity and include backward-compatibility note on field changes.
- [x] W7-0253 DONE Map NTFS MFT Fidelity rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0254 DONE Add correlation hooks so NTFS MFT Fidelity can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0255 DONE Add counts/summary block for NTFS MFT Fidelity (total_available, total_returned, quality flags, warning counts).
- [x] W7-0256 DONE Add graceful-warning behavior for NTFS MFT Fidelity when source files are missing, unreadable, or unparseable.
- [x] W7-0257 DONE Document known coverage limits for NTFS MFT Fidelity and list unsupported sub-artifacts explicitly.
- [x] W7-0258 DONE Add benchmark test for NTFS MFT Fidelity parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0259 DONE Run clippy cleanup for NTFS MFT Fidelity code paths and remove low-value complexity before merge.
- [x] W7-0260 DONE Gate NTFS MFT Fidelity with full workspace build/test and record regression notes in weekly tracker.

## Workstream 14: USN Journal Fidelity

- [x] W7-0261 DONE Build fixture manifest for USN Journal Fidelity with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0262 DONE Add strict input-shape detector for USN Journal Fidelity (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0263 DONE Implement primary parser pass for USN Journal Fidelity with no inferred fields and explicit null handling.
- [x] W7-0264 DONE Implement secondary fallback parser pass for USN Journal Fidelity to tolerate partially malformed records.
- [x] W7-0265 DONE Normalize timestamps for USN Journal Fidelity into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0266 DONE Normalize identity fields for USN Journal Fidelity (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0267 DONE Add deterministic sort order for USN Journal Fidelity output and enforce tie-break keys in tests.
- [x] W7-0268 DONE Add dedupe rules for USN Journal Fidelity and emit dedupe_reason metadata where rows collapse.
- [x] W7-0269 DONE Add parser-level unit tests for USN Journal Fidelity covering happy path, partial records, and malformed input.
- [x] W7-0270 DONE Add CLI smoke test for USN Journal Fidelity using --json-result and verify envelope + payload contract.
- [x] W7-0271 DONE Add CLI validation tests for USN Journal Fidelity for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0272 DONE Add JSON golden contract snapshot for USN Journal Fidelity and include backward-compatibility note on field changes.
- [x] W7-0273 DONE Map USN Journal Fidelity rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0274 DONE Add correlation hooks so USN Journal Fidelity can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0275 DONE Add counts/summary block for USN Journal Fidelity (total_available, total_returned, quality flags, warning counts).
- [x] W7-0276 DONE Add graceful-warning behavior for USN Journal Fidelity when source files are missing, unreadable, or unparseable.
- [x] W7-0277 DONE Document known coverage limits for USN Journal Fidelity and list unsupported sub-artifacts explicitly.
- [x] W7-0278 DONE Add benchmark test for USN Journal Fidelity parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0279 DONE Run clippy cleanup for USN Journal Fidelity code paths and remove low-value complexity before merge.
- [x] W7-0280 DONE Gate USN Journal Fidelity with full workspace build/test and record regression notes in weekly tracker.

## Workstream 15: NTFS LogFile Signals

- [x] W7-0281 DONE Build fixture manifest for NTFS LogFile Signals with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0282 DONE Add strict input-shape detector for NTFS LogFile Signals (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0283 DONE Implement primary parser pass for NTFS LogFile Signals with no inferred fields and explicit null handling.
- [x] W7-0284 DONE Implement secondary fallback parser pass for NTFS LogFile Signals to tolerate partially malformed records.
- [x] W7-0285 DONE Normalize timestamps for NTFS LogFile Signals into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0286 DONE Normalize identity fields for NTFS LogFile Signals (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0287 DONE Add deterministic sort order for NTFS LogFile Signals output and enforce tie-break keys in tests.
- [x] W7-0288 DONE Add dedupe rules for NTFS LogFile Signals and emit dedupe_reason metadata where rows collapse.
- [x] W7-0289 DONE Add parser-level unit tests for NTFS LogFile Signals covering happy path, partial records, and malformed input.
- [x] W7-0290 DONE Add CLI smoke test for NTFS LogFile Signals using --json-result and verify envelope + payload contract.
- [x] W7-0291 DONE Add CLI validation tests for NTFS LogFile Signals for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0292 DONE Add JSON golden contract snapshot for NTFS LogFile Signals and include backward-compatibility note on field changes.
- [x] W7-0293 DONE Map NTFS LogFile Signals rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0294 DONE Add correlation hooks so NTFS LogFile Signals can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0295 DONE Add counts/summary block for NTFS LogFile Signals (total_available, total_returned, quality flags, warning counts).
- [x] W7-0296 DONE Add graceful-warning behavior for NTFS LogFile Signals when source files are missing, unreadable, or unparseable.
- [x] W7-0297 DONE Document known coverage limits for NTFS LogFile Signals and list unsupported sub-artifacts explicitly.
- [x] W7-0298 DONE Add benchmark test for NTFS LogFile Signals parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0299 DONE Run clippy cleanup for NTFS LogFile Signals code paths and remove low-value complexity before merge.
- [x] W7-0300 DONE Gate NTFS LogFile Signals with full workspace build/test and record regression notes in weekly tracker.

## Workstream 16: Recycle Bin and Deletion Artifacts

- [x] W7-0301 DONE Build fixture manifest for Recycle Bin and Deletion Artifacts with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0302 DONE Add strict input-shape detector for Recycle Bin and Deletion Artifacts (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0303 DONE Implement primary parser pass for Recycle Bin and Deletion Artifacts with no inferred fields and explicit null handling.
- [x] W7-0304 DONE Implement secondary fallback parser pass for Recycle Bin and Deletion Artifacts to tolerate partially malformed records.
- [x] W7-0305 DONE Normalize timestamps for Recycle Bin and Deletion Artifacts into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0306 DONE Normalize identity fields for Recycle Bin and Deletion Artifacts (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0307 DONE Add deterministic sort order for Recycle Bin and Deletion Artifacts output and enforce tie-break keys in tests.
- [x] W7-0308 DONE Add dedupe rules for Recycle Bin and Deletion Artifacts and emit dedupe_reason metadata where rows collapse.
- [x] W7-0309 DONE Add parser-level unit tests for Recycle Bin and Deletion Artifacts covering happy path, partial records, and malformed input.
- [x] W7-0310 DONE Add CLI smoke test for Recycle Bin and Deletion Artifacts using --json-result and verify envelope + payload contract.
- [x] W7-0311 DONE Add CLI validation tests for Recycle Bin and Deletion Artifacts for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0312 DONE Add JSON golden contract snapshot for Recycle Bin and Deletion Artifacts and include backward-compatibility note on field changes.
- [x] W7-0313 DONE Map Recycle Bin and Deletion Artifacts rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0314 DONE Add correlation hooks so Recycle Bin and Deletion Artifacts can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0315 DONE Add counts/summary block for Recycle Bin and Deletion Artifacts (total_available, total_returned, quality flags, warning counts).
- [x] W7-0316 DONE Add graceful-warning behavior for Recycle Bin and Deletion Artifacts when source files are missing, unreadable, or unparseable.
- [x] W7-0317 DONE Document known coverage limits for Recycle Bin and Deletion Artifacts and list unsupported sub-artifacts explicitly.
- [x] W7-0318 DONE Add benchmark test for Recycle Bin and Deletion Artifacts parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0319 DONE Run clippy cleanup for Recycle Bin and Deletion Artifacts code paths and remove low-value complexity before merge.
- [x] W7-0320 DONE Gate Recycle Bin and Deletion Artifacts with full workspace build/test and record regression notes in weekly tracker.

## Workstream 17: Prefetch Fidelity

- [x] W7-0321 DONE Build fixture manifest for Prefetch Fidelity with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0322 DONE Add strict input-shape detector for Prefetch Fidelity (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0323 DONE Implement primary parser pass for Prefetch Fidelity with no inferred fields and explicit null handling.
- [x] W7-0324 DONE Implement secondary fallback parser pass for Prefetch Fidelity to tolerate partially malformed records.
- [x] W7-0325 DONE Normalize timestamps for Prefetch Fidelity into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0326 DONE Normalize identity fields for Prefetch Fidelity (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0327 DONE Add deterministic sort order for Prefetch Fidelity output and enforce tie-break keys in tests.
- [x] W7-0328 DONE Add dedupe rules for Prefetch Fidelity and emit dedupe_reason metadata where rows collapse.
- [x] W7-0329 DONE Add parser-level unit tests for Prefetch Fidelity covering happy path, partial records, and malformed input.
- [x] W7-0330 DONE Add CLI smoke test for Prefetch Fidelity using --json-result and verify envelope + payload contract.
- [x] W7-0331 DONE Add CLI validation tests for Prefetch Fidelity for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0332 DONE Add JSON golden contract snapshot for Prefetch Fidelity and include backward-compatibility note on field changes.
- [x] W7-0333 DONE Map Prefetch Fidelity rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0334 DONE Add correlation hooks so Prefetch Fidelity can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0335 DONE Add counts/summary block for Prefetch Fidelity (total_available, total_returned, quality flags, warning counts).
- [x] W7-0336 DONE Add graceful-warning behavior for Prefetch Fidelity when source files are missing, unreadable, or unparseable.
- [x] W7-0337 DONE Document known coverage limits for Prefetch Fidelity and list unsupported sub-artifacts explicitly.
- [x] W7-0338 DONE Add benchmark test for Prefetch Fidelity parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0339 DONE Run clippy cleanup for Prefetch Fidelity code paths and remove low-value complexity before merge.
- [x] W7-0340 DONE Gate Prefetch Fidelity with full workspace build/test and record regression notes in weekly tracker.

## Workstream 18: JumpList Fidelity

- [x] W7-0341 DONE Build fixture manifest for JumpList Fidelity with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0342 DONE Add strict input-shape detector for JumpList Fidelity (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0343 DONE Implement primary parser pass for JumpList Fidelity with no inferred fields and explicit null handling.
- [x] W7-0344 DONE Implement secondary fallback parser pass for JumpList Fidelity to tolerate partially malformed records.
- [x] W7-0345 DONE Normalize timestamps for JumpList Fidelity into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0346 DONE Normalize identity fields for JumpList Fidelity (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0347 DONE Add deterministic sort order for JumpList Fidelity output and enforce tie-break keys in tests.
- [x] W7-0348 DONE Add dedupe rules for JumpList Fidelity and emit dedupe_reason metadata where rows collapse.
- [x] W7-0349 DONE Add parser-level unit tests for JumpList Fidelity covering happy path, partial records, and malformed input.
- [x] W7-0350 DONE Add CLI smoke test for JumpList Fidelity using --json-result and verify envelope + payload contract.
- [x] W7-0351 DONE Add CLI validation tests for JumpList Fidelity for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0352 DONE Add JSON golden contract snapshot for JumpList Fidelity and include backward-compatibility note on field changes.
- [x] W7-0353 DONE Map JumpList Fidelity rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0354 DONE Add correlation hooks so JumpList Fidelity can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0355 DONE Add counts/summary block for JumpList Fidelity (total_available, total_returned, quality flags, warning counts).
- [x] W7-0356 DONE Add graceful-warning behavior for JumpList Fidelity when source files are missing, unreadable, or unparseable.
- [x] W7-0357 DONE Document known coverage limits for JumpList Fidelity and list unsupported sub-artifacts explicitly.
- [x] W7-0358 DONE Add benchmark test for JumpList Fidelity parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0359 DONE Run clippy cleanup for JumpList Fidelity code paths and remove low-value complexity before merge.
- [x] W7-0360 DONE Gate JumpList Fidelity with full workspace build/test and record regression notes in weekly tracker.

## Workstream 19: LNK Shortcut Fidelity

- [x] W7-0361 DONE Build fixture manifest for LNK Shortcut Fidelity with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0362 DONE Add strict input-shape detector for LNK Shortcut Fidelity (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0363 DONE Implement primary parser pass for LNK Shortcut Fidelity with no inferred fields and explicit null handling.
- [x] W7-0364 DONE Implement secondary fallback parser pass for LNK Shortcut Fidelity to tolerate partially malformed records.
- [x] W7-0365 DONE Normalize timestamps for LNK Shortcut Fidelity into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0366 DONE Normalize identity fields for LNK Shortcut Fidelity (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0367 DONE Add deterministic sort order for LNK Shortcut Fidelity output and enforce tie-break keys in tests.
- [x] W7-0368 DONE Add dedupe rules for LNK Shortcut Fidelity and emit dedupe_reason metadata where rows collapse.
- [x] W7-0369 DONE Add parser-level unit tests for LNK Shortcut Fidelity covering happy path, partial records, and malformed input.
- [x] W7-0370 DONE Add CLI smoke test for LNK Shortcut Fidelity using --json-result and verify envelope + payload contract.
- [x] W7-0371 DONE Add CLI validation tests for LNK Shortcut Fidelity for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0372 DONE Add JSON golden contract snapshot for LNK Shortcut Fidelity and include backward-compatibility note on field changes.
- [x] W7-0373 DONE Map LNK Shortcut Fidelity rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0374 DONE Add correlation hooks so LNK Shortcut Fidelity can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0375 DONE Add counts/summary block for LNK Shortcut Fidelity (total_available, total_returned, quality flags, warning counts).
- [x] W7-0376 DONE Add graceful-warning behavior for LNK Shortcut Fidelity when source files are missing, unreadable, or unparseable.
- [x] W7-0377 DONE Document known coverage limits for LNK Shortcut Fidelity and list unsupported sub-artifacts explicitly.
- [x] W7-0378 DONE Add benchmark test for LNK Shortcut Fidelity parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0379 DONE Run clippy cleanup for LNK Shortcut Fidelity code paths and remove low-value complexity before merge.
- [x] W7-0380 DONE Gate LNK Shortcut Fidelity with full workspace build/test and record regression notes in weekly tracker.

## Workstream 20: Browser Forensics (Chrome/Edge/Firefox)

- [x] W7-0381 DONE Build fixture manifest for Browser Forensics (Chrome/Edge/Firefox) with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0382 DONE Add strict input-shape detector for Browser Forensics (Chrome/Edge/Firefox) (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0383 DONE Implement primary parser pass for Browser Forensics (Chrome/Edge/Firefox) with no inferred fields and explicit null handling.
- [x] W7-0384 DONE Implement secondary fallback parser pass for Browser Forensics (Chrome/Edge/Firefox) to tolerate partially malformed records.
- [x] W7-0385 DONE Normalize timestamps for Browser Forensics (Chrome/Edge/Firefox) into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0386 DONE Normalize identity fields for Browser Forensics (Chrome/Edge/Firefox) (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0387 DONE Add deterministic sort order for Browser Forensics (Chrome/Edge/Firefox) output and enforce tie-break keys in tests.
- [x] W7-0388 DONE Add dedupe rules for Browser Forensics (Chrome/Edge/Firefox) and emit dedupe_reason metadata where rows collapse.
- [x] W7-0389 DONE Add parser-level unit tests for Browser Forensics (Chrome/Edge/Firefox) covering happy path, partial records, and malformed input.
- [x] W7-0390 DONE Add CLI smoke test for Browser Forensics (Chrome/Edge/Firefox) using --json-result and verify envelope + payload contract.
- [x] W7-0391 DONE Add CLI validation tests for Browser Forensics (Chrome/Edge/Firefox) for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0392 DONE Add JSON golden contract snapshot for Browser Forensics (Chrome/Edge/Firefox) and include backward-compatibility note on field changes.
- [x] W7-0393 DONE Map Browser Forensics (Chrome/Edge/Firefox) rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0394 DONE Add correlation hooks so Browser Forensics (Chrome/Edge/Firefox) can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0395 DONE Add counts/summary block for Browser Forensics (Chrome/Edge/Firefox) (total_available, total_returned, quality flags, warning counts).
- [x] W7-0396 DONE Add graceful-warning behavior for Browser Forensics (Chrome/Edge/Firefox) when source files are missing, unreadable, or unparseable.
- [x] W7-0397 DONE Document known coverage limits for Browser Forensics (Chrome/Edge/Firefox) and list unsupported sub-artifacts explicitly.
- [x] W7-0398 DONE Add benchmark test for Browser Forensics (Chrome/Edge/Firefox) parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0399 DONE Run clippy cleanup for Browser Forensics (Chrome/Edge/Firefox) code paths and remove low-value complexity before merge.
- [x] W7-0400 DONE Gate Browser Forensics (Chrome/Edge/Firefox) with full workspace build/test and record regression notes in weekly tracker.

## Workstream 21: RDP and Remote Access Artifacts

- [x] W7-0401 DONE Build fixture manifest for RDP and Remote Access Artifacts with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0402 DONE Add strict input-shape detector for RDP and Remote Access Artifacts (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0403 DONE Implement primary parser pass for RDP and Remote Access Artifacts with no inferred fields and explicit null handling.
- [x] W7-0404 DONE Implement secondary fallback parser pass for RDP and Remote Access Artifacts to tolerate partially malformed records.
- [x] W7-0405 DONE Normalize timestamps for RDP and Remote Access Artifacts into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0406 DONE Normalize identity fields for RDP and Remote Access Artifacts (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0407 DONE Add deterministic sort order for RDP and Remote Access Artifacts output and enforce tie-break keys in tests.
- [x] W7-0408 DONE Add dedupe rules for RDP and Remote Access Artifacts and emit dedupe_reason metadata where rows collapse.
- [x] W7-0409 DONE Add parser-level unit tests for RDP and Remote Access Artifacts covering happy path, partial records, and malformed input.
- [x] W7-0410 DONE Add CLI smoke test for RDP and Remote Access Artifacts using --json-result and verify envelope + payload contract.
- [x] W7-0411 DONE Add CLI validation tests for RDP and Remote Access Artifacts for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0412 DONE Add JSON golden contract snapshot for RDP and Remote Access Artifacts and include backward-compatibility note on field changes.
- [x] W7-0413 DONE Map RDP and Remote Access Artifacts rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0414 DONE Add correlation hooks so RDP and Remote Access Artifacts can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0415 DONE Add counts/summary block for RDP and Remote Access Artifacts (total_available, total_returned, quality flags, warning counts).
- [x] W7-0416 DONE Add graceful-warning behavior for RDP and Remote Access Artifacts when source files are missing, unreadable, or unparseable.
- [x] W7-0417 DONE Document known coverage limits for RDP and Remote Access Artifacts and list unsupported sub-artifacts explicitly.
- [x] W7-0418 DONE Add benchmark test for RDP and Remote Access Artifacts parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0419 DONE Run clippy cleanup for RDP and Remote Access Artifacts code paths and remove low-value complexity before merge.
- [x] W7-0420 DONE Gate RDP and Remote Access Artifacts with full workspace build/test and record regression notes in weekly tracker.

## Workstream 22: USB and Device History

- [x] W7-0421 DONE Build fixture manifest for USB and Device History with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0422 DONE Add strict input-shape detector for USB and Device History (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0423 DONE Implement primary parser pass for USB and Device History with no inferred fields and explicit null handling.
- [x] W7-0424 DONE Implement secondary fallback parser pass for USB and Device History to tolerate partially malformed records.
- [x] W7-0425 DONE Normalize timestamps for USB and Device History into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0426 DONE Normalize identity fields for USB and Device History (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0427 DONE Add deterministic sort order for USB and Device History output and enforce tie-break keys in tests.
- [x] W7-0428 DONE Add dedupe rules for USB and Device History and emit dedupe_reason metadata where rows collapse.
- [x] W7-0429 DONE Add parser-level unit tests for USB and Device History covering happy path, partial records, and malformed input.
- [x] W7-0430 DONE Add CLI smoke test for USB and Device History using --json-result and verify envelope + payload contract.
- [x] W7-0431 DONE Add CLI validation tests for USB and Device History for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0432 DONE Add JSON golden contract snapshot for USB and Device History and include backward-compatibility note on field changes.
- [x] W7-0433 DONE Map USB and Device History rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0434 DONE Add correlation hooks so USB and Device History can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0435 DONE Add counts/summary block for USB and Device History (total_available, total_returned, quality flags, warning counts).
- [x] W7-0436 DONE Add graceful-warning behavior for USB and Device History when source files are missing, unreadable, or unparseable.
- [x] W7-0437 DONE Document known coverage limits for USB and Device History and list unsupported sub-artifacts explicitly.
- [x] W7-0438 DONE Add benchmark test for USB and Device History parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0439 DONE Run clippy cleanup for USB and Device History code paths and remove low-value complexity before merge.
- [x] W7-0440 DONE Gate USB and Device History with full workspace build/test and record regression notes in weekly tracker.

## Workstream 23: Restore Points and Shadow Copies

- [x] W7-0441 DONE Build fixture manifest for Restore Points and Shadow Copies with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0442 DONE Add strict input-shape detector for Restore Points and Shadow Copies (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0443 DONE Implement primary parser pass for Restore Points and Shadow Copies with no inferred fields and explicit null handling.
- [x] W7-0444 DONE Implement secondary fallback parser pass for Restore Points and Shadow Copies to tolerate partially malformed records.
- [x] W7-0445 DONE Normalize timestamps for Restore Points and Shadow Copies into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0446 DONE Normalize identity fields for Restore Points and Shadow Copies (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0447 DONE Add deterministic sort order for Restore Points and Shadow Copies output and enforce tie-break keys in tests.
- [x] W7-0448 DONE Add dedupe rules for Restore Points and Shadow Copies and emit dedupe_reason metadata where rows collapse.
- [x] W7-0449 DONE Add parser-level unit tests for Restore Points and Shadow Copies covering happy path, partial records, and malformed input.
- [x] W7-0450 DONE Add CLI smoke test for Restore Points and Shadow Copies using --json-result and verify envelope + payload contract.
- [x] W7-0451 DONE Add CLI validation tests for Restore Points and Shadow Copies for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0452 DONE Add JSON golden contract snapshot for Restore Points and Shadow Copies and include backward-compatibility note on field changes.
- [x] W7-0453 DONE Map Restore Points and Shadow Copies rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0454 DONE Add correlation hooks so Restore Points and Shadow Copies can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0455 DONE Add counts/summary block for Restore Points and Shadow Copies (total_available, total_returned, quality flags, warning counts).
- [x] W7-0456 DONE Add graceful-warning behavior for Restore Points and Shadow Copies when source files are missing, unreadable, or unparseable.
- [x] W7-0457 DONE Document known coverage limits for Restore Points and Shadow Copies and list unsupported sub-artifacts explicitly.
- [x] W7-0458 DONE Add benchmark test for Restore Points and Shadow Copies parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0459 DONE Run clippy cleanup for Restore Points and Shadow Copies code paths and remove low-value complexity before merge.
- [x] W7-0460 DONE Gate Restore Points and Shadow Copies with full workspace build/test and record regression notes in weekly tracker.

## Workstream 24: User Activity and MRU Ecosystem

- [x] W7-0461 DONE Build fixture manifest for User Activity and MRU Ecosystem with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0462 DONE Add strict input-shape detector for User Activity and MRU Ecosystem (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0463 DONE Implement primary parser pass for User Activity and MRU Ecosystem with no inferred fields and explicit null handling.
- [x] W7-0464 DONE Implement secondary fallback parser pass for User Activity and MRU Ecosystem to tolerate partially malformed records.
- [x] W7-0465 DONE Normalize timestamps for User Activity and MRU Ecosystem into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0466 DONE Normalize identity fields for User Activity and MRU Ecosystem (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0467 DONE Add deterministic sort order for User Activity and MRU Ecosystem output and enforce tie-break keys in tests.
- [x] W7-0468 DONE Add dedupe rules for User Activity and MRU Ecosystem and emit dedupe_reason metadata where rows collapse.
- [x] W7-0469 DONE Add parser-level unit tests for User Activity and MRU Ecosystem covering happy path, partial records, and malformed input.
- [x] W7-0470 DONE Add CLI smoke test for User Activity and MRU Ecosystem using --json-result and verify envelope + payload contract.
- [x] W7-0471 DONE Add CLI validation tests for User Activity and MRU Ecosystem for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0472 DONE Add JSON golden contract snapshot for User Activity and MRU Ecosystem and include backward-compatibility note on field changes.
- [x] W7-0473 DONE Map User Activity and MRU Ecosystem rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0474 DONE Add correlation hooks so User Activity and MRU Ecosystem can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0475 DONE Add counts/summary block for User Activity and MRU Ecosystem (total_available, total_returned, quality flags, warning counts).
- [x] W7-0476 DONE Add graceful-warning behavior for User Activity and MRU Ecosystem when source files are missing, unreadable, or unparseable.
- [x] W7-0477 DONE Document known coverage limits for User Activity and MRU Ecosystem and list unsupported sub-artifacts explicitly.
- [x] W7-0478 DONE Add benchmark test for User Activity and MRU Ecosystem parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0479 DONE Run clippy cleanup for User Activity and MRU Ecosystem code paths and remove low-value complexity before merge.
- [x] W7-0480 DONE Gate User Activity and MRU Ecosystem with full workspace build/test and record regression notes in weekly tracker.

## Workstream 25: Timeline Correlation, QA, and Performance

- [x] W7-0481 DONE Build fixture manifest for Timeline Correlation, QA, and Performance with at least 30 labeled samples across Windows 10 and 11.
- [x] W7-0482 DONE Add strict input-shape detector for Timeline Correlation, QA, and Performance (raw format vs exported format) and return truthful mode metadata.
- [x] W7-0483 DONE Implement primary parser pass for Timeline Correlation, QA, and Performance with no inferred fields and explicit null handling.
- [x] W7-0484 DONE Implement secondary fallback parser pass for Timeline Correlation, QA, and Performance to tolerate partially malformed records.
- [x] W7-0485 DONE Normalize timestamps for Timeline Correlation, QA, and Performance into unix + RFC3339 UTC fields with source-time precision notes.
- [x] W7-0486 DONE Normalize identity fields for Timeline Correlation, QA, and Performance (SID/user/device/process) with canonical casing and path formatting.
- [x] W7-0487 DONE Add deterministic sort order for Timeline Correlation, QA, and Performance output and enforce tie-break keys in tests.
- [x] W7-0488 DONE Add dedupe rules for Timeline Correlation, QA, and Performance and emit dedupe_reason metadata where rows collapse.
- [x] W7-0489 DONE Add parser-level unit tests for Timeline Correlation, QA, and Performance covering happy path, partial records, and malformed input.
- [x] W7-0490 DONE Add CLI smoke test for Timeline Correlation, QA, and Performance using --json-result and verify envelope + payload contract.
- [x] W7-0491 DONE Add CLI validation tests for Timeline Correlation, QA, and Performance for missing/invalid args and ensure EXIT_VALIDATION behavior.
- [x] W7-0492 DONE Add JSON golden contract snapshot for Timeline Correlation, QA, and Performance and include backward-compatibility note on field changes.
- [x] W7-0493 DONE Map Timeline Correlation, QA, and Performance rows into timeline event shape with conservative severity mapping and source_module markers.
- [x] W7-0494 DONE Add correlation hooks so Timeline Correlation, QA, and Performance can enrich execution/persistence clusters when shared keys exist.
- [x] W7-0495 DONE Add counts/summary block for Timeline Correlation, QA, and Performance (total_available, total_returned, quality flags, warning counts).
- [x] W7-0496 DONE Add graceful-warning behavior for Timeline Correlation, QA, and Performance when source files are missing, unreadable, or unparseable.
- [x] W7-0497 DONE Document known coverage limits for Timeline Correlation, QA, and Performance and list unsupported sub-artifacts explicitly.
- [x] W7-0498 DONE Add benchmark test for Timeline Correlation, QA, and Performance parser runtime on medium and large fixtures and capture memory usage.
- [x] W7-0499 DONE Run clippy cleanup for Timeline Correlation, QA, and Performance code paths and remove low-value complexity before merge.
- [x] W7-0500 DONE Gate Timeline Correlation, QA, and Performance with full workspace build/test and record regression notes in weekly tracker.

## Totals

- Total tasks: 500
- Workstreams: 25
- Tasks per workstream: 20








