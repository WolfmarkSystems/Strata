# Timeline API Contract

Timeline consumers (CLI and GUI) should treat timeline rows as immutable event records with source attribution.

## Required fields

- `id`: stable event identifier
- `source`: parser/module source label
- `timestamp_utc`: UTC timestamp string
- `event_type`: event category/type
- `summary`: concise description
- `severity`: `info|warn|error`

## Optional fields

- `event_category`
- `artifact_id`
- `evidence_id`
- `source_module`
- `source_record_id`
- `data_json`

## Contract guarantees

- Events are mergeable by timestamp.
- Deduplication should use source + ID + timestamp + type + summary.
- Missing optional fields must not break rendering.
