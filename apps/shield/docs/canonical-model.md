# Canonical Artifact Model

The canonical model is defined in `engine/src/model/entities.rs` and correlation helpers in `engine/src/model/correlation.rs`.

## Core entities

- `Identity`
- `Device`
- `Account`
- `Message`
- `Call`
- `Location`
- `Media`
- `WebEvent`
- `SystemEvent`
- `AppEvent`

## Correlation behavior

- Inputs are normalized via `CorrelationInput`.
- `hints` are deduplicated into lower-cased identity keys.
- Stable `dedupe_key` generation combines source module, source record ID, normalized timestamp, and canonical payload.
- Confidence defaults:
  - `0.85` when identity hints exist
  - `0.50` when no identity hints exist

## Persistence model

Canonical records and relationships are stored in:

- `canonical_records`
- `canonical_relationships`

within `CaseDatabase`.
