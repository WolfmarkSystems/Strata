# Parser Contract (Phase 1)

`engine/src/parsers/parser_contract.rs` defines the minimum parser contract expected by ingest.

## Required parser contract behavior

- `can_handle(source_hint)`  
  Determines if parser should be considered for source.

- `parse(source_hint)`  
  Executes parsing and returns a `ParserContractResult`.

- `emit_provenance(source_hint)`  
  Emits source-to-parser traceability records.

- `emit_confidence()`  
  Declares parser confidence (`High`, `Medium`, `Low`).

- `emit_warnings(source_hint)`  
  Emits parse warnings in deterministic order.

## Required result fields

- `parser_name`
- `parser_version`
- `warnings`
- `unsupported_sections`
- `confidence`
- `provenance`

## Error semantics

- Hard parse failures should return `Err` from `parse()`.
- Partial parse success should return `Ok` with warnings and unsupported sections populated.
- Parsers should never silently drop unsupported sections.
