# Plugin Development Guide

## Build Model
Tree supports dynamic plugin loading and per-plugin enable/disable controls.

## Minimum Metadata
- Name
- Version
- Type (Parser/Analyzer/Carver/Hasher/Reporter)
- Description

## Runtime Expectations
- Must be non-destructive.
- Must tolerate malformed input.
- Must return errors instead of panicking.

## Logging
Plugins should emit clear status/error messages for UI log display and audit traceability.

## Packaging
Ship plugin library with matching platform extension:
- Windows: `.dll`
- Linux: `.so`
- macOS: `.dylib`
