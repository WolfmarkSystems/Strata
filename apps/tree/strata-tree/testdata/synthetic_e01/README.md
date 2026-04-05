# Synthetic E01 Fixture

This folder contains a synthetic E01-like fixture for smoke and wiring tests.

- File: `synthetic_minimal.E01`
- Size: `1,048,576` bytes (1 MiB)
- Magic bytes at offset `0x00`: `45 57 46 2D 53 30 31` (`EWF-S01`)
- Purpose: validate E01 detection/open-path handling in UI and loaders without touching real evidence.

The fixture is intentionally minimal and does not represent a full forensic acquisition image.
