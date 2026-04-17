# tdd-guide — TDD for Strata forensic parsers

Loaded when writing or reviewing tests for Strata artifact parsers.
Every parser lands with tests that encode its contract.

## Minimum tests per parser

Three mandatory cases; more when variants exist.

1. **Valid known-good fixture** — the smallest real artifact that
   exercises every declared field. Assert specific values: timestamp,
   string contents, enum variant. Fixtures embedded as `&[u8]`
   constants when they are under ~2 KB; otherwise placed in the
   plugin's `tests/fixtures/` directory and loaded via
   `include_bytes!`.
2. **Empty / zero-byte input** — `parse(&[])` (or a valid-but-empty
   database) returns an empty `Vec` or `None`. Never panics.
3. **Corrupt / truncated input** — prefix of a valid fixture, magic
   mutated, length fields inflated. Returns empty / partial results;
   never panics.

Additional tests that are not optional:

* One test per **Windows version variant** (Windows 7 / 10 / 11) for
  Windows artifacts whose schema changed across versions.
* One test per **format version** for parsers that declare a
  `version` field (Prefetch 17/23/26/30/31, AmCache N/W, etc.).
* One test per **stream type** for multi-stream containers (Biome,
  KnowledgeC, Unified Log).
* One test per **MITRE mapping branch** when the MITRE technique is
  computed from record contents.

## Fixture guidelines

* **Minimal inputs only.** A fixture that exercises the parser in 256
  bytes is preferable to a 2 MB capture. Tests are run on every
  `cargo test` — keep them fast.
* **Binary fixtures embed as `&[u8]` constants** with a leading
  comment describing source provenance: real artifact from version
  X.Y.Z, synthetic-constructed, copyrighted-redacted, etc.
* **No `.unwrap()` in test code.** Use
  `assert!(result.is_some())` then destructure via `let`, or use
  `.expect("<contract being tested>")` where the expect message is
  the contract.
* **Timestamp fixtures use known values with verified UTC output.**
  Document the conversion arithmetic in a comment: `"// CoreData
  738_936_000 == Unix 1_717_243_200 == 2024-06-01 12:00:00 UTC"`.
  The test asserts the resulting UTC seconds exactly.

## Test naming convention

```
test_parse_<artifact>_valid         # happy path
test_parse_<artifact>_empty         # empty input
test_parse_<artifact>_corrupt       # corrupt / truncated input
test_parse_<artifact>_<variant>     # format / version variant
```

All other descriptive names are fine; these four are the canonical
starting set a reviewer will look for.

## Performance budgets

* Unit tests per parser: under 100 ms total.
* Parsers processing >10 MB fixtures complete in under 5 seconds on
  CI hardware.
* No test may spawn a process or reach the network.

## What to test when refactoring

When you change parser internals, add a test that locks in the
current behaviour before the refactor lands. "Golden output" tests
that serialise the full parsed structure to JSON and compare
byte-for-byte are encouraged for large parsers — regressions then
show up as precise diffs rather than vague assertion failures.
