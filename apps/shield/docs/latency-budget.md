# Latency Budget

Initial phase budget for analyst-facing operations:

- Evidence table first paint: <= 1200 ms
- Timeline tab switch with existing data: <= 500 ms
- Timeline filtered query update (client-side): <= 250 ms
- Row selection to preview update: <= 200 ms
- Hex/strings preview request roundtrip: <= 1500 ms

## Enforcement

- Use virtualized list/table rendering for large datasets.
- Avoid full list re-sort when only row selection changes.
- Keep default timeline viewport bounded and lazily rendered.
