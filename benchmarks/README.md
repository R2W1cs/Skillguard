# Benchmarks

Fixtures live under `tests/fixtures/`:

- `benign/` — should not trigger critical forbidden rules
- `malicious/` — inert samples expected to trigger labeled rules
- `mixed/` — benign docs with planted issues
- `edge_cases/` — malformed metadata and false-positive traps

Run:

```bash
skillguard benchmark run
# or
skillguard benchmark run --fixtures tests/fixtures --json-out benchmarks/latest.json
```

Results are computed at runtime — do not hand-edit metrics as if they were measured.
