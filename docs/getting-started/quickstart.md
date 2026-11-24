# Quickstart

## Scan a skill

```bash
skillguard scan ./my-skill
```

## Machine-readable reports

```bash
skillguard scan ./my-skill --format json -o report.json
skillguard scan ./my-skill --format sarif -o skillguard.sarif
```

## Fail CI on severity

```bash
skillguard scan ./skills --fail-on high --quiet
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success (and no findings at/above `--fail-on`, if set) |
| 1 | Findings met the fail threshold |
| 2 | Error (bad path, discovery failure, etc.) |

## Inspect rules

```bash
skillguard rules list
skillguard rules show SG-SECRET-001
```

## Regression compare

```bash
skillguard scan ./skills --format json -o old.json
# …change skills…
skillguard scan ./skills --format json -o new.json
skillguard compare old.json new.json --fail-on-introduced high
```

## Baselines (annotations only)

```bash
skillguard baseline init -o .skillguard-baseline.json
skillguard scan ./skills --baseline .skillguard-baseline.json --fail-on high
```

Suppressed findings remain in the report; they are not deleted.

## Audit manifest

```bash
skillguard audit ./my-skill -o audit.json --source-commit "$(git rev-parse HEAD)"
```

## Optional sandbox

```bash
skillguard scan ./my-skill --sandbox
skillguard scan ./my-skill --sandbox --sandbox-strict \
  --sandbox-image 'python@sha256:<64-hex-digest>'
```

## Reproduce benchmarks

```bash
skillguard benchmark run --dataset adversarial --json-out benchmarks/adversarial-latest.json
```

See [Benchmark methodology](../BENCHMARK_METHODOLOGY.md).
