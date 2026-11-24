# Adversarial (synthetic) results

!!! warning "Maintainer-run results"
    These numbers are from **project-maintainer runs** of the published corpus.
    They are reproducible by third parties, but they are **not** independently
    verified audits until an external party publishes a confirmation.

## Dataset

| Field | Value |
|-------|-------|
| Location | `tests/fixtures/adversarial/` |
| Manifest | `tests/fixtures/adversarial/manifest.json` |
| Generator | `scripts/generate_adversarial_corpus.py` |
| Nature | Synthetic, **inert** labeled cases |
| Version | See `dataset_version` in JSON snapshot |

Malicious samples are fixtures for detection research. They must not include
operational malware or real credentials.

## Snapshot (checked into repo)

File: [`benchmarks/adversarial-latest.json`](https://github.com/R2W1cs/Skillguard/blob/master/benchmarks/adversarial-latest.json)

Reproduce and overwrite locally:

```bash
skillguard benchmark run --dataset adversarial --json-out benchmarks/adversarial-latest.json
```

## How to read the score

- Synthetic results must **never** be averaged with real-world results into one number.
- Cases with `static_detectable=false` are excluded from FN accounting; the methodology
  documents that exclusion and its impact.
- High precision/recall here means agreement with labels on this corpus, not completeness
  against novel attacks.

See [BENCHMARK_METHODOLOGY.md](../BENCHMARK_METHODOLOGY.md) for TP/FP/TN/FN definitions
and independent reproduction steps.
