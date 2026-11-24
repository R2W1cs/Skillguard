# Benchmark Methodology

## Datasets

| Dataset | Location | Version | Description |
|---------|----------|---------|-------------|
| Adversarial synthetic | `tests/fixtures/adversarial/` | manifest `2.0.0` | 105 labeled inert cases |
| Legacy regression | `tests/fixtures/{benign,malicious,mixed,edge_cases}/` | `0.1.0` | Original v0.1 fixtures |
| Real-world sample | `benchmarks/real_world/anthropics-skills/` | git commit recorded in `COLLECTION.json` | Public Apache-2.0 skills |

Synthetic and real-world metrics are **never mixed** into one score.

## Labels

Each adversarial case declares:

- `classification` — benign / malicious / mixed / fp_trap / edge
- `expected_rules` — rule IDs that should fire (malicious/mixed)
- `expected_severity` — intended severity band
- `static_detectable` — if false, excluded from FN accounting
- `max_severity_allowed` — for benign/fp traps
- `explanation` — why the label exists

Manifest generation: `python scripts/generate_adversarial_corpus.py`

## Metrics

- Precision, Recall, F1
- False-positive rate = FP / (FP + TN)
- False-negative rate = FN / (FN + TP)
- Per-category and per-severity TP/FP/FN
- Wall-clock scan duration

## Commands

```bash
skillguard benchmark run --dataset adversarial --json-out benchmarks/adversarial-latest.json
skillguard benchmark run --dataset legacy --json-out benchmarks/legacy-latest.json
```

## Drift protection

Integration tests assert:

- Manifest has ≥100 cases
- Every `path` exists on disk
- Required label fields are present
- Benchmark JSON includes FPR/FNR/by_severity

## Honest interpretation

High scores on the synthetic corpus mean the labeled heuristics match the labeled fixtures.
They are **not** proof of security against novel attacks. Real-world evaluation is reported separately and does not equate findings with malice.
