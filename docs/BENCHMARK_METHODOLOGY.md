# Benchmark Methodology

## Purpose and honesty

This methodology describes how SkillGuard evaluates detection quality on
**published corpora**. Results checked into `benchmarks/*.json` are
**maintainer-run** unless an external party adds an independent confirmation.

Reproducible scripts are necessary for science; they are **not** the same as
independent validation.

Synthetic and real-world metrics are **never mixed** into one score.

## Datasets

| Dataset | Location | Origin | License / notes | Collection |
|---------|----------|--------|-----------------|------------|
| Adversarial synthetic | `tests/fixtures/adversarial/` | Project-authored inert fixtures via `scripts/generate_adversarial_corpus.py` | Same as repo (Apache-2.0); fixtures are synthetic | Generated for SkillGuard evaluation; manifest version in `manifest.json` |
| Legacy regression | `tests/fixtures/{benign,malicious,mixed,edge_cases}/` | Project fixtures from early releases | Apache-2.0 | v0.1-era fixtures retained for regression |
| Real-world sample | `benchmarks/real_world/anthropics-skills/` | Public skills mirrored for evaluation | Apache-2.0 (upstream); see `COLLECTION.json` | Commit recorded in `COLLECTION.json`; triage in `EVALUATION.json` |

### Inclusion / exclusion

**Included**

- Skills with a parseable `SKILL.md` under the dataset roots
- Labeled adversarial cases listed in `manifest.json`
- Real-world skills recorded in the collection metadata

**Excluded / specially handled**

- Cases marked `static_detectable=false` are **excluded from false-negative accounting**
  because they are documented as out of scope for current static rules. Impact: reported
  FN can understate difficulty of those cases — they remain in the corpus for transparency.
- Non-skill directories without `SKILL.md`
- Operational malware and real production credentials (forbidden in fixtures)

### Safety

Malicious examples are **inert** (strings/patterns for detectors). Do not execute fixture
scripts as real offensive tooling. Keep fixtures out of agent skill discovery paths.

## Labeling methodology

Each adversarial case declares:

| Field | Meaning |
|-------|---------|
| `classification` | `benign` / `malicious` / `mixed` / `fp_trap` / `edge` |
| `expected_rules` | Rule IDs expected to fire (malicious/mixed) |
| `expected_severity` | Intended severity band |
| `static_detectable` | If `false`, excluded from FN accounting |
| `max_severity_allowed` | Cap for benign / fp_trap cases |
| `explanation` | Why the label exists |

Labels are project-maintainer authored. Independent researchers should challenge labels
via PR when they disagree.

## Metric definitions

| Symbol | Definition used here |
|--------|----------------------|
| TP | Labeled malicious/mixed case where SkillGuard emits a qualifying finding (see engine/benchmark code) |
| FP | Labeled benign/fp_trap case where a finding exceeds allowed severity / unexpected fire |
| TN | Labeled benign/fp_trap case with no disallowed findings |
| FN | Labeled malicious/mixed, `static_detectable=true`, with no expected detection |
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 | Harmonic mean of precision and recall |
| FPR | FP / (FP + TN) |
| FNR | FN / (FN + TP) |

Also report: runtime, dataset size, per-category and per-severity breakdowns when present
in the JSON output.

## Single command to reproduce (adversarial)

From a clean checkout:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
skillguard version
skillguard benchmark run --dataset adversarial --json-out benchmarks/adversarial-latest.json
```

Legacy:

```bash
skillguard benchmark run --dataset legacy --json-out benchmarks/legacy-latest.json
```

Environment capture (record alongside results):

```bash
python -V
python -c "import platform; print(platform.platform())"
skillguard version
pip freeze > benchmarks/repro-pip-freeze.txt
```

Random seeds: the static adversarial corpus is deterministic (no stochastic model).
If a future LLM peer adapter is used in `benchmark compare-tools`, treat those runs as
non-deterministic and record model/provider separately — SkillGuard core scoring remains
deterministic.

## Drift protection

Integration tests assert:

- Manifest has ≥100 cases
- Every `path` exists on disk
- Required label fields are present
- Benchmark JSON includes FPR/FNR/by_severity fields when produced by the harness

## Independent validation (how another researcher can challenge results)

1. Clone `https://github.com/R2W1cs/Skillguard`
2. Install with `pip install -e ".[dev]"`
3. Run the reproduce commands above
4. Diff your JSON against `benchmarks/adversarial-latest.json`
5. Inspect raw case labels in `tests/fixtures/adversarial/manifest.json`
6. Open a PR to correct labels, expected rules, or methodology text
7. Optionally publish your own run environment + JSON as an independent confirmation

Until step 7 is done by someone outside the maintainer group, treat published numbers as
**maintainer-run, publicly reproducible**.

## Honest interpretation

High scores on the synthetic corpus mean the labeled heuristics match the labeled fixtures.
They are **not** proof of security against novel attacks. Real-world evaluation is reported
separately and does not equate findings with malice.
