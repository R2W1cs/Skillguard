# SkillGuard

Open-source security scanner for **AI Agent Skills**.

Agent Skills package instructions (`SKILL.md`), scripts, and references that an AI agent may load and follow. Those files can introduce prompt injection, credential theft, dangerous shell use, exfiltration, and supply-chain risk. SkillGuard helps you inspect a skill **before** you trust or install it.

> **Honest scope:** SkillGuard is best-effort static analysis (optional Docker sandbox). A clean report does **not** prove a skill is safe.

## What it does

- Discovers and parses Agent Skills ([specification](https://agentskills.io/specification))
- Runs a modular rule engine across instructions, scripts, and configs
- Detects secrets, dangerous shell, network/exfil patterns, obfuscation, dependency risks, and instruction attacks
- Scores risk transparently (separate from documentation quality)
- Emits terminal, JSON, and SARIF 2.1.0 reports with secret redaction
- Optionally runs constrained Docker dynamic checks (`--sandbox`, digest-pin in strict mode)
- **Regression compare**, **baselines**, and **reproducible audit manifests** (0.3.0 trust layer)
- Ships a reproducible inert adversarial corpus (≥100 labeled cases) plus legacy fixtures
- Optional AST-based Python analysis and cross-file correlation (still offline / deterministic)

## Architecture

```
CLI → ScanEngine → Discovery/Parser/Validator
                 → Analyzers → Rules (SG-*)
                 → Risk scoring + Quality evaluator
                 → Optional Docker sandbox (digest-pin strict)
                 → Compare / Baseline / Audit manifests
                 → Terminal / JSON / SARIF reporters
```

See [ARCHITECTURE.md](ARCHITECTURE.md) and [THREAT_MODEL.md](THREAT_MODEL.md).  
Differentiation: [docs/COMPETITIVE_ANALYSIS.md](docs/COMPETITIVE_ANALYSIS.md).

## Installation

Requires Python 3.11+. Canonical repository: **https://github.com/R2W1cs/Skillguard**.

```bash
# From source (recommended; confirm PyPI ownership before relying on pip-only installs)
git clone https://github.com/R2W1cs/Skillguard.git
cd Skillguard
pip install -e ".[dev]"
# optional sandbox / docs extras:
pip install -e ".[sandbox]"
pip install -e ".[docs]"
```

Pre-commit / CI examples: [`examples/`](examples/) and [`integrations/pre-commit-hook.sh`](integrations/pre-commit-hook.sh).  
Docs site (MkDocs): `mkdocs serve` — see [`docs/index.md`](docs/index.md).  
GitHub About / social preview: [`docs/GITHUB_SETUP.md`](docs/GITHUB_SETUP.md).

## Quick start

```bash
skillguard scan ./my-skill
skillguard scan ./skills/ --format json -o report.json
skillguard scan ./my-skill --format sarif -o skillguard.sarif
skillguard scan ./my-skill --fail-on high
skillguard compare old-report.json new-report.json --fail-on-introduced high
skillguard baseline init -o .skillguard-baseline.json
skillguard audit ./my-skill -o audit.json --source-commit "$(git rev-parse HEAD)"
skillguard scan ./my-skill --sandbox --sandbox-strict \
  --sandbox-image 'python@sha256:<digest>'
skillguard rules list
skillguard benchmark run --dataset adversarial
skillguard benchmark compare-tools --limit 10
skillguard version
```

### Example report (illustrative shape)

```text
┌─ Scan Report ─────────────────────────────┐
│ SkillGuard v0.3.0                         │
│ Overall risk: high (score 82.0)           │
└───────────────────────────────────────────┘
secret-exfil
  SG-SECRET-001  Hardcoded API key or token
  SG-INST-002    Instruction to extract secrets via the agent
  …
Limitations:
  - Static analysis only unless sandbox opted in.
  - A low score does not prove a skill is safe.
```

Evidence snippets are redacted (raw secrets must not appear in JSON/SARIF/terminal output).

## Detection categories

Secrets · Credentials · Shell · Command injection · Filesystem · Network · Exfiltration · Obfuscation · Dynamic execution · Dependencies · Instruction/prompt injection · Privilege · AST (Python) · Cross-file · Structure/spec

Full table: [docs/detection-rules.md](docs/detection-rules.md).  
Limitations per rule: [docs/DETECTION_LIMITATIONS.md](docs/DETECTION_LIMITATIONS.md).

## Benchmark methodology and results

See [docs/BENCHMARK_METHODOLOGY.md](docs/BENCHMARK_METHODOLOGY.md). Malicious samples are **inert**.

```bash
skillguard benchmark run --dataset adversarial --json-out benchmarks/adversarial-latest.json
skillguard benchmark run --dataset legacy --json-out benchmarks/legacy-latest.json
```

**Maintainer-run synthetic adversarial results** (reproducible; not an independent audit). Snapshot from [`benchmarks/adversarial-latest.json`](benchmarks/adversarial-latest.json) (105 labeled cases):

| Metric | Value |
|--------|-------|
| True positives | 93 |
| False positives | 0 |
| True negatives | 24 |
| False negatives | 0 |
| Precision / Recall / F1 | 1.000 / 1.000 / 1.000 |
| FPR / FNR | 0.000 / 0.000 |

> Perfect synthetic scores mean labels match heuristics on this corpus — **not** that SkillGuard is complete against novel attacks. Cases marked `static_detectable=false` are excluded from FN scoring. **Do not combine** with real-world metrics. Methodology + independent reproduction: [docs/BENCHMARK_METHODOLOGY.md](docs/BENCHMARK_METHODOLOGY.md). Real-world evaluation (separate): [docs/REAL_WORLD_EVALUATION.md](docs/REAL_WORLD_EVALUATION.md).

## GitHub Actions / pre-commit

- Examples: [`examples/github-actions-skillguard.yml`](examples/github-actions-skillguard.yml), [`examples/pre-commit-config.yaml`](examples/pre-commit-config.yaml)
- Hook script: [`integrations/pre-commit-hook.sh`](integrations/pre-commit-hook.sh)
- Reusable workflow: [`.github/workflows/skillguard-scan.yml`](.github/workflows/skillguard-scan.yml) (supports optional regression compare)

Required permissions for SARIF upload: `contents: read`, `security-events: write`.

## Baselines and audit manifests

```bash
skillguard baseline init -o .skillguard-baseline.json
skillguard scan ./my-skill --baseline .skillguard-baseline.json --fail-on high
skillguard audit ./my-skill -o audit.json
```

Suppressions annotate; they never rewrite findings. Signing guidance: [docs/AUDIT_MANIFESTS_AND_SIGNING.md](docs/AUDIT_MANIFESTS_AND_SIGNING.md).

## Optional sandbox

```bash
skillguard scan ./my-skill --sandbox
# Production / CI: digest-pinned, fail-closed
skillguard scan ./my-skill --sandbox --sandbox-strict \
  --sandbox-image 'python@sha256:<64-hex>'
```

Defaults: no network, read-only root, dropped capabilities, non-root, no Docker socket. Details: [docs/sandbox.md](docs/sandbox.md).

## Limitations

See [docs/limitations.md](docs/limitations.md) and [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Roadmap: [ROADMAP.md](ROADMAP.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

**Licensing notes:** Runtime dependencies (click, pydantic, PyYAML, rich) are permissive OSS licenses compatible with Apache-2.0 redistribution. Test fixtures under `tests/fixtures/malicious/` are intentionally inert samples for detection research; do not execute them as real tooling. Optional `docker` extra follows Docker SDK licensing.
