# SkillGuard Architecture

## Overview

```
CLI (click) → Config → Scanner Engine
                           ├─ Discovery (find SKILL.md trees)
                           ├─ Parser / Validator (frontmatter + files)
                           ├─ Analyzers (instruction, script, secrets, …)
                           │     └─ Rules (registry of SG-* detectors)
                           ├─ Quality evaluator (separate from security)
                           ├─ Risk scorer (explainable aggregation)
                           ├─ Optional Docker sandbox (opt-in)
                           └─ Reporters (terminal / JSON / SARIF)
```

## Package Layout

```
skillguard/
  cli.py                 # Entry points: scan, rules, benchmark, version
  config.py              # Defaults, exclusions, fail-on thresholds
  scanner/
    engine.py            # Orchestrates analyzers and scoring
    discovery.py         # Recursive skill discovery, symlink safety
    parser.py            # SKILL.md frontmatter + body parsing
    validator.py         # Spec validation, size/encoding guards
  analyzers/             # Domain analyzers that invoke rules
  rules/                 # Modular rule definitions + registry
  models/                # Finding, Report, Skill models (Pydantic)
  reporting/             # Terminal, JSON, SARIF emitters
  sandbox/               # Docker runner + execution policy
  evaluation/            # Quality scoring + benchmark runner
```

## Data Flow

1. Resolve path → discover skill roots (or single skill).
2. Parse each skill into a `Skill` model (files catalogued, never executed).
3. Run analyzers; each rule emits zero or more `Finding` objects with evidence.
4. Aggregate findings → risk score + explanation.
5. Optionally run quality evaluation (independent of risk).
6. Optionally run sandbox behavioral checks if `--sandbox` and Docker available.
7. Emit report(s); set exit code from `--fail-on`.

## Design Constraints

- **No host execution** of skill scripts during static analysis.
- **Safe YAML**: `yaml.safe_load` only.
- **Secret redaction** in all report formats.
- **Deterministic rules** preferred; confidence/context reduce false positives.
- **Extensibility**: new rules register without touching the engine core.

## Dependencies (significant)

| Package | Why |
|---------|-----|
| pydantic | Validated models for findings/reports |
| click | Professional CLI with exit codes |
| pyyaml | Safe frontmatter parsing |
| rich | Readable terminal reports |
| docker (optional) | Isolated dynamic analysis |

Dev: pytest, pytest-cov, ruff, mypy, build, pip-audit.
