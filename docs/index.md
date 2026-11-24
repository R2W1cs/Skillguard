# SkillGuard

**Offline-first security scanner for AI Agent Skills.**

SkillGuard helps you inspect an Agent Skill **before** you trust or install it. It is best-effort static analysis (with an optional Docker sandbox). A clean report does **not** prove a skill is safe.

## What is an AI Agent Skill?

An [Agent Skill](https://agentskills.io/specification) is a portable package—typically a `SKILL.md` plus scripts, references, and assets—that an AI agent may load and follow. Skills are powerful because they combine natural-language instructions with executable code and dependencies.

## Why skills introduce security risk

Skills are both **untrusted prompts** and **untrusted software**:

- Instruction text can attempt prompt injection or privilege escalation via the agent
- Bundled scripts can perform dangerous shell, filesystem, or network actions
- Secrets and credentials may be harvested or exfiltrated
- Dependencies and installers introduce supply-chain risk
- Behavior can be split across files to evade single-file review

## What SkillGuard detects

Deterministic offline checks across instructions, scripts, and configs, including:

- Secrets and credential exposure
- Dangerous shell / command injection patterns
- Network and exfiltration cues
- Obfuscation and dynamic execution
- Dependency / supply-chain risk signals
- Instruction / prompt-injection patterns
- Optional AST-based Python analysis and cross-file correlation

It also provides **compare**, **baseline**, and **audit manifest** workflows for CI trust verification.

## Install

Requires Python 3.11+.

```bash
# From source (recommended until a PyPI release is published for your environment)
git clone https://github.com/R2W1cs/Skillguard.git
cd Skillguard
pip install -e ".[dev]"
```

Optional sandbox extra:

```bash
pip install -e ".[sandbox]"
```

## First scan

```bash
skillguard scan ./path/to/skill
skillguard scan ./skills --format json -o report.json
skillguard scan ./path/to/skill --fail-on high
skillguard version
```

## Interpreting results

- Findings include rule ID, severity, confidence, file path, redacted evidence, and remediation
- Overall risk is a transparent score derived from findings — **not** a safety certificate
- Exit code `1` with `--fail-on` means findings met the threshold; exit `0` does not mean “safe”
- Baselines annotate accepted findings; they never rewrite or delete them from reports

## Known limitations

- Pattern/AST static analysis can miss novel or semantic attacks
- Synthetic benchmark F1 is not proof against real adversaries
- Optional sandbox is not a perfect isolation boundary
- See [detection limitations](DETECTION_LIMITATIONS.md) and [security model](SECURITY_MODEL.md)

## Contribute

See [contributing](development/contributing.md), open issues at
[github.com/R2W1cs/Skillguard/issues](https://github.com/R2W1cs/Skillguard/issues),
and read the [architecture overview](development/architecture.md).
