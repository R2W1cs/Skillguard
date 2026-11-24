# Changelog

All notable changes to SkillGuard are documented in this file.

## [0.3.0] — 2026-03-24

### Added

- Competitive analysis of NVIDIA SkillSpector, Cisco skill-scanner, and Snyk agent-scan
  (`docs/COMPETITIVE_ANALYSIS.md`).
- `skillguard compare` — version-to-version security regression with stable fingerprints,
  configurable CI fail thresholds (introduced severity, risk increase, new scripts).
- Baseline management (`skillguard baseline init|accept|show`) — accept known findings with
  justification/expiry; annotations only (findings never rewritten); critical suppressions
  blocked by default.
- Reproducible audit manifests (`skillguard audit`, `--audit-manifest`) with file SHA-256,
  ruleset/config hashes, environment, limitations; signing guidance via cosign/gpg/minisign
  (`docs/AUDIT_MANIFESTS_AND_SIGNING.md`).
- Sandbox strict mode: digest-pinned images required; mutable tags rejected; runtime digest
  verification fail-closed (`docs/sandbox.md`).
- Developer integrations: pre-commit hook, GitHub Actions example, example config, SARIF CI path.
- Third-party comparison harness (`skillguard benchmark compare-tools`) without superiority claims.
- Docs: `BASELINES.md`, `THIRD_PARTY_COMPARISON.md`, `PHASE_3_AUDIT.md`.

### Changed

- Version bumped to 0.3.0.
- Findings now carry stable SHA-256 fingerprints (line-number independent).

## [0.2.0] — 2026-03-24

### Added

- Independent detection-limitation review (`docs/DETECTION_LIMITATIONS.md`).
- Adversarial corpus of **105** labeled inert cases with manifest labels.
- AST-based Python detector `SG-AST-001`.
- Cross-file download/exec correlation `SG-XFILE-001`.
- Expanded instruction patterns (indirect injection cues; description-field scan).
- Sandbox policy validations (non-root enforcement, forbidden mounts, timeout kill).
- Benchmark pipeline with FPR/FNR, per-severity metrics, adversarial vs legacy datasets.
- Real-world evaluation sample from `anthropics/skills` (Apache-2.0) with triage notes.
- Docs: `BENCHMARK_METHODOLOGY.md`, `SECURITY_MODEL.md`, `REAL_WORLD_EVALUATION.md`, `PHASE_2_AUDIT.md`.

### Changed

- Secret detector skips common placeholders (`YOUR_KEY`, `example`, …).
- Privilege / env-exposure rules reduce educational false positives.
- Default sandbox image pinned to versioned tag `python:3.12.8-alpine`.
- Version bumped to 0.2.0.

### Security

- Description frontmatter now included in instruction analysis.
- Sandbox runner sets `privileged=False` explicitly and validates volume mounts.

## [0.1.0] — 2026-03-24

### Added

- Initial public release of SkillGuard.
- Skill discovery and Agent Skills specification validation.
- Modular rule engine with detectors for secrets, shell, filesystem, network,
  exfiltration, obfuscation, dependencies, privilege escalation, and instruction attacks.
- Explainable risk scoring separate from quality evaluation.
- Terminal, JSON, and SARIF 2.1.0 reporting with secret redaction.
- Optional Docker sandbox dynamic analysis (explicit opt-in).
- Benchmark corpus and CLI (`skillguard benchmark run`).
- GitHub Actions CI and reusable skill-scan workflow.
