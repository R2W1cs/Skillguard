# Roadmap

## v0.1.0 — First public release (this codebase)

- Skill discovery & Agent Skills spec validation
- Modular rule engine with ≥20 detection categories
- Instruction, script, secrets, network, filesystem, obfuscation, dependency analyzers
- Explainable risk scoring
- Separate quality evaluator
- Terminal / JSON / SARIF reporting
- Benchmark corpus + reproducible metrics
- Optional Docker sandbox (opt-in)
- GitHub Actions workflow examples
- Unit, integration, security, and CLI tests

## v0.2.0 — Hardening

- Additional language parsers (AST for Python/JS where beneficial)
- Community rule packs
- HTML report option
- Incremental / cached scanning for large skill collections

## v0.3.0 — Ecosystem

- Pre-commit hook
- VS Code / Cursor extension (thin CLI wrapper)
- Signed rule packs
- Expanded multilingual prompt-injection patterns

## Explicitly Deferred

- Mandatory cloud AI semantic analysis (optional plugin only)
- Windows container sandbox parity (Docker Desktop documented as best-effort)
- Formal verification of skills
