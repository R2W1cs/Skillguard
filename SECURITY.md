# Security Policy

## Reporting Vulnerabilities

If you discover a security issue in SkillGuard itself (for example, secret leakage in reports, path traversal during discovery, or unsafe sandbox defaults), please open a private security advisory on the repository or email the maintainers. Do not open a public issue with exploit details until a fix is available.

Include:

- Affected version / commit
- Reproduction steps
- Impact assessment

## Supported Versions

Security fixes are applied to the latest released version on the default branch.

## Security Design Guarantees (and Non-Guarantees)

**SkillGuard does:**

- Static analysis without executing skill scripts on the host
- Redact likely secrets in terminal, JSON, and SARIF output
- Refuse unsafe YAML loading
- Bound file size/count during discovery
- Require explicit opt-in for Docker-based dynamic analysis
- Default sandbox policy: no network, no Docker socket, dropped capabilities, non-root

**SkillGuard does not:**

- Prove a skill is safe
- Detect every prompt-injection or obfuscation technique
- Replace organizational review or sandboxing of agent runtimes
- Guarantee container escape immunity

## Scanning Untrusted Skills

1. Prefer static analysis first (`skillguard scan`).
2. Only enable `--sandbox` when you understand Docker risk.
3. Review findings and exclusions; exclusions appear in the report.
4. Never paste raw secrets from findings into tickets — evidence is redacted by design.

## Dependency Security

CI runs `pip-audit` where practical. Pin GitHub Actions to commit SHAs.
