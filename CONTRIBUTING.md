# Contributing to SkillGuard

Thanks for helping harden Agent Skill security tooling.

## Development setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Unix: source .venv/bin/activate
pip install -e ".[dev]"
```

## Checks before opening a PR

```bash
ruff check .
ruff format --check .
mypy skillguard
pytest --cov=skillguard --cov-report=term-missing
pip-audit
python -m build
```

## Adding a detection rule

1. Create or extend a module under `skillguard/rules/`.
2. Register it in `skillguard/rules/registry.py` (via the module `RULES` list).
3. Give it a stable ID (`SG-AREA-NNN`), remediation text, and severity.
4. Add unit tests under `tests/unit/` and, when relevant, an inert fixture.
5. Update benchmark expectations if the fixture set changes.
6. Never execute untrusted skill code on the host from a rule.

## Security-sensitive changes

Changes to discovery, redaction, sandbox policy, or report serialization require
security tests under `tests/security/`.

## Code of conduct

Please follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
