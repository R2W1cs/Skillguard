# Testing

```bash
# Unit + integration + CLI
pytest -q

# Coverage gate (fail_under=85 in pyproject.toml)
pytest --cov=skillguard --cov-report=term-missing

# Lint / types
ruff check .
mypy skillguard

# Adversarial corpus benchmark
skillguard benchmark run --dataset adversarial --json-out benchmarks/adversarial-latest.json

# Docs site
pip install -e ".[docs]"
mkdocs build --strict
```

Security-focused tests use the `@pytest.mark.security` marker.
Integration workflows use `@pytest.mark.integration`.

Fixture corpora live under `tests/fixtures/` (including `adversarial/`). Malicious
samples are **inert** by design — do not treat them as operational malware.
