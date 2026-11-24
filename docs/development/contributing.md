# Contributing

Canonical guide: **[CONTRIBUTING.md](https://github.com/R2W1cs/Skillguard/blob/master/CONTRIBUTING.md)**

## Quick contributor loop

```bash
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy skillguard
pytest --cov=skillguard --cov-fail-under=85
```

Code of conduct: [CODE_OF_CONDUCT.md](https://github.com/R2W1cs/Skillguard/blob/master/CODE_OF_CONDUCT.md)
