# Installation

## Requirements

- Python **3.11+**
- Optional: Docker + `docker` Python package for `--sandbox`

## From source (recommended)

The GitHub repository is the authoritative distribution until a PyPI release for
this project is confirmed published under the same name.

```bash
git clone https://github.com/R2W1cs/Skillguard.git
cd Skillguard
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -e ".[dev]"
skillguard version
```

## Optional extras

```bash
pip install -e ".[sandbox]"   # Docker SDK for dynamic analysis
pip install -e ".[docs]"      # MkDocs Material documentation site
```

## Verify the CLI

```bash
skillguard --help
skillguard rules list
skillguard scan tests/fixtures/benign/hello-world --quiet
```

## Note on `pip install skillguard`

A package named `skillguard` may or may not exist on PyPI independently of this
repository. Prefer installing from
[github.com/R2W1cs/Skillguard](https://github.com/R2W1cs/Skillguard) unless you
have verified the PyPI project ownership and version match this release.
