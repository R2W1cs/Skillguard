# GitHub Actions

## Consumer example

See [`examples/github-actions-skillguard.yml`](https://github.com/R2W1cs/Skillguard/blob/master/examples/github-actions-skillguard.yml).

Minimal pattern:

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: pip install -e ".[dev]"   # or a pinned release once published
- run: |
    skillguard scan skills \
      --format json -o skillguard-report.json \
      --fail-on high --quiet
- run: |
    skillguard scan skills --format sarif -o skillguard.sarif --quiet || true
```

## Reusable workflow

```yaml
jobs:
  scan:
    uses: R2W1cs/Skillguard/.github/workflows/skillguard-scan.yml@v0.3.0
    with:
      path: skills/
      fail-on: high
      upload-sarif: true
```

Optional regression compare input: `baseline-report` (path to a prior JSON report in the caller repo).

## Permissions

SARIF upload requires `security-events: write` (and `contents: read`).

## Secrets

SkillGuard redacts secret-like evidence in reports. Still avoid printing raw env
secrets in workflow logs. Prefer uploading artifacts over echoing report bodies.
