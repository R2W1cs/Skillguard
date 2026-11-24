# Pre-commit

## Config example

[`examples/pre-commit-config.yaml`](https://github.com/R2W1cs/Skillguard/blob/master/examples/pre-commit-config.yaml):

```yaml
repos:
  - repo: local
    hooks:
      - id: skillguard
        name: SkillGuard skill security scan
        entry: skillguard scan
        language: system
        files: '(^|/)SKILL\.md$'
        pass_filenames: false
        args: ["skills", "--quiet", "--fail-on", "high", "--format", "terminal"]
```

Install:

```bash
pip install -e .
pre-commit install
pre-commit run skillguard --all-files
```

## Changed-skill hook script

[`integrations/pre-commit-hook.sh`](https://github.com/R2W1cs/Skillguard/blob/master/integrations/pre-commit-hook.sh)
scans staged paths that look like skills. It uses the real `skillguard` CLI and
does **not** require Docker unless you add sandbox flags yourself.

Set `SKILLGUARD_FAIL_ON` (default `high`) to control the fail threshold.
