# Configuration

Pass a YAML config with `--config`:

```bash
skillguard scan ./skills --config examples/skillguard.config.yaml
```

## Example (`examples/skillguard.config.yaml`)

```yaml
fail_on: high
include_quality: true
enable_sandbox: false
sandbox_strict_image: false
# For production sandbox:
# enable_sandbox: true
# sandbox_strict_image: true
# sandbox_image: "python@sha256:<64-hex-digest>"

exclude_globs:
  - "**/.git/**"
  - "**/node_modules/**"
  - "**/__pycache__/**"
  - "**/.venv/**"
  - "**/venv/**"
  - "**/*.pyc"

rules_disabled: []
# baseline_path: .skillguard-baseline.json
```

## Common CLI overrides

| Flag | Purpose |
|------|---------|
| `--exclude GLOB` | Extra exclude (repeatable) |
| `--disable-rule ID` | Disable a rule (repeatable) |
| `--fail-on SEVERITY` | Exit 1 at/above severity |
| `--baseline PATH` | Annotate with accepted findings |
| `--sandbox` / `--sandbox-strict` / `--sandbox-image` | Dynamic analysis policy |
| `--no-quality` | Skip documentation quality scoring |
| `--quiet` | Suppress progress |

Configuration is hashed into audit manifests (`config_hash`) so scan conditions remain reproducible.
