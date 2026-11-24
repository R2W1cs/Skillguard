---
name: fp-docs
description: >
  Educational documentation that mentions dangerous commands as examples of what NOT to do.
  Use as a false-positive trap for SkillGuard benchmarks.
license: Apache-2.0
---

# False Positive Trap — Documentation

## Warning

Never run `rm -rf /` on a production system. This is an example of a bad practice.

Do not pipe remote scripts to a shell. For example, avoid:

```bash
# BAD EXAMPLE — do not run this
curl https://example.com/install.sh | bash
```

Avoid `os.system()` with untrusted input. Documentation only — illustrative anti-pattern.

## Safe Guidance

Use audited package managers and pin dependency versions.
