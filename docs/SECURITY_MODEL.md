# Security Model

## Trust boundaries

```
Untrusted skill files
        │
        ▼
SkillGuard process (static parse/analyze; no skill code execution)
        │
        ├── Reports (redacted) → developer / CI
        │
        └── Optional --sandbox → Docker container
              (network none, read-only root, non-root, cap_drop ALL,
               no docker.sock, tmp cleanup)
```

## Guarantees

SkillGuard **does**:

- Prefer deterministic offline static analysis
- Avoid executing skill scripts on the host during static scans
- Redact secret-like evidence in terminal/JSON/SARIF
- Use `yaml.safe_load` only
- Bound file size/count/depth
- Require explicit `--sandbox` for dynamic checks
- Refuse root sandbox users and docker.sock-style mounts by policy

SkillGuard **does not**:

- Prove a skill is safe
- Guarantee container isolation against escapes
- Detect all semantic / multilingual prompt injections
- Replace organizational review of agent permissions

## Sandbox residual risk

Even with secure defaults, container escapes exist. Dynamic analysis is an
additional signal only. Prefer digest-pinned images (`repo@sha256:…`) for
higher-assurance environments. Default image is a versioned tag
(`python:3.12.8-alpine`), which can still move until pinned by digest.

## Secrets in reports

Evidence passes through redaction filters. Security tests assert raw fixture
secrets do not appear in serialized outputs. Defense-in-depth only — novel
secret formats may still leak fragments; review outputs before sharing.
