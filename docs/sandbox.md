# Sandbox Dynamic Analysis

Dynamic analysis is **optional** and requires an explicit `--sandbox` flag.

## Defaults

- Image: `python:3.12.8-alpine` (mutable tag — fine for local experiments)
- Network disabled (`network_mode=none`)
- Read-only root filesystem + tmpfs `/tmp`
- Capabilities dropped (`cap_drop=ALL`)
- `no-new-privileges`
- Non-root user (`nobody` / `65534:65534`) — root users rejected by policy
- Memory / CPU / PID limits
- Timeout with container kill on expiry
- `privileged=False`
- **No Docker socket mount** (mount validator refuses `docker.sock`)
- **No host credential mounts**

## Production / strict mode (digest pinning)

Mutable tags (`latest`, `main`, floating version tags) can change underneath you.
For production CI and high-assurance sandbox runs, SkillGuard supports **fail-closed**
image policy:

```bash
skillguard scan ./my-skill --sandbox --sandbox-strict \
  --sandbox-image 'python@sha256:<64-hex-digest>'
```

Or in config:

```yaml
enable_sandbox: true
sandbox_strict_image: true
sandbox_image: "python@sha256:<64-hex-digest>"
```

### Behavior

| Mode | Mutable tags (`:latest`, etc.) | Tag without digest | Digest-pinned `@sha256:…` |
|------|--------------------------------|--------------------|---------------------------|
| Default | Allowed (warned in docs) | Allowed | Preferred |
| `--sandbox-strict` / `strict_image` | **Rejected** | **Rejected** | Required |
| `expected_image_digest` set | N/A | Must match after inspect | Must match configured digest |

Before any container starts, SkillGuard:

1. Validates the image reference against the policy (fail-closed).
2. Inspects the local Docker image and verifies repo digests / image ID against the configured digest when required.
3. Refuses to start if verification fails (sandbox reports `performed=false` with the error).

### How developers update trusted images

1. Pull the candidate image: `docker pull python:3.12.8-alpine`
2. Record its digest: `docker image inspect python:3.12.8-alpine --format '{{index .RepoDigests 0}}'`
3. Review the upstream image changelog / SBOM as your org requires.
4. Update `sandbox_image` to `repo@sha256:…` in config / CI.
5. Open a PR so digest changes are reviewed like any other dependency bump.
6. Re-run CI with `--sandbox-strict` to confirm fail-closed acceptance of the new digest.

Do **not** invent custom signature schemes for images; use Docker Content Trust / cosign / your registry’s attestation pipeline if you need image provenance beyond digest pinning.

## What it does

SkillGuard copies the skill into a temporary staging directory and runs a fixed
observer script that:

1. Confirms the container started
2. Counts files
3. Bytecode-compiles Python sources (`compileall`) — **does not** execute skill entrypoints as a shell payload

If Docker or the `docker` Python package is unavailable, SkillGuard reports that
dynamic analysis was **not performed**. Static analysis is not claimed to be
equivalent.

## Residual risks

Container escapes exist in the wild. Treat sandbox results as an additional signal,
not a guarantee. Never enable network unless you accept increased exfiltration risk.
Digest pinning proves **which image bytes** ran — not that the image is free of
vulnerabilities.
