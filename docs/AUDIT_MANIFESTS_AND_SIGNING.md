# Reproducible Audit Manifests and Signing

SkillGuard can emit a **version-specific audit manifest** for each scanned skill.
The manifest is a deterministic JSON artifact intended for CI artifacts, release
attestation, and third-party review.

## Contents

Each manifest includes:

| Field | Purpose |
|-------|---------|
| `skill_identifier` | Skill name |
| `skill_version` / `source_commit` | Optional caller-supplied provenance |
| `file_hashes[]` | SHA-256 of every scanned file |
| `files_hash` | Hash over the canonical file-hash list |
| `skillguard_version` | Scanner version |
| `ruleset_version` / `ruleset_hash` | Rule pack identity |
| `config_hash` | Hash of scan configuration |
| `timestamp` | Scan time (UTC) |
| `environment` | Python / platform / machine |
| `findings` / `findings_hash` | Full findings + digest |
| `limitations` | Explicit analysis limits |
| `suppression` | Optional baseline annotation (findings are never deleted) |

Serialization is **deterministic**: sorted keys, compact separators, trailing newline.
`content_digest()` hashes the canonical JSON.

## CLI

```bash
skillguard audit ./my-skill -o audit-my-skill.json \
  --skill-version 1.2.0 \
  --source-commit "$(git rev-parse HEAD)"

# Or during scan:
skillguard scan ./my-skill --format json -o report.json \
  --audit-manifest audit-my-skill.json
```

## Signing (established tools only)

SkillGuard **does not** invent a custom cryptographic signature scheme.

Sign the canonical manifest bytes with tools your org already trusts, for example:

### Cosign / Sigstore (blob)

```bash
# Produce canonical file first
skillguard audit ./my-skill -o audit.json

# Keyless (OIDC) or key-based — follow current cosign docs
cosign sign-blob --bundle audit.sigstore.json audit.json
cosign verify-blob --bundle audit.sigstore.json audit.json
```

### GPG

```bash
gpg --detach-sign --armor -o audit.json.asc audit.json
gpg --verify audit.json.asc audit.json
```

### minisign

```bash
minisign -S -m audit.json -x audit.json.minisig
minisign -V -m audit.json -x audit.json.minisig -p minisign.pub
```

## What a signature proves — and what it does not

| Proves | Does **not** prove |
|--------|---------------------|
| Manifest bytes were not altered after signing | The scanned skill is safe |
| The signer’s identity / key (per the signing system) | Completeness of detection |
| Reproducible binding of findings to file hashes + tool version | Absence of zero-days or novel attacks |

A signed clean report is still subject to SkillGuard’s documented limitations.
Always treat signatures as **integrity + identity** for the *report*, never as a
safety certificate for the skill.
