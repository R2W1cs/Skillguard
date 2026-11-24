# SkillGuard Threat Model

## Assets

- Developer host credentials, SSH keys, cloud tokens.
- Source code and proprietary data in the workspace.
- Trust in AI agent behavior (instruction integrity).
- CI secrets and GitHub Code Scanning integrity.

## Attackers / Abuse Cases

| Actor | Goal |
|-------|------|
| Malicious skill author | Steal secrets, exfiltrate data, RCE via agent |
| Compromised skill supply chain | Inject payloads into popular skills |
| Skill that abuses agent trust | Override system prompts, conceal actions |
| Adversarial input to scanner | Crash scanner, leak secrets via reports, escape sandbox |

## Skill-side Threats Detected (best-effort)

1. Hardcoded secrets / private keys
2. Credential file / env exposure instructions
3. Dangerous shell / destructive FS ops
4. Command injection / dynamic code execution
5. Suspicious network / exfiltration patterns
6. Obfuscation / encoded payloads
7. Download-and-execute / install risks
8. Prompt injection / instruction override
9. Secret-extraction via agent
10. Concealment / privilege escalation instructions

## Scanner-side Threats Mitigated

| Threat | Mitigation |
|--------|------------|
| Path traversal | Resolve within skill root; reject escapes |
| Symlink escape | Do not follow links outside root; detect loops |
| Unsafe YAML | `safe_load` only |
| Resource exhaustion | Max file size / count / depth |
| Secret leakage in reports | Redact evidence; security tests |
| Host RCE via scan | Never execute skill code on host |
| Docker escape / socket | No socket mount; drop caps; non-root; network off by default |

## Out of Scope / Residual Risk

- Novel semantic prompt injections without lexical patterns.
- Side-channel attacks via agent tooling not present in skill files.
- Guaranteed detection of all obfuscation.
- Perfect sandbox isolation (container escapes remain a residual risk).
- Skills that are malicious only at runtime via external downloads (static analysis cannot fully cover).

## Trust Boundaries

```
[Untrusted skill files] --parse/analyze--> [SkillGuard process]
[SkillGuard] --opt-in--> [Docker sandbox] --no network/creds--> isolated run
[SkillGuard] --reports--> [CI / developer]  (redacted)
```
