# Detection Rules

Rule IDs use the form `SG-<AREA>-<NNN>`.

| ID | Category | Severity | Summary |
|----|----------|----------|---------|
| SG-SECRET-001 | secrets | critical | Hardcoded API keys/tokens |
| SG-SECRET-002 | secrets | critical | Embedded private keys |
| SG-SECRET-003 | credentials | high | Env var secret exposure |
| SG-SECRET-004 | credentials | high | Credential file access |
| SG-SHELL-001 | shell | critical | Dangerous shell commands |
| SG-SHELL-002 | command_injection | high | Command injection patterns |
| SG-SHELL-003 | supply_chain | critical | Download-and-execute |
| SG-SHELL-004 | dynamic_execution | high | Dynamic code execution |
| SG-FS-001 | filesystem | high | Destructive filesystem ops |
| SG-FS-002 | filesystem | high | Sensitive file access |
| SG-PRIV-001 | privilege | high | Privilege escalation |
| SG-NET-001 | network | medium | Suspicious network requests |
| SG-NET-002 | exfiltration | critical | Data exfiltration patterns |
| SG-OBF-001 | obfuscation | high | Encoded/obfuscated payloads |
| SG-OBF-002 | obfuscation | medium | Hidden/zero-width content |
| SG-INST-001 | instruction | high | Prompt injection / override |
| SG-INST-002 | instruction | critical | Secret extraction via agent |
| SG-INST-003 | instruction | high | Concealment instructions |
| SG-INST-004 | instruction | high | Bypass security controls |
| SG-DEP-001 | dependency | medium | Risky installs |
| SG-DEP-002 | supply_chain | medium | Unexpected binaries |
| SG-AST-001 | dynamic_execution | high | Python AST dangerous calls |
| SG-XFILE-001 | supply_chain | high | Cross-file download + execute |
| SG-STRUCT-* | structure | varies | Spec / parsing issues |

List live rules with:

```bash
skillguard rules list
skillguard rules show SG-SECRET-001
```
