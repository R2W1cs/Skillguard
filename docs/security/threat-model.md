# Threat model (docs site)

The canonical threat model lives in the repository root:

**[THREAT_MODEL.md](https://github.com/R2W1cs/Skillguard/blob/master/THREAT_MODEL.md)**

## Summary

SkillGuard assumes skills are **untrusted**. Primary threats include prompt injection
via instructions, malicious or risky scripts, secret harvesting, exfiltration,
obfuscation, and supply-chain compromise through dependencies or mutable references.

SkillGuard itself must not execute untrusted skill code on the host during static
analysis, must redact secret-like evidence in reports, and must keep sandbox use
explicit and constrained.

For sandbox isolation assumptions and residual risk, see [sandbox.md](../sandbox.md).
