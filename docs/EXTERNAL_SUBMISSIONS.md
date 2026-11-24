# External directory submissions (prepared, not submitted)

**Prepared:** 2026-11-24  
**Status:** Materials only — **no PRs opened** from this phase unless a human explicitly submits.

Do not spam. Do not claim a listing is merged.

## Candidate directories

### 1. basitalisandhu/awesome-agent-security — **SUITABLE**

| Field | Detail |
|-------|--------|
| URL | https://github.com/basitalisandhu/awesome-agent-security |
| Checked | 2026-11-24 (README + contributing criteria) |
| Active | Yes (public curated list; scanners section present) |
| Relevant section | **Scanners for MCP servers and skills** |
| Rules | Entry must be public, maintained, documented; description in project’s own words; run link check before PR (`contributing.md`) |
| Fits? | Yes — SkillGuard is an offline Agent Skills security scanner |

**Proposed entry (PR-ready):**

```markdown
- [SkillGuard](https://github.com/R2W1cs/Skillguard) - Open-source, offline-first security scanner for AI Agent Skills that detects prompt injection, credential exposure, malicious scripts, and supply-chain risks (static analysis; optional Docker sandbox).
```

**Submission method:** Fork → edit README under “Scanners for MCP servers and skills” → open PR.  
**Restrictions:** No unverified “best/only” claims; keep description factual.

Prepared file: [`docs/submissions/awesome-agent-security.md`](submissions/awesome-agent-security.md)

---

### 2. iFurySt/awesome-skills-security — **SUITABLE (with disambiguation)**

| Field | Detail |
|-------|--------|
| URL | https://github.com/iFurySt/awesome-skills-security |
| Checked | 2026-11-24 |
| Active | Yes (last reviewed note in README: 2026-08-23; repo updated 2026-09-22) |
| Relevant section | **Skill Security Scanners** |
| Rules | Public source + license; document analysis/execution/network behavior; threat model/limitations; factual description; CONTRIBUTING.md |
| Fits? | Yes |
| Caution | README already lists a different **SkillGuard** at `RudrenduPaul/skillguard`. Use owner path in the title/link text. |

**Proposed entry (PR-ready):**

```markdown
- [SkillGuard (R2W1cs)](https://github.com/R2W1cs/Skillguard) - Offline-first Python scanner for Agent Skills with deterministic rules, SARIF/JSON output, regression compare, baselines, and optional digest-pinned Docker sandbox. `Apache-2.0`.
```

**Submission method:** PR per CONTRIBUTING.md.  
Prepared file: [`docs/submissions/awesome-skills-security.md`](submissions/awesome-skills-security.md)

---

### 3. scadastrangelove/awesome-ai-security-tools — **NOT VERIFIED / DO NOT SUBMIT YET**

| Field | Detail |
|-------|--------|
| URL | https://github.com/scadastrangelove/awesome-ai-security-tools |
| Checked | 2026-11-24 |
| Status | Could not confirm contribution rules and relevance with confidence in this pass |
| Action | Human should re-check existence, license, and contributing guide before any PR |

---

### 4. thirtysix/awesome-agent-skills — **LIKELY NOT A SCANNER DIRECTORY**

| Field | Detail |
|-------|--------|
| URL | https://github.com/thirtysix/awesome-agent-skills |
| Checked | 2026-11-24 |
| Description | Security-first **catalog of agent skills** + offline scanner results for many skills |
| Fits as a “tool listing”? | Unclear — primary content is skills, not scanners |
| Action | Do **not** submit SkillGuard as a skill. Only submit if the project adds an explicit “scanners/tools” contribution path |

---

## General submission checklist

1. Confirm Apache-2.0 LICENSE is present
2. Confirm README honest-scope language
3. Use disambiguated name when collisions exist
4. Link to https://github.com/R2W1cs/Skillguard
5. Do not claim independent audits or superiority
