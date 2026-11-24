# Competitive Analysis (verified from public docs, 2026-03-24)

Sources inspected via public GitHub READMEs and documentation (not proprietary code):

| Project | Source |
|---------|--------|
| NVIDIA SkillSpector | https://github.com/NVIDIA/SkillSpector |
| Cisco AI Defense Skill Scanner | https://github.com/cisco-ai-defense/skill-scanner |
| Snyk Agent Scan | https://github.com/snyk/agent-scan |

Claims below are limited to what public docs state. Features not documented are marked unknown.

---

## NVIDIA SkillSpector

**Positioning:** Broad security scanner for agent skills (Claude Code, Codex, MCP) with a LangGraph pipeline.

**Verified strengths:**
- Multi-input: Git URL, zip, directory, single file
- Large pattern surface (docs cite many categories / analyzers)
- Static + optional LLM semantic stage; deterministic findings retained when LLM disagrees
- SARIF / JSON / Markdown / terminal
- Risk score 0–100
- Baseline / false-positive suppression (glob or fingerprint)
- Optional OSV.dev dependency lookups with offline fallback
- States it does not execute scanned skill code

**Limitations / tradeoffs (from docs):**
- LLM stage adds cost, non-determinism, and model dependency
- LangGraph-centric architecture is powerful but heavier for “pip install and scan offline”
- Baseline exists; **report-to-report regression compare** is not a first-class documented CLI workflow
- Image/sandbox digest-pinning for dynamic analysis is not a highlighted trust feature

---

## Cisco AI Defense Skill Scanner

**Positioning:** Best-effort skill package scanner with YAML/YARA, AST/dataflow, optional LLM/meta, optional VirusTotal / Cisco cloud.

**Verified strengths:**
- Rich analyzer matrix (static, bytecode, pipeline taint, behavioral, LLM, meta)
- Policy presets (`strict` / `balanced` / `permissive`) and custom policy YAML
- SARIF, JSON, Markdown, HTML, table
- Pre-commit hook and API server
- Cross-skill overlap checks
- Published eval numbers on MaliciousSkillBench (honest about rules-alone recall)

**Limitations / tradeoffs:**
- Optional cloud / VirusTotal / LLM reduce offline purity
- Complexity of policy + multi-engine setup is higher for individual developers
- Explicit “no findings ≠ safe” messaging (good honesty)
- Reproducible **audit manifests** (file hashes + config/rule-set hashes + signing guidance) are not the primary product story

---

## Snyk Agent Scan

**Positioning:** Discovers local agents, MCP servers, and skills; analyzes via local checks + **Agent Scan API**.

**Verified strengths:**
- Broader than skills-only: MCP tool risks, agent configs, enterprise/MDM background mode
- Named risk indicators with scores
- CI mode (`--ci`), JSON output, risk ignore list
- Redacts secrets before transmission (v0.6+)

**Limitations / tradeoffs:**
- **Not offline-first**: analysis depends on Snyk API / terms of use
- Skills are one facet among MCP/agent inventory
- Less suited as a pure “scan this skill directory with fully local, reproducible artifacts” tool
- Custom cryptographic audit manifests / digest-pinned sandboxes are out of scope relative to SkillGuard’s trust angle

---

## Where SkillGuard can offer genuine value (gaps)

| Gap | SkillGuard 0.3.0 response |
|-----|---------------------------|
| Report-to-report security regression | `skillguard compare` with stable fingerprints, risk deltas, new files/scripts |
| Suppressions that don’t fake cleanliness | Baselines that **annotate** suppressions; critical findings cannot be silently dropped |
| Reproducible audit evidence | Audit manifests: file SHA-256, rule-set/config hashes, env, limitations |
| Offline-by-default trust | Core scan never requires LLM or cloud APIs |
| Sandbox image provenance | Strict mode requires digest-pinned images; fail-closed on mismatch |
| Honest evaluation culture | Separate synthetic vs real-world metrics; competitive comparison framework without unfounded superiority claims |
| Developer-first CI | Pre-commit + Actions focused on regression gates, not only “scan once” |

## What SkillGuard should *not* chase

- Matching Cisco/NVIDIA analyzer count or YARA pack size as a vanity metric
- Making LLM judging mandatory
- Claiming more detections without measured evidence
- Inventing a custom signature cryptosystem

## Contribution opportunities (ecosystem)

- Shared inert adversarial corpora and label schemas
- SARIF property conventions for skill-specific metadata
- Common fingerprint formats so baselines can interoperate
- Independent bake-offs using identical fixtures where formats allow
