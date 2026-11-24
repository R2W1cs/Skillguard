# Competitive Analysis (neutral, documentation-based)

**Date checked:** 2026-11-24 (updated from earlier 2026-03-24 notes)  
**Method:** Public GitHub READMEs and docs only. No proprietary code review.  
**No superiority claim.** Unknown capabilities are marked **Not verified**.

| Project | Source | License (public) |
|---------|--------|------------------|
| SkillGuard (this project) | https://github.com/R2W1cs/Skillguard | Apache-2.0 |
| NVIDIA SkillSpector | https://github.com/NVIDIA/SkillSpector | Apache-2.0 (per upstream README) |
| Cisco AI Defense skill-scanner | https://github.com/cisco-ai-defense/skill-scanner | Apache-2.0 (per upstream README) |
| Snyk Agent Scan | https://github.com/snyk/agent-scan | Apache-2.0 (per upstream README) |

## Comparison matrix (verifiable dimensions)

| Dimension | SkillGuard (R2W1cs) | NVIDIA SkillSpector | Cisco skill-scanner | Snyk agent-scan |
|-----------|---------------------|---------------------|---------------------|-----------------|
| Supported inputs | Local skill dir / tree with `SKILL.md` | Docs: Git URL, zip, directory, file | Docs: skill packages / layouts | Docs: discovers agents, MCP, skills |
| Detection approach | Deterministic rules + analyzers | Rules + optional LLM semantic stage | YAML/YARA/AST/dataflow + optional LLM/cloud | Local checks + Agent Scan API |
| Static analysis | Yes | Yes | Yes | Yes (partially local) |
| AST analysis | Yes (Python `SG-AST-*`) | Docs mention AST / analyzers | Docs mention AST/dataflow | Not verified |
| Cross-file analysis | Yes (`SG-XFILE-*`) | Not verified | Docs mention cross-skill overlap | Not verified |
| Secret detection | Yes | Yes (docs) | Yes (docs) | Yes (docs; redacts before send) |
| Prompt-injection detection | Yes (instruction rules) | Yes (docs) | Yes (docs) | Yes (docs) |
| Sandbox / dynamic | Optional Docker; digest-pin strict mode | Docs: does not execute skill code as primary model | Optional VT/cloud/LLM; dynamic not claimed equivalent | Not verified as local sandbox |
| CLI usability | `skillguard` Click CLI | Documented CLI | Documented CLI / API server | Documented CLI (`--ci`) |
| CI integration | GHA reusable workflow + examples | Not verified in this pass | Pre-commit + API (docs) | CI mode (docs) |
| Output formats | Terminal, JSON, SARIF 2.1.0 | SARIF/JSON/Markdown/terminal (docs) | SARIF/JSON/Markdown/HTML/table (docs) | JSON (docs) |
| Benchmark transparency | Published synthetic + separate real-world; maintainer-run | Eval numbers on public benches (docs) | MaliciousSkillBench numbers (docs) | Not verified |
| Installation | `pip install -e .` from GitHub; PyPI not verified published | See upstream | See upstream | See upstream; API terms |
| Offline-first | Yes (core) | Partial (LLM optional; OSV optional) | Partial (cloud/VT/LLM optional) | Typically API-dependent |
| License | Apache-2.0 | Apache-2.0 (docs) | Apache-2.0 (docs) | Apache-2.0 (docs) |

## SkillGuard positioning (gaps, not “wins”)

Documented product gaps SkillGuard intentionally targets (without claiming uniqueness):

- Report-to-report **`skillguard compare`** regression
- Baselines that **annotate** rather than rewrite findings
- Reproducible **audit manifests** + signing guidance via established tools
- Digest-pinned sandbox **fail-closed** policy
- Offline-by-default core path

## What this analysis does *not* do

- No fabricated competitor benchmark scores
- No “best / fastest / most accurate” statements
- No assumption that undocumented features are absent — they are **Not verified**

For a harness that records peer availability without inventing metrics, see
[THIRD_PARTY_COMPARISON.md](THIRD_PARTY_COMPARISON.md) and
`skillguard benchmark compare-tools`.
