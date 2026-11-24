# Third-Party Comparison Framework

SkillGuard ships a **reproducible evaluation harness** (`skillguard benchmark compare-tools`)
that compares SkillGuard against publicly documented open-source peers when they are
installed — and records honest SKIPPED status when they are not.

## Peers considered

| Tool | Repository | Offline? |
|------|------------|----------|
| NVIDIA SkillSpector | https://github.com/NVIDIA/SkillSpector | Partial (LLM optional) |
| Cisco skill-scanner | https://github.com/cisco-ai-defense/skill-scanner | Partial (cloud/VT optional) |
| Snyk agent-scan | https://github.com/snyk/agent-scan | Typically API-dependent |

See also [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md).

## What is measured

When a tool can be run on identical SkillGuard adversarial fixtures:

- Detection differences (TP / FP / FN / TN under SkillGuard’s label schema)
- Runtime
- Installation complexity
- Offline capability
- Output quality notes

## Integrity rules

1. **Do not claim superiority without evidence** from matching inputs.
2. **Do not misrepresent competitors** — document capabilities from public docs only.
3. Peers without a verified CLI adapter are marked available-or-skipped; detection metrics
   are **not invented**.
4. LLM/cloud scanners are non-deterministic; scores are not 1:1 comparable to offline tools.

## Usage

```bash
skillguard benchmark compare-tools --fixtures tests/fixtures --json-out benchmarks/comparison.json
skillguard benchmark compare-tools --limit 10  # smoke
```

Install peers locally per their READMEs, then re-run. Extend
`skillguard/evaluation/comparison.py` with verified adapters only after confirming
CLI contracts against upstream documentation.
