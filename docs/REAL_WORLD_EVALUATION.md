# Real-World Evaluation

## Scope

Sample of **8** public skills from [`anthropics/skills`](https://github.com/anthropics/skills)
(Apache-2.0), collected **2026-03-24** via git sparse checkout.

Exact commit and file lists: `benchmarks/real_world/anthropics-skills/COLLECTION.json`  
Full scan dump: `benchmarks/real_world/EVALUATION.json`

**Third-party scripts were not executed.**

## Methodology

1. Sparse-clone selected skill directories.
2. Run SkillGuard static scan (`include_quality=True`, no sandbox).
3. Record risk score, findings, files inspected.
4. Triage findings as signals — **do not** auto-label official skills as malicious.

## Results summary (measured)

| Skill | Findings | Overall risk | Notes |
|-------|----------|--------------|-------|
| brand-guidelines | 0 | informational | Clean on static heuristics |
| frontend-design | 0 | informational | Clean |
| doc-coauthoring | 0 | informational | Clean |
| internal-comms | 0 | informational | Clean |
| theme-factory | 1 | low | `SG-DEP-002` binary/asset heuristic — needs review |
| webapp-testing | 2 | medium | `SG-SHELL-002` / `SG-AST-001` — likely codegen/test FP |
| skill-creator | 9 | critical | Heavy `eval`/`exec` patterns in creator tooling — **likely FPs** in context |
| mcp-builder | 27 | critical | Same class: generator/tooling patterns + env/network heuristics — **needs review, not malice** |

4 / 8 skills produced zero findings. Skills with many findings are predominantly
**code-generation / tooling** skills where `eval`/`exec` appear in templates or
examples — SkillGuard correctly matches patterns but human triage is required.

## Attribution

Copyright and license remain with Anthropic / contributors under Apache-2.0.
This evaluation redistributes only the sampled skill trees for reproducible
offline scanning.

## Limitations

- Small sample; not representative of the entire ecosystem.
- API rate limits initially blocked blob API fetching; git sparse succeeded.
- Findings ≠ malicious classification.
- No dynamic sandbox runs against these skills in this evaluation pass.
