# SkillGuard — Project Plan

## Mission

SkillGuard is a CLI-first, open-source static (and optional dynamic) security scanner for AI Agent Skills. It helps developers and platform maintainers inspect a skill before trusting or installing it.

## Spec Alignment

Skill discovery and validation follow the [Agent Skills specification](https://agentskills.io/specification):

- A skill is a directory containing `SKILL.md`.
- YAML frontmatter requires `name` and `description`.
- Optional fields: `license`, `compatibility`, `metadata`, `allowed-tools` (and Cursor extensions such as `paths`).

## Phases

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Architecture & threat model docs | Done |
| 2 | Packaging, models, discovery, parser | Done |
| 3 | Rule engine & analyzers | Done |
| 4 | Risk scoring & reporting | Done |
| 5 | CLI & configuration | Done |
| 6 | Benchmark corpus & metrics | Done |
| 7 | Optional Docker sandbox | Done |
| 8 | GitHub Actions | Done |
| 9 | Full test suite & hardening | Done |
| 10 | Docs & independent release audit | Done |

## Non-Goals (v1)

- Guaranteeing a skill is safe.
- Requiring paid AI APIs for core scanning.
- Executing untrusted skill code on the host.
- Detecting every semantic prompt-injection variant.

## Success Criteria

See Definition of Done in the master engineering prompt: working scanner, tested rules, real benchmarks, CI, docs, and an honest release audit.
