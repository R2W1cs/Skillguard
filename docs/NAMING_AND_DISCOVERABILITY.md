# Naming and discoverability audit

**Date checked:** 2026-11-24  
**This project:** https://github.com/R2W1cs/Skillguard (Python, Apache-2.0)

## Verified name collisions / near-collisions

| Project | URL | Notes |
|---------|-----|-------|
| Stella SkillGuard | https://github.com/stella/skillguard | Bun/TypeScript local-first Agent Skills scanner; same product name |
| RudrenduPaul SkillGuard | https://github.com/RudrenduPaul/skillguard | Listed in awesome-skills-security as “SkillGuard”; distinct repo |
| skill-guard | https://github.com/vaibhavtupe/skill-guard | Hyphenated; validate/secure/conflict gates for skills |
| Placeholder org URLs | `github.com/skillguard/skillguard` | Previously referenced in this repo’s metadata; not this project |

Search ambiguity is **high** for the bare string “SkillGuard” on GitHub and web search.

## Discoverability impact

- Users searching “SkillGuard” may land on another scanner with different language,
  threat model, and CLI.
- PyPI name `skillguard` may also collide or be unpublished (PyPI JSON for
  `/pypi/skillguard/json` returned **404** when checked on 2026-11-24).
- Descriptive subtitle helps: “offline-first security scanner for AI Agent Skills.”

## Recommendation (no automatic rename)

**Keep `SkillGuard` for now**, with mandatory disambiguation in README, docs, and
package description:

1. Always include the GitHub path `R2W1cs/Skillguard` in install docs.
2. Prefer “SkillGuard (R2W1cs)” or “SkillGuard — Agent Skills scanner” in listings.
3. Do **not** purchase a domain or rebrand until: (a) PyPI ownership is secured or
   a distinct package name is chosen, and (b) at least one external listing exists
   that uses the disambiguated form.
4. Revisit rename only if collisions cause repeated support confusion or trademark risk.

### Trade-offs

| Keep SkillGuard | Rename |
|-----------------|--------|
| Existing docs/CLI/`skillguard` command | Cleaner search, less confusion |
| Matches prior releases (0.1–0.3) | Breaks muscle memory / scripts |
| Still needs strong subtitle | Needs coordinated PyPI + docs migration |

**Decision for this phase:** keep name; fix URLs; document collisions; disambiguate in copy.
