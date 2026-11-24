# Visibility & Credibility Audit Findings (verified)

**Date checked:** 2026-11-24  
**Repo:** https://github.com/R2W1cs/Skillguard  
**Commit inspected:** `ffaccfa` (master)

This document lists problems verified by reading the repository before edits. It is not a marketing brief.

## Verified problems

1. **Incorrect package URLs** — `pyproject.toml` and SARIF `informationUri` point to `https://github.com/skillguard/skillguard` (nonexistent org for this project). Real home is `https://github.com/R2W1cs/Skillguard`.
2. **Reusable workflow comment** — `.github/workflows/skillguard-scan.yml` documents `uses: skillguard/skillguard/...`.
3. **No documentation site** — Markdown docs exist under `docs/` but there is no MkDocs/Sphinx site, no Pages workflow, no docs CI build.
4. **GitHub presentation incomplete** — No `docs/GITHUB_SETUP.md` with description/topics; no social preview asset; repository About metadata not verified as set.
5. **Benchmark messaging drift** — README still labels adversarial results as “SkillGuard 0.2.0” while package is 0.3.0; methodology lacks a single end-to-end reproduce command with environment capture and independent-validation instructions.
6. **Release assets incomplete for a public 0.3.0** — No `RELEASE_NOTES_v0.3.0.md`, no release checklist, no checksum artifacts, no verification script; no Git tag verified on remote.
7. **External adoption prep missing** — No `EXTERNAL_SUBMISSIONS.md`, no security-review request pack, no naming-collision analysis despite clear GitHub name collisions (e.g. `stella/skillguard`, `vaibhavtupe/skill-guard`).
8. **`pip install skillguard` may be aspirational** — README leads with PyPI install; package may not be published to PyPI yet (not verified as published). Source install remains the reliable path until publication is confirmed.

## Verified strengths (preserve)

- Working CLI (`scan`, `compare`, `baseline`, `audit`, `benchmark`, `rules`)
- Tests, coverage gate (≥85%), ruff, mypy, CI workflows
- Honest limitation language in README / SECURITY docs
- Competitive analysis already avoids superiority claims
- Pre-commit example + reusable GHA workflow already present
- Adversarial corpus + separate real-world evaluation already exist

## Out of scope for this phase

- Rebuilding scanners or adding detection rules for vanity
- Fabricating adoption metrics
- Auto-submitting to awesome lists
- Renaming the repository without explicit human decision
