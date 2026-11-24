# Visibility, Credibility & Release Engineering — Phase Report

**Branch:** `chore/visibility-and-credibility`  
**Date:** 2026-11-24  
**Base commit inspected:** `ffaccfa`  
**Repository:** https://github.com/R2W1cs/Skillguard

## 1. Problems found (verified)

See also [VISIBILITY_AUDIT_FINDINGS.md](VISIBILITY_AUDIT_FINDINGS.md).

1. Incorrect GitHub URLs in `pyproject.toml` and SARIF `informationUri` (`skillguard/skillguard`).
2. Reusable workflow comment referenced wrong org path.
3. No MkDocs documentation site / Pages workflow / docs CI gate.
4. GitHub About empty (description/topics/homepage unset before this phase).
5. No social preview asset or setup instructions.
6. Benchmark docs lacked explicit independent-validation steps and maintainer-run labeling.
7. README still framed adversarial results as “0.2.0” and led with unverified PyPI install.
8. Missing release notes, checklist, checksum workflow, verification script.
9. Missing external submission / security-review / naming-collision prep.
10. PyPI project `skillguard` returned **404** (not published under this name when checked).
11. Name collisions with other SkillGuard projects (stella, RudrenduPaul, skill-guard).

## 2. Changes made

- Fixed package metadata URLs; expanded classifiers/keywords; added `docs` optional extra.
- Fixed SARIF `informationUri` and workflow `uses:` comment to `R2W1cs/Skillguard`.
- Applied GitHub About description, homepage, and topics via `gh repo edit` (verified via API).
- Added social preview image + `docs/GITHUB_SETUP.md` (manual social-preview upload still required).
- Added MkDocs Material site (`mkdocs.yml`, structured docs pages) + `.github/workflows/docs.yml`.
- Strengthened benchmark methodology (datasets, TP/FP definitions, reproduce command, independent validation).
- Refreshed competitive analysis matrix with “Not verified” discipline (2026-11-24).
- Prepared `RELEASE_NOTES_v0.3.0.md`, release checklist, `scripts/prepare_release_assets.py`, `scripts/verify_release.py`, `release/SHA256SUMS-0.3.0.txt`.
- Improved install examples to prefer Git install until PyPI ownership is verified.
- Prepared external submissions, security review pack, naming audit.
- Added package URL tests and CI docs/metadata checks.

## 3. Files created or modified (high level)

**Created:** `mkdocs.yml`, `docs/index.md`, `docs/getting-started/*`, `docs/detection/overview.md`, `docs/security/*`, `docs/development/*`, `docs/integrations/*`, `docs/evaluation/adversarial-results.md`, `docs/faq.md`, `docs/GITHUB_SETUP.md`, `docs/NAMING_AND_DISCOVERABILITY.md`, `docs/EXTERNAL_SUBMISSIONS.md`, `docs/EXTERNAL_SECURITY_REVIEW.md`, `docs/REVIEW_REQUEST.md`, `docs/submissions/*`, `docs/VISIBILITY_AUDIT_FINDINGS.md`, `docs/VISIBILITY_PHASE_REPORT.md`, `assets/*`, `release/*`, `RELEASE_NOTES_v0.3.0.md`, `scripts/prepare_release_assets.py`, `scripts/verify_release.py`, `.github/workflows/docs.yml`, `tests/unit/test_package_urls.py`

**Modified:** `pyproject.toml`, `README.md`, `docs/BENCHMARK_METHODOLOGY.md`, `docs/COMPETITIVE_ANALYSIS.md`, `skillguard/reporting/sarif_report.py`, `.github/workflows/ci.yml`, `.github/workflows/skillguard-scan.yml`, `examples/*`, `.gitignore`

## 4. Tests executed

| Check | Result |
|-------|--------|
| `ruff check` / `ruff format` | Pass (after autofix) |
| `mypy skillguard` | Pass |
| `pytest --cov-fail-under=85` | Pass — coverage **85.07%** |
| `pip-audit --path .` | No known vulnerabilities |
| `mkdocs build --strict` | Pass |
| `python -m build` + PKG-INFO URL assert | Pass (`Version: 0.3.0`, `R2W1cs/Skillguard`) |
| Wheel reinstall + `skillguard version` | `0.3.0` |
| JSON scan smoke (benign fixture) | Pass |
| Adversarial benchmark reproduce | Run during phase (`skillguard benchmark run --dataset adversarial`) |
| Git tag `v0.3.0` | **Not present** (correct — do not create until release publish) |

## 5. Remaining limitations

- Docs Pages deploy needs human enablement; deploy step is `continue-on-error` until Pages works.
- Social preview still needs Settings UI upload.
- PyPI publish not done (package 404); install docs correctly prefer Git.
- Awesome-list PRs prepared but **not submitted**.
- No external security review completed or claimed.
- Synthetic perfect scores remain maintainer-run corpus agreement, not security proof.
- Name collision remains; rename deferred by design.

## 6. External actions requiring human approval

1. Upload social preview in GitHub Settings.
2. Enable GitHub Pages (Source: GitHub Actions).
3. Merge this branch; then create annotated tag `v0.3.0` + GitHub Release attaching `dist/*` and `release/SHA256SUMS-0.3.0.txt`.
4. Optionally open awesome-list PRs using `docs/submissions/*`.
5. Send `docs/REVIEW_REQUEST.md` to a reviewer of your choosing.
6. Decide PyPI publishing / package-name strategy given collisions.

## 7. Exact manual GitHub configuration steps

Documented in [GITHUB_SETUP.md](GITHUB_SETUP.md).

## 8. Suggested next steps

1. Open PR from `chore/visibility-and-credibility` → `master`.
2. After merge: publish GitHub Release 0.3.0 with prepared notes/assets.
3. Enable Pages; verify `https://r2w1cs.github.io/Skillguard/`.
4. Submit 1–2 carefully disambiguated awesome-list PRs.
5. Secure a distinct PyPI name or verified `skillguard` ownership before advertising `pip install skillguard`.

## Completion summary

| Item | Status |
|------|--------|
| Branch name | `chore/visibility-and-credibility` |
| Documentation builds | Yes (`mkdocs build --strict`) |
| Release assets prepared | Yes (`dist/skillguard-0.3.0.*`, `release/SHA256SUMS-0.3.0.txt`) |
| External submissions prepared | Yes (not submitted) |
| Tasks blocked on access | Social preview UI upload; Pages enablement; PyPI ownership; tag/release publish; awesome PRs |
