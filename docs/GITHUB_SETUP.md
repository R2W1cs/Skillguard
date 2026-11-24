# GitHub repository setup (manual + verified)

**Repository:** https://github.com/R2W1cs/Skillguard

## About section (recommended)

**Description:**

```text
Open-source, offline-first security scanner for AI Agent Skills. Detect prompt injection, credential exposure, malicious scripts, and supply-chain risks.
```

**Homepage:** `https://github.com/R2W1cs/Skillguard#readme`  
(or GitHub Pages URL once enabled: `https://r2w1cs.github.io/Skillguard/`)

**Topics (verified relevant to this codebase):**

- `ai-agents`
- `agent-skills`
- `cybersecurity`
- `security-scanner`
- `prompt-injection`
- `llm-security`
- `static-analysis`
- `python`
- `devsecops`
- `supply-chain-security`

### Automation note

During the visibility phase, `gh repo edit` was used to apply description, homepage, and
topics when credentials allowed. Re-check **Settings → General → About** if anything drifted.

## Social preview image

Asset in-repo (repository root, not the MkDocs tree):
`assets/skillguard-social-preview.png` on
[GitHub](https://github.com/R2W1cs/Skillguard/blob/master/assets/skillguard-social-preview.png)

Spec:

- Target size: **1200 × 630** (Open Graph)
- Dark navy background, cyan/blue accents
- Title: SkillGuard
- Tagline: Security scanning for AI Agent Skills
- No fake badges, customer logos, or certifications

### Upload steps (manual — requires repo admin UI)

1. Open https://github.com/R2W1cs/Skillguard/settings
2. Scroll to **Social preview**
3. Click **Edit** / upload `assets/skillguard-social-preview.png`
4. Confirm the preview on a test link share

GitHub does not expose a stable public API for social preview upload in all token scopes;
treat this as a **human** step even if About metadata was updated via CLI.

## GitHub Pages (documentation site)

Workflow: `.github/workflows/docs.yml` (builds MkDocs Material).

Enable:

1. **Settings → Pages**
2. Source: **GitHub Actions**
3. After the workflow runs on `master`, site URL should be
   `https://r2w1cs.github.io/Skillguard/`

Do not claim the site is live until Pages is enabled and the workflow succeeds on the
default branch.
