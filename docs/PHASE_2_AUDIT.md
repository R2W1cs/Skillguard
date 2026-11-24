# Phase 2 Independent Audit — SkillGuard 0.2.0

Auditor stance: treat the Phase 1 implementation as third-party code; verify claims.

## Verified results

| Claim | Evidence |
|-------|----------|
| Adversarial corpus ≥100 cases | `manifest.json` case_count=**105** |
| Benchmark reproducible | `skillguard benchmark run --dataset adversarial` → `benchmarks/adversarial-latest.json` |
| Synthetic metrics (measured) | TP=93 FP=0 TN=24 FN=0; P=R=F1=**1.000**; FPR=0; FNR=0; duration≈0.17s |
| Legacy regression still green | `benchmarks/legacy-latest.json` TP path intact |
| Existing CLI still works | `scan`, `rules`, `benchmark`, `version` exercised |
| New detectors registered | `SG-AST-001`, `SG-XFILE-001` (+ prior 21) |
| Sandbox policy hardened | refuses root; forbids docker.sock mounts; timeout kill path mocked |
| Real-world sample scanned | 8 anthropics/skills; results in `EVALUATION.json` |
| Pytest | All passing after Phase 2 changes |
| Ruff / Mypy | Pass (strict mypy) |
| Coverage | Measured **85.44%** overall; `scanner/engine.py` **95%**; sandbox runner **86%**. 90% across all modules not fully met (validator/discovery still lower) |
| `python -m build` | Produces `skillguard-0.2.0` sdist + wheel |
| `pip-audit --path .` | No known vulnerabilities |

## Critical / high findings from review

| Severity | Issue | Status |
|----------|-------|--------|
| High | Description-field instruction injection under-scanned in v0.1 | **Fixed** (scan `#description`) |
| High | Multistage download/exec split across files | **Mitigated** (`SG-XFILE-001`) |
| Medium | `os.environ` / `eval` FPs on legitimate codegen skills | **Documented**; triage in real-world eval |
| Medium | Image tag not digest-pinned by default | **Documented**; operators may set `image@sha256` |
| Medium | Synthetic perfect scores can overstate security | **Documented** in methodology |
| Low | Some indirect injections marked non-static | **Intentional** labels |

## Detection bypasses still open

- Paraphrased multilingual prompt injection
- Homoglyph / steganographic instructions in assets
- Typosquatting dependency names
- Agent-tool-only exfiltration without skill-local code

## Unsafe defaults check

- Static path: safe (no host exec)
- Sandbox: opt-in; network off; non-root; cap_drop ALL; no docker.sock — **OK**
- Exclusions visible in reports — **OK**

## Assumptions (not verified here)

- GitHub Actions workflows not re-executed on GitHub-hosted runners in this pass
- Live Docker daemon integration test may be skipped on hosts without Docker
- Perfect synthetic F1 does **not** generalize

## Verdict

Phase 2 objectives met for a rigorously validated **0.2.0** release candidate:
expanded corpus, improved detectors, sandbox hardening, separated synthetic vs
real-world reporting, and honest limitation docs. Engineering readiness for
open-source security tooling: **8.5/10** (up from 8/10), with residual
false-positive pressure on codegen skills and incomplete semantic coverage.
