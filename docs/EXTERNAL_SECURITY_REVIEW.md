# External security review preparation

**Project:** SkillGuard (https://github.com/R2W1cs/Skillguard)  
**Version in scope (current):** 0.3.0  
**License:** Apache-2.0  

This document prepares an independent review. It does **not** claim a review was completed.

## Project purpose

SkillGuard is an offline-first static security scanner for AI Agent Skills
(`SKILL.md` + bundled scripts/references). Optional Docker sandbox analysis is
explicitly opt-in.

## Suggested review scope

| In scope | Out of scope (unless agreed) |
|----------|------------------------------|
| Discovery/parser path safety | Full formal verification |
| Rule false positives/negatives | Guaranteeing zero misses |
| Redaction effectiveness | Cloud/LLM competitor engines |
| Baseline/compare correctness | Trademark/legal naming disputes |
| Sandbox policy / isolation assumptions | Host Docker daemon hardening |
| CI/integration secret leakage | PyPI publishing operations |

## Threat model & architecture pointers

- [THREAT_MODEL.md](https://github.com/R2W1cs/Skillguard/blob/master/THREAT_MODEL.md)
- [docs/SECURITY_MODEL.md](SECURITY_MODEL.md)
- [ARCHITECTURE.md](https://github.com/R2W1cs/Skillguard/blob/master/ARCHITECTURE.md)
- [docs/sandbox.md](sandbox.md)
- [docs/DETECTION_LIMITATIONS.md](DETECTION_LIMITATIONS.md)
- [docs/BENCHMARK_METHODOLOGY.md](BENCHMARK_METHODOLOGY.md)

## Known limitations (start here)

- Static pattern/AST analysis misses novel semantic attacks
- Synthetic corpus scores are maintainer-run and not security proofs
- Sandbox is not escape-proof; mutable tags rejected only in strict mode
- Baselines can reduce CI noise but must not be mistaken for “clean”
- Name collisions exist with other “SkillGuard” projects

## Reproduction

```bash
git clone https://github.com/R2W1cs/Skillguard.git
cd Skillguard
pip install -e ".[dev]"
pytest -q
skillguard scan tests/fixtures/malicious/secret-exfil --format json -o /tmp/sg.json
skillguard benchmark run --dataset adversarial --json-out /tmp/adv.json
```

## Areas reviewers should challenge

1. Detection bypasses (encoding, indirection, multi-file staging)
2. False positives on educational / documented dangerous examples
3. False negatives on `static_detectable=false` and unlabeled novel cases
4. Parser / frontmatter edge cases and path containment
5. Cross-file analysis gaps
6. Prompt-injection blind spots in references/assets
7. Sandbox isolation assumptions (mounts, image trust, observer script)
8. Unsafe handling of scanned files (zip bombs, huge trees, symlink tricks)
9. Report redaction gaps (secrets surviving into JSON/SARIF/logs)
10. Compare/baseline fingerprint stability under benign refactors

## Deliverable request from reviewer

- Written findings with severity and reproduction
- Distinction between SkillGuard product bugs vs. inherent static-analysis limits
- Permission to cite the review (or keep private) — reviewer choice

Outreach draft: [REVIEW_REQUEST.md](REVIEW_REQUEST.md)
