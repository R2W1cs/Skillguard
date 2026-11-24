# FAQ

## Does a clean scan mean a skill is safe?

**No.** It means no enabled rule fired under the current configuration. Semantic,
novel, or multi-stage attacks can be missed.

## Does SkillGuard execute skills?

Static analysis does **not** execute skill entrypoints on the host. Optional
`--sandbox` runs a fixed observer in Docker and still does not treat skill scripts
as trusted payloads.

## Is the synthetic F1 score a security proof?

**No.** Perfect scores on the labeled adversarial corpus mean labels and detectors
agree on that corpus. Real-world evaluation is reported separately and must not be
merged into one headline score.

## Is SkillGuard better than SkillSpector / skill-scanner / agent-scan?

SkillGuard does **not** claim superiority without a fair, reproducible bake-off.
See [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) and
[THIRD_PARTY_COMPARISON.md](THIRD_PARTY_COMPARISON.md).

## Why are there other projects named SkillGuard?

Name collisions exist on GitHub. See [NAMING_AND_DISCOVERABILITY.md](NAMING_AND_DISCOVERABILITY.md).
This project’s canonical home is https://github.com/R2W1cs/Skillguard.

## Can I suppress findings?

Yes, via baselines — with justification, optional expiry, and critical-suppression
controls. Findings remain in the report; suppressions are annotations only.
