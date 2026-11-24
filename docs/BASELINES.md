# Audit Baselines

Baselines let developers **accept known findings** without pretending they are gone.

## Design rules

1. Suppressions are **annotations**. Scan findings are never deleted or rewritten because they are accepted.
2. CI fail-on can ignore actively suppressed findings while the JSON/SARIF report still lists them.
3. Critical findings cannot be suppressed unless `allow_critical_suppressions` is explicitly enabled.
4. Acceptances require a non-empty **justification** and optional expiry.
5. Expired, mismatched, or orphaned baseline entries are reported as invalid/expired — they do not silently hide issues.

## Workflow

```bash
# 1. Scan and keep a JSON report
skillguard scan ./my-skill --format json -o report.json

# 2. Create a baseline
skillguard baseline init -o .skillguard-baseline.json

# 3. Accept a finding by fingerprint (from report JSON)
skillguard baseline accept report.json \
  --baseline .skillguard-baseline.json \
  --fingerprint <fp> \
  --justification "Tracked in ISSUE-123; vendor false positive until upstream fix" \
  --expires-days 90

# 4. Scan with baseline (fail-on uses active findings only)
skillguard scan ./my-skill --baseline .skillguard-baseline.json --fail-on high
```

## Distinguishing suppressed vs clean

| Situation | Report findings | Suppression annotation | Meaning |
|-----------|-----------------|------------------------|---------|
| No findings | empty | empty | Clean (for this tool’s rules) |
| Findings + none suppressed | present | `active` | Real open findings |
| Findings + some suppressed | **still present** | `suppressed` + `active` | Known accepted risk, not “clean” |
| Expired acceptance | present | `expired` (+ active) | Must re-accept or fix |

Never treat “exit 0 with baseline” as equivalent to “no findings.”
