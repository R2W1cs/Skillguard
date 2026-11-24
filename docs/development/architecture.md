# Architecture

Canonical document: **[ARCHITECTURE.md](https://github.com/R2W1cs/Skillguard/blob/master/ARCHITECTURE.md)**

```text
CLI → ScanEngine → Discovery/Parser/Validator
                 → Analyzers → Rules (SG-*)
                 → Risk scoring + Quality evaluator
                 → Optional Docker sandbox (digest-pin strict)
                 → Compare / Baseline / Audit manifests
                 → Terminal / JSON / SARIF reporters
```

Core design constraints:

- No LLM in the core scanner path
- Offline-first defaults
- Explicit sandbox opt-in
- Findings never rewritten by baselines
