# Limitations

SkillGuard is a best-effort static analyzer (with optional sandbox checks).

It does **not**:

- Prove a skill is safe
- Detect every semantic prompt-injection variant
- Fully understand natural-language attacks without lexical cues
- Replace human review for high-trust environments
- Guarantee Docker isolation against container escapes

False positives and false negatives are expected. Educational documentation that
mentions dangerous commands is intentionally de-weighted or skipped when clear
anti-pattern context is present, but heuristics are imperfect.
