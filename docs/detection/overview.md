# Detection overview

SkillGuard’s core engine is **deterministic and offline**. It does not require an LLM
or cloud API for scanning.

## Pipeline

1. Discover skill roots (`SKILL.md`) under a path
2. Parse frontmatter and inventory files (size/count bounded)
3. Validate structure against the Agent Skills specification
4. Run analyzers → modular rules (`SG-*`)
5. Score risk (separate from documentation quality)
6. Optionally annotate baselines / emit audit manifests
7. Optionally run Docker sandbox checks (`--sandbox`)

## Categories

Secrets · Credentials · Shell · Command injection · Filesystem · Network ·
Exfiltration · Obfuscation · Dynamic execution · Dependencies · Instruction /
prompt injection · Privilege · AST (Python) · Cross-file · Structure

Full table: [detection-rules.md](../detection-rules.md)  
Per-rule limits: [DETECTION_LIMITATIONS.md](../DETECTION_LIMITATIONS.md)

## Honesty

Absence of findings means “no matching rule fired under this configuration,”
not “safe to install.”
