"""Non-security quality evaluation."""

from __future__ import annotations

from skillguard.models.report import QualityScore
from skillguard.models.skill import FileKind, Skill


def evaluate_quality(skill: Skill) -> QualityScore:
    """Score documentation/structure quality independently of security risk."""
    notes: list[str] = []
    meta = skill.metadata

    # Metadata completeness
    meta_points = 0.0
    if meta.name:
        meta_points += 25
    else:
        notes.append("Missing name")
    if meta.description:
        meta_points += 25
        if len(meta.description) >= 40:
            meta_points += 15
        if "use when" in meta.description.lower() or "when " in meta.description.lower():
            meta_points += 10
        else:
            notes.append("Description could clarify when to use the skill")
    else:
        notes.append("Missing description")
    if meta.license:
        meta_points += 15
    else:
        notes.append("No license field")
    if meta.compatibility or meta.metadata:
        meta_points += 10
    meta_score = min(100.0, meta_points)

    # Documentation quality
    body = skill.body.strip()
    doc_score = 0.0
    if len(body) >= 100:
        doc_score += 40
    elif len(body) >= 20:
        doc_score += 20
        notes.append("SKILL.md body is quite short")
    else:
        notes.append("SKILL.md body missing or empty")
    headings = sum(1 for line in body.splitlines() if line.startswith("#"))
    if headings >= 2:
        doc_score += 25
    elif headings == 1:
        doc_score += 10
    if any(x in body.lower() for x in ("example", "usage", "when to use")):
        doc_score += 20
    refs = [f for f in skill.files if f.kind == FileKind.REFERENCE]
    if refs:
        doc_score += 15
    doc_score = min(100.0, doc_score)

    # Instruction clarity
    clarity = 50.0
    if headings >= 2:
        clarity += 20
    if "```" in body:
        clarity += 15
    if len(body.split()) >= 80:
        clarity += 15
    clarity = min(100.0, clarity)

    # Script organization
    scripts = skill.scripts
    script_score = 70.0
    if scripts:
        under_scripts = all(
            f.relative_path.replace("\\", "/").startswith("scripts/") for f in scripts
        )
        if under_scripts:
            script_score = 90.0
        else:
            script_score = 55.0
            notes.append("Scripts exist outside a scripts/ directory")
        # Missing dependency manifests when scripts present
        names = {f.relative_path.replace("\\", "/").lower() for f in skill.files}
        needs_py = any(f.relative_path.endswith(".py") for f in scripts)
        if needs_py and not any(
            n in names or n.endswith("requirements.txt") or n.endswith("pyproject.toml")
            for n in names
        ):
            script_score -= 15
            notes.append("Python scripts present without declared dependencies")
    else:
        script_score = 80.0  # docs-only skills are fine

    overall = round(
        0.3 * meta_score + 0.3 * doc_score + 0.2 * clarity + 0.2 * script_score,
        1,
    )
    notes.append("Quality scores are not security assessments.")

    return QualityScore(
        score=overall,
        metadata_completeness=meta_score,
        documentation_quality=doc_score,
        instruction_clarity=clarity,
        script_organization=script_score,
        notes=notes,
    )
