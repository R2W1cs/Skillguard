"""Agent Skills specification validation."""

from __future__ import annotations

import re

from skillguard.models.finding import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from skillguard.models.skill import Skill

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def validate_skill(skill: Skill) -> list[Finding]:
    """Validate metadata against the Agent Skills specification.

    Returns structure findings (not necessarily security issues).
    """
    findings: list[Finding] = []
    meta = skill.metadata
    path = "SKILL.md"

    for err in meta.parse_errors:
        findings.append(
            Finding(
                rule_id="SG-STRUCT-001",
                title="Malformed SKILL.md frontmatter",
                description=err,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.STRUCTURE,
                file_path=path,
                line=1,
                evidence=Evidence(snippet=err[:200], line_start=1),
                remediation="Fix YAML frontmatter so it is a valid mapping with required fields.",
                tags=["spec", "frontmatter"],
            )
        )

    if not meta.name:
        findings.append(
            Finding(
                rule_id="SG-STRUCT-002",
                title="Missing required frontmatter field: name",
                description="Agent Skills require a 'name' field in SKILL.md frontmatter.",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.STRUCTURE,
                file_path=path,
                remediation="Add a valid 'name' field (lowercase, digits, hyphens).",
                tags=["spec"],
            )
        )
    else:
        if len(meta.name) > 64:
            findings.append(
                _struct(
                    "SG-STRUCT-003",
                    "Skill name exceeds 64 characters",
                    Severity.MEDIUM,
                    path,
                )
            )
        if not NAME_RE.fullmatch(meta.name):
            findings.append(
                Finding(
                    rule_id="SG-STRUCT-004",
                    title="Invalid skill name format",
                    description=(
                        "Name must be lowercase alphanumeric with single hyphens, "
                        "not starting/ending with a hyphen."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category=Category.STRUCTURE,
                    file_path=path,
                    evidence=Evidence(snippet=f"name: {meta.name}"),
                    remediation="Rename to match Agent Skills name constraints.",
                    tags=["spec"],
                )
            )
        if meta.name != skill.root.name:
            findings.append(
                Finding(
                    rule_id="SG-STRUCT-005",
                    title="Skill name does not match directory name",
                    description=(
                        f"Frontmatter name '{meta.name}' should match parent directory "
                        f"'{skill.root.name}'."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    category=Category.STRUCTURE,
                    file_path=path,
                    remediation="Rename the directory or update the name field to match.",
                    tags=["spec"],
                )
            )

    if not meta.description:
        findings.append(
            Finding(
                rule_id="SG-STRUCT-006",
                title="Missing required frontmatter field: description",
                description="Agent Skills require a non-empty 'description' field.",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.STRUCTURE,
                file_path=path,
                remediation="Add a description (1–1024 chars) covering what and when.",
                tags=["spec"],
            )
        )
    elif len(meta.description) > 1024:
        findings.append(
            _struct(
                "SG-STRUCT-007",
                "Description exceeds 1024 characters",
                Severity.MEDIUM,
                path,
            )
        )

    if meta.compatibility and len(meta.compatibility) > 500:
        findings.append(
            _struct(
                "SG-STRUCT-008",
                "Compatibility field exceeds 500 characters",
                Severity.LOW,
                path,
            )
        )

    for sf in skill.files:
        if sf.truncated:
            findings.append(
                Finding(
                    rule_id="SG-STRUCT-009",
                    title="File exceeds size limit and was truncated",
                    description=(
                        f"{sf.relative_path} exceeded the configured max file size; "
                        "analysis may be incomplete."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    category=Category.STRUCTURE,
                    file_path=sf.relative_path,
                    remediation="Split large files or raise max_file_size_bytes deliberately.",
                    tags=["limits"],
                )
            )
        if sf.is_symlink and sf.content is None and sf.binary:
            findings.append(
                Finding(
                    rule_id="SG-STRUCT-010",
                    title="Symlink outside skill root or unreadable",
                    description=(
                        f"Symlink {sf.relative_path} -> {sf.symlink_target} was not followed "
                        "because it escapes the skill root or could not be read."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category=Category.STRUCTURE,
                    file_path=sf.relative_path,
                    remediation="Remove outbound symlinks from published skills.",
                    tags=["symlink"],
                )
            )

    return findings


def _struct(rule_id: str, title: str, severity: Severity, path: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=title,
        severity=severity,
        confidence=Confidence.HIGH,
        category=Category.STRUCTURE,
        file_path=path,
        remediation="Correct the SKILL.md metadata to match the Agent Skills specification.",
        tags=["spec"],
    )
