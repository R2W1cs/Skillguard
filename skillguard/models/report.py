"""Scan report models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from skillguard.models.finding import Finding, Severity


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class QualityScore(BaseModel):
    """Non-security quality evaluation (independent of risk)."""

    score: float = Field(ge=0.0, le=100.0)
    metadata_completeness: float = Field(ge=0.0, le=100.0)
    documentation_quality: float = Field(ge=0.0, le=100.0)
    instruction_clarity: float = Field(ge=0.0, le=100.0)
    script_organization: float = Field(ge=0.0, le=100.0)
    notes: list[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    level: RiskLevel
    score: float = Field(ge=0.0, le=100.0)
    explanation: str
    finding_counts: dict[str, int] = Field(default_factory=dict)
    caveats: list[str] = Field(
        default_factory=lambda: [
            "A low score does not prove a skill is safe.",
            "Static analysis cannot detect all semantic attacks.",
        ]
    )


class SkillReport(BaseModel):
    skill_name: str
    skill_path: str
    findings: list[Finding] = Field(default_factory=list)
    risk: RiskAssessment
    quality: QualityScore | None = None
    files_inspected: list[str] = Field(default_factory=list)
    checks_performed: list[str] = Field(default_factory=list)
    exclusions_applied: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    sandbox: dict[str, Any] | None = None


class ScanReport(BaseModel):
    scanner_version: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: str
    skills: list[SkillReport] = Field(default_factory=list)
    overall_risk: RiskLevel = RiskLevel.INFORMATIONAL
    overall_score: float = 0.0
    analysis_limitations: list[str] = Field(
        default_factory=lambda: [
            "Core scanning is static and pattern-based; optional AI analysis is not required.",
            "Dynamic analysis runs only with explicit --sandbox opt-in and Docker.",
            "False positives and false negatives are expected; review findings in context.",
        ]
    )

    @property
    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for s in self.skills:
            out.extend(s.findings)
        return out

    def max_severity(self) -> Severity | None:
        order = {
            Severity.INFORMATIONAL: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        findings = self.all_findings
        if not findings:
            return None
        return max(findings, key=lambda f: order[f.severity]).severity
