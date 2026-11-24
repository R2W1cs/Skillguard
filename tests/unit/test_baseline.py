"""Baseline / suppression annotation tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from skillguard import __version__
from skillguard.baseline import (
    Baseline,
    accept_finding,
    annotate_report,
    max_active_severity,
    save_baseline,
)
from skillguard.models.finding import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from skillguard.models.report import RiskAssessment, RiskLevel, ScanReport, SkillReport


def _finding(sev: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id="SG-TEST-001",
        title="Test finding",
        description="d",
        severity=sev,
        confidence=Confidence.HIGH,
        category=Category.OTHER,
        file_path="scripts/x.py",
        evidence=Evidence(snippet="dangerous()"),
        remediation="fix it",
    ).with_fingerprint()


def _report(findings: list[Finding]) -> ScanReport:
    return ScanReport(
        scanner_version=__version__,
        target=".",
        skills=[
            SkillReport(
                skill_name="demo",
                skill_path=".",
                findings=findings,
                risk=RiskAssessment(
                    level=RiskLevel.HIGH,
                    score=70.0,
                    explanation="t",
                ),
                files_inspected=["scripts/x.py"],
            )
        ],
    )


def test_accept_requires_justification() -> None:
    bl = Baseline()
    with pytest.raises(ValueError, match="Justification"):
        accept_finding(bl, _finding(), justification="  ")


def test_blocks_critical_by_default() -> None:
    bl = Baseline()
    with pytest.raises(ValueError, match="critical"):
        accept_finding(bl, _finding(Severity.CRITICAL), justification="nope")


def test_annotate_does_not_remove_findings(tmp_path: Path) -> None:
    f = _finding()
    bl = Baseline()
    accept_finding(bl, f, justification="tracked in ticket")
    save_baseline(bl, tmp_path / "b.json")
    report = _report([f])
    annotated, suppression = annotate_report(report, bl)
    assert len(annotated.skills[0].findings) == 1
    assert len(suppression.suppressed) == 1
    assert len(suppression.active) == 0
    assert max_active_severity(annotated, suppression) is None


def test_expired_suppression_reactivates() -> None:
    f = _finding()
    bl = Baseline()
    entry = accept_finding(bl, f, justification="temp", expires_days=1)
    entry.expires_at = datetime.now(UTC) - timedelta(days=1)
    bl.entries = [entry]
    report = _report([f])
    _, suppression = annotate_report(report, bl)
    assert suppression.expired
    assert suppression.active
    assert not suppression.suppressed
