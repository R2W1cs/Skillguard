"""Risk scoring unit tests."""

from __future__ import annotations

from skillguard.evaluation.scoring import assess_risk, dedupe_findings
from skillguard.models.finding import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from skillguard.models.report import RiskLevel


def _f(
    rule: str,
    sev: Severity,
    conf: Confidence = Confidence.HIGH,
    path: str = "a.py",
    line: int = 1,
) -> Finding:
    return Finding(
        rule_id=rule,
        title="t",
        description="d",
        severity=sev,
        confidence=conf,
        category=Category.OTHER,
        file_path=path,
        line=line,
        evidence=Evidence(snippet="x", line_start=line),
        remediation="fix",
    )


def test_empty_findings_informational() -> None:
    risk = assess_risk([])
    assert risk.level == RiskLevel.INFORMATIONAL
    assert risk.score == 0
    assert "does not prove" in risk.explanation.lower()


def test_critical_elevates() -> None:
    risk = assess_risk([_f("SG-X", Severity.CRITICAL)])
    assert risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert risk.score >= 40


def test_dedupe() -> None:
    a = _f("SG-X", Severity.HIGH)
    b = _f("SG-X", Severity.HIGH)
    assert len(dedupe_findings([a, b])) == 1


def test_low_confidence_reduces_score() -> None:
    high = assess_risk([_f("SG-X", Severity.HIGH, Confidence.HIGH)])
    low = assess_risk([_f("SG-X", Severity.HIGH, Confidence.LOW)])
    assert high.score > low.score
