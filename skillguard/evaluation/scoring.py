"""Explainable risk scoring."""

from __future__ import annotations

from skillguard.models.finding import SEVERITY_ORDER, Confidence, Finding, Severity
from skillguard.models.report import RiskAssessment, RiskLevel

_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 25.0,
    Severity.MEDIUM: 12.0,
    Severity.LOW: 5.0,
    Severity.INFORMATIONAL: 1.0,
}

_CONFIDENCE_FACTOR = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.7,
    Confidence.LOW: 0.4,
}

_RISK_LEVELS = [
    (75.0, RiskLevel.CRITICAL),
    (50.0, RiskLevel.HIGH),
    (25.0, RiskLevel.MEDIUM),
    (5.0, RiskLevel.LOW),
    (0.0, RiskLevel.INFORMATIONAL),
]


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        key = f"{f.rule_id}|{f.file_path}|{f.line}|{f.evidence.snippet if f.evidence else ''}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def assess_risk(findings: list[Finding]) -> RiskAssessment:
    """Derive an explainable risk score from findings (not mere finding count)."""
    unique = dedupe_findings(findings)
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    score = 0.0
    drivers: list[str] = []
    rule_hit_counts: dict[str, int] = {}

    ordered = sorted(
        unique,
        key=lambda f: (SEVERITY_ORDER[f.severity], _CONFIDENCE_FACTOR[f.confidence]),
        reverse=True,
    )

    for f in ordered:
        counts[f.severity.value] += 1
        rule_hit_counts[f.rule_id] = rule_hit_counts.get(f.rule_id, 0) + 1
        contribution = _SEVERITY_WEIGHT[f.severity] * _CONFIDENCE_FACTOR[f.confidence]
        hits = rule_hit_counts[f.rule_id]
        if hits > 3:
            contribution *= 0.35
        elif hits > 1:
            contribution *= 0.6
        score += contribution
        if len(drivers) < 5 and f.severity in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
        ):
            drivers.append(
                f"{f.rule_id} ({f.severity.value}/{f.confidence.value}) in {f.file_path}"
            )

    score = min(100.0, round(score, 1))
    level = RiskLevel.INFORMATIONAL
    for threshold, lvl in _RISK_LEVELS:
        if score >= threshold:
            level = lvl
            break

    explanation_extra = ""
    if any(f.severity == Severity.CRITICAL and f.confidence == Confidence.HIGH for f in unique):
        if level in (RiskLevel.INFORMATIONAL, RiskLevel.LOW, RiskLevel.MEDIUM):
            level = RiskLevel.HIGH
        explanation_extra = " At least one high-confidence critical finding is present."

    if not unique:
        explanation = (
            "No security findings were produced by static analysis. "
            "This does not prove the skill is safe."
        )
    else:
        explanation = (
            f"Score {score}/100 based on weighted severity×confidence "
            f"(critical={counts['critical']}, high={counts['high']}, "
            f"medium={counts['medium']}, low={counts['low']}). "
        )
        if drivers:
            explanation += "Top drivers: " + "; ".join(drivers) + "."
        explanation += explanation_extra

    return RiskAssessment(
        level=level,
        score=score,
        explanation=explanation.strip(),
        finding_counts={k: v for k, v in counts.items() if v},
    )


def assess_overall_risk(assessments: list[RiskAssessment]) -> tuple[RiskLevel, float]:
    if not assessments:
        return RiskLevel.INFORMATIONAL, 0.0
    order = {
        RiskLevel.INFORMATIONAL: 0,
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    worst = max(assessments, key=lambda a: (order[a.level], a.score))
    return worst.level, worst.score
