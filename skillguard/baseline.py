"""Audit baselines — accept known findings without rewriting scan results."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from skillguard.fingerprint import fingerprint_from_finding_dict
from skillguard.models.finding import SEVERITY_ORDER, Finding, Severity
from skillguard.models.report import ScanReport


class BaselineEntry(BaseModel):
    fingerprint: str
    rule_id: str
    file_path: str
    title: str
    severity: str
    justification: str
    accepted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    accepted_by: str | None = None
    expires_at: datetime | None = None
    skill_name: str | None = None


class Baseline(BaseModel):
    version: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    entries: list[BaselineEntry] = Field(default_factory=list)
    # Policy: critical findings cannot be suppressed unless explicitly allowed
    allow_critical_suppressions: bool = False

    def by_fingerprint(self) -> dict[str, BaselineEntry]:
        return {e.fingerprint: e for e in self.entries}


class SuppressionResult(BaseModel):
    """Annotation layer — does not remove findings from the scan report."""

    active: list[dict[str, Any]] = Field(default_factory=list)
    suppressed: list[dict[str, Any]] = Field(default_factory=list)
    expired: list[dict[str, Any]] = Field(default_factory=list)
    invalid: list[dict[str, Any]] = Field(default_factory=list)
    blocked_critical: list[dict[str, Any]] = Field(default_factory=list)


def load_baseline(path: Path) -> Baseline:
    data = json.loads(path.read_text(encoding="utf-8"))
    return Baseline.model_validate(data)


def save_baseline(baseline: Baseline, path: Path) -> None:
    baseline.updated_at = datetime.now(UTC)
    path.write_text(
        json.dumps(json.loads(baseline.model_dump_json()), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def accept_finding(
    baseline: Baseline,
    finding: dict[str, Any] | Finding,
    *,
    justification: str,
    accepted_by: str | None = None,
    expires_days: int | None = 90,
    skill_name: str | None = None,
) -> BaselineEntry:
    if not justification or not justification.strip():
        raise ValueError("Justification is required to accept a finding")

    if isinstance(finding, Finding):
        finding = finding.model_dump(mode="json")

    severity = str(finding.get("severity", "informational"))
    if severity == Severity.CRITICAL.value and not baseline.allow_critical_suppressions:
        raise ValueError(
            "Refusing to suppress a critical finding. "
            "Set allow_critical_suppressions=true in the baseline only with explicit policy approval."
        )

    fp = fingerprint_from_finding_dict(finding)
    expires_at = None
    if expires_days is not None:
        expires_at = datetime.now(UTC) + timedelta(days=expires_days)

    entry = BaselineEntry(
        fingerprint=fp,
        rule_id=str(finding.get("rule_id", "")),
        file_path=str(finding.get("file_path", "")),
        title=str(finding.get("title", "")),
        severity=severity,
        justification=justification.strip(),
        accepted_by=accepted_by,
        expires_at=expires_at,
        skill_name=skill_name,
    )
    # Replace existing same fingerprint
    baseline.entries = [e for e in baseline.entries if e.fingerprint != fp]
    baseline.entries.append(entry)
    return entry


def annotate_report(
    report: ScanReport,
    baseline: Baseline,
    *,
    now: datetime | None = None,
) -> tuple[ScanReport, SuppressionResult]:
    """Return the original findings unchanged, plus a suppression annotation.

    Suppressed findings remain in ``report.findings``; consumers must use the
    annotation to distinguish suppressed vs active. Critical suppressions are
    blocked unless ``allow_critical_suppressions`` is enabled.
    """
    now = now or datetime.now(UTC)
    index = baseline.by_fingerprint()
    result = SuppressionResult()

    # Ensure fingerprints exist
    for skill in report.skills:
        updated: list[Finding] = []
        for finding in skill.findings:
            f = finding.with_fingerprint()
            updated.append(f)
            item = {
                "fingerprint": f.fingerprint,
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "file_path": f.file_path,
                "skill_name": skill.skill_name,
            }
            entry = index.get(f.fingerprint or "")
            if entry is None:
                result.active.append(item)
                continue
            if entry.expires_at and entry.expires_at <= now:
                result.expired.append({**item, "justification": entry.justification})
                result.active.append(item)
                continue
            if f.severity == Severity.CRITICAL and not baseline.allow_critical_suppressions:
                result.blocked_critical.append({**item, "justification": entry.justification})
                result.active.append(item)
                continue
            # Validate rule/file still match (invalid if drift)
            if entry.rule_id != f.rule_id or entry.file_path.replace(
                "\\", "/"
            ) != f.file_path.replace("\\", "/"):
                result.invalid.append(
                    {
                        **item,
                        "reason": "baseline entry rule_id/file_path mismatch",
                        "justification": entry.justification,
                    }
                )
                result.active.append(item)
                continue
            result.suppressed.append(
                {
                    **item,
                    "justification": entry.justification,
                    "accepted_at": entry.accepted_at.isoformat(),
                    "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
                }
            )
        skill.findings = updated

    # Orphan baseline entries (accepted but not present now)
    seen = {f.fingerprint for s in report.skills for f in s.findings if f.fingerprint}
    for fp, entry in index.items():
        if fp not in seen:
            result.invalid.append(
                {
                    "fingerprint": fp,
                    "rule_id": entry.rule_id,
                    "file_path": entry.file_path,
                    "title": entry.title,
                    "severity": entry.severity,
                    "reason": "baseline entry no longer matches any finding",
                    "justification": entry.justification,
                }
            )

    return report, result


def active_findings_for_fail_on(
    report: ScanReport,
    suppression: SuppressionResult,
) -> list[Finding]:
    """Findings that should count toward CI fail-on (excludes actively suppressed)."""
    suppressed_fps = {s["fingerprint"] for s in suppression.suppressed}
    out: list[Finding] = []
    for skill in report.skills:
        for f in skill.findings:
            fp = f.fingerprint or f.compute_fingerprint()
            if fp in suppressed_fps:
                continue
            out.append(f)
    return out


def max_active_severity(
    report: ScanReport,
    suppression: SuppressionResult,
) -> Severity | None:
    active = active_findings_for_fail_on(report, suppression)
    if not active:
        return None
    return max(active, key=lambda f: SEVERITY_ORDER[f.severity]).severity
