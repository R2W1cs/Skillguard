"""End-to-end scan workflow tests."""

from __future__ import annotations

from pathlib import Path

from skillguard.config import ScanConfig
from skillguard.models.finding import Severity
from skillguard.models.report import RiskLevel
from skillguard.scanner.engine import ScanEngine


def test_scan_benign(benign_skill: Path) -> None:
    report = ScanEngine(ScanConfig()).scan_path(benign_skill)
    assert len(report.skills) == 1
    skill = report.skills[0]
    critical = [f for f in skill.findings if f.severity == Severity.CRITICAL]
    assert critical == []
    assert skill.quality is not None
    assert skill.risk.level in (
        RiskLevel.INFORMATIONAL,
        RiskLevel.LOW,
        RiskLevel.MEDIUM,
    )


def test_scan_malicious_triggers_rules(malicious_secret: Path) -> None:
    report = ScanEngine(ScanConfig()).scan_path(malicious_secret)
    ids = {f.rule_id for f in report.skills[0].findings}
    assert "SG-SECRET-001" in ids
    assert report.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_scan_directory_of_skills(fixtures_root: Path) -> None:
    report = ScanEngine(ScanConfig()).scan_path(fixtures_root / "malicious")
    assert len(report.skills) >= 3


def test_sandbox_skipped_without_opt_in(benign_skill: Path) -> None:
    report = ScanEngine(ScanConfig(enable_sandbox=False)).scan_path(benign_skill)
    assert report.skills[0].sandbox is None
