"""Audit manifest tests."""

from __future__ import annotations

from pathlib import Path

from skillguard import __version__
from skillguard.audit import build_audit_manifest, verify_manifest_digest, write_audit_manifest
from skillguard.models.finding import Category, Confidence, Finding, Severity
from skillguard.models.report import RiskAssessment, RiskLevel, ScanReport, SkillReport


def test_deterministic_manifest(tmp_path: Path) -> None:
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: demo\n---\n# Demo\n", encoding="utf-8")
    report = ScanReport(
        scanner_version=__version__,
        target=str(skill),
        skills=[
            SkillReport(
                skill_name="demo",
                skill_path=str(skill),
                findings=[
                    Finding(
                        rule_id="SG-T",
                        title="t",
                        description="d",
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        category=Category.OTHER,
                        file_path="SKILL.md",
                        remediation="r",
                    ).with_fingerprint()
                ],
                risk=RiskAssessment(level=RiskLevel.LOW, score=5.0, explanation="e"),
                files_inspected=["SKILL.md"],
                limitations=["static only"],
            )
        ],
    )
    m1 = build_audit_manifest(report, config_dict={"fail_on": None})[0]
    m2 = build_audit_manifest(report, config_dict={"fail_on": None})[0]
    # timestamps differ — compare structural digests of findings/files
    assert m1.files_hash == m2.files_hash
    assert m1.findings_hash == m2.findings_hash
    assert m1.skillguard_version == __version__
    assert m1.file_hashes[0].sha256
    out = tmp_path / "audit.json"
    write_audit_manifest(m1, out)
    digest = verify_manifest_digest(out)
    assert len(digest) == 64
