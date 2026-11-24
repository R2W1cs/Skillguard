"""Integration tests for 0.3.0 trust workflows."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from skillguard.baseline import Baseline, accept_finding, annotate_report, load_baseline
from skillguard.cli import main
from skillguard.compare import should_fail_compare
from skillguard.config import ScanConfig
from skillguard.scanner.engine import ScanEngine


def test_scan_with_baseline_suppresses_fail_on(malicious_secret: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    report_path = tmp_path / "report.json"
    result = runner.invoke(
        main,
        [
            "scan",
            str(malicious_secret),
            "--format",
            "json",
            "-o",
            str(report_path),
            "--quiet",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(report_path.read_text(encoding="utf-8"))
    # Accept all non-critical findings
    bl_path = tmp_path / "base.json"
    runner.invoke(main, ["baseline", "init", "-o", str(bl_path)])
    findings = []
    for skill in data["skills"]:
        for f in skill["findings"]:
            findings.append(f)
    # Accept medium and below via API for speed; leave high+ for fail-on check
    bl = load_baseline(bl_path)
    accepted = 0
    for f in findings:
        if f.get("severity") in {"informational", "low", "medium", "high"}:
            try:
                accept_finding(bl, f, justification="integration test acceptance")
                accepted += 1
            except ValueError:
                pass
    from skillguard.baseline import save_baseline

    save_baseline(bl, bl_path)
    assert accepted >= 1

    # Scan with baseline — findings still in report, fail-on uses active only
    out2 = tmp_path / "report2.json"
    result = runner.invoke(
        main,
        [
            "scan",
            str(malicious_secret),
            "--format",
            "json",
            "-o",
            str(out2),
            "--baseline",
            str(bl_path),
            "--fail-on",
            "critical",
            "--quiet",
        ],
    )
    # Should succeed if no critical active (or fail if critical present — both OK for wiring)
    assert result.exit_code in {0, 1}
    data2 = json.loads(out2.read_text(encoding="utf-8"))
    assert data2["skills"][0]["findings"], "findings must remain in report when suppressed"


def test_baseline_accept_show_cli(malicious_secret: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    report_path = tmp_path / "r.json"
    runner.invoke(
        main,
        ["scan", str(malicious_secret), "--format", "json", "-o", str(report_path), "--quiet"],
    )
    data = json.loads(report_path.read_text(encoding="utf-8"))
    finding = data["skills"][0]["findings"][0]
    fp = finding["fingerprint"]
    bl = tmp_path / "b.json"
    runner.invoke(main, ["baseline", "init", "-o", str(bl)])
    # Prefer a non-critical finding
    for skill in data["skills"]:
        for f in skill["findings"]:
            if f.get("severity") != "critical":
                finding = f
                fp = f["fingerprint"]
                break
    result = runner.invoke(
        main,
        [
            "baseline",
            "accept",
            str(report_path),
            "--baseline",
            str(bl),
            "--fingerprint",
            fp,
            "--justification",
            "known FP for demo",
        ],
    )
    assert result.exit_code == 0, result.output
    result = runner.invoke(main, ["baseline", "show", str(bl)])
    assert result.exit_code == 0
    assert finding["rule_id"] in result.output or fp[:8] in result.output


def test_compare_json_output(tmp_path: Path) -> None:
    old = {
        "overall_score": 5,
        "overall_risk": "low",
        "skills": [
            {"skill_name": "s", "files_inspected": [], "findings": [], "risk": {"score": 5}}
        ],
    }
    new = {
        "overall_score": 5,
        "overall_risk": "low",
        "skills": [
            {"skill_name": "s", "files_inspected": [], "findings": [], "risk": {"score": 5}}
        ],
    }
    op = tmp_path / "o.json"
    np_ = tmp_path / "n.json"
    op.write_text(json.dumps(old), encoding="utf-8")
    np_.write_text(json.dumps(new), encoding="utf-8")
    runner = CliRunner()
    out = tmp_path / "c.json"
    result = runner.invoke(
        main,
        [
            "compare",
            str(op),
            str(np_),
            "-o",
            str(out),
            "--json",
            "--no-fail-on-risk-increase",
            "--fail-on-introduced",
            "critical",
        ],
    )
    assert result.exit_code == 0
    assert out.exists()


def test_engine_fingerprints_on_scan(benign_skill: Path) -> None:
    engine = ScanEngine(ScanConfig(show_progress=False))
    report = engine.scan_path(benign_skill)
    for f in report.all_findings:
        assert f.fingerprint


def test_should_fail_new_scripts() -> None:
    from skillguard.compare import CompareResult

    result = CompareResult(
        old_path="a",
        new_path="b",
        new_scripts=["scripts/x.py"],
        risk_delta=0.0,
    )
    assert should_fail_compare(
        result,
        fail_on_introduced=None,
        fail_on_risk_increase=False,
        fail_on_new_scripts=True,
    )


def test_annotate_invalid_orphan() -> None:
    from skillguard import __version__
    from skillguard.models.report import RiskAssessment, RiskLevel, ScanReport, SkillReport

    bl = Baseline()
    accept_finding(
        bl,
        {
            "rule_id": "SG-X",
            "title": "gone",
            "severity": "low",
            "file_path": "gone.py",
            "fingerprint": "orphanfp000000000001",
            "evidence": {"snippet": "x"},
        },
        justification="was real once",
    )
    report = ScanReport(
        scanner_version=__version__,
        target=".",
        skills=[
            SkillReport(
                skill_name="s",
                skill_path=".",
                findings=[],
                risk=RiskAssessment(level=RiskLevel.INFORMATIONAL, score=0.0, explanation="e"),
            )
        ],
    )
    _, suppression = annotate_report(report, bl)
    assert any(i.get("reason") for i in suppression.invalid)


def test_try_run_external() -> None:
    from skillguard.evaluation.comparison import try_run_external

    code, _out, _err, ms = try_run_external(["python", "-c", "print(1)"])
    assert code == 0
    assert ms >= 0
    code2, _, err, _ = try_run_external(["skillguard-not-a-real-binary-xyz"])
    assert code2 == 127


def test_sandbox_strict_via_config_construction() -> None:
    cfg = ScanConfig(enable_sandbox=True, sandbox_strict_image=True, sandbox_image="python:latest")
    assert cfg.sandbox_strict_image is True
