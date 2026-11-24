"""CLI tests via Click test runner."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from skillguard.cli import main


def test_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert "skillguard" in result.output


def test_rules_list_and_show() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["rules", "list"])
    assert result.exit_code == 0
    assert "SG-SECRET-001" in result.output
    result = runner.invoke(main, ["rules", "show", "SG-SECRET-001"])
    assert result.exit_code == 0
    assert "Hardcoded" in result.output or "API" in result.output
    result = runner.invoke(main, ["rules", "show", "SG-NOPE"])
    assert result.exit_code == 2


def test_scan_json(benign_skill: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "r.json"
    result = runner.invoke(
        main,
        ["scan", str(benign_skill), "--format", "json", "--output", str(out), "--quiet"],
    )
    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["skills"]


def test_scan_sarif(malicious_secret: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", str(malicious_secret), "--format", "sarif", "--quiet"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"


def test_fail_on_high(malicious_secret: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", str(malicious_secret), "--fail-on", "high", "--format", "json", "--quiet"],
    )
    assert result.exit_code == 1


def test_fail_on_high_benign_ok(benign_skill: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", str(benign_skill), "--fail-on", "critical", "--format", "json", "--quiet"],
    )
    assert result.exit_code == 0


def test_benchmark_run(fixtures_root: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["benchmark", "run", "--fixtures", str(fixtures_root)])
    assert result.exit_code == 0
    assert (
        "Precision" in result.output
        or "precision" in result.output.lower()
        or "TP=" in result.output
    )


def test_compare_cli(tmp_path: Path) -> None:
    old = {
        "overall_score": 10,
        "overall_risk": "low",
        "skills": [
            {
                "skill_name": "a",
                "files_inspected": ["a.py"],
                "findings": [],
                "risk": {"score": 10, "level": "low"},
            }
        ],
    }
    new = {
        "overall_score": 80,
        "overall_risk": "high",
        "skills": [
            {
                "skill_name": "a",
                "files_inspected": ["a.py", "scripts/x.py"],
                "findings": [
                    {
                        "rule_id": "SG-X",
                        "title": "Bad",
                        "severity": "critical",
                        "file_path": "scripts/x.py",
                        "fingerprint": "fp-cli-test-00000001",
                        "evidence": {"snippet": "x"},
                    }
                ],
                "risk": {"score": 80, "level": "high"},
            }
        ],
    }
    old_p = tmp_path / "old.json"
    new_p = tmp_path / "new.json"
    old_p.write_text(json.dumps(old), encoding="utf-8")
    new_p.write_text(json.dumps(new), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(old_p), str(new_p)])
    assert result.exit_code == 1
    assert "Introduced" in result.output


def test_baseline_and_audit_cli(benign_skill: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    bl = tmp_path / "base.json"
    result = runner.invoke(main, ["baseline", "init", "-o", str(bl)])
    assert result.exit_code == 0
    assert bl.exists()
    audit_out = tmp_path / "audit.json"
    result = runner.invoke(
        main,
        ["audit", str(benign_skill), "-o", str(audit_out), "--quiet"],
    )
    assert result.exit_code == 0
    assert audit_out.exists()
    data = json.loads(audit_out.read_text(encoding="utf-8"))
    assert "file_hashes" in data
    assert data["skillguard_version"]


def test_compare_tools_cli(fixtures_root: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "cmp.json"
    result = runner.invoke(
        main,
        [
            "benchmark",
            "compare-tools",
            "--fixtures",
            str(fixtures_root),
            "--limit",
            "3",
            "--json-out",
            str(out),
        ],
    )
    assert result.exit_code == 0
    assert out.exists()
    assert "SkillGuard" in result.output
