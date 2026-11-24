"""Regression compare tests."""

from __future__ import annotations

import json
from pathlib import Path

from skillguard.compare import compare_reports, should_fail_compare
from skillguard.models.finding import Severity


def _report(path: Path, findings: list[dict], files: list[str], score: float = 10.0) -> Path:
    data = {
        "overall_score": score,
        "overall_risk": "medium" if score >= 40 else "low",
        "skills": [
            {
                "skill_name": "demo",
                "files_inspected": files,
                "findings": findings,
                "risk": {"score": score, "level": "medium"},
            }
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_compare_introduced_and_resolved(tmp_path: Path) -> None:
    old_f = {
        "rule_id": "SG-A",
        "title": "Old",
        "severity": "high",
        "file_path": "a.py",
        "evidence": {"snippet": "old"},
        "fingerprint": "fp-old-0000000001",
    }
    new_f = {
        "rule_id": "SG-B",
        "title": "New",
        "severity": "critical",
        "file_path": "b.py",
        "evidence": {"snippet": "new"},
        "fingerprint": "fp-new-0000000001",
    }
    old = _report(tmp_path / "old.json", [old_f], ["a.py"], 50)
    new = _report(tmp_path / "new.json", [new_f], ["a.py", "scripts/x.py"], 80)
    result = compare_reports(old, new)
    assert len(result.introduced) == 1
    assert result.introduced[0].rule_id == "SG-B"
    assert len(result.resolved) == 1
    assert "scripts/x.py" in result.new_scripts
    assert result.risk_delta == 30.0
    assert should_fail_compare(result, fail_on_introduced=Severity.HIGH)


def test_line_only_change_same_fingerprint(tmp_path: Path) -> None:
    from skillguard.fingerprint import stable_fingerprint

    snip = "rm -rf /"
    fp = stable_fingerprint(
        rule_id="SG-SHELL-001", file_path="run.sh", title="Danger", snippet=snip
    )
    old_f = {
        "rule_id": "SG-SHELL-001",
        "title": "Danger",
        "severity": "high",
        "file_path": "run.sh",
        "line": 3,
        "evidence": {"snippet": snip},
        "fingerprint": fp,
    }
    new_f = {**old_f, "line": 10}
    old = _report(tmp_path / "old.json", [old_f], ["run.sh"])
    new = _report(tmp_path / "new.json", [new_f], ["run.sh"])
    result = compare_reports(old, new)
    assert result.introduced == []
    assert result.resolved == []


def test_severity_increase(tmp_path: Path) -> None:
    shared = {
        "rule_id": "SG-X",
        "title": "Same",
        "file_path": "x.py",
        "evidence": {"snippet": "abc"},
    }
    old = _report(
        tmp_path / "old.json",
        [{**shared, "severity": "medium", "fingerprint": "fp1"}],
        ["x.py"],
    )
    new = _report(
        tmp_path / "new.json",
        [{**shared, "severity": "critical", "fingerprint": "fp2"}],
        ["x.py"],
    )
    result = compare_reports(old, new)
    assert result.severity_increased
    assert should_fail_compare(result, fail_on_introduced=Severity.HIGH)
