"""Additional compare coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skillguard.compare import compare_reports, should_fail_compare
from skillguard.models.finding import Severity


def test_compare_bad_json(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("[1,2,3]", encoding="utf-8")
    good = tmp_path / "good.json"
    good.write_text(
        json.dumps({"skills": [], "overall_score": 0, "overall_risk": "informational"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        compare_reports(p, good)


def test_format_terminal_with_lists(tmp_path: Path) -> None:
    old = {
        "overall_score": 10,
        "overall_risk": "low",
        "skills": [
            {
                "skill_name": "s",
                "files_inspected": ["a.py"],
                "findings": [
                    {
                        "rule_id": "SG-A",
                        "title": "A",
                        "severity": "medium",
                        "file_path": "a.py",
                        "fingerprint": "fp-a",
                        "evidence": {"snippet": "old"},
                    }
                ],
                "risk": {"score": 10},
            }
        ],
    }
    new = {
        "overall_score": 40,
        "overall_risk": "medium",
        "skills": [
            {
                "skill_name": "s",
                "files_inspected": ["a.py", "b.py"],
                "findings": [
                    {
                        "rule_id": "SG-A",
                        "title": "A",
                        "severity": "high",
                        "file_path": "a.py",
                        "fingerprint": "fp-a2",
                        "evidence": {"snippet": "new"},
                    },
                    {
                        "rule_id": "SG-B",
                        "title": "B",
                        "severity": "high",
                        "file_path": "b.py",
                        "fingerprint": "fp-b",
                        "evidence": {"snippet": "x"},
                    },
                ],
                "risk": {"score": 40},
            }
        ],
    }
    op = tmp_path / "o.json"
    np_ = tmp_path / "n.json"
    op.write_text(json.dumps(old), encoding="utf-8")
    np_.write_text(json.dumps(new), encoding="utf-8")
    result = compare_reports(op, np_)
    text = result.format_terminal()
    assert "Severity increased" in text or "severity" in text.lower()
    assert "New findings" in text or "Introduced" in text
    assert should_fail_compare(result, fail_on_introduced=Severity.MEDIUM)
