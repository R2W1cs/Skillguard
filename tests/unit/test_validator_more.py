"""Additional validator coverage."""

from __future__ import annotations

from pathlib import Path

from skillguard.config import ScanConfig
from skillguard.scanner.parser import load_skill
from skillguard.scanner.validator import validate_skill


def test_name_directory_mismatch(tmp_path: Path) -> None:
    skill = tmp_path / "folder-a"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: folder-b\ndescription: Mismatch fixture for validator coverage tests.\n---\n\n# X\n",
        encoding="utf-8",
    )
    findings = validate_skill(load_skill(skill, ScanConfig()))
    assert any(f.rule_id == "SG-STRUCT-005" for f in findings)


def test_invalid_name_chars(tmp_path: Path) -> None:
    skill = tmp_path / "Bad_Name"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: Bad_Name\ndescription: Invalid name chars fixture for validator tests.\n---\n\n# X\n",
        encoding="utf-8",
    )
    findings = validate_skill(load_skill(skill, ScanConfig()))
    assert any(f.rule_id == "SG-STRUCT-004" for f in findings)
