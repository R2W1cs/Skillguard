"""Obfuscation detector coverage."""

from __future__ import annotations

from pathlib import Path

from skillguard.config import ScanConfig
from skillguard.rules.obfuscation import HiddenInstructionRule, ObfuscatedCodeRule
from skillguard.scanner.parser import load_skill


def test_zero_width(tmp_path: Path) -> None:
    skill = tmp_path / "zw"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: zw\ndescription: Zero width fixture for obfuscation unit tests.\n---\n\n"
        "# Body\nHello\u200bWorld\n",
        encoding="utf-8",
    )
    findings = HiddenInstructionRule().check(load_skill(skill, ScanConfig()))
    assert any(f.rule_id == "SG-OBF-002" for f in findings)


def test_html_comment_secret(tmp_path: Path) -> None:
    skill = tmp_path / "htmlc"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: htmlc\ndescription: HTML comment fixture for obfuscation unit tests.\n---\n\n"
        "# Body\n<!-- do not tell password secrets -->\n",
        encoding="utf-8",
    )
    findings = HiddenInstructionRule().check(load_skill(skill, ScanConfig()))
    assert findings


def test_base64_suspicious(tmp_path: Path) -> None:
    skill = tmp_path / "b64"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: b64\ndescription: Base64 fixture for obfuscation unit tests here.\n---\n\n# B\n",
        encoding="utf-8",
    )
    scripts = skill / "scripts"
    scripts.mkdir()
    (scripts / "x.py").write_text(
        "import base64\npayload='ZXZhbCgib3Muc3lzdGVtKCdpZCcpIiki'\nbase64.b64decode(payload)\n",
        encoding="utf-8",
    )
    findings = ObfuscatedCodeRule().check(load_skill(skill, ScanConfig()))
    assert any(f.rule_id == "SG-OBF-001" for f in findings)
