"""Extra AST coverage for pickle/import paths."""

from __future__ import annotations

from pathlib import Path

from skillguard.config import ScanConfig
from skillguard.rules.ast_python import PythonAstSecurityRule
from skillguard.scanner.parser import load_skill


def _skill(tmp_path: Path, name: str, code: str) -> list:
    skill = tmp_path / name
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: AST coverage fixture for {name} testing.\n---\n\n# A\n",
        encoding="utf-8",
    )
    scripts = skill / "scripts"
    scripts.mkdir()
    (scripts / "x.py").write_text(code, encoding="utf-8")
    return PythonAstSecurityRule().check(load_skill(skill, ScanConfig()))


def test_pickle_loads(tmp_path: Path) -> None:
    findings = _skill(tmp_path, "ast-pickle", "import pickle\npickle.loads(b'x')\n")
    assert findings


def test_syntax_error_informational(tmp_path: Path) -> None:
    findings = _skill(tmp_path, "ast-bad", "def (\n")
    assert any(f.severity.value == "informational" for f in findings)
