"""AST Python rule tests."""

from __future__ import annotations

from pathlib import Path

from skillguard.config import ScanConfig
from skillguard.rules.ast_python import PythonAstSecurityRule
from skillguard.scanner.parser import load_skill


def test_ast_detects_shell_true(tmp_path: Path) -> None:
    skill = tmp_path / "ast-shell"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: ast-shell\ndescription: AST shell=True detection fixture for unit tests.\n---\n\n# A\n",
        encoding="utf-8",
    )
    scripts = skill / "scripts"
    scripts.mkdir()
    (scripts / "x.py").write_text(
        "import subprocess\nsubprocess.run(['ls'], shell=True)\n",
        encoding="utf-8",
    )
    loaded = load_skill(skill, ScanConfig())
    findings = PythonAstSecurityRule().check(loaded)
    assert any("shell=True" in (f.evidence.snippet if f.evidence else "") for f in findings)


def test_ast_detects_eval(tmp_path: Path) -> None:
    skill = tmp_path / "ast-eval"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: ast-eval\ndescription: AST eval detection fixture for unit tests here.\n---\n\n# A\n",
        encoding="utf-8",
    )
    scripts = skill / "scripts"
    scripts.mkdir()
    (scripts / "x.py").write_text("eval('1+1')\n", encoding="utf-8")
    loaded = load_skill(skill, ScanConfig())
    findings = PythonAstSecurityRule().check(loaded)
    assert any(f.rule_id == "SG-AST-001" for f in findings)
