"""Ensure published metadata points at the real GitHub repository."""

from __future__ import annotations

from pathlib import Path

from skillguard.config import ScanConfig
from skillguard.reporting.sarif_report import write_sarif_report
from skillguard.scanner.engine import ScanEngine


def test_pyproject_urls() -> None:
    text = Path("pyproject.toml").read_text(encoding="utf-8")
    assert "https://github.com/R2W1cs/Skillguard" in text
    assert "https://github.com/skillguard/skillguard" not in text


def test_sarif_information_uri(benign_skill: Path, tmp_path: Path) -> None:
    report = ScanEngine(ScanConfig(show_progress=False)).scan_path(benign_skill)
    out = tmp_path / "out.sarif"
    write_sarif_report(report, out)
    blob = out.read_text(encoding="utf-8")
    assert "https://github.com/R2W1cs/Skillguard" in blob
    assert "skillguard/skillguard" not in blob


def test_integration_examples_exist() -> None:
    assert Path("examples/pre-commit-config.yaml").is_file()
    assert Path("examples/github-actions-skillguard.yml").is_file()
    assert Path("integrations/pre-commit-hook.sh").is_file()
    assert Path(".github/workflows/skillguard-scan.yml").is_file()
    assert Path("mkdocs.yml").is_file()
