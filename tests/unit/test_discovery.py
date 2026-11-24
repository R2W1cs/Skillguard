"""Discovery unit tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from skillguard.config import ScanConfig
from skillguard.scanner.discovery import DiscoveryError, find_skill_roots


def test_discover_single_skill(benign_skill: Path) -> None:
    roots = find_skill_roots(benign_skill, ScanConfig())
    assert roots == [benign_skill.resolve()]


def test_discover_collection(fixtures_root: Path) -> None:
    roots = find_skill_roots(fixtures_root / "benign", ScanConfig())
    assert any(r.name == "hello-world" for r in roots)


def test_missing_path(tmp_path: Path) -> None:
    with pytest.raises(DiscoveryError):
        find_skill_roots(tmp_path / "nope", ScanConfig())


def test_symlink_dir_not_descended(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "SKILL.md").write_text(
        "---\nname: real\ndescription: real skill for symlink test cases here.\n---\n\n# R\n",
        encoding="utf-8",
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    link = tmp_path / "link-skill"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not available")
    roots = find_skill_roots(tmp_path, ScanConfig())
    # Should find real, but not treat outside as skill via symlink descent
    assert any(r.name == "real" for r in roots)
    assert all(r.name != "outside" for r in roots)
