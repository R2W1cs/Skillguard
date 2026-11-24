"""Additional discovery/parser edge coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from skillguard.config import ScanConfig
from skillguard.scanner.discovery import DiscoveryError, find_skill_roots
from skillguard.scanner.parser import classify_file, load_skill


def test_discover_skill_md_file(benign_skill: Path) -> None:
    roots = find_skill_roots(benign_skill / "SKILL.md", ScanConfig())
    assert roots == [benign_skill.resolve()]


def test_discover_regular_file_errors(tmp_path: Path) -> None:
    f = tmp_path / "readme.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(DiscoveryError):
        find_skill_roots(f, ScanConfig())


def test_classify_file() -> None:
    assert classify_file("SKILL.md").value == "skill_md"
    assert classify_file("scripts/a.py").value == "script"
    assert classify_file("references/x.md").value == "reference"
    assert classify_file("package.json").value == "config"


def test_binary_file_not_loaded_as_text(tmp_path: Path) -> None:
    skill = tmp_path / "bin-skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: bin-skill\ndescription: binary fixture for parser coverage tests.\n---\n\n# B\n",
        encoding="utf-8",
    )
    (skill / "blob.bin").write_bytes(b"\x00\x01\x02\x03" + b"A" * 100)
    loaded = load_skill(skill, ScanConfig())
    blob = next(f for f in loaded.files if f.relative_path.endswith("blob.bin"))
    assert blob.binary
    assert blob.content is None
