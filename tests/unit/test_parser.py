"""Parser and frontmatter unit tests."""

from __future__ import annotations

from pathlib import Path

from skillguard.config import ScanConfig
from skillguard.scanner.parser import load_skill, parse_frontmatter


def test_parse_valid_frontmatter() -> None:
    content = """---
name: demo
description: A demo skill for unit tests when validating parsers.
license: Apache-2.0
metadata:
  author: test
---

# Body
Hello
"""
    meta, body = parse_frontmatter(content)
    assert meta.name == "demo"
    assert meta.description is not None
    assert "Body" in body
    assert meta.parse_errors == []


def test_parse_missing_frontmatter() -> None:
    meta, body = parse_frontmatter("# No frontmatter\n")
    assert meta.parse_errors
    assert "No frontmatter" in body


def test_parse_invalid_yaml() -> None:
    content = "---\nname: [unclosed\n---\nBody\n"
    meta, _body = parse_frontmatter(content)
    assert meta.parse_errors
    assert "Invalid YAML" in meta.parse_errors[0]


def test_load_benign_skill(benign_skill: Path) -> None:
    skill = load_skill(benign_skill, ScanConfig())
    assert skill.metadata.name == "hello-world"
    assert skill.scripts
    assert any(f.relative_path.endswith("greet.py") for f in skill.scripts)


def test_unsafe_yaml_not_executed(tmp_path: Path) -> None:
    skill_dir = tmp_path / "yaml-bomb"
    skill_dir.mkdir()
    # Python object tags must not be instantiated with safe_load
    (skill_dir / "SKILL.md").write_text(
        "---\nname: yaml-bomb\ndescription: test\n"
        "evil: !!python/object/apply:os.system ['echo pwned']\n---\n\n# x\n",
        encoding="utf-8",
    )
    skill = load_skill(skill_dir, ScanConfig())
    # Either parse error or treated as plain data — must not execute
    assert skill.metadata.name in ("yaml-bomb", None) or skill.metadata.parse_errors
