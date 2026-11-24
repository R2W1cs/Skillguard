"""Config unit tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from skillguard.config import ScanConfig


def test_from_file(tmp_path: Path) -> None:
    path = tmp_path / "cfg.yaml"
    path.write_text(
        "max_file_size_bytes: 1234\nexclude_globs:\n  - '**/vendor/**'\n",
        encoding="utf-8",
    )
    cfg = ScanConfig.from_file(path)
    assert cfg.max_file_size_bytes == 1234
    assert "**/vendor/**" in cfg.exclude_globs


def test_from_file_invalid(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("- not a mapping\n", encoding="utf-8")
    with pytest.raises(ValueError):
        ScanConfig.from_file(path)


def test_is_excluded() -> None:
    cfg = ScanConfig()
    assert cfg.is_excluded("node_modules/pkg/index.js")
    assert cfg.is_excluded(".git/config")
    assert not cfg.is_excluded("scripts/ok.py")
