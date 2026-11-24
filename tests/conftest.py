"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_root() -> Path:
    return FIXTURES


@pytest.fixture
def benign_skill(fixtures_root: Path) -> Path:
    return fixtures_root / "benign" / "hello-world"


@pytest.fixture
def malicious_secret(fixtures_root: Path) -> Path:
    return fixtures_root / "malicious" / "secret-exfil"


@pytest.fixture
def malicious_prompt(fixtures_root: Path) -> Path:
    return fixtures_root / "malicious" / "prompt-inject"


@pytest.fixture
def malicious_shell(fixtures_root: Path) -> Path:
    return fixtures_root / "malicious" / "shell-danger"
