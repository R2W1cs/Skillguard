"""Sandbox unit tests (no Docker required)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from skillguard.config import ScanConfig
from skillguard.sandbox.docker_runner import docker_available, run_sandbox_analysis
from skillguard.sandbox.policy import DEFAULT_POLICY
from skillguard.scanner.engine import ScanEngine
from skillguard.scanner.parser import load_skill


def test_policy_secure_defaults() -> None:
    assert DEFAULT_POLICY.network_disabled
    assert DEFAULT_POLICY.read_only_root
    assert DEFAULT_POLICY.allow_network is False
    assert "ALL" in DEFAULT_POLICY.cap_drop


def test_docker_available_false_without_binary() -> None:
    with patch("skillguard.sandbox.docker_runner.shutil.which", return_value=None):
        assert docker_available() is False


def test_run_sandbox_skipped_when_unavailable(benign_skill: Path) -> None:
    skill = load_skill(benign_skill, ScanConfig())
    with patch("skillguard.sandbox.docker_runner.docker_available", return_value=False):
        result = run_sandbox_analysis(skill)
    assert result.performed is False
    assert result.available is False


def test_engine_sandbox_path(benign_skill: Path) -> None:
    fake = MagicMock()
    fake.performed = False
    fake.available = False
    fake.summary = "skipped"
    fake.observations = []
    fake.error = None
    with patch(
        "skillguard.sandbox.docker_runner.run_sandbox_analysis",
        return_value=fake,
    ):
        report = ScanEngine(ScanConfig(enable_sandbox=True)).scan_path(benign_skill)
    assert report.skills[0].sandbox is not None
    assert report.skills[0].sandbox["performed"] is False
