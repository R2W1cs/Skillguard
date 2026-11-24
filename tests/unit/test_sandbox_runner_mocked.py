"""Sandbox runner unit tests with mocks (no Docker required)."""

from __future__ import annotations

import contextlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from skillguard.config import ScanConfig
from skillguard.sandbox.docker_runner import _copy_skill, run_sandbox_analysis
from skillguard.sandbox.policy import SandboxPolicy
from skillguard.scanner.parser import load_skill


def test_copy_skill_skips_symlinks(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("hi", encoding="utf-8")
    link = src / "link.txt"
    with contextlib.suppress(OSError):
        link.symlink_to(tmp_path / "outside.txt")
    dest = tmp_path / "dest"
    _copy_skill(src, dest)
    assert (dest / "a.txt").read_text(encoding="utf-8") == "hi"


def test_run_sandbox_success_mocked(benign_skill: Path) -> None:
    skill = load_skill(benign_skill, ScanConfig())
    container = MagicMock()
    container.wait.return_value = {"StatusCode": 0}
    container.logs.return_value = b"SANDBOX_OK\nFILES 2\nPY_COMPILE ok\n"
    client = MagicMock()
    client.containers.run.return_value = container

    with (
        patch("skillguard.sandbox.docker_runner.docker_available", return_value=True),
        patch("docker.from_env", return_value=client),
    ):
        result = run_sandbox_analysis(skill, SandboxPolicy(timeout_seconds=5))

    assert result.performed is True
    assert result.available is True
    assert any("SANDBOX_OK" in line for line in result.observations)
    # Ensure privileged=False and network none in call kwargs
    kwargs = client.containers.run.call_args.kwargs
    assert kwargs.get("privileged") is False
    assert kwargs.get("network_mode") == "none"
    assert kwargs.get("user") == "65534:65534"


def test_run_sandbox_timeout_kills(benign_skill: Path) -> None:
    skill = load_skill(benign_skill, ScanConfig())
    container = MagicMock()
    container.wait.side_effect = Exception("timeout")
    client = MagicMock()
    client.containers.run.return_value = container
    with (
        patch("skillguard.sandbox.docker_runner.docker_available", return_value=True),
        patch("docker.from_env", return_value=client),
    ):
        result = run_sandbox_analysis(skill, SandboxPolicy(timeout_seconds=1))
    assert result.performed is False
    assert result.error
    container.kill.assert_called()
