"""Strict image / digest pinning fail-closed tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from skillguard.sandbox.docker_runner import _verify_image_digest
from skillguard.sandbox.policy import SandboxPolicy


def test_strict_rejects_mutable_latest() -> None:
    with pytest.raises(ValidationError):
        SandboxPolicy(image="python:latest", strict_image=True)


def test_strict_rejects_tag_without_digest() -> None:
    with pytest.raises(ValidationError):
        SandboxPolicy(image="python:3.12.8-alpine", strict_image=True)


def test_strict_accepts_digest_pin() -> None:
    digest = "a" * 64
    p = SandboxPolicy(image=f"python@sha256:{digest}", strict_image=True)
    assert p.is_digest_pinned()
    assert p.require_digest is True


def test_expected_digest_mismatch() -> None:
    digest = "b" * 64
    with pytest.raises(ValidationError):
        SandboxPolicy(
            image=f"python@sha256:{'a' * 64}",
            expected_image_digest=f"sha256:{digest}",
            strict_image=True,
        )


def test_verify_image_digest_fail_closed() -> None:
    digest = "c" * 64
    pol = SandboxPolicy(image=f"python@sha256:{digest}", strict_image=True)
    client = MagicMock()
    img = MagicMock()
    img.attrs = {"RepoDigests": ["python@sha256:" + ("d" * 64)], "Id": "sha256:" + ("e" * 64)}
    client.images.get.return_value = img
    with pytest.raises(ValueError, match="digest verification failed"):
        _verify_image_digest(client, pol)


def test_verify_image_digest_ok() -> None:
    digest = "f" * 64
    pol = SandboxPolicy(image=f"python@sha256:{digest}", strict_image=True)
    client = MagicMock()
    img = MagicMock()
    img.attrs = {"RepoDigests": [f"python@sha256:{digest}"], "Id": f"sha256:{digest}"}
    client.images.get.return_value = img
    _verify_image_digest(client, pol)  # no raise
